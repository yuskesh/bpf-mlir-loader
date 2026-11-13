#include "req/check_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "req/uprobe.h"
#include "util/gostr.h"
#include "util/mutation.h"

char *ck_dupn(const char *s)
{
	return strdup(s ? s : "");
}

char *ck_fmtd(const char *f, ...) __attribute__((format(printf, 1, 2)));
char *ck_fmtd(const char *f, ...)
{
	struct bml_buf b = {0};
	va_list ap;
	va_start(ap, f);
	int k = vsnprintf(NULL, 0, f, ap);
	va_end(ap);
	if (k < 0)
		return NULL;
	char *p = malloc((size_t)k + 1);
	if (!p)
		return NULL;
	va_start(ap, f);
	vsnprintf(p, (size_t)k + 1, f, ap);
	va_end(ap);
	(void)b;
	return p;
}


void ck_add(struct ck *c, const char *kind, const char *program, const char *name, int64_t id, char *detail)
{
	struct bml_unmets *v = c->out;
	if (v->n == v->cap) {
		size_t nc = v->cap ? v->cap * 2 : 8;
		struct bml_unmet *nu = realloc(v->u, nc * sizeof(*nu));
		if (!nu) {
			c->oom = 1;
			free(detail);
			return;
		}
		v->u = nu;
		v->cap = nc;
	}
	struct bml_unmet *u = &v->u[v->n];
	u->kind = kind;
	u->program = ck_dupn(program);
	u->name = ck_dupn(name);
	u->id = id;
	u->detail = detail ? detail : ck_dupn("");
	if (!u->program || !u->name || !u->detail) {
		free(u->program);
		free(u->name);
		free(u->detail);
		c->oom = 1;
		return;
	}
	v->n++;
}

int ck_has(const struct ck *c, void *fnptr, const char *q)
{
	if (!fnptr)
		return 0;
	return !c->caps->has_query || c->caps->has_query(c->caps->ctx, q);
}
#define HAS(c, f, q) ck_has((c), (void *)(c)->caps->f, (q))

const struct bml_loader_decl *ck_loader_of(const struct ck *c)
{
	if (c->caps->loader)
		return c->caps->loader(c->caps->ctx);
	return &bml_loader_cilium022;
}


int ck_fail(struct ck *c, char *msg)
{
	*c->err = msg ? msg : ck_dupn("check failed");
	return -1;
}

void ck_add_diffs(struct ck *c, const char *kind, const char *program, const char *name, struct bml_strs *d)
{
	for (size_t i = 0; i < d->n; i++) {
		ck_add(c, kind, program, name, 0, d->s[i]);
		d->s[i] = NULL;
	}
	bml_strs_free(d);
}

const char *ck_tracing_attach(const struct bml_requirements *r, const char *prog)
{
	for (size_t i = 0; i < r->n_attaches; i++) {
		const struct bml_attach *a = &r->attaches[i];
		if (strcmp(a->program.p, prog) == 0) {
			const char *t = a->attach_type.p;
			if (!strcmp(t, "trace_fentry") || !strcmp(t, "trace_fexit") || !strcmp(t, "trace_raw_tp"))
				return t;
			if (!strcmp(t, "trace_iter"))
				return "trace_iter";
			if (!strcmp(t, "trace_fmod_ret") || !strcmp(t, "modify_return"))
				return "modify_return";
		}
	}
	return "";
}
int ck_may_hold_field(const struct bml_map *m)
{
	if (strncmp(m->value.p ? m->value.p : "", "record:", 7) != 0)
		return 0;

	return strcmp(m->map_type.p, "ringbuf") != 0 && strcmp(m->map_type.p, "perf_event_array") != 0 && strcmp(m->map_type.p, "user_ringbuf") != 0;
}

int ck_in_list(const char **l, size_t n, const char *s)
{
	for (size_t i = 0; i < n; i++)
		if (strcmp(l[i], s) == 0)
			return 1;
	return 0;
}

const char *ck_btf_rewrite_name(const char *f)
{
	if (!strcmp(f, "func_global"))
		return "StripFuncLinkage (global FUNC → static)";
	if (!strcmp(f, "decl_tag"))
		return "ReplaceDeclTags";
	if (!strcmp(f, "type_tag"))
		return "ReplaceTypeTags";
	if (!strcmp(f, "enum64"))
		return "ReplaceEnum64";
	return NULL;
}

/* CONTRACT: requirements with NUL in a string field are not checked (not representable as C strings; a known strict difference, Go compares byte sequences) */
int ck_int_spelling(const char *s)
{
	static const char *const ok[] = {"i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64"};
	for (size_t i = 0; i < sizeof ok / sizeof *ok; i++)
		if (!strcmp(s, ok[i]))
			return 1;
	return 0;
}

int ck_has_nul(const struct bml_requirements *r)
{
#define N(s) ((s).p && strlen((s).p) != (s).len)
	for (size_t i = 0; i < r->n_programs; i++) {
		if (N(r->programs[i].symbol) || N(r->programs[i].prog_type))
			return 1;
		for (size_t j = 0; j < r->programs[i].n_helpers; j++)
			if (N(r->programs[i].helpers[j].name))
				return 1;
	}
	for (size_t i = 0; i < r->n_maps; i++)
		if (N(r->maps[i].symbol) || N(r->maps[i].map_type) || N(r->maps[i].key) || N(r->maps[i].value))
			return 1;
	for (size_t i = 0; i < r->n_kfields; i++)
		if (N(r->kfields[i].program) || N(r->kfields[i].strct) || N(r->kfields[i].field) || N(r->kfields[i].type))
			return 1;
	for (size_t i = 0; i < r->n_attaches; i++) {
		const struct bml_attach *a = &r->attaches[i];
		if (N(a->program) || N(a->attach_type) || N(a->target) || N(a->ret_type) || N(a->arch) || N(a->binary_sha256))
			return 1;
		for (size_t j = 0; j < a->n_args; j++)
			if (N(a->args[j]))
				return 1;
		for (size_t j = 0; j < a->n_fargs; j++)
			if (N(a->fargs[j]))
				return 1;
		for (size_t j = 0; j < a->n_ctxfields; j++)
			if (N(a->ctxfields[j].strct) || N(a->ctxfields[j].field))
				return 1;
		for (size_t j = 0; j < a->n_kprobe_args; j++)
			if (N(a->kprobe_args[j].type))
				return 1;
		for (size_t j = 0; j < a->n_uprobe_args; j++)
			if (N(a->uprobe_args[j].type))
				return 1;

		if (N(a->tkind) || N(a->tval) || N(a->ext_ret) || N(a->sop_struct) || N(a->sop_member))
			return 1;
		for (size_t j = 0; j < a->n_tpfields; j++)
			if (N(a->tpfields[j].field) || N(a->tpfields[j].sign))
				return 1;
		for (size_t j = 0; j < a->n_ext_args; j++)
			if (N(a->ext_args[j]))
				return 1;

		if (N(a->usdt_sem) || N(a->tpbuf_type))
			return 1;
		for (size_t j = 0; j < a->n_mtargets; j++)
			if (N(a->mtargets[j]))
				return 1;
		for (size_t j = 0; j < a->n_usdt_args; j++)
			if (N(a->usdt_args[j].type))
				return 1;
		for (size_t j = 0; j < a->n_sys_args; j++)
			if (N(a->sys_args[j].type))
				return 1;
		for (size_t j = 0; j < a->n_mtarget_args; j++)
			if (N(a->mtarget_args[j].type))
				return 1;
	}
	for (size_t i = 0; i < r->n_kfuncs; i++) {
		const struct bml_kfunc *k = &r->kfuncs[i];
		if (N(k->program) || N(k->name) || N(k->ret))
			return 1;
		for (size_t j = 0; j < k->n_args; j++)
			if (N(k->args[j]))
				return 1;
	}
	for (size_t i = 0; i < r->n_innermaps; i++) {
		const struct bml_innermap *im = &r->innermaps[i];
		if (N(im->outer) || N(im->map_type) || N(im->key) || N(im->value))
			return 1;
	}
	for (size_t i = 0; i < r->n_ctxaccesses; i++) {
		const struct bml_ctxaccess *x = &r->ctxaccesses[i];
		if (N(x->program) || N(x->attach_type) || N(x->strct) || N(x->field) || N(x->mode))
			return 1;
	}
	for (size_t i = 0; i < r->n_argtags; i++)
		if (N(r->argtags[i].program) || N(r->argtags[i].tag) || N(r->argtags[i].cls))
			return 1;
	for (size_t i = 0; i < r->n_tailslots; i++)
		if (N(r->tailslots[i].map) || N(r->tailslots[i].program))
			return 1;
#undef N
	return 0;
}
