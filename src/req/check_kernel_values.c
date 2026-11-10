
#include "req/check_internal.h"

#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"

int ck_check_enum_values(struct ck *c)
{
	for (int core = 0; core < 2; core++) {
		const struct bml_enum_value *rows = core ? c->req->core_enums : c->req->enum_values;
		size_t nr = core ? c->req->n_core_enums : c->req->n_enum_values;
		const char *kind = core ? "coreenum" : "enumval", *unknown = core ? "coreenum_unknown" : "enumval_unknown";
		for (size_t i = 0; i < nr; i++) {
			const struct bml_enum_value *e = &rows[i];
			char *name = ck_fmtd("%s.%s", e->enumeration.p, e->name.p);
			if (!name) return ck_fail(c, ck_dupn("out of memory"));
			if (!HAS(c, enum_value, BML_QUERY_ENUM_VALUES)) {
				ck_add(c, unknown, e->program.p, name, 0, ck_dupn("no enum value probe"));
				free(name); continue;
			}
			uint64_t value = 0;
			char *msg = NULL;
			int st = c->caps->enum_value(c->caps->ctx, e->enumeration.p, e->name.p, &value, &msg);
			if (st == BML_Q_UNKNOWN) ck_add(c, unknown, e->program.p, name, 0, msg);
			else if (st == BML_Q_ABSENT) {
				if (core) ck_add(c, kind, e->program.p, name, 0, msg);
				else {
					ck_add(c, kind, e->program.p, name, 0, ck_fmtd("%s (the object was compiled with 0x%016llx)", msg, (unsigned long long)e->value));
					free(msg);
				}
			} else if (st != BML_Q_OK) { free(name); return ck_fail(c, msg); }
			else if (!core && value != e->value)
				ck_add(c, kind, e->program.p, name, 0, ck_fmtd("the target's %s is 0x%016llx, the object was compiled with 0x%016llx", name,
					(unsigned long long)value, (unsigned long long)e->value));
			free(name);
		}
	}
	return 0;
}

int ck_check_struct_sizes(struct ck *c)
{
	for (size_t i = 0; i < c->req->n_struct_sizes; i++) {
		const struct bml_struct_size *s = &c->req->struct_sizes[i];
		char *name = ck_fmtd("%s/%u", s->strct.p, s->size);
		if (!name) return ck_fail(c, ck_dupn("out of memory"));
		if (!HAS(c, struct_size, BML_QUERY_STRUCT_SIZE)) {
			ck_add(c, "kstructsize_unknown", "", name, 0, ck_dupn("no struct size probe")); free(name); continue;
		}
		uint32_t size = 0;
		char *msg = NULL;
		int st = c->caps->struct_size(c->caps->ctx, s->strct.p, &size, &msg);
		if (st == BML_Q_UNKNOWN) ck_add(c, "kstructsize_unknown", "", name, 0, msg);
		else if (st == BML_Q_ABSENT) {
			ck_add(c, "kstructsize", "", name, 0, ck_fmtd("%s (the object embeds %u bytes)", msg, s->size)); free(msg);
		} else if (st != BML_Q_OK) { free(name); return ck_fail(c, msg); }
		else if (size > s->size)
			ck_add(c, "kstructsize", "", name, 0, ck_fmtd("the target's struct %s is %u bytes, the object embeds %u", s->strct.p, size, s->size));
		free(name);
	}
	return 0;
}

int ck_check_fib_flags(struct ck *c)
{
	for (size_t i = 0; i < c->req->n_fib_flags; i++) {
		const struct bml_fib_flag *f = &c->req->fib_flags[i];
		char *name = ck_fmtd("%s (mask %u)", f->name.p, f->mask);
		if (!name) return ck_fail(c, ck_dupn("out of memory"));
		if (!HAS(c, fib_flags, BML_QUERY_FIB_FLAGS)) {
			ck_add(c, "fibflags_unknown", f->program.p, name, 0, ck_dupn("no fib_lookup_flags probe")); free(name); continue;
		}
		const struct bml_program *p = NULL;
		for (size_t j = 0; j < c->req->n_programs; j++)
			if (!strcmp(c->req->programs[j].symbol.p, f->program.p)) p = &c->req->programs[j];
		if (!p) { free(name); return ck_fail(c, ck_fmtd("fibflags for unknown program %s", f->program.p)); }
		int has = 0;
		char *msg = NULL;
		int st = c->caps->fib_flags(c->caps->ctx, p->prog_type.p, p->prog_type_id, f->mask, &has, &msg);
		if (st == BML_Q_UNKNOWN) ck_add(c, "fibflags_unknown", f->program.p, name, 0, msg);
		else if (st != BML_Q_OK) { free(name); return ck_fail(c, msg); }
		else if (!has) ck_add(c, "fibflags", f->program.p, name, 0, ck_dupn(p->prog_type.p));
		free(name);
	}
	return 0;
}

void ck_check_loader_rows(struct ck *c)
{
	const struct bml_loader_decl *d = ck_loader_of(c);
	const char *hidden = d->hidden_data_vars ? d->hidden_data_vars : "";
	for (size_t i = 0; i < c->req->n_data_kptrs; i++) {
		if (!strcmp(hidden, "no_mmap")) continue;
		int mmap = !strcmp(hidden, "mmap");
		ck_add(c, mmap ? "datakptr_loader" : "datakptr_loader_unknown", "", c->req->data_kptrs[i].p, 0,
			ck_fmtd(mmap ? "loader %s declares hidden_data_vars mmap" : "loader %s does not declare hidden_data_vars", d->name));
	}
	struct bml_buf definite = {0}, unknown = {0};
	const char *values[] = {d->arena_cast, d->arena_premmap};
	const char *keys[] = {"arena_cast", "arena_premmap"};
	const char *good[] = {"preserve", "create_then_mmap"}, *bad[] = {"corrupt", "none"};
	for (size_t i = 0; i < 2; i++) {
		const char *v = values[i] ? values[i] : "";
		if (!strcmp(v, good[i])) continue;
		struct bml_buf *b = !strcmp(v, bad[i]) ? &definite : &unknown;
		if (b->len) bml_buf_adds(b, ", ");
		bml_buf_adds(b, keys[i]);
		if (b == &definite) bml_buf_addf(b, " %s", v);
	}
	for (size_t i = 0; i < c->req->n_arenas; i++) {
		if (definite.len) ck_add(c, "arena_loader", "", c->req->arenas[i].p, 0, ck_fmtd("loader %s declares %s", d->name, definite.p));
		else if (unknown.len) ck_add(c, "arena_loader_unknown", "", c->req->arenas[i].p, 0, ck_fmtd("loader %s does not declare %s", d->name, unknown.p));
	}
	if (definite.oom || unknown.oom) c->oom = 1;
	bml_buf_free(&definite); bml_buf_free(&unknown);
}
