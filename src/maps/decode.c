#include "maps/internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btf/layout.h"
#include "json/json.h"
#include "util/gostr.h"



void bml_map_decl_free(struct bml_map_decl *x)
{
	free(x->name);
	free(x->kind);
	free(x->key);
	free(x->value);
	free(x->inner_kind);
	free(x->inner_key);
	free(x->inner_value);
	free(x->struct_ops);
	memset(x, 0, sizeof(*x));
}

void bml_map_decls_free(struct bml_map_decls *d)
{
	for (size_t i = 0; i < d->n_maps; i++)
		bml_map_decl_free(&d->maps[i]);
	free(d->maps);
	for (size_t i = 0; i < d->n_records; i++) {
		free(d->records[i].name);
		for (size_t j = 0; j < d->records[i].n_members; j++) {
			free(d->records[i].members[j].name);
			free(d->records[i].members[j].type);
		}
		free(d->records[i].members);
	}
	free(d->records);
	for (size_t i = 0; i < d->n_globals; i++) {
		free(d->globals[i].name);
		free(d->globals[i].section);
		free(d->globals[i].type);
	}
	free(d->globals);
	memset(d, 0, sizeof(*d));
}

static int keys_ok(const struct bml_json *o, const char *const *allowed, size_t n, char **err)
{
	for (size_t i = 0; i < o->n; i++) {
		int ok = 0;
		for (size_t k = 0; k < n; k++)
			if (strlen(allowed[k]) == o->members[i].key_len && !memcmp(allowed[k], o->members[i].key, o->members[i].key_len))
				ok = 1;
		if (!ok) {
			*err = md_fmts("json: unknown field \"%s\" (key names are exact — case matters)", o->members[i].key);
			return -1;
		}
	}
	return 0;
}

static int jstr(const struct bml_json *o, const char *key, char **out, char **err)
{
	const struct bml_json *v = bml_json_get(o, key);
	if (!v || v->type == BML_JSON_NULL) {
		*out = md_xstrdup("");
		return *out ? 0 : -1;
	}
	if (v->type != BML_JSON_STRING) {
		*err = md_fmts("json: cannot unmarshal into field %s of type string", key);
		return -1;
	}
	if (memchr(v->str, 0, v->len)) {
		*err = md_fmts("json: field %s contains a NUL byte (not supported)", key);
		return -1;
	}
	*out = md_xstrdup(v->str);
	return *out ? 0 : -1;
}

static int juint(const struct bml_json *o, const char *key, int bits, int *set, uint64_t *out, char **err)
{
	*set = 0;
	*out = 0;
	const struct bml_json *v = bml_json_get(o, key);
	if (!v || v->type == BML_JSON_NULL)
		return 0;
	uint64_t x;
	if (v->type != BML_JSON_NUMBER || bml_go_parse_uint(v->str, v->len, bits, &x)) {
		*err = md_fmts("json: cannot unmarshal into field %s of type uint%d", key, bits);
		return -1;
	}
	*set = 1;
	*out = x;
	return 0;
}


static const struct bml_json_desc md_string = {.kind = BML_JD_STRING};
static const struct bml_json_desc md_bool = {.kind = BML_JD_BOOL};
static const struct bml_json_desc md_u64 = {.kind = BML_JD_UINT, .bits = 64};
static const struct bml_json_desc md_u32 = {.kind = BML_JD_UINT, .bits = 32};
static const struct bml_json_field mf_member[] = {{"name", &md_string}, {"offset", &md_u32}, {"type", &md_string}};
static const struct bml_json_desc md_member = {.kind = BML_JD_STRUCT, .fields = mf_member, .n_fields = 3};
static const struct bml_json_desc md_members = {.kind = BML_JD_ARRAY, .child = &md_member};
static const struct bml_json_field mf_record[] = {{"size", &md_u32}, {"members", &md_members}};
static const struct bml_json_desc md_record = {.kind = BML_JD_STRUCT, .fields = mf_record, .n_fields = 2};
static const struct bml_json_desc md_records = {.kind = BML_JD_MAP, .child = &md_record};
static const struct bml_json_field mf_inner[] = {{"kind", &md_string}, {"key", &md_string}, {"value", &md_string}, {"max_entries", &md_u64}, {"flags", &md_u64}};
static const struct bml_json_desc md_inner = {.kind = BML_JD_STRUCT, .fields = mf_inner, .n_fields = 5};
static const struct bml_json_field mf_sop_op[] = {{"member", &md_string}, {"program", &md_string}};
static const struct bml_json_desc md_sop_op = {.kind = BML_JD_STRUCT, .fields = mf_sop_op, .n_fields = 2};
static const struct bml_json_desc md_sop_ops = {.kind = BML_JD_ARRAY, .child = &md_sop_op};
static const struct bml_json_field mf_sop[] = {{"type", &md_string}, {"name", &md_string}, {"ops", &md_sop_ops}};
static const struct bml_json_desc md_sop = {.kind = BML_JD_STRUCT, .fields = mf_sop, .n_fields = 3};
static const struct bml_json_field mf_decl[] = {{"name", &md_string}, {"kind", &md_string},     {"key", &md_string},
						{"value", &md_string}, {"max_entries", &md_u64}, {"flags", &md_u64}, {"inner", &md_inner},
						{"struct_ops", &md_sop}, {"map_extra", &md_u64}};
static const struct bml_json_desc md_decl = {.kind = BML_JD_STRUCT, .fields = mf_decl, .n_fields = 8};
static const struct bml_json_desc md_arena_decl = {.kind = BML_JD_STRUCT, .fields = mf_decl, .n_fields = 9};
static const struct bml_json_desc md_decls = {.kind = BML_JD_ARRAY, .child = &md_decl};
static const struct bml_json_field mf_global[] = {{"name", &md_string}, {"section", &md_string}, {"type", &md_string}};
static const struct bml_json_desc md_global = {.kind = BML_JD_STRUCT, .fields = mf_global, .n_fields = 3};
static const struct bml_json_desc md_globals = {.kind = BML_JD_ARRAY, .child = &md_global};
static const struct bml_json_field mf_top[] = {{"allow_undeclared", &md_bool}, {"records", &md_records},
					       {"globals", &md_globals},        {"allow_undeclared_globals", &md_bool},
					       {"maps", &md_decls}};
static const struct bml_json_desc md_top = {.kind = BML_JD_STRUCT, .fields = mf_top, .n_fields = 5};

struct sop_kv {
	char *k, *v;
};

static int cmp_sop(const void *a, const void *b)
{
	return strcmp(((const struct sop_kv *)a)->k, ((const struct sop_kv *)b)->k);
}



static int decode_struct_ops(const struct bml_json *so, struct bml_map_decl *x, char **err)
{
	if (!so || so->type == BML_JSON_NULL)
		return 0;
	if (so->type != BML_JSON_OBJECT) {
		*err = md_xstrdup("json: cannot unmarshal into field struct_ops of type StructOpsDecl");
		return -1;
	}
	static const char *const sk[] = {"type", "name", "ops"};
	char *type = NULL, *name = NULL;
	struct sop_kv *ops = NULL;
	size_t no = 0;
	int rc = -1;
	if (keys_ok(so, sk, 3, err) || jstr(so, "type", &type, err) || jstr(so, "name", &name, err))
		goto out;
	const struct bml_json *oa = bml_json_get(so, "ops");
	if (oa && oa->type != BML_JSON_NULL && oa->type != BML_JSON_ARRAY) {
		*err = md_xstrdup("json: cannot unmarshal into field ops of type []StructOpsOpDecl");
		goto out;
	}
	static const char *const ok[] = {"member", "program"};
	for (size_t i = 0; oa && oa->type == BML_JSON_ARRAY && i < oa->n; i++) {
		const struct bml_json *o = oa->items[i];
		char *mem = NULL, *prog = NULL;
		if (o->type == BML_JSON_NULL)
			continue;
		if (o->type != BML_JSON_OBJECT) {
			*err = md_xstrdup("json: cannot unmarshal into an element of ops of type StructOpsOpDecl");
			goto out;
		}
		if (keys_ok(o, ok, 2, err) || jstr(o, "member", &mem, err) || jstr(o, "program", &prog, err)) {
			free(mem), free(prog);
			goto out;
		}
		size_t j = 0;
		while (j < no && strcmp(ops[j].k, mem ? mem : ""))
			j++;
		if (j < no) {
			free(ops[j].v);
			ops[j].v = prog ? prog : md_xstrdup("");
			free(mem);
			continue;
		}
		struct sop_kv *na = realloc(ops, (no + 1) * sizeof *ops);
		if (!na) {
			free(mem), free(prog);
			goto out;
		}
		ops = na;
		ops[no].k = mem ? mem : md_xstrdup("");
		ops[no++].v = prog ? prog : md_xstrdup("");
	}
	if (no)
		qsort(ops, no, sizeof *ops, cmp_sop);
	struct bml_buf b = {0};
	bml_buf_addf(&b, "type=%s;", type ? type : "");
	if (name && name[0])
		bml_buf_addf(&b, "name=%s;", name);
	for (size_t i = 0; i < no; i++)
		bml_buf_addf(&b, "%s=%s;", ops[i].k, ops[i].v);
	x->struct_ops = bml_buf_take(&b);
	rc = x->struct_ops ? 0 : -1;
out:
	for (size_t i = 0; i < no; i++)
		free(ops[i].k), free(ops[i].v);
	free(ops), free(type), free(name);
	return rc;
}


static int decode_decl(const struct bml_json *m, struct bml_map_decl *x, char **err)
{
	if (m->type != BML_JSON_OBJECT) {
		*err = md_xstrdup("json: cannot unmarshal into a map declaration");
		return -1;
	}
	static const char *const mk[] = {"name", "kind", "key", "value", "max_entries", "flags", "inner", "struct_ops", "map_extra"};
	int set;
	if (keys_ok(m, mk, md_json_is_arena(m) ? 9 : 8, err) || jstr(m, "name", &x->name, err) || jstr(m, "kind", &x->kind, err) || jstr(m, "key", &x->key, err) ||
	    jstr(m, "value", &x->value, err) || juint(m, "max_entries", 64, &set, &x->max_entries, err) ||
	    juint(m, "flags", 64, &x->has_flags, &x->flags, err))
		return -1;
	if (md_json_is_arena(m) && juint(m, "map_extra", 64, &x->has_map_extra, &x->map_extra, err)) return -1;

	const struct bml_json *in = bml_json_get(m, "inner");
	if (in && in->type != BML_JSON_NULL) {
		if (in->type != BML_JSON_OBJECT) {
			*err = md_xstrdup("json: cannot unmarshal into field inner of type InnerDecl");
			return -1;
		}
		static const char *const ik[] = {"kind", "key", "value", "max_entries", "flags"};
		x->has_inner = 1;
		if (keys_ok(in, ik, 5, err) || jstr(in, "kind", &x->inner_kind, err) || jstr(in, "key", &x->inner_key, err) ||
		    jstr(in, "value", &x->inner_value, err) || juint(in, "max_entries", 64, &set, &x->inner_max_entries, err) ||
		    juint(in, "flags", 64, &set, &x->inner_flags, err))
			return -1;
	}
	return decode_struct_ops(bml_json_get(m, "struct_ops"), x, err);
}


static int decode_records(const struct bml_json *rs, struct bml_map_decls *d, char **err)
{
	if (rs && rs->type != BML_JSON_NULL) {
		if (rs->type != BML_JSON_OBJECT) {
			*err = md_xstrdup("json: cannot unmarshal into field records of type map[string]RecordShape");
			return -1;
		}
		d->records = calloc(rs->n + 1, sizeof(*d->records));
		if (!d->records)
			return -1;
		for (size_t i = 0; i < rs->n; i++) {
			const struct bml_json *r = rs->members[i].value;
			struct bml_record_decl *x = &d->records[d->n_records++];
			if (memchr(rs->members[i].key, 0, rs->members[i].key_len)) {
				*err = md_xstrdup("json: a record name contains a NUL byte (not supported)");
				return -1;
			}
			if (!(x->name = md_xstrdup(rs->members[i].key)))
				return -1;
			if (r->type == BML_JSON_NULL)
				continue;
			if (r->type != BML_JSON_OBJECT) {
				*err = md_xstrdup("json: cannot unmarshal into a record");
				return -1;
			}
			static const char *const rk[] = {"size", "members"};
			int set;
			uint64_t sz;
			if (keys_ok(r, rk, 2, err) || juint(r, "size", 32, &set, &sz, err))
				return -1;
			x->size = (uint32_t)sz;
			const struct bml_json *mm = bml_json_get(r, "members");
			if (!mm || mm->type == BML_JSON_NULL)
				continue;
			if (mm->type != BML_JSON_ARRAY) {
				*err = md_xstrdup("json: cannot unmarshal into field members of type []Member");
				return -1;
			}
			x->members = calloc(mm->n + 1, sizeof(*x->members));
			if (!x->members)
				return -1;
			for (size_t k = 0; k < mm->n; k++) {
				const struct bml_json *e = mm->items[k];
				struct bml_record_member *y = &x->members[x->n_members++];
				if (e->type == BML_JSON_NULL) {
					if (!(y->name = md_xstrdup("")) || !(y->type = md_xstrdup("")))
						return -1;
					continue;
				}
				if (e->type != BML_JSON_OBJECT) {
					*err = md_xstrdup("json: cannot unmarshal into a member");
					return -1;
				}
				static const char *const ek[] = {"name", "offset", "type"};
				uint64_t off;
				if (keys_ok(e, ek, 3, err) || jstr(e, "name", &y->name, err) || juint(e, "offset", 32, &set, &off, err) ||
				    jstr(e, "type", &y->type, err)) {
					if (!*err)
						return -1;
					return -1;
				}
				y->offset = (uint32_t)off;
			}
		}
	}
	return 0;
}


static int decode_globals(const struct bml_json *gs, struct bml_map_decls *d, char **err)
{
	if (!gs || gs->type == BML_JSON_NULL)
		return 0;
	if (gs->type != BML_JSON_ARRAY) {
		*err = md_xstrdup("json: cannot unmarshal into field globals of type []GlobalDecl");
		return -1;
	}
	d->has_globals = 1;
	d->globals = calloc(gs->n + 1, sizeof(*d->globals));
	if (!d->globals)
		return -1;
	for (size_t i = 0; i < gs->n; i++) {
		const struct bml_json *g = gs->items[i];
		struct bml_global_decl *x = &d->globals[d->n_globals++];
		if (g->type == BML_JSON_NULL) {
			if (!(x->name = md_xstrdup("")) || !(x->section = md_xstrdup("")) || !(x->type = md_xstrdup("")))
				return -1;
			continue;
		}
		if (g->type != BML_JSON_OBJECT) {
			*err = md_xstrdup("json: cannot unmarshal into a global declaration");
			return -1;
		}
		static const char *const gk[] = {"name", "section", "type"};
		if (keys_ok(g, gk, 3, err) || jstr(g, "name", &x->name, err) || jstr(g, "section", &x->section, err) ||
		    jstr(g, "type", &x->type, err))
			return -1;
	}
	return 0;
}

int md_map_decls_parse(const char *data, size_t len, struct bml_map_decls *d, char **err, enum bml_json_rule *rule, int arena)
{
	memset(d, 0, sizeof(*d));
	*err = NULL;
	if (rule)
		*rule = BML_JR_NONE;
	struct bml_json *j;
	char *jerr = NULL;
	if (bml_json_parse_ex(data, len, &md_top, 0, &j, &jerr, rule)) {
		*err = md_fmts("maps: json: %s", jerr ? jerr : "");
		free(jerr);
		return -1;
	}
	if (arena ? md_validate_map_json(j, &md_top, &md_decl, &md_arena_decl, 0, &jerr, rule) : bml_json_validate(j, &md_top, &jerr, rule)) {
		*err = md_fmts("maps: %s", jerr ? jerr : "");
		free(jerr);
		bml_json_free(j);
		return -1;
	}
	int rc = -1;
	if (j->type == BML_JSON_NULL) {
		rc = 0;
		goto out;
	}
	if (j->type != BML_JSON_OBJECT) {
		*err = md_xstrdup("json: cannot unmarshal into the map declarations (want an object)");
		goto out;
	}
	static const char *const top[] = {"allow_undeclared", "records", "globals", "allow_undeclared_globals", "maps"};
	if (keys_ok(j, top, 5, err))
		goto out;
	const struct bml_json *au = bml_json_get(j, "allow_undeclared");
	if (au && au->type != BML_JSON_NULL) {
		if (au->type != BML_JSON_BOOL) {
			*err = md_xstrdup("json: cannot unmarshal into field allow_undeclared of type bool");
			goto out;
		}
		d->allow_undeclared = au->boolean;
	}
	const struct bml_json *aug = bml_json_get(j, "allow_undeclared_globals");
	if (aug && aug->type != BML_JSON_NULL) {
		if (aug->type != BML_JSON_BOOL) {
			*err = md_xstrdup("json: cannot unmarshal into field allow_undeclared_globals of type bool");
			goto out;
		}
		d->allow_undeclared_globals = aug->boolean;
	}
	if (decode_globals(bml_json_get(j, "globals"), d, err)) {
		if (!*err)
			goto oom;
		goto out;
	}
	const struct bml_json *ms = bml_json_get(j, "maps");
	if (ms && ms->type != BML_JSON_NULL) {
		d->has_maps = 1;
		if (ms->type != BML_JSON_ARRAY) {
			*err = md_xstrdup("json: cannot unmarshal into field maps of type []MapDecl");
			goto out;
		}
		d->maps = calloc(ms->n + 1, sizeof(*d->maps));
		if (!d->maps)
			goto oom;
		for (size_t i = 0; i < ms->n; i++) {
			const struct bml_json *m = ms->items[i];
			struct bml_map_decl *x = &d->maps[d->n_maps++];
			if (m->type == BML_JSON_NULL) {
				if (!(x->name = md_xstrdup("")) || !(x->kind = md_xstrdup("")) || !(x->key = md_xstrdup("")) || !(x->value = md_xstrdup("")))
					goto oom;
				continue;
			}
			if (decode_decl(m, x, err)) {
				if (!*err)
					goto oom;
				goto out;
			}
		}
	}
	if (decode_records(bml_json_get(j, "records"), d, err)) {
		if (!*err)
			goto oom;
		goto out;
	}
	rc = 0;
	goto out;
oom:
	*err = md_xstrdup("out of memory");
out:
	bml_json_free(j);
	if (rc)
		bml_map_decls_free(d);
	return rc;
}


int md_map_decl_parse_one(const char *data, size_t len, struct bml_map_decl *x, char **err, int arena)
{
	memset(x, 0, sizeof(*x));
	*err = NULL;
	struct bml_json *j = NULL;
	char *jerr = NULL;
	if (bml_json_parse_ex(data, len, &md_decl, 0, &j, &jerr, NULL) || (arena ? md_validate_map_json(j, NULL, &md_decl, &md_arena_decl, 1, &jerr, NULL) : bml_json_validate(j, &md_decl, &jerr, NULL))) {
		*err = md_fmts("json: %s", jerr ? jerr : "");
		free(jerr);
		if (j)
			bml_json_free(j);
		return -1;
	}
	int rc = 0;
	if (j->type == BML_JSON_NULL) {
		if (!(x->name = md_xstrdup("")) || !(x->kind = md_xstrdup("")) || !(x->key = md_xstrdup("")) || !(x->value = md_xstrdup("")))
			rc = -1;
	} else if (decode_decl(j, x, err))
		rc = -1;
	if (rc && !*err)
		*err = md_xstrdup("out of memory");
	bml_json_free(j);
	if (rc)
		bml_map_decl_free(x);
	return rc;
}


int bml_record_decls_parse(const char *data, size_t len, struct bml_map_decls *out, int *is_null, char **err)
{
	memset(out, 0, sizeof(*out));
	*err = NULL;
	*is_null = 0;
	struct bml_json *j = NULL;
	char *jerr = NULL;
	if (bml_json_parse_ex(data, len, &md_records, 0, &j, &jerr, NULL) || bml_json_validate(j, &md_records, &jerr, NULL)) {
		*err = md_fmts("json: %s", jerr ? jerr : "");
		free(jerr);
		if (j)
			bml_json_free(j);
		return -1;
	}
	*is_null = j->type == BML_JSON_NULL;
	int rc = decode_records(j, out, err);
	if (rc && !*err)
		*err = md_xstrdup("out of memory");
	bml_json_free(j);
	if (rc)
		bml_map_decls_free(out);
	return rc;
}


const struct bml_json_desc *bml_map_decls_desc(void)
{
	return &md_top;
}
