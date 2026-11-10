





#define _GNU_SOURCE
#include "abi/internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "btf/globals.h"
#include "json/json.h"
#include "util/gostr.h"


static int type_bits(const char *t)
{
	if (t[0] != 'u' && t[0] != 'i')
		return 0;
	int b = atoi(t + 1);
	return (b == 8 || b == 16 || b == 32 || b == 64) ? b : 0;
}

static const struct bml_global_decl *find_global(const struct bml_map_decls *d, const char *name, size_t len)
{
	for (size_t i = 0; i < d->n_globals; i++)
		if (strlen(d->globals[i].name) == len && !memcmp(d->globals[i].name, name, len))
			return &d->globals[i];
	return NULL;
}

static int64_t fail_name(int64_t kind, const char *pre, const char *name, size_t len, const char *post)
{
	struct bml_buf b = {0};
	bml_buf_adds(&b, pre);
	bml_buf_add_goquote(&b, name, len);
	bml_buf_adds(&b, post);
	struct abi_result r = {.kind = kind, .msg_len = b.len};
	r.msg = bml_buf_take(&b);
	return abi_put(&r);
}

int64_t abi_config(const char *cfg, int64_t cfg_len, const struct bml_map_decls *d, const uint8_t *elf, size_t elf_len,
		   struct bml_rodata_value **vals, size_t *n_vals)
{
	*vals = NULL;
	*n_vals = 0;
	struct bml_json *j = NULL;
	const struct bml_json *set = NULL, *opt = NULL;
	char *err = NULL;
	if (cfg_len > 0) {
		if (bml_json_parse(cfg, (size_t)cfg_len, &j, &err) != 0) {
			int64_t e = abi_fail(BML_PRECHECK_FAILED, "bml: the configuration document is unreadable: %s", err ? err : "");
			free(err);
			return e;
		}
		if (j->type != BML_JSON_OBJECT) {
			bml_json_free(j);
			return abi_fail(BML_PRECHECK_FAILED, "bml: the configuration document is unreadable: want an object {\"set\": {…}, \"optional\": […]}");
		}
		for (size_t i = 0; i < j->n; i++)
			if (strcmp(j->members[i].key, "set") && strcmp(j->members[i].key, "optional")) {
				int64_t e = fail_name(BML_PRECHECK_FAILED, "bml: the configuration document is unreadable: unknown key ", j->members[i].key,
						      strlen(j->members[i].key), " (the keys are set and optional)");
				bml_json_free(j);
				return e;
			}
		set = bml_json_get(j, "set");
		opt = bml_json_get(j, "optional");
		if ((set && set->type != BML_JSON_OBJECT) || (opt && opt->type != BML_JSON_ARRAY)) {
			bml_json_free(j);
			return abi_fail(BML_PRECHECK_FAILED, "bml: the configuration document is unreadable: set is an object and optional is an array");
		}
	}
	size_t ns = set ? set->n : 0, no = opt ? opt->n : 0;
	int64_t e = 0;
	if ((ns || no) && !d->has_globals) {
		e = abi_fail(BML_PRECHECK_FAILED,
			     "bml: configuration values are given, but the map declarations have no \"globals\" (the value widths are checked against the declared globals)");
		goto out;
	}
	*vals = calloc(ns + 1, sizeof **vals);
	char *covered = calloc(d->n_globals + 1, 1);
	if (!*vals || !covered) {
		free(covered);
		e = abi_fail(BML_OTHER, "bml: out of memory");
		goto out;
	}
	for (size_t i = 0; i < ns + no && !e; i++) {
		int is_set = i < ns;
		const struct bml_json *v = is_set ? set->members[i].value : opt->items[i - ns];
		const char *nm = is_set ? set->members[i].key : v->str;
		if (!is_set && v->type != BML_JSON_STRING) {
			e = abi_fail(BML_PRECHECK_FAILED, "bml: the configuration document is unreadable: optional holds global names (strings)");
			break;
		}
		size_t nl = strlen(nm);
		const struct bml_global_decl *g = find_global(d, nm, nl);
		if (!g || strcmp(g->section, "rodata") != 0) {
			e = fail_name(BML_MAP_MISMATCH, is_set ? "bml: config " : "bml: optional config ", nm, nl,
				      g ? " is a .bss counter, not a .rodata configuration value" : " is not a declared .rodata global of the object");
			break;
		}
		covered[g - d->globals] = 1;
		if (!is_set)
			continue;
		uint64_t bits;
		int w = type_bits(g->type);
		if (v->type != BML_JSON_NUMBER || bml_go_parse_uint(v->str, v->len, 64, &bits) != 0) {
			e = fail_name(BML_PRECHECK_FAILED, "bml: the configuration document is unreadable: the value of ", nm, nl,
				      " is not an unsigned integer of at most 64 bits (give the bits of the value)");
			break;
		}
		if (w < 64 && bits >> w) {
			e = abi_fail(BML_VALUE_RANGE, "bml: config %s: the value bits %#llx do not fit %s (%d bits)", nm, (unsigned long long)bits, g->type, w);
			break;
		}
		uint64_t off, size;
		if (btf_global_offset(elf, elf_len, nm, &off, &size) != 0 || size * 8 != (uint64_t)w) {
			e = abi_fail(BML_OTHER, "bml: config %s: the ELF symbol cannot be read (after the global check — not expected)", nm);
			break;
		}
		(*vals)[(*n_vals)++] = (struct bml_rodata_value){off, (uint32_t)size, bits};
	}
	if (!e) {
		struct bml_buf b = {0};
		size_t missing = 0;
		for (size_t i = 0; i < d->n_globals; i++)
			if (!strcmp(d->globals[i].section, "rodata") && !covered[i]) {
				bml_buf_adds(&b, missing++ ? ", " : "bml: config ");
				bml_buf_adds(&b, d->globals[i].name);
			}
		if (missing) {
			bml_buf_adds(&b, missing > 1 ? " are not set" : " is not set");
			bml_buf_adds(&b, " — give the values as load arguments ({\"set\": {…}}), or declare them optional to load the ELF's initial values");
			struct abi_result r = {.kind = BML_CONFIG_NOT_SET, .msg_len = b.len};
			r.msg = bml_buf_take(&b);
			e = abi_put(&r);
		} else
			bml_buf_free(&b);
	}
	free(covered);
out:
	if (j)
		bml_json_free(j);
	if (e) {
		free(*vals);
		*vals = NULL;
		*n_vals = 0;
	}
	return e;
}

int abi_globals_keep(struct abi_object *o, const struct bml_map_decls *d)
{
	if (!d->n_globals)
		return 0;
	o->globals = calloc(d->n_globals, sizeof *o->globals);
	if (!o->globals)
		return -1;
	for (size_t i = 0; i < d->n_globals; i++) {
		struct bml_global_decl *g = &o->globals[o->n_globals++];
		g->name = strdup(d->globals[i].name);
		g->section = strdup(d->globals[i].section);
		g->type = strdup(d->globals[i].type);
		if (!g->name || !g->section || !g->type)
			return -1;
	}
	return 0;
}

void abi_globals_free(struct abi_object *o)
{
	for (size_t i = 0; i < o->n_globals; i++) {
		free(o->globals[i].name);
		free(o->globals[i].section);
		free(o->globals[i].type);
	}
	free(o->globals);
	o->globals = NULL;
	o->n_globals = 0;
}


static int parse_global(const char *s, int64_t n, char **name, char **section, char **type)
{
	struct bml_json *j = NULL;
	char *err = NULL;
	*name = *section = *type = NULL;
	if (bml_json_parse(s, (size_t)n, &j, &err) != 0) {
		free(err);
		return -1;
	}
	int rc = -1;
	if (j->type == BML_JSON_OBJECT && j->n == 3) {
		const struct bml_json *a = bml_json_get(j, "name"), *b = bml_json_get(j, "section"), *c = bml_json_get(j, "type");
		if (a && b && c && a->type == BML_JSON_STRING && b->type == BML_JSON_STRING && c->type == BML_JSON_STRING) {
			*name = strdup(a->str);
			*section = strdup(b->str);
			*type = strdup(c->str);
			rc = *name && *section && *type ? 0 : -1;
		}
	}
	bml_json_free(j);
	return rc;
}

static int64_t global_get_body(int64_t obj, const char *decl, int64_t decl_len)
{
	int64_t e;
	if (decl_len < 0 || (!decl && decl_len))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL string with a length");
	char *name, *section, *type;
	if (parse_global(decl ? decl : "", decl_len, &name, &section, &type) != 0) {
		free(name), free(section), free(type);
		return abi_fail(BML_OTHER, "bml: unreadable global declaration (want {\"name\", \"section\", \"type\"})");
	}
	struct abi_object *o = abi_object_get(obj, &e);
	const struct bml_global_decl *g = NULL;
	if (o)
		for (size_t i = 0; i < o->n_globals; i++)
			if (!strcmp(o->globals[i].name, name))
				g = &o->globals[i];
	if (!o)
		;
	else if (!g)
		e = abi_fail(BML_STATE, "bml: the object declares no global %s (maps.json globals)", name);
	else if (strcmp(g->section, section) || strcmp(g->type, type))
		e = abi_fail(BML_MAP_MISMATCH, "bml: global %s: declared here as %s %s, but the object was loaded with %s %s", name, section, type, g->section, g->type);
	else {

		struct bpf_map *m, *sm = NULL;
		char suffix[16];
		snprintf(suffix, sizeof suffix, ".%s", section);
		bpf_object__for_each_map(m, bml_obj_bpf(o->lo))
		{
			const char *nm = bpf_map__name(m);
			size_t l = strlen(nm), sl = strlen(suffix);
			if (bpf_map__is_internal(m) && l >= sl && !strcmp(nm + l - sl, suffix))
				sm = m;
		}
		uint64_t off, size;
		uint32_t vs = sm ? bpf_map__value_size(sm) : 0, key = 0;
		uint8_t *buf = vs ? calloc(1, vs) : NULL;
		if (!sm || !buf || btf_global_offset(o->elf, o->elf_len, name, &off, &size) != 0 || size > 8 || off > vs || vs - off < size)
			e = abi_fail(BML_OTHER, "bml: global %s: the %s map or the symbol cannot be read", name, suffix);
		else if (bpf_map__lookup_elem(sm, &key, sizeof key, buf, vs, 0) != 0)
			e = abi_fail(BML_OTHER, "bml: global %s: reading %s: %s", name, suffix, abi_errno(errno));
		else {
			uint64_t bits = 0;
			for (uint64_t b = 0; b < size; b++)
				bits |= (uint64_t)buf[off + b] << (8 * b);
			e = abi_ok((int64_t)bits);
		}
		free(buf);
	}
	free(name), free(section), free(type);
	return e;
}


int64_t bml_global_get(int64_t obj, const char *decl, int64_t decl_len)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = global_get_body(obj, decl, decl_len);
	abi_object_release(o);
	return e;
}
