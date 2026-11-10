
#include "bml-precheck/precheck.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bml/bml.h"
#include "caps/recorded.h"
#include "json/json.h"
#include "req/from_elf.h"


static int kv_equal(const struct bml_kv *a, size_t na, int ha, const struct bml_kv *b, size_t nb, int hb)
{
	if (ha != hb || na != nb)
		return 0;
	for (size_t i = 0; i < na; i++) {
		const char *v = bml_kv_get(b, nb, a[i].key);
		if (!v || strcmp(v, a[i].value) != 0)
			return 0;
	}
	return 1;
}

static int same_or_absent(const char *rec, const char *decl)
{
	return !rec || !rec[0] || (decl && !strcmp(rec, decl));
}

int pc_decl_equal(const struct bml_loader_decl *a, const struct bml_loader_decl *b)
{
	return !strcmp(a->name, b->name) && a->uprobe_reopens_path == b->uprobe_reopens_path &&
	       a->core_poisons_missing_field == b->core_poisons_missing_field &&
	       kv_equal(a->kprobe_alias_prefix, a->n_kprobe_alias_prefix, a->has_kprobe_alias_prefix, b->kprobe_alias_prefix,
			b->n_kprobe_alias_prefix, b->has_kprobe_alias_prefix) &&
	       kv_equal(a->btf_rewrite, a->n_btf_rewrite, a->has_btf_rewrite, b->btf_rewrite, b->n_btf_rewrite, b->has_btf_rewrite) &&

	       same_or_absent(a->usdt_attach, b->usdt_attach) && same_or_absent(a->sockmap_attach, b->sockmap_attach) &&
	       same_or_absent(a->lsm_cgroup_load, b->lsm_cgroup_load) && same_or_absent(a->fsession_load, b->fsession_load) &&
	       same_or_absent(a->ksyscall_attach, b->ksyscall_attach);
}
static int is_bool_flag(const char *n)
{
	return !strcmp(n, "live") || !strcmp(n, "version");
}

static const char **str_flag(struct flags *f, const char *n)
{
	if (!strcmp(n, "loader")) return &f->loader;
	if (!strcmp(n, "loader-file")) return &f->loader_file;
	if (!strcmp(n, "caps")) return &f->caps;
	if (!strcmp(n, "schema-sha256")) return &f->schema;
	if (!strcmp(n, "hint")) return &f->hint;
	if (!strcmp(n, "requirements")) return &f->requirements;
	if (!strcmp(n, "maps")) return &f->maps;
	if (!strcmp(n, "record")) return &f->record;
	if (!strcmp(n, "load-as")) return &f->load_as;
	return NULL;
}

int pc_parse_flags(int argc, char **argv, struct flags *f, struct bml_buf *err)
{
	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (a[0] != '-' || a[1] == 0)
			break;
		const char *n = a + 1;
		if (n[0] == '-') {
			n++;
			if (n[0] == 0) {
				i++;
				break;
			}
		}
		if (n[0] == '-' || n[0] == '=') {
			bml_buf_addf(err, "bad flag syntax: %s", a);
			return -1;
		}
		char name[64];
		const char *eq = strchr(n, '=');
		size_t nl = eq ? (size_t)(eq - n) : strlen(n);
		if (nl >= sizeof(name)) {
			bml_buf_addf(err, "flag provided but not defined: -%s", n);
			return -1;
		}
		memcpy(name, n, nl);
		name[nl] = 0;
		if (is_bool_flag(name)) {
			int v = 1;
			if (eq) {
				const char *s = eq + 1;
				if (!strcmp(s, "1") || !strcmp(s, "t") || !strcmp(s, "T") || !strcmp(s, "true") || !strcmp(s, "TRUE") || !strcmp(s, "True"))
					v = 1;
				else if (!strcmp(s, "0") || !strcmp(s, "f") || !strcmp(s, "F") || !strcmp(s, "false") || !strcmp(s, "FALSE") || !strcmp(s, "False"))
					v = 0;
				else {
					bml_buf_addf(err, "invalid boolean value \"%s\" for -%s: parse error", s, name);
					return -1;
				}
			}
			if (!strcmp(name, "live"))
				f->live = v;
			else
				f->version = v;
			continue;
		}
		const char **dst = str_flag(f, name);
		int binary = !strcmp(name, "binary"), ext = !strcmp(name, "ext-target"), debug = !strcmp(name, "debug");
		if (!strcmp(name, "debug-root"))
			dst = &f->debug_root, f->debug_root_set = 1;
		if (!dst && !binary && !ext && !debug) {
			bml_buf_addf(err, "flag provided but not defined: -%s", name);
			return -1;
		}
		const char *val;
		if (eq) {
			val = eq + 1;
		} else if (i + 1 < argc) {
			val = argv[++i];
		} else {
			bml_buf_addf(err, "flag needs an argument: -%s", name);
			return -1;
		}
		if (binary) {
			if (f->n_binary == (int)(sizeof f->binary / sizeof *f->binary)) {
				bml_buf_adds(err, "too many --binary flags (bml-precheck takes at most 256)");
				return -1;
			}
			f->binary[f->n_binary++] = val;
		} else if (ext) {
			if (f->n_ext_target == (int)(sizeof f->ext_target / sizeof *f->ext_target)) {
				bml_buf_adds(err, "too many --ext-target flags (bml-precheck takes at most 256)");
				return -1;
			}
			f->ext_target[f->n_ext_target++] = val;
		} else if (debug) {
			if (f->n_debug == (int)(sizeof f->debug / sizeof *f->debug)) {
				bml_buf_adds(err, "too many --debug flags (bml-precheck takes at most 256)");
				return -1;
			}
			f->debug[f->n_debug++] = val;
		} else
			*dst = val;
	}
	f->args = argv + i;
	f->n_args = argc - i;
	return 0;
}

int pc_load_loader_file(const char *path, struct bml_loader_decl *d, char **err)
{
	size_t len;
	char *data = pc_read_file(path, &len, err);
	if (!data) {
		char *m = malloc(strlen(*err) + 16);
		if (m)
			sprintf(m, "loader file: %s", *err);
		free(*err);
		*err = m;
		return -1;
	}

	char *e = NULL;
	int rc = bml_loader_decl_parse(data, len, d, &e, NULL);
	free(data);
	struct bml_buf m = {0};
	if (rc) {
		bml_buf_addf(&m, "loader file %s: %s", path, e ? e : "");
		free(e);
		*err = bml_buf_take(&m);
		return -1;
	}
	if (!d->name || !d->name[0]) {
		bml_loader_decl_free(d);
		bml_buf_addf(&m, "loader file %s: a declaration needs a name", path);
		*err = bml_buf_take(&m);
		return -1;
	}
	char *ve = NULL;
	if (bml_loader_decl_validate(d, &ve)) {
		bml_buf_addf(&m, "loader file %s: %s", path, ve ? ve : "");
		free(ve);
		bml_loader_decl_free(d);
		*err = bml_buf_take(&m);
		return -1;
	}
	return 0;
}
