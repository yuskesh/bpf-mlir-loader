

#define _GNU_SOURCE
#include "caps/value_sources.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "caps/live_internal.h"

struct bml_kernel_sources *lv_value_sources(struct bml_live *l)
{
	if (!l->kernel_sources) l->kernel_sources = calloc(1, sizeof(*l->kernel_sources));
	return l->kernel_sources;
}

void lv_value_sources_free(struct bml_live *l)
{
	struct bml_kernel_sources *s = l->kernel_sources;
	if (!s) return;
	for (size_t i = 0; i < s->count; i++) {
		struct lv_value_module *m = &s->modules[i];
		free(m->name);
		for (size_t j = 0; j < m->count; j++) free(m->types[j].name);
		free(m->types);
	}
	free(s->modules); free(s->module_error); free(s->config_error);
	for (size_t i = 0; i < s->config_count; i++) { free(s->config[i].key); free(s->config[i].value); }
	free(s->config); free(s); l->kernel_sources = NULL;
}

int lv_value_read(const char *path, uint8_t **out, size_t *len, char **err)
{
	*out = NULL; *len = 0; *err = NULL;
	FILE *f = fopen(path, "rb");
	if (!f) { *err = bml_go_errno_str(errno); return -1; }
	struct bml_buf b = {0};
	uint8_t buf[8192];
	for (;;) {
		size_t n = fread(buf, 1, sizeof(buf), f);
		bml_buf_add(&b, (const char *)buf, n);
		if (b.oom) { *err = strdup("out of memory"); break; }
		if (n < sizeof(buf)) {
			if (ferror(f)) *err = bml_go_errno_str(errno);
			break;
		}
	}
	if (fclose(f) && !*err) *err = bml_go_errno_str(errno);
	if (*err || b.oom) { bml_buf_free(&b); return -1; }
	*len = b.len; *out = (uint8_t *)bml_buf_take(&b);
	return *out ? 0 : (*err = strdup("out of memory"), -1);
}

static int by_name(const struct dirent **a, const struct dirent **b) { return strcmp((*a)->d_name, (*b)->d_name); }
static int module_entry(const struct dirent *e) { return strcmp(e->d_name, ".") && strcmp(e->d_name, "..") && strcmp(e->d_name, "vmlinux"); }

static int module_names(struct bml_kernel_sources *s, const struct bml_kbtf *base, const char *name, char **err)
{
	char *path = NULL;
	if (asprintf(&path, "/sys/kernel/btf/%s", name) < 0) return (*err = strdup("out of memory"), -1);
	uint8_t *raw = NULL; size_t len;
	int st = lv_value_read(path, &raw, &len, err);
	free(path);
	if (st) return -1;
	struct bml_kbtf split;
	st = bml_kbtf_from_split_raw(raw, len, base, &split, err);
	if (st) return -1;
	struct lv_value_module *arr = realloc(s->modules, (s->count + 1) * sizeof(*arr));
	if (!arr) { bml_kbtf_free(&split); return (*err = strdup("out of memory"), -1); }
	s->modules = arr;
	struct lv_value_module *m = &s->modules[s->count++];
	memset(m, 0, sizeof(*m)); m->name = strdup(name);
	if (!m->name) goto oom;
	for (uint32_t i = base->n; i < split.n; i++) {
		struct kbtf_type t;
		bml_kbtf_type(&split, i, &t);
		if ((t.kind != KBTF_VAR && t.kind != KBTF_STRUCT) || !t.name[0]) continue;
		struct lv_module_name *types = realloc(m->types, (m->count + 1) * sizeof(*types));
		if (!types) goto oom;
		m->types = types;
		char *copy = strdup(t.name);
		if (!copy) goto oom;
		m->types[m->count++] = (struct lv_module_name){copy, t.kind};
	}
	bml_kbtf_free(&split); return 0;
oom:
	bml_kbtf_free(&split); *err = strdup("out of memory"); return -1;
}

void lv_value_modules(struct bml_live *l, struct bml_kernel_sources *s)
{
	if (s->modules_done) return;
	s->modules_done = 1;
	const char *err;
	const struct bml_kbtf *base = lv_kb(l, &err);
	if (!base) return;
	struct dirent **entries = NULL;
	int n = scandir("/sys/kernel/btf", &entries, module_entry, by_name);
	if (n < 0) {
		s->modules_failed = 1;
		char *why = bml_go_errno_str(errno);
		if (asprintf(&s->module_error, "module BTF set /sys/kernel/btf: %s", why ? why : "") < 0) s->module_error = NULL;
		free(why);
		if (!s->module_error) s->module_error = strdup("out of memory");
		return;
	}
	for (int i = 0; i < n; i++) {
		char *why = NULL;
		if (!s->modules_failed && module_names(s, base, entries[i]->d_name, &why)) {
			s->modules_failed = 1;
			if (asprintf(&s->module_error, "module BTF %s: %s", entries[i]->d_name, why ? why : "out of memory") < 0) s->module_error = NULL;
			free(why);
			if (!s->module_error) s->module_error = strdup("out of memory");
		}
		free(entries[i]);
	}
	free(entries);
}

int lv_value_absent(struct bml_kernel_sources *s, const char *what, const char *name, uint32_t kind, const char *sentinel, char **msg)
{
	struct bml_buf b = {0};
	if (s->modules_failed) {
		bml_buf_addf(&b, "%s: vmlinux has none and %s: cannot be determined on this target", what, s->module_error ? s->module_error : "out of memory");
		*msg = bml_buf_take(&b); return *msg ? BML_Q_UNKNOWN : BML_Q_ERROR;
	}
	for (size_t i = 0; i < s->count; i++) {
		const struct lv_value_module *m = &s->modules[i];
		int found = 0;
		for (size_t j = 0; j < m->count; j++)
			if (m->types[j].kind == kind && !strcmp(m->types[j].name, name)) found = 1;
		if (found) { if (b.len) bml_buf_adds(&b, ","); bml_buf_adds(&b, m->name); }
	}
	char *modules = bml_buf_take(&b);
	if (!modules) return (*msg = strdup("out of memory"), BML_Q_ERROR);
	int st = modules[0] ? BML_Q_UNKNOWN : BML_Q_ABSENT;
	if (modules[0]) bml_buf_addf(&b, "%s: only in module BTF %s: cannot be determined on this target", what, modules);
	else bml_buf_addf(&b, "%s: neither vmlinux nor the %zu module BTFs have it: %s", what, s->count, sentinel);
	free(modules); *msg = bml_buf_take(&b); return *msg ? st : BML_Q_ERROR;
}
