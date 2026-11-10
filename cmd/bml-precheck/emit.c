
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

char *pc_read_file(const char *path, size_t *len, char **err)
{
	FILE *f = fopen(path, "rb");
	if (!f) {
		struct bml_buf b = {0};
		char *es = bml_go_errno_str(errno);
		bml_buf_addf(&b, "open %s: %s", path, es ? es : "");
		free(es);
		*err = bml_buf_take(&b);
		return NULL;
	}
	struct bml_buf b = {0};
	char tmp[65536];
	size_t n;
	while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0)
		bml_buf_add(&b, tmp, n);
	fclose(f);
	if (!b.p)
		bml_buf_add(&b, "", 0);
	*len = b.len;
	return bml_buf_take(&b);
}

void pc_run_as(long long *uid, char **cap)
{
	*uid = (long long)geteuid();
	*cap = strdup("");
	FILE *f = fopen("/proc/self/status", "r");
	if (!f)
		return;
	char line[512];
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "CapEff:", 7) == 0) {
			char *p = line + 7;
			while (*p == ' ' || *p == '\t')
				p++;
			p[strcspn(p, "\n")] = 0;
			size_t e = strlen(p);
			while (e && (p[e - 1] == ' ' || p[e - 1] == '\t'))
				p[--e] = 0;
			free(*cap);
			*cap = strdup(p);
		}
	}
	fclose(f);
}

static void jstr(struct bml_buf *b, const char *s)
{
	bml_json_write_string(b, s, strlen(s));
}

static void jkv(struct bml_buf *b, const struct bml_kv *kv, size_t n, int has)
{
	if (!has) {
		bml_buf_adds(b, "null");
		return;
	}

	size_t *idx = calloc(n ? n : 1, sizeof(*idx));
	for (size_t i = 0; i < n; i++)
		idx[i] = i;
	for (size_t i = 1; i < n; i++)
		for (size_t j = i; j > 0 && strcmp(kv[idx[j - 1]].key, kv[idx[j]].key) > 0; j--) {
			size_t t = idx[j];
			idx[j] = idx[j - 1];
			idx[j - 1] = t;
		}
	bml_buf_adds(b, "{");
	for (size_t i = 0; i < n; i++) {
		if (i)
			bml_buf_adds(b, ",");
		jstr(b, kv[idx[i]].key);
		bml_buf_adds(b, ":");
		jstr(b, kv[idx[i]].value);
	}
	bml_buf_adds(b, "}");
	free(idx);
}

int pc_emit(struct out *o, const char *result, int code)
{
	struct bml_buf b = {0};
	long long uid;
	char *cap;
	pc_run_as(&uid, &cap);
	bml_buf_adds(&b, "{\"format\":\"ebpf-precheck 1\",\"result\":");
	jstr(&b, result);
	bml_buf_adds(&b, ",\"unmet\":[");
	for (size_t i = 0; i < o->unmet.n; i++) {
		const struct bml_unmet *u = &o->unmet.u[i];
		char *d = bml_unmet_string(u);
		bml_buf_adds(&b, i ? ",{\"kind\":" : "{\"kind\":");
		jstr(&b, u->kind);
		bml_buf_adds(&b, ",\"program\":");
		jstr(&b, u->program);
		bml_buf_adds(&b, ",\"name\":");
		jstr(&b, u->name);
		bml_buf_addf(&b, ",\"id\":%lld,\"blocks_load\":%s,\"detail\":", (long long)u->id, bml_unmet_blocks_load(u) ? "true" : "false");
		jstr(&b, d ? d : "");
		bml_buf_adds(&b, "}");
		free(d);
	}
	bml_buf_adds(&b, "]");
	if (o->has_err && o->err.len) {
		bml_buf_adds(&b, ",\"error\":");
		bml_json_write_string(&b, o->err.p, o->err.len);
	}
	if (o->has_parse_error) {
		bml_buf_addf(&b, ",\"parse_error\":{\"line\":%d", o->pe.line);
		if (o->pe.row[0]) {
			bml_buf_adds(&b, ",\"row\":");
			jstr(&b, o->pe.row);
		}
		bml_buf_adds(&b, ",\"rule\":");
		jstr(&b, o->pe.rule);
		bml_buf_adds(&b, "}");
	}
	if (o->mp.n) {
		bml_buf_adds(&b, ",\"map_problems\":[");
		for (size_t i = 0; i < o->mp.n; i++) {
			bml_buf_adds(&b, i ? ",{\"map\":" : "{\"map\":");
			jstr(&b, o->mp.p[i].map);
			bml_buf_adds(&b, ",\"field\":");
			jstr(&b, o->mp.p[i].field);
			bml_buf_adds(&b, ",\"declared\":");
			jstr(&b, o->mp.p[i].declared);
			bml_buf_adds(&b, ",\"elf\":");
			jstr(&b, o->mp.p[i].elf);
			bml_buf_adds(&b, "}");
		}
		bml_buf_adds(&b, "]");
	}
	bml_buf_addf(&b, ",\"versions\":{\"format_max\":%d,\"policy\":%d", BML_MAX_FORMAT_VERSION, BML_POLICY_VERSION);
	if (o->object_format)
		bml_buf_addf(&b, ",\"object_format\":%d", o->object_format);
	bml_buf_adds(&b, ",\"bpf_mlir\":");
	jstr(&b, bml_version());
	bml_buf_addf(&b, "},\"run_as\":{\"uid\":%lld,\"cap_eff\":", uid);
	jstr(&b, cap);
	bml_buf_adds(&b, "}");
	if (o->has_probed_as) {
		bml_buf_addf(&b, ",\"probed_as\":{\"uid\":%lld,\"cap_eff\":", o->probed_uid);
		jstr(&b, o->probed_cap ? o->probed_cap : "");
		bml_buf_adds(&b, "}");
	}
	if (o->has_load_as) {
		bml_buf_addf(&b, ",\"load_as\":{\"uid\":%lld,\"cap_eff\":", o->load_uid);
		jstr(&b, o->load_cap ? o->load_cap : "");
		bml_buf_adds(&b, "}");
	}
	if (o->reprobed)
		bml_buf_adds(&b, ",\"reprobed\":true");
	if (o->loader) {
		const struct bml_loader_decl *d = o->loader;
		bml_buf_adds(&b, ",\"loader\":{\"name\":");
		jstr(&b, d->name);
		bml_buf_adds(&b, ",\"kprobe_alias_prefix\":");
		jkv(&b, d->kprobe_alias_prefix, d->n_kprobe_alias_prefix, d->has_kprobe_alias_prefix);
		bml_buf_addf(&b, ",\"uprobe_reopens_path\":%s,\"core_poisons_missing_field\":%s,\"btf_rewrite\":",
			     d->uprobe_reopens_path ? "true" : "false", d->core_poisons_missing_field ? "true" : "false");
		jkv(&b, d->btf_rewrite, d->n_btf_rewrite, d->has_btf_rewrite);

		const char *const lkeys[] = {"usdt_attach", "sockmap_attach", "lsm_cgroup_load", "fsession_load", "ksyscall_attach",
			"hidden_data_vars", "typed_ksym", "kconfig", "arena_cast", "arena_premmap"};
		const char *const lvals[] = {d->usdt_attach, d->sockmap_attach, d->lsm_cgroup_load, d->fsession_load, d->ksyscall_attach,
			d->hidden_data_vars, d->typed_ksym, d->kconfig, d->arena_cast, d->arena_premmap};
		for (size_t i = 0; i < sizeof(lkeys) / sizeof(lkeys[0]); i++)
			if (lvals[i] && lvals[i][0]) {
				bml_buf_addf(&b, ",\"%s\":", lkeys[i]);
				jstr(&b, lvals[i]);
			}
		bml_buf_adds(&b, "}");
	}
	bml_buf_adds(&b, "}\n");
	fwrite(b.p, 1, b.len, stdout);
	bml_buf_free(&b);
	free(cap);
	return code;
}

int pc_usage(struct out *o, const char *msg)
{
	o->has_err = 1;
	bml_buf_adds(&o->err, msg);
	return pc_emit(o, "usage_error", EXIT_USAGE);
}
