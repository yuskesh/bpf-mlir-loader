#include "caps/caps.h"

#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"

#define CILIUM_MEMORY_DECLS .hidden_data_vars = "no_mmap", .typed_ksym = "kallsyms_addr", .kconfig = "strong_only", \
	.arena_cast = "corrupt", .arena_premmap = "none"

const struct bml_loader_decl bml_loader_cilium022 = {
	CILIUM_MEMORY_DECLS,
	.name = "cilium-v0.22",
	.kprobe_alias_prefix = (struct bml_kv[]){{"x86_64", "__x64_"}},
	.n_kprobe_alias_prefix = 1,
	.has_kprobe_alias_prefix = 1,
	.uprobe_reopens_path = 1,
	.core_poisons_missing_field = 1,
	.btf_rewrite = (struct bml_kv[]){{"func_global", "rewrite"}, {"decl_tag", "rewrite"}, {"type_tag", "rewrite"}, {"enum64", "rewrite"}},
	.n_btf_rewrite = 4,
	.has_btf_rewrite = 1,
	.usdt_attach = "none",

	.sockmap_attach = "link",
	.lsm_cgroup_load = "none",
	.fsession_load = "none",
	.ksyscall_attach = "none",
};

#define CILIUM022_BODY                                                                                                                       \
	CILIUM_MEMORY_DECLS,                                                                                                               \
	.kprobe_alias_prefix = (struct bml_kv[]){{"x86_64", "__x64_"}}, .n_kprobe_alias_prefix = 1, .has_kprobe_alias_prefix = 1,              \
	.uprobe_reopens_path = 1, .core_poisons_missing_field = 1,                                                                            \
	.btf_rewrite = (struct bml_kv[]){{"func_global", "rewrite"}, {"decl_tag", "rewrite"}, {"type_tag", "rewrite"}, {"enum64", "rewrite"}}, \
	.n_btf_rewrite = 4, .has_btf_rewrite = 1, .lsm_cgroup_load = "none", .fsession_load = "none", .ksyscall_attach = "none"


const struct bml_loader_decl bml_loader_cilium022usdt = {
	.name = "cilium-v0.22-usdt",
	CILIUM022_BODY,
	.usdt_attach = "ref_ctr",
	.sockmap_attach = "link",
};


const struct bml_loader_decl bml_loader_cilium022progattach = {
	.name = "cilium-v0.22-progattach",
	CILIUM022_BODY,
	.usdt_attach = "none",
	.sockmap_attach = "prog_attach",
};



const struct bml_loader_decl bml_loader_cilium022ksyscall = {
	CILIUM_MEMORY_DECLS,
	.name = "cilium-v0.22-ksyscall",
	.kprobe_alias_prefix = (struct bml_kv[]){{"x86_64", "__x64_"}},
	.n_kprobe_alias_prefix = 1,
	.has_kprobe_alias_prefix = 1,
	.uprobe_reopens_path = 1,
	.core_poisons_missing_field = 1,
	.btf_rewrite = (struct bml_kv[]){{"func_global", "rewrite"}, {"decl_tag", "rewrite"}, {"type_tag", "rewrite"}, {"enum64", "rewrite"}},
	.n_btf_rewrite = 4,
	.has_btf_rewrite = 1,
	.usdt_attach = "none",
	.sockmap_attach = "link",
	.lsm_cgroup_load = "none",
	.fsession_load = "none",
	.ksyscall_attach = "prefix",
};



const struct bml_loader_decl bml_loader_cilium022usdtksyscall = {
	CILIUM_MEMORY_DECLS,
	.name = "cilium-v0.22-usdt-ksyscall",
	.kprobe_alias_prefix = (struct bml_kv[]){{"x86_64", "__x64_"}},
	.n_kprobe_alias_prefix = 1,
	.has_kprobe_alias_prefix = 1,
	.uprobe_reopens_path = 1,
	.core_poisons_missing_field = 1,
	.btf_rewrite = (struct bml_kv[]){{"func_global", "rewrite"}, {"decl_tag", "rewrite"}, {"type_tag", "rewrite"}, {"enum64", "rewrite"}},
	.n_btf_rewrite = 4,
	.has_btf_rewrite = 1,
	.usdt_attach = "ref_ctr",
	.sockmap_attach = "link",
	.lsm_cgroup_load = "none",
	.fsession_load = "none",
	.ksyscall_attach = "prefix",
};

static int one_of(const char *v, const char *a, const char *b)
{
	return !strcmp(v, a) || !strcmp(v, b);
}

int bml_loader_decl_validate(const struct bml_loader_decl *d, char **err)
{
	const char *u = d->usdt_attach ? d->usdt_attach : "";
	struct bml_buf b = {0};
	bml_buf_adds(&b, "loader ");
	bml_buf_add_goquote(&b, d->name ? d->name : "", d->name ? strlen(d->name) : 0);
	if (u[0] && strcmp(u, "none") && strcmp(u, "plain") && strcmp(u, "ref_ctr")) {
		bml_buf_adds(&b, ": usdt_attach ");
		bml_buf_add_goquote(&b, u, strlen(u));
		bml_buf_adds(&b, ", want \"none\", \"plain\" or \"ref_ctr\" (or no key — unknown)");
		*err = bml_buf_take(&b);
		return -1;
	}

	const struct {
		const char *key, *v, *a, *b;
	} kv[] = {
		{"sockmap_attach", d->sockmap_attach, "link", "prog_attach"},
		{"lsm_cgroup_load", d->lsm_cgroup_load, "none", "btf_id"},
		{"fsession_load", d->fsession_load, "none", "btf_id"},
		{"ksyscall_attach", d->ksyscall_attach, "none", "prefix"},
		{"hidden_data_vars", d->hidden_data_vars, "no_mmap", "mmap"},
		{"typed_ksym", d->typed_ksym, "btf_id", "kallsyms_addr"},
		{"kconfig", d->kconfig, "weak_zero", "strong_only"},
		{"arena_cast", d->arena_cast, "preserve", "corrupt"},
		{"arena_premmap", d->arena_premmap, "create_then_mmap", "none"},
	};
	for (size_t i = 0; i < sizeof(kv) / sizeof(kv[0]); i++) {
		const char *v = kv[i].v ? kv[i].v : "";
		if (!v[0] || one_of(v, kv[i].a, kv[i].b))
			continue;
		bml_buf_addf(&b, ": %s ", kv[i].key);
		bml_buf_add_goquote(&b, v, strlen(v));
		bml_buf_adds(&b, " is not a known value (or no key — not declared)");
		*err = bml_buf_take(&b);
		return -1;
	}
	bml_buf_free(&b);
	return 0;
}

const char *bml_kv_get(const struct bml_kv *kv, size_t n, const char *key)
{

	for (size_t i = 0; i < n; i++)
		if (strcmp(kv[i].key, key) == 0)
			return kv[i].value;
	return NULL;
}

void bml_loader_decl_free(struct bml_loader_decl *d)
{
	free(d->name);
	for (size_t i = 0; i < d->n_kprobe_alias_prefix; i++) {
		free(d->kprobe_alias_prefix[i].key);
		free(d->kprobe_alias_prefix[i].value);
	}
	free(d->kprobe_alias_prefix);
	for (size_t i = 0; i < d->n_btf_rewrite; i++) {
		free(d->btf_rewrite[i].key);
		free(d->btf_rewrite[i].value);
	}
	free(d->btf_rewrite);
	free(d->usdt_attach);
	free(d->sockmap_attach);
	free(d->lsm_cgroup_load);
	free(d->fsession_load);
	free(d->ksyscall_attach);
	free(d->hidden_data_vars);
	free(d->typed_ksym);
	free(d->kconfig);
	free(d->arena_cast);
	free(d->arena_premmap);
	memset(d, 0, sizeof(*d));
}

void bml_strs_free(struct bml_strs *v)
{
	for (size_t i = 0; i < v->n; i++)
		free(v->s[i]);
	free(v->s);
	v->s = NULL;
	v->n = 0;
}



const struct bml_loader_decl bml_loader_bmllibbpf17 = {
	.arena_cast = "preserve",
	.arena_premmap = "create_then_mmap",
	.name = "bml-libbpf-v1.7",
	.kprobe_alias_prefix = (struct bml_kv[]){{"x86_64", ""}},
	.n_kprobe_alias_prefix = 1,
	.has_kprobe_alias_prefix = 1,
	.uprobe_reopens_path = 1,
	.core_poisons_missing_field = 1,
	.btf_rewrite = (struct bml_kv[]){{"func_global", "keep"}, {"decl_tag", "keep"}, {"type_tag", "keep"}, {"enum64", "keep"}},
	.n_btf_rewrite = 4,
	.has_btf_rewrite = 1,
};


const struct bml_loader_decl *bml_loader_preset(const char *name)
{
	if (!strcmp(name, bml_loader_cilium022.name))
		return &bml_loader_cilium022;
	if (!strcmp(name, bml_loader_bmllibbpf17.name))
		return &bml_loader_bmllibbpf17;
	if (!strcmp(name, bml_loader_cilium022progattach.name))
		return &bml_loader_cilium022progattach;
	if (!strcmp(name, bml_loader_cilium022usdt.name))
		return &bml_loader_cilium022usdt;
	if (!strcmp(name, bml_loader_cilium022ksyscall.name))
		return &bml_loader_cilium022ksyscall;
	if (!strcmp(name, bml_loader_cilium022usdtksyscall.name))
		return &bml_loader_cilium022usdtksyscall;
	return NULL;
}
