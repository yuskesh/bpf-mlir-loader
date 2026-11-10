/* CONTRACT: C form of the check queries (requirements_format.md section 5) and
 * the loader declaration (section 8).
 *
 * Go's "implements the interface and QuerySet.HasQuery" is the single has_query: a NULL function pointer or a false has_query means
 * "does not have it". prog_type, helper and map_type are required.
 * Answers have 3 states: BML_Q_OK (value), BML_Q_UNKNOWN (cannot be judged), BML_Q_ERROR (other errors).
 * UNKNOWN and ERROR put malloc'd text in *msg. */
#ifndef BML_CAPS_H
#define BML_CAPS_H

#include <stddef.h>
#include <stdint.h>

#include "req/req.h"

enum { BML_Q_OK = 0, BML_Q_UNKNOWN = 1, BML_Q_ERROR = 2, BML_Q_ABSENT = 3 };


#define BML_QUERY_PROG_TYPE "prog_type"
#define BML_QUERY_HELPER "helper"
#define BML_QUERY_MAP_TYPE "map_type"
#define BML_QUERY_TCX "tcx"
#define BML_QUERY_FUNC_SIG "func_sig"
#define BML_QUERY_FUNC "func"
#define BML_QUERY_TRACEPOINT "tracepoint"
#define BML_QUERY_FUNC_ARGS "func_args"
#define BML_QUERY_KFIELDS "kfields"
#define BML_QUERY_BTF_FEATURE "btf_feature"
#define BML_QUERY_ARG_TAG "arg_tag"
#define BML_QUERY_ARCH "arch"
#define BML_QUERY_STRUCT_FIELD "struct_field"
#define BML_QUERY_KERNEL_SYM "kernel_symbol"
#define BML_QUERY_FUNC_PARAM "func_param"
#define BML_QUERY_UPROBE_BIN "uprobe_binary"
#define BML_QUERY_UPROBE_DEBUG "uprobe_debug"
#define BML_QUERY_MAP_FIELD "map_field"
#define BML_QUERY_NULLABLE_ARGS "nullable_args"
#define BML_QUERY_TRACING_HELPER "tracing_helpers"
#define BML_QUERY_ATTACH_TYPE "attach_types"
#define BML_QUERY_ATTACH_TARGET "attach_targets"
#define BML_QUERY_CTX_ACCESS "ctx_access"
#define BML_QUERY_TP_FIELDS "tracepoint_fields"
#define BML_QUERY_STRUCT_OPS_MEMBERS "struct_ops_members"
#define BML_QUERY_EXT_TARGETS "ext_targets"
#define BML_QUERY_KFUNC_PROTOS "kfunc_protos"
#define BML_QUERY_SYSCALL_ARGS "syscall_args"
#define BML_QUERY_KFUNC_LOADS "kfunc_loads"
#define BML_QUERY_TRACEPOINT_BUFFER "tracepoint_buffer"
#define BML_QUERY_ENUM_VALUES "enum_values"
#define BML_QUERY_FIB_FLAGS "fib_lookup_flags"
#define BML_QUERY_KSYM_VARS "ksym_vars"
#define BML_QUERY_KCONFIG "kconfig"
#define BML_QUERY_BTF_PRESENCE "btf_presence"
#define BML_QUERY_FUNC_RET "func_ret"
#define BML_QUERY_STRUCT_SIZE "kstruct_size"
#define BML_QUERY_NETKIT "netkit"
#define BML_QUERY_HELPER_TARGET "helper_target"
#define BML_QUERY_SLEEPABLE "sleepable_types"


struct bml_kfunc_profile {
	const char *kind, *section, *prog_type;
	int64_t prog_type_id;
	uint32_t prog_flags;
	const char *attach_type, *target_kind, *target, *context_identity, *recipe;
};


char *bml_caps_kfunc_load_key(const struct bml_kfunc_profile *p, const char *name, const char *ret, const struct bml_str *args, size_t n);

char *bml_caps_helper_target_key(const char *prog_type, int64_t prog_type_id, const struct bml_helper_target *h);

struct bml_kv {
	char *key, *value;
};


struct bml_loader_decl {
	char *name;
	struct bml_kv *kprobe_alias_prefix;
	size_t n_kprobe_alias_prefix;
	int has_kprobe_alias_prefix;
	int uprobe_reopens_path, core_poisons_missing_field;
	struct bml_kv *btf_rewrite;
	size_t n_btf_rewrite;
	int has_btf_rewrite;
	char *usdt_attach;
	

	char *sockmap_attach, *lsm_cgroup_load, *fsession_load, *ksyscall_attach;
	char *hidden_data_vars, *typed_ksym, *kconfig, *arena_cast, *arena_premmap;
};

extern const struct bml_loader_decl bml_loader_cilium022;
extern const struct bml_loader_decl bml_loader_bmllibbpf17;
extern const struct bml_loader_decl bml_loader_cilium022usdt;
extern const struct bml_loader_decl bml_loader_cilium022progattach;
extern const struct bml_loader_decl bml_loader_cilium022ksyscall;

extern const struct bml_loader_decl bml_loader_cilium022usdtksyscall;

int bml_loader_decl_validate(const struct bml_loader_decl *d, char **err);

const struct bml_loader_decl *bml_loader_preset(const char *name);
#define BML_LOADER_PRESETS "bml-libbpf-v1.7, cilium-v0.22, cilium-v0.22-ksyscall, cilium-v0.22-progattach, cilium-v0.22-usdt, cilium-v0.22-usdt-ksyscall"

const char *bml_kv_get(const struct bml_kv *kv, size_t n, const char *key);
void bml_loader_decl_free(struct bml_loader_decl *d);


struct bml_strs {
	char **s;
	size_t n;
};
void bml_strs_free(struct bml_strs *v);

struct bml_caps {
	void *ctx;
	int (*has_query)(void *ctx, const char *query);
	const struct bml_loader_decl *(*loader)(void *ctx);


	int (*prog_type)(void *ctx, const char *name, int64_t id, int *out, char **msg);
	int (*helper)(void *ctx, const char *prog_type, int64_t prog_type_id, const char *helper, int64_t helper_id, int *out,
		      char **msg);
	int (*map_type)(void *ctx, const char *name, int64_t id, int *out, char **msg);
	int (*tracing_helper)(void *ctx, const char *attach_type, const char *helper, int64_t helper_id, int *out, char **msg);
	int (*tcx)(void *ctx, int *out, char **msg);
	int (*btf_feature)(void *ctx, const char *feature, int *out, char **msg);
	int (*arg_tag)(void *ctx, const char *prog_type, int64_t prog_type_id, const char *tag, const char *cls, int *out,
		       char **msg);
	int (*kernel_symbol)(void *ctx, const char *name, int *out, char **msg);
	int (*map_field)(void *ctx, const char *prog_type, int64_t prog_type_id, const char *field, int *out, char **msg);
	int (*nullable_args)(void *ctx, int *out, char **msg);
	

	int (*attach_type)(void *ctx, const char *prog_type, int64_t prog_type_id, const char *attach_type, int *out, char **msg);
	int (*attach_target)(void *ctx, const char *attach_type, const char *kind, const char *value, int *out, char **msg);
	int (*ctx_access)(void *ctx, const char *prog_type, int64_t prog_type_id, const char *attach_type, const char *strct,
			  const char *field, const char *mode, int64_t bytes, int *out, char **msg);


	int (*func_sig)(void *ctx, const char *name, int64_t nargs, const char *ret, struct bml_strs *out, char **msg);
	int (*func)(void *ctx, const char *name, struct bml_strs *out, char **msg);
	int (*tracepoint)(void *ctx, const char *name, const struct bml_str *args, size_t n_args, struct bml_strs *out,
			  char **msg);

	int (*func_args)(void *ctx, const char *name, const struct bml_str *args, size_t n_args, struct bml_strs *out, char **msg);
	

	int (*tp_field)(void *ctx, const char *event, const char *field, int64_t offset, int64_t bytes, const char *sign, struct bml_strs *out,
			char **msg);
	int (*struct_ops_member)(void *ctx, const char *strct, const char *member, int64_t nargs, const char *ret, const struct bml_str *args,
				 size_t n_args, struct bml_strs *out, char **msg);
	int (*ext_target)(void *ctx, const char *program, const char *fn, int64_t nargs, const char *ret, const struct bml_str *args, size_t n_args,
			  struct bml_strs *out, char **msg);
	int (*kfields)(void *ctx, const struct bml_kfield *kf, size_t n, struct bml_strs *out, char **msg);
	int (*struct_field)(void *ctx, const char *st, const char *field, int64_t offset, int64_t size, struct bml_strs *out,
			    char **msg);
	int (*func_param)(void *ctx, const char *name, int64_t n, const char *type, struct bml_strs *out, char **msg);

	int (*kfunc)(void *ctx, const char *name, const char *ret, const struct bml_str *args, size_t n_args, struct bml_strs *out, char **msg);
	int (*syscall_arg)(void *ctx, const char *name, int64_t n, const char *type, struct bml_strs *out, char **msg);

	int (*kfunc_load)(void *ctx, const struct bml_kfunc_profile *p, const char *name, const char *ret, const struct bml_str *args, size_t n_args,
			  int *out, char **msg);
	int (*tracepoint_buffer)(void *ctx, const char *name, const char *pointee, struct bml_strs *out, char **msg);

	int (*enum_value)(void *ctx, const char *enumeration, const char *name, uint64_t *out, char **msg);
	int (*fib_flags)(void *ctx, const char *prog_type, int64_t id, uint32_t mask, int *out, char **msg);
	int (*ksym_var)(void *ctx, const char *name, char **out, char **msg);
	int (*kconfig)(void *ctx, const char *name, char **out, char **msg);
	int (*btf_presence)(void *ctx, const char *kind, const char *target, int *out, char **msg);
	int (*func_ret)(void *ctx, const char *name, const char *type, struct bml_strs *out, char **msg);
	int (*struct_size)(void *ctx, const char *name, uint32_t *out, char **msg);

	int (*netkit)(void *ctx, const char *direction, int *out, char **msg);
	int (*sleepable)(void *ctx, const char *prog_type, const char *attach_type, int *out, char **msg);
	int (*helper_target)(void *ctx, const char *prog_type, int64_t prog_type_id, const struct bml_helper_target *h, struct bml_strs *out, char **msg);


	int (*arch)(void *ctx, char **out, char **msg);

	int (*uprobe_binary)(void *ctx, const char *program, uint8_t **data, size_t *len, char **msg);
	/* CONTRACT: byte snapshot of the split DWARF file (malloc; alive only during the check, the caller frees) and the path to record (*path,
 * malloc, NULL if none). UNKNOWN text is fixed ASCII (debug_file.c) or the recorded answer */
	int (*uprobe_debug)(void *ctx, const char *program, const uint8_t *id, size_t id_len, uint8_t **data, size_t *len, char **path, char **msg);
};



char *bml_caps_uprobe_debug_key(const char *program, const uint8_t *id, size_t n);
int bml_caps_debug_build_id_path(const char *root, const uint8_t *id, size_t n, char **path, char **msg);
int bml_caps_debug_read_file(const char *path, uint8_t **data, size_t *len, char **abs, char **msg);

#endif
