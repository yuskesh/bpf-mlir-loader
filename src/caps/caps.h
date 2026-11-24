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

/* Query names: the keys of "queries" in caps.json, the same strings as the Go constants Query*. */
#define BML_QUERY_PROG_TYPE "prog_type"
#define BML_QUERY_HELPER "helper"
#define BML_QUERY_MAP_TYPE "map_type"
#define BML_QUERY_TCX "tcx"
#define BML_QUERY_FUNC_SIG "func_sig"
#define BML_QUERY_FUNC "func"
#define BML_QUERY_TRACEPOINT "tracepoint"
#define BML_QUERY_FUNC_ARGS "func_args" /* added with bpf-mlir v0.17.0 (ebpf-caps 3): whether a function's argument is a pointer to a struct */
#define BML_QUERY_KFIELDS "kfields"
#define BML_QUERY_BTF_FEATURE "btf_feature"
#define BML_QUERY_ARG_TAG "arg_tag"
#define BML_QUERY_ARCH "arch"
#define BML_QUERY_STRUCT_FIELD "struct_field"
#define BML_QUERY_KERNEL_SYM "kernel_symbol"
#define BML_QUERY_FUNC_PARAM "func_param"
#define BML_QUERY_UPROBE_BIN "uprobe_binary"
#define BML_QUERY_UPROBE_DEBUG "uprobe_debug" /* ebpf-caps recording format 10: the separated DWARF file of a binary (the answer does not depend on privilege) */
#define BML_QUERY_MAP_FIELD "map_field"
#define BML_QUERY_NULLABLE_ARGS "nullable_args"
#define BML_QUERY_TRACING_HELPER "tracing_helpers"
#define BML_QUERY_ATTACH_TYPE "attach_types"   /* ebpf-caps recording format 4 */
#define BML_QUERY_ATTACH_TARGET "attach_targets"
#define BML_QUERY_CTX_ACCESS "ctx_access"
#define BML_QUERY_TP_FIELDS "tracepoint_fields"        /* ebpf-caps recording format 5 */
#define BML_QUERY_STRUCT_OPS_MEMBERS "struct_ops_members"
#define BML_QUERY_EXT_TARGETS "ext_targets"
#define BML_QUERY_KFUNC_PROTOS "kfunc_protos" /* ebpf-caps recording format 8 */
#define BML_QUERY_SYSCALL_ARGS "syscall_args"
#define BML_QUERY_KFUNC_LOADS "kfunc_loads"             /* ebpf-caps recording format 9; the answer depends on privilege */
#define BML_QUERY_TRACEPOINT_BUFFER "tracepoint_buffer" /* answered from BTF alone */
#define BML_QUERY_ENUM_VALUES "enum_values"
#define BML_QUERY_FIB_FLAGS "fib_lookup_flags"
#define BML_QUERY_KSYM_VARS "ksym_vars"
#define BML_QUERY_KCONFIG "kconfig"
#define BML_QUERY_BTF_PRESENCE "btf_presence"
#define BML_QUERY_FUNC_RET "func_ret"
#define BML_QUERY_STRUCT_SIZE "kstruct_size"
#define BML_QUERY_NETKIT "netkit"                /* ebpf-caps recording format 18; the answer depends on privilege */
#define BML_QUERY_HELPER_TARGET "helper_target"  /* ebpf-caps recording format 19; depends on privilege and is also bound to the UID */
#define BML_QUERY_SLEEPABLE "sleepable_types"    /* ebpf-caps recording format 20; depends on privilege */

/* KfuncProfile (ebpf-caps recording format 9): the initial profile for the question "may this kfunc be used?".
 * FromELF derives it from the ELF; the strings belong to the caller. */
struct bml_kfunc_profile {
	const char *kind, *section, *prog_type;
	int64_t prog_type_id;
	uint32_t prog_flags;
	const char *attach_type, *target_kind, *target, *context_identity, *recipe;
};
/* KfuncLoadKey: what Go's json.Marshal([recipe, name, ret, args, prog_type, id, kind, section, flags, attach_type, target_kind, target, context])
 * produces, including its HTML escaping of <, > and & (malloc'd). */
char *bml_caps_kfunc_load_key(const struct bml_kfunc_profile *p, const char *name, const char *ret, const struct bml_str *args, size_t n);
/* HelperTargetKey: a canonical JSON array of 8 elements (malloc'd). */
char *bml_caps_helper_target_key(const char *prog_type, int64_t prog_type_id, const struct bml_helper_target *h);

struct bml_kv {
	char *key, *value;
};

/* The loader declaration (Go's LoaderDecl). kprobe_alias_prefix and btf_rewrite distinguish "declared" from "not declared"
 * (a key that is absent means unknown). */
struct bml_loader_decl {
	char *name;
	struct bml_kv *kprobe_alias_prefix;
	size_t n_kprobe_alias_prefix;
	int has_kprobe_alias_prefix; /* tells JSON null / absent apart from {} (Go's nil map versus empty map, which reflect.DeepEqual distinguishes) */
	int uprobe_reopens_path, core_poisons_missing_field;
	struct bml_kv *btf_rewrite;
	size_t n_btf_rewrite;
	int has_btf_rewrite;
	char *usdt_attach; /* none, plain or ref_ctr; NULL or "" means not declared (usdt_loader_unknown) */
	/* From ebpf-caps recording format 8: NULL or "" means not declared. sockmap_attach is link or prog_attach ("" means link);
	 * lsm_cgroup_load and fsession_load are none or btf_id; ksyscall_attach is none or prefix ("" gives the matching *_loader_unknown). */
	char *sockmap_attach, *lsm_cgroup_load, *fsession_load, *ksyscall_attach;
	char *hidden_data_vars, *typed_ksym, *kconfig, *arena_cast, *arena_premmap;
};

extern const struct bml_loader_decl bml_loader_cilium022;
extern const struct bml_loader_decl bml_loader_bmllibbpf17;
extern const struct bml_loader_decl bml_loader_cilium022usdt; /* same as Cilium022, but usdt_attach is ref_ctr */
extern const struct bml_loader_decl bml_loader_cilium022progattach; /* same as Cilium022, but sockmap_attach is prog_attach */
extern const struct bml_loader_decl bml_loader_cilium022ksyscall; /* same as Cilium022, but ksyscall_attach is prefix */
/* The combination of Cilium022USDT and Cilium022Ksyscall: usdt_attach is ref_ctr and ksyscall_attach is prefix. */
extern const struct bml_loader_decl bml_loader_cilium022usdtksyscall;
/* LoaderDecl.Validate: an unknown value for usdt_attach or for the four keys added with ebpf-caps recording format 8 (checked in
 * that order) gives -1 and a message in *err (Go's wording, malloc'd). */
int bml_loader_decl_validate(const struct bml_loader_decl *d, char **err);
/* A named preset (Go's requirements.LoaderPresets); NULL if there is none. BML_LOADER_PRESETS is in ascending name order
 * (the order of the "known" list in Go's usage text). */
const struct bml_loader_decl *bml_loader_preset(const char *name);
#define BML_LOADER_PRESETS "bml-libbpf-v1.7, cilium-v0.22, cilium-v0.22-ksyscall, cilium-v0.22-progattach, cilium-v0.22-usdt, cilium-v0.22-usdt-ksyscall"
/* The value of a key (NULL if absent). */
const char *bml_kv_get(const struct bml_kv *kv, size_t n, const char *key);
void bml_loader_decl_free(struct bml_loader_decl *d);

/* The list of mismatch sentences (the answer of "diffs"); the caller releases it with bml_strs_free. */
struct bml_strs {
	char **s;
	size_t n;
};
void bml_strs_free(struct bml_strs *v);

struct bml_caps {
	void *ctx;
	int (*has_query)(void *ctx, const char *query);
	const struct bml_loader_decl *(*loader)(void *ctx); /* NULL means Cilium022 (a caps that does not implement Go's LoaderCaps) */

	/* Boolean queries */
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
	/* Policy version 7: prog type x expected attach type; attach type x target kind x value;
	 * prog type x attach type ("-" means none) x struct x field x mode ("r" / "w") x byte count. */
	int (*attach_type)(void *ctx, const char *prog_type, int64_t prog_type_id, const char *attach_type, int *out, char **msg);
	int (*attach_target)(void *ctx, const char *attach_type, const char *kind, const char *value, int *out, char **msg);
	int (*ctx_access)(void *ctx, const char *prog_type, int64_t prog_type_id, const char *attach_type, const char *strct,
			  const char *field, const char *mode, int64_t bytes, int *out, char **msg);

	/* Matching queries (the answer is the mismatch sentences; empty means a match) */
	int (*func_sig)(void *ctx, const char *name, int64_t nargs, const char *ret, struct bml_strs *out, char **msg);
	int (*func)(void *ctx, const char *name, struct bml_strs *out, char **msg);
	int (*tracepoint)(void *ctx, const char *name, const struct bml_str *args, size_t n_args, struct bml_strs *out,
			  char **msg);
	/* Added with bpf-mlir v0.17.0 (ebpf-caps 3): whether argument i of the FUNC_PROTO of FUNC name is a pointer to the struct named by args[i]
	 * ("-" is not matched). The answer is the mismatch sentences. */
	int (*func_args)(void *ctx, const char *name, const struct bml_str *args, size_t n_args, struct bml_strs *out, char **msg);
	/* Policy version 9: the fields of a tracepoint event (`<cat>/<event>`); the members of a struct_ops (nargs < 0 and ret ""
	 * are not matched); the replacement target of an ext program (one per program, supplied by the loader). */
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
	/* Policy version 12: the prototype of a kfunc (spelling of the return type and the arguments); the spelling of argument n
	 * (counted from 1) of a syscall. */
	int (*kfunc)(void *ctx, const char *name, const char *ret, const struct bml_str *args, size_t n_args, struct bml_strs *out, char **msg);
	int (*syscall_arg)(void *ctx, const char *name, int64_t n, const char *type, struct bml_strs *out, char **msg);
	/* Policy version 13: whether a kfunc may be used (a boolean: can it be loaded with the initial profile?) and the pointee of
	 * argument 0 of a tracepoint's buffer. */
	int (*kfunc_load)(void *ctx, const struct bml_kfunc_profile *p, const char *name, const char *ret, const struct bml_str *args, size_t n_args,
			  int *out, char **msg);
	int (*tracepoint_buffer)(void *ctx, const char *name, const char *pointee, struct bml_strs *out, char **msg);
	/* ABSENT is a known absence and is returned only by the newer value queries (msg carries a sentence that includes the sentinel). */
	int (*enum_value)(void *ctx, const char *enumeration, const char *name, uint64_t *out, char **msg);
	int (*fib_flags)(void *ctx, const char *prog_type, int64_t id, uint32_t mask, int *out, char **msg);
	int (*ksym_var)(void *ctx, const char *name, char **out, char **msg);
	int (*kconfig)(void *ctx, const char *name, char **out, char **msg);
	int (*btf_presence)(void *ctx, const char *kind, const char *target, int *out, char **msg);
	int (*func_ret)(void *ctx, const char *name, const char *type, struct bml_strs *out, char **msg);
	int (*struct_size)(void *ctx, const char *name, uint32_t *out, char **msg);
	/* Per-direction netkit links; whether a program type x attach type is sleepable; helpers typed against the real target
	 * (the answer is the mismatch sentences; empty means accepted). */
	int (*netkit)(void *ctx, const char *direction, int *out, char **msg);
	int (*sleepable)(void *ctx, const char *prog_type, const char *attach_type, int *out, char **msg);
	int (*helper_target)(void *ctx, const char *prog_type, int64_t prog_type_id, const struct bml_helper_target *h, struct bml_strs *out, char **msg);

	/* Value queries */
	int (*arch)(void *ctx, char **out, char **msg);
	/* The contents of a uprobe's binary (malloc'd; the caller frees it). */
	int (*uprobe_binary)(void *ctx, const char *program, uint8_t **data, size_t *len, char **msg);
	/* CONTRACT: byte snapshot of the split DWARF file (malloc; alive only during the check, the caller frees) and the path to record (*path,
 * malloc, NULL if none). UNKNOWN text is fixed ASCII (debug_file.c) or the recorded answer */
	int (*uprobe_debug)(void *ctx, const char *program, const uint8_t *id, size_t id_len, uint8_t **data, size_t *len, char **path, char **msg);
};

/* debug_file.c (ebpf-caps recording format 10): the query key "<program>/<lowercase hex>" (malloc'd); the implicit path derived
 * from a build ID (an empty root gives Unknown, "separate DWARF lookup is disabled"); and the file snapshot (*abs is the
 * absolute path, which may be malloc'd even when the read failed). */
char *bml_caps_uprobe_debug_key(const char *program, const uint8_t *id, size_t n);
int bml_caps_debug_build_id_path(const char *root, const uint8_t *id, size_t n, char **path, char **msg);
int bml_caps_debug_read_file(const char *path, uint8_t **data, size_t *len, char **abs, char **msg);

#endif
