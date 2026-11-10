/* CONTRACT: live caps that query the target kernel
 * (the probes follow cilium/ebpf v0.22 features, prog and btf).
 *
 * Answer kinds (value, Unknown, error, mismatch) match the Go loader's, and mismatch text copies Go's format byte for byte (recorded diffs become the Unmet text).
 * Cache granularity is copied too: cilium's FeatureTest (present / absent only, for the process lifetime; other errors are not remembered), and
 * the Go memo (tracing helper, arg_tag, map_field also remember errors) and Once (vmlinux, nullable).
 *
 * Process state is not changed: signal masks, handlers, threads and rlimits are not touched. Every probe fd is closed (no cilium token is created;
 * in the init user namespace cilium cannot create one either). */
#ifndef BML_CAPS_LIVE_H
#define BML_CAPS_LIVE_H

#include "btf/kernel.h"
#include "caps/caps.h"


enum { LV_UNSET = 0, LV_OK = 1, LV_NOTSUP = 2 };

enum {
	LVF_BTF, LVF_MAP_BTF, LVF_PROG_BTF, LVF_FUNC_LINKAGE, LVF_DECL_TAGS, LVF_TYPE_TAGS, LVF_ENUM64, LVF_OBJ_NAME,
	LVF_OBJ_NAME_DOT, LVF_EXT_INFOS, LVF_BPF2BPF, LVF_PROBE_READ_KERNEL, LVF_N
};

struct lv_memo {
	char *key;
	int rc, value;
	char *msg;
};

struct lv_helper_cache {
	uint32_t pt, helper;
	int state;
};

struct bml_live {
	struct bml_kernel_sources *kernel_sources;

	int kb_done, kb_rc;
	char *kb_err;
	struct bml_kbtf kb;

	int feat[LVF_N];

	int kver_done, kver_ok;
	uint32_t kver;

	int prog_type[33], map_type[34];
	int prog_type_errno[33];
	struct lv_helper_cache *helpers;
	size_t n_helpers;

	struct lv_memo *memo;
	size_t n_memo;
	int nullable_done, nullable_rc, nullable_value;
};

void bml_live_free(struct bml_live *l);


int bml_live_func(struct bml_live *l, const char *name, struct bml_strs *out, char **msg);
int bml_live_func_sig(struct bml_live *l, const char *name, int64_t nargs, const char *ret, struct bml_strs *out, char **msg);
int bml_live_enum_value(struct bml_live *l, const char *en, const char *name, uint64_t *out, char **msg);
int bml_live_func_ret(struct bml_live *l, const char *name, const char *ret, struct bml_strs *out, char **msg);
int bml_live_ksym_var(struct bml_live *l, const char *name, char **out, char **msg);
int bml_live_struct_size(struct bml_live *l, const char *name, uint32_t *out, char **msg);
int bml_live_btf_presence(struct bml_live *l, const char *kind, const char *target, int *out, char **msg);
int bml_live_kconfig(struct bml_live *l, const char *name, char **out, char **msg);
int bml_live_fib_flags(struct bml_live *l, const char *prog, int64_t id, uint32_t mask, int *out, char **msg);
int bml_live_tracepoint(struct bml_live *l, const char *name, const struct bml_str *args, size_t n_args, struct bml_strs *out,
			char **msg);
int bml_live_kfields(struct bml_live *l, const struct bml_kfield *kf, size_t n, struct bml_strs *out, char **msg);
int bml_live_struct_field(struct bml_live *l, const char *st, const char *field, int64_t offset, int64_t size,
			  struct bml_strs *out, char **msg);
int bml_live_func_param(struct bml_live *l, const char *name, int64_t n, const char *type, struct bml_strs *out, char **msg);

int bml_live_kfunc(struct bml_live *l, const char *name, const char *ret, const struct bml_str *args, size_t n_args, struct bml_strs *out, char **msg);
int bml_live_syscall_arg(struct bml_live *l, const char *name, int64_t n, const char *typ, struct bml_strs *out, char **msg);

int bml_live_kfunc_load(struct bml_live *l, const struct bml_kfunc_profile *p, const char *name, const char *ret, const struct bml_str *args, size_t n,
			int *out, char **msg);
int bml_live_tracepoint_buffer(struct bml_live *l, const char *name, const char *pointee, struct bml_strs *out, char **msg);

int bml_live_func_args(struct bml_live *l, const char *name, const struct bml_str *args, size_t n_args, struct bml_strs *out, char **msg);

int bml_live_netkit(struct bml_live *l, const char *direction, int *out, char **msg);
int bml_live_sleepable(struct bml_live *l, const char *prog_type, const char *attach_type, int *out, char **msg);
int bml_live_helper_target(struct bml_live *l, const char *prog_type, int64_t prog_type_id, const struct bml_helper_target *h, struct bml_strs *out, char **msg);

enum { BML_LV_FALSE = 0, BML_LV_TRUE = 1, BML_LV_UNKNOWN = -1, BML_LV_UNEXPECTED = -2 };
int bml_live_netkit_answer(int link_rc);
int bml_live_sleepable_refused_by_type(int verifier, const char *const *lines, size_t n);
int bml_live_helper_target_denied(int err, int verifier, const char *const *lines, size_t n);


int bml_live_struct_ops_member(struct bml_live *l, const char *strct, const char *member, int64_t nargs, const char *ret, const struct bml_str *args,
			       size_t n_args, struct bml_strs *out, char **msg);
int bml_live_tp_field(struct bml_live *l, const char *event, const char *field, int64_t off, int64_t bytes, const char *sign, struct bml_strs *out,
		      char **msg);

int bml_ext_target_load(const char *target, struct bml_kbtf *kb, char **err);

int bml_ext_target_check(const struct bml_kbtf *kb, const char *fn, int64_t nargs, const char *ret, const struct bml_str *args, size_t n,
			 struct bml_strs *out, char **msg);


int bml_live_func_btf_id(struct bml_live *l, const char *name, uint32_t *id, char **err);


int bml_live_arch(char **out, char **msg);
int bml_live_kernel_symbol(const char *name, int *out, char **msg);


int bml_live_prog_type(struct bml_live *l, int64_t id, int *out, char **msg);
int bml_live_helper(struct bml_live *l, int64_t prog_type_id, int64_t helper_id, int *out, char **msg);
int bml_live_tracing_helper(struct bml_live *l, const char *attach_type, const char *helper, int64_t helper_id, int *out, char **msg);
int bml_live_tcx(struct bml_live *l, int *out, char **msg);
int bml_live_map_type(struct bml_live *l, int64_t id, int *out, char **msg);
int bml_live_map_field(struct bml_live *l, const char *prog_type, int64_t prog_type_id, const char *field, int *out, char **msg);
int bml_live_btf_feature(struct bml_live *l, const char *feature, int *out, char **msg);
int bml_live_arg_tag(struct bml_live *l, const char *prog_type, int64_t prog_type_id, const char *tag, const char *cls, int *out, char **msg);
int bml_live_nullable_args(struct bml_live *l, int *out, char **msg);

int bml_live_attach_type(struct bml_live *l, const char *pt, int64_t ptid, const char *at, int *out, char **msg);
int bml_live_attach_target(struct bml_live *l, const char *at, const char *kind, const char *value, int *out, char **msg);
int bml_live_ctx_access(struct bml_live *l, const char *pt, int64_t ptid, const char *at, const char *st, const char *field, const char *mode,
			int64_t bytes, int *out, char **msg);

#endif
