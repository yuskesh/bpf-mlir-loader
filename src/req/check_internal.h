/* req/check_internal.h — internal parts of the checker (Check); used inside req/ only. check.c was split into several files in a restructuring before the map-declaration records work. */
#ifndef BML_REQ_CHECK_INTERNAL_H
#define BML_REQ_CHECK_INTERNAL_H

#include <stdint.h>

#include "req/check.h"

struct ck {
	const struct bml_requirements *req;
	const struct bml_caps *caps;
	struct bml_unmets *out;
	char **err;
	int oom;
	/* The (program, attach type) pairs already asked about, so the generic attach rows and ctxaccess ask only once ("<program>\0<attach type>"). */
	char **asked;
	size_t n_asked, cap_asked;
};

char *ck_dupn(const char *s);
char *ck_fmtd(const char *f, ...) __attribute__((format(printf, 1, 2)));
/* CONTRACT: adds an Unmet; ownership of detail moves (NULL means "") */
void ck_add(struct ck *c, const char *kind, const char *program, const char *name, int64_t id, char *detail);
int ck_has(const struct ck *c, void *fnptr, const char *q);
#define HAS(c, f, q) ck_has((c), (void *)(c)->caps->f, (q))
const struct bml_loader_decl *ck_loader_of(const struct ck *c);
/* CONTRACT: stops with a check error (ownership of msg moves to *err) */
int ck_fail(struct ck *c, char *msg);
void ck_add_diffs(struct ck *c, const char *kind, const char *program, const char *name, struct bml_strs *d);
const char *ck_tracing_attach(const struct bml_requirements *r, const char *prog);
int ck_may_hold_field(const struct bml_map *m);
int ck_in_list(const char **l, size_t n, const char *s);
const char *ck_btf_rewrite_name(const char *f);
int ck_has_nul(const struct bml_requirements *r);
int ck_check_enum_values(struct ck *c);
int ck_check_struct_sizes(struct ck *c);
int ck_check_fib_flags(struct ck *c);
void ck_check_loader_rows(struct ck *c);
int ck_guards_state(struct ck *c, const struct bml_guard_list *gs, int *state, char **why);
int ck_check_kfields_guarded(struct ck *c);
int ck_check_ksym_vars(struct ck *c);
int ck_check_kconfigs(struct ck *c);
int bml_unmet_kernel_string(const struct bml_unmet *u, char **out);
/* check_target_rows.c: helper_target, netkit and sleepable, which are checked before the generic helper check. */
int ck_needs_helper_target(const struct bml_program *p, const struct bml_helper *h);
int ck_check_helper_targets(struct ck *c);
int ck_check_netkit(struct ck *c, const struct bml_attach *a);
int ck_check_sleepable(struct ck *c, const struct bml_attach *a);

/* Checking of the attach rows (check_attach.c). */
int ck_check_nullable(struct ck *c, const struct bml_attach *a);
int ck_check_arch_ctx(struct ck *c, const struct bml_attach *a, char **target_arch);
/* ask_alias asks about the name the loader re-attaches to (the single kprobe and kretprobe only). The multi family does not ask. */
int ck_check_kprobe_target(struct ck *c, const struct bml_attach *a, const char *target_arch, int ask_alias);
int ck_check_uprobe(struct ck *c, const struct bml_attach *a);
/* The uprobe check is split in two: opening the binary (returns 1 when it was opened, and the caller closes *bin and *elf; 0 when an Unmet
 * stops the check; -1 for an error) and checking one target. */
struct bml_elf;
int ck_uprobe_open(struct ck *c, const struct bml_attach *a, const char *name, uint8_t **bin, struct bml_elf *elf);
/* uprobe_source.c (judgement version 16): the DWARF source of an attach, either embedded in the binary or in a split file. It is resolved once
 * and shared by all targets of a multi attach. */
#include "elf/elf.h"
struct bml_dwarf;
struct bml_dwarf_sub;
struct ck_dsrc {
	const struct bml_elf *body;
	const char *program;
	int resolved, split_open;
	struct bml_dwarf *d; /* the resolved DWARF (when there is no err) */
	uint8_t *raw;        /* a snapshot of the bytes of the split file (kept only during the check) */
	size_t rawn;
	struct bml_elf split;
	char *err;        /* text of a source error (the Detail of uprobearg_unknown and the cause of uretprobe_abi_unknown) */
	const char *kind; /* the Unmet of a definite mismatch (uprobe_debug_build_id or uprobe_debug_crc); NULL if there is none */
};
void ck_dsrc_init(struct ck_dsrc *s, const struct bml_elf *body, const char *program);
void ck_dsrc_free(struct ck_dsrc *s);
void ck_dsrc_read(struct ck *c, struct ck_dsrc *s);
int ck_dsrc_subprogram(const struct ck_dsrc *s, const char *target, int parameters, const uint8_t *raw, size_t n_raw, struct bml_dwarf_sub *out,
		       char **err);
void ck_uprobe_target(struct ck *c, const struct bml_attach *a, struct bml_elf *elf, const char *target, int ret, struct ck_dsrc *src);
/* check_v9.c: the generic attach rows (attach_type, and attach_target for a target that has a value) and the ctxaccess rows (ctx_access). */
int ck_check_generic_attach(struct ck *c, const struct bml_attach *a);
/* checkAttachType (once per program and attach type). Returns 0 to continue and -1 for a checking error. */
int ck_check_attach_type(struct ck *c, const char *program, const char *at);
/* check_v12.c (judgement version 11): the multi family, usdt, and the map type of innermap. */
int ck_check_multi(struct ck *c, const struct bml_attach *a);
int ck_check_usdt(struct ck *c, const struct bml_attach *a);
int ck_check_innermaps(struct ck *c);
/* check_v13.c (judgement version 12): the loader's lsm_cgroup / fsession load, kfunc, trace_lsm_cgroup and ksyscall. */
int ck_check_prog_loader(struct ck *c, const struct bml_attach *a);
int ck_check_kfuncs(struct ck *c);
int ck_check_v13(struct ck *c, const struct bml_attach *a);
int ck_check_tpbuf(struct ck *c, const struct bml_attach *a); /* tpbuf (judgement version 13) */
int ck_check_ctx_accesses(struct ck *c);
int ck_check_fmod_ret(struct ck *c, const struct bml_attach *a); /* fmod_ret (format version 10) */
/* check_v11.c (judgement version 9): the companion-row families trace_lsm, trace_tp, trace_perf, freplace and trace_struct_ops. */
int ck_check_v11(struct ck *c, const struct bml_attach *a);
int ck_lsm_args(struct ck *c, const struct bml_attach *a); /* checkLSMArgs (for trace_lsm and trace_lsm_cgroup) */
int ck_fentry_args(struct ck *c, const struct bml_attach *a); /* checkFentryArgs (judgement version 15, check_v15.c) */
/* validIntSpelling (i8…u64) */
int ck_int_spelling(const char *s);
void ck_asked_free(struct ck *c);

#endif
