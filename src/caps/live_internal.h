/* caps/live_internal.h — what the live caps probes share (live_sys.c and live_feat.c).
 *
 * cilium's error chain is kept as three values: (errno, is it a VerifierError, is it ErrNotSupported). The answer rules look at
 * these three only: for prog_type, "the chain holds EINVAL or E2BIG"; for kload's have, "Is(ErrNotSupported)"; for helpers,
 * "VerifierError and EINVAL". */
#ifndef BML_CAPS_LIVE_INTERNAL_H
#define BML_CAPS_LIVE_INTERNAL_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "caps/live.h"

/* bpf(2), like cilium's sys.BPF: PROG_LOAD is retried on EAGAIN and an fd of 0 is dup'ed. Returns an fd or 0 on success and
 * -errno on failure. */
int lv_bpf(int cmd, void *attr, unsigned size);
void lv_close(int fd);
int lv_close_checked(int fd); /* 0 or -errno (for probes that fold a failure to close into their answer) */

enum { LV_LOG_DISABLED, LV_LOG_0, LV_LOG_1 };
enum { LV_NO_KIND = 0 };

/* Loading one program, following the steps of cilium's NewProgramWithOptions */
struct lv_prog {
	uint32_t type, attach_type, flags;
	const uint8_t *insns; /* 8 bytes per instruction (the output of cilium's Marshal, before any rewriting) */
	size_t n_insns;
	const char *license, *name;
	int log_mode;
	const uint8_t *btf; /* the program's BTF, in the form where every KernelMarshalOptions flag is false (the load applies StripFuncLinkage) */
	size_t btf_len;
	const uint8_t *func_info; /* 8 bytes per entry */
	uint32_t func_info_cnt;
	const char *attach_to; /* name of the type to look up in vmlinux (NULL means do not resolve) */
	uint32_t attach_kind;
	uint32_t attach_btf_id, attach_prog_fd; /* the raw values of an Extension program */
	int bpf2bpf; /* the program has bpf-to-bpf calls (the haveBPFToBPFCalls branch) */
};

/* The error chain */
struct lv_res {
	int fd;       /* >= 0 on success (the caller closes it), -1 on failure */
	int err;      /* errno of the chain (0 means an error without an errno, such as a replaced cause or a vDSO error) */
	int verifier; /* whether it is a VerifierError */
	int notsup;   /* whether Is(ErrNotSupported) holds */
	char **lines; /* the lines of ErrorWithLog, right-trimmed (for a VerifierError) */
	size_t n_lines;
	/* For the probe sentences: the suffix of cilium's "load program: %w<suffix>" (NULL if none; a static string), and the cause
	 * that replaced err with 0 (1 is errBadRelocation "bad CO-RE relocation", 2 is errUnknownKfunc "unknown kfunc") */
	const char *suffix;
	int cause;
	char *text; /* the sentence of an error before the load (cilium's attach-target resolution, kload's raw load); lv_res_text returns it if set (malloc'd) */
};
/* The error sentence of cilium's NewProgram (err.Error(): "load program: ..."; for a VerifierError it copies Error()). Malloc'd. */
char *lv_res_text(const struct lv_res *r);
void lv_res_free(struct lv_res *r);
int lv_prog_load(struct bml_live *l, const struct lv_prog *p, struct lv_res *r);

/* NewHandleFromRawBTF, including the log retry and the haveBTF re-check. Returns an fd on success, or -1 with r filled (the
 * error is not a VerifierError). */
int lv_btf_handle(struct bml_live *l, const uint8_t *btf, size_t len, struct lv_res *r);
int lv_btf_handle_reason(struct bml_live *l, const uint8_t *btf, size_t len, struct lv_res *r);

/* kload's helperAnswer (kload's helper-log rule, live_helperlog.c): the helper probe's result after cilium's check. ok is the probe
 * loading (or cilium's EACCES), notsup cilium's ErrNotSupported (its last-five-line check). The answer is LV_OK, LV_NOTSUP,
 * LV_HELPER_KEPT (a checking error, never Unknown), or LV_HELPER_UNKNOWN (only the rescue_unknown mutant). */
struct lv_helper_in {
	int ok, notsup, verifier, err;
	char **lines;
	size_t n_lines;
};
/* helperLogOpts; NULL or the zero value is the product. The unit test (test/caps/helperlog_unit.c) sets the fields as
 * bpf-mlir's mutants M1 (any_helper), M2 (window 5) and M3 (rescue_unknown). */
struct lv_helper_opts {
	int any_helper, window, rescue_unknown;
};
enum { LV_HELPER_KEPT = -1, LV_HELPER_UNKNOWN = -2 };
int lv_helper_answer(const struct lv_helper_in *in, uint32_t id, const struct lv_helper_opts *o);

/* cilium's internal FeatureTest: LV_OK, LV_NOTSUP, or -errno for an error that is not remembered (LV_NO_ERRNO for an error
 * without an errno: the no-errno sentinel, INT_MIN, which no -errno can be). lv_feat_errno turns a negative answer into its errno (0 for
 * LV_NO_ERRNO). */
enum { LV_NO_ERRNO = INT_MIN };
int lv_feat(struct bml_live *l, int which);
int lv_feat_errno(int st);
/* KernelMarshalOptions (the four are evaluated in order; each flag means "!= nil") */
struct lv_kmo {
	int strip_func_linkage, replace_decl_tags, replace_type_tags, replace_enum64;
};
void lv_kmo(struct bml_live *l, struct lv_kmo *o);
/* Make every FUNC of a raw BTF static (StripFuncLinkage); returns a malloc'd copy. */
uint8_t *lv_strip_func_linkage(const uint8_t *btf, size_t len);
/* linux.KernelVersion (read from the Linux note of the vDSO). Returns 0 and fills *v, or -1 on failure. */
int lv_kernel_version(struct bml_live *l, uint32_t *v);
/* maybeFillObjName (it triggers haveObjName and objNameAllowsDot); dst is 16 bytes */
void lv_obj_name(struct bml_live *l, const char *name, char dst[16]);
/* vmlinux (kload's Once) and how it differs from a failure of cilium's LoadKernelSpec: 0 means it was read; -2 means cilium also
 * finds none; -1 means cilium's load fails; -3 means an error only of the C type validation (cilium validates lazily). */
int lv_vmlinux(struct bml_live *l, const struct bml_kbtf **kb);

/* The lines of ErrorWithLog: cut the buffer at the first NUL, trim whitespace at both ends, split at '\n', then right-trim each line. */
void lv_log_lines(const char *buf, size_t size, char ***lines, size_t *n);

/* kload's memo */
struct lv_memo *lv_memo_get(struct bml_live *l, const char *key);
int lv_memo_put(struct bml_live *l, const char *key, int rc, int value);
int lv_unknownf(char **msg,const char *fmt,...);
void lv_btf_reason(struct lv_res *r,int load_error,const char *log,size_t size);
int lv_memo_answer(const struct lv_memo *m,int *out,char **msg);
int lv_memo_reason(struct bml_live *l,const char *key,int rc,int value,char *why,int *out,char **msg);
void lv_caps_kernel_values(struct bml_caps *out);

/* What live_btf.c shares with live_btf_func.c (which was split out of it): the vmlinux BTF (NULL and *err if there is none), a
 * prefix + err sentence, appending a mismatch sentence (empties b; -1 on out of memory), the out-of-memory answer, the spelling
 * of an integer type (i32, u64, ...), and the type of a name (-1 is out of memory, 1 is ErrNotFound, 2 means several). */
struct bml_buf;
const struct bml_kbtf *lv_kb(struct bml_live *l, const char **err);
int lv_msg(char **msg, int rc, const char *prefix, const char *err);
int lv_push(struct bml_strs *out, struct bml_buf *b);
int lv_oom(struct bml_strs *out, char **msg);
void lv_int_spell(const struct bml_kbtf *kb, const struct kbtf_type *t, char *dst, size_t n);
/* requirements.ArgName: an empty name becomes `unnamed` (live_btf_func.c) */
const char *bml_arg_name(const char *n);
/* kload's compareProto: compares the FUNC_PROTO fp with (nargs, where < 0 is not compared; ret, where "" is not compared; args, each
 * a struct name, an integer spelling, or "-") and appends the mismatch sentences to out (live_btf_func.c). -1 means out of memory. */
int lv_compare_proto(const struct bml_kbtf *kb, const struct kbtf_type *fp, const char *what, int64_t nargs, const char *ret,
		     const struct bml_str *args, size_t n_args, struct bml_strs *out);
/* Kind tp of HasAttachTarget: whether the tracefs file events/<cat>/<name>/id exists. A missing or unreadable file is Unknown (live_v11.c). */
int lv_tracefs_event_id(const char *event, int *out, char **msg);
/* The sockmap link probe for the sk_skb and sk_msg attach types (live_sockmap.c). If the load is not accepted it returns -2 (the
 * caller decides with its paired load); otherwise it returns a BML_Q_* value, with *val and *why (the Unknown sentence, malloc'd). */
int lv_sockmap_link_probe(struct bml_live *l, const char *pt_name, uint32_t pt, const char *at_name, uint32_t at, int *val, char **why);
/* live_multi.c: the link probe for kprobe multi and session. -2 means the load was rejected (the caller's paired load decides);
 * anything else is BML_Q_OK or BML_Q_UNKNOWN. */
int lv_multi_link_probe(struct bml_live *l, const char *pt_name, const char *at_name, uint32_t at, int *val, char **why);
/* Read the whole file at path (malloc'd; *data is NUL-terminated). Returns -1 with *e (errno) on failure (live_v11.c). */
int lv_read_file(const char *path, char **data, size_t *len, int *e);
int lv_lookup(const struct bml_kbtf *kb, const char *name, uint32_t kind, uint32_t *id, char **err);
/* live_kpath.c: findMember along a path a.b(.c), one step at a time (1 means found, 0 means absent, -1 means out of memory), and
 * the check of a type struct:T (0 means it matches, 1 means a mismatch sentence was written to b). */
struct kbtf_member;
int lv_find_member_path(const struct bml_kbtf *kb, uint32_t struct_id, const char *path, struct kbtf_member *out, int *twice);
int lv_kfield_embedded(const struct bml_kbtf *kb, const struct kbtf_member *mb, const char *name, struct bml_buf *b);
/* live_str.c: the char pointer depth of strptr and strarray in tpfield and sysarg. A return of 1 means known (*depth; a non-char type
 * gives 0 or -1) and 0 means not known (Unknown). lv_tp_field_name returns the range [*s, *e) of the name matched by tpFieldName's
 * regular expression (0 if there is none). */
int lv_tp_field_name(const char *d, size_t n, size_t *s, size_t *e);
int lv_tp_char_depth(const char *decl, size_t n, int *depth);
/* tpByteArrayShape: 1 means known (*count is the element count of the array or 0, *sign is 'u', 'i' or 0); 0 means not known */
int lv_tp_array_shape(const char *decl, size_t n, int64_t *count, char *sign);
int lv_sys_char_depth(const struct bml_kbtf *kb, const char *typ, int *depth);
int lv_sys_btf_char_depth(const struct bml_kbtf *kb, uint32_t id, int *depth);
int lv_str_depth_ok(int depth, const char *typ);
int lv_is_str(const char *typ);
/* The value of argument n in compareSysarg: typ if the depth matches, otherwise not-<typ> (malloc'd) */
char *lv_str_arg(int depth, const char *typ);
/* CONTRACT: tracefsRoots (shared by tracepoint id, format and syscall format). The product does not change it; only the classification differential tool replaces it
 * with a constructed tracefs directory (the Go oracle points its copy at the same directory) */
extern const char *lv_tracefs_roots[2];
/* CheckTracepointField on the text of a tracefs format file, after it has been read (live_v11.c; the classification differential
 * tool also calls it). Returns a BML_Q_* value. */
int lv_tp_field_text(const char *text, size_t len, const char *event, const char *field, int64_t off, int64_t bytes, const char *sign,
		     struct bml_strs *out, char **msg);

#endif
