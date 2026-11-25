/* load/internal.h — internals of the load guard (shared by load.c, pre.c and post.c) */
#ifndef BML_LOAD_INTERNAL_H
#define BML_LOAD_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "load/load.h"
#include "util/gostr.h"

struct bpf_object;
struct lb_arena;

struct bml_obj {
	struct bpf_object *obj;
	struct lb_arena *arena;
	int print_held; /* counted as a holder of libbpf's print callback (the count is lowered on close) */
};

/* The values of enum kern_feature_id in libbpf v1.7.0's src/libbpf_internal.h (not a public API; the gate pins the
 * version by a hash of the source, see scripts/libbpf-pin.sh) and feat_supported (a GLOBAL symbol in features.o of
 * libbpf.a). If no token is used, it reads the same per-process cache as the load path's kernel_supports(obj, f), so a
 * value read earlier is the value the load will use. */
enum {
	LBF_PROG_NAME = 0, LBF_GLOBAL_DATA = 1, LBF_BTF = 2, LBF_BTF_FUNC = 3, LBF_BTF_DATASEC = 4, LBF_BTF_GLOBAL_FUNC = 5,
	LBF_ARRAY_MMAP = 6, LBF_EXP_ATTACH_TYPE = 7, LBF_PROBE_READ_KERN = 8, LBF_BTF_FLOAT = 11, LBF_BTF_DECL_TAG = 13,
	LBF_BTF_TYPE_TAG = 14, LBF_BTF_ENUM64 = 17, LBF_BTF_QMARK_DATASEC = 21,
};
bool feat_supported(void *cache, int feat_id);
const char *lb_feat_name(int feat_id);
/* CONTRACT: errno text (Go's syscall.Errno spelling; downstream tests match it. Per-thread buffer) */
const char *lb_errno(int e);

/* Put an error in r (a stage and a malloc'd message). Returns -1. */
int lb_fail(struct bml_load_result *r, int stage, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

/* guards before load (pre.c) */
int lb_check_shape(const uint8_t *elf, size_t len, struct bml_load_result *r);
/* 1 when the section is a program section of the guard's table (load/sections.c), else 0 */
int lb_prog_section(const char *section);
struct bpf_object;
int lb_mark_sleepable(struct bpf_object *obj, struct bml_load_result *r); /* marks the program sleepable; called after open and before load */
int lb_check_features(const uint8_t *elf, size_t len, const struct bml_requirements *req, const struct bml_caps *caps,
		      struct bml_load_result *r);
/* Does libbpf's sanitize rewrite the ELF's BTF? The result is the missing feature (LBF_*), -1 for no rewrite, or -2 if it cannot be determined. */
int lb_btf_rewrite(const uint8_t *elf, size_t len);
/* (secdefs.c) Whether the first definition in libbpf's section_defs that matches sec has SEC_EXP_ATTACH_OPT (that is,
 * whether libbpf sets expected_attach_type to 0 for this program when FEAT_EXP_ATTACH_TYPE is missing), and a
 * printout of the table for tests (the gate compares it with the table extracted from libbpf's source). */
int lb_sec_exp_attach_opt(const char *sec);
void lb_secdefs_print(void);

/* After open and before load, record libbpf's map definitions (the BTF id and flags read from the ELF) (post.c) */
struct lb_map_def {
	char *name;
	uint32_t key_id, value_id, flags;
};
int lb_capture_maps(struct bpf_object *obj, struct lb_map_def **defs, size_t *n);
void lb_free_maps(struct lb_map_def *defs, size_t n);
/* guards after load (post.c) */
int lb_check_loaded(struct bpf_object *obj, const struct lb_map_def *defs, size_t n, struct bml_load_result *r);

#endif
