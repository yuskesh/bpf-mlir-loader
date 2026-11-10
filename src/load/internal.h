
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
	int print_held;
};




enum {
	LBF_PROG_NAME = 0, LBF_GLOBAL_DATA = 1, LBF_BTF = 2, LBF_BTF_FUNC = 3, LBF_BTF_DATASEC = 4, LBF_BTF_GLOBAL_FUNC = 5,
	LBF_ARRAY_MMAP = 6, LBF_EXP_ATTACH_TYPE = 7, LBF_PROBE_READ_KERN = 8, LBF_BTF_FLOAT = 11, LBF_BTF_DECL_TAG = 13,
	LBF_BTF_TYPE_TAG = 14, LBF_BTF_ENUM64 = 17, LBF_BTF_QMARK_DATASEC = 21,
};
bool feat_supported(void *cache, int feat_id);
const char *lb_feat_name(int feat_id);
/* CONTRACT: errno text (Go's syscall.Errno spelling; downstream tests match it. Per-thread buffer) */
const char *lb_errno(int e);


int lb_fail(struct bml_load_result *r, int stage, const char *fmt, ...) __attribute__((format(printf, 3, 4)));


int lb_check_shape(const uint8_t *elf, size_t len, struct bml_load_result *r);
struct bpf_object;
int lb_mark_sleepable(struct bpf_object *obj, struct bml_load_result *r);
int lb_check_features(const uint8_t *elf, size_t len, const struct bml_requirements *req, const struct bml_caps *caps,
		      struct bml_load_result *r);

int lb_btf_rewrite(const uint8_t *elf, size_t len);


int lb_sec_exp_attach_opt(const char *sec);
void lb_secdefs_print(void);


struct lb_map_def {
	char *name;
	uint32_t key_id, value_id, flags;
};
int lb_capture_maps(struct bpf_object *obj, struct lb_map_def **defs, size_t *n);
void lb_free_maps(struct lb_map_def *defs, size_t n);

int lb_check_loaded(struct bpf_object *obj, const struct lb_map_def *defs, size_t n, struct bml_load_result *r);

#endif
