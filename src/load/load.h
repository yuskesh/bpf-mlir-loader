









#ifndef BML_LOAD_H
#define BML_LOAD_H

#include <stddef.h>
#include <stdint.h>

#include "caps/caps.h"
#include "req/req.h"

struct bpf_object;

enum bml_load_stage {
	BML_LOAD_OK = 0,
	BML_LOAD_ENV,
	BML_LOAD_SHAPE,
	BML_LOAD_PREDICT,
	BML_LOAD_SANITIZE,
	BML_LOAD_REWRITE,
	BML_LOAD_OPEN,
	BML_LOAD_LIBBPF,
	BML_LOAD_BTF_DROPPED,
	BML_LOAD_BTF_CHANGED,
	BML_LOAD_EXT_INFO,
	BML_LOAD_MAP_BTF,
	BML_LOAD_MAP_FLAGS,
	BML_LOAD_ARENA,
};

const char *bml_load_stage_name(int stage);


enum { BML_RUN_NONE = 0, BML_RUN_XDP, BML_RUN_TRACING, BML_RUN_SKB, BML_RUN_FLOW, BML_RUN_CTX, BML_RUN_NF };
const char *bml_load_section_kind(const char *section, int *family);

struct bml_load_result {
	int stage;
	char *msg;
	char *log;
	int verifier;
};
void bml_load_result_free(struct bml_load_result *r);

struct bml_obj;



int bml_load_guarded(const uint8_t *elf, size_t len, const struct bml_requirements *req, const struct bml_caps *caps,
		     struct bml_obj **out, struct bml_load_result *r);


struct bml_rodata_value {
	uint64_t off;
	uint32_t size;
	uint64_t bits;
};

int bml_load_guarded_values(const uint8_t *elf, size_t len, const struct bml_requirements *req, const struct bml_caps *caps,
			    const struct bml_rodata_value *values, size_t n_values, struct bml_obj **out, struct bml_load_result *r);
void bml_obj_close(struct bml_obj *o);
/* CONTRACT: libbpf object (map and program access and attach, used by the ABI). Only bml_obj_close closes it */
struct bpf_object *bml_obj_bpf(const struct bml_obj *o);
#ifdef BML_TEST_CAPS

void bml_load_testonly_usdt_multi(int keep);
#endif

#endif
