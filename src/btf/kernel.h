#ifndef BML_BTF_KERNEL_H
#define BML_BTF_KERNEL_H

#include <stddef.h>
#include <stdint.h>

#include "util/gostr.h"

enum {
	KBTF_UNKN = 0, KBTF_INT, KBTF_PTR, KBTF_ARRAY, KBTF_STRUCT, KBTF_UNION, KBTF_ENUM, KBTF_FWD, KBTF_TYPEDEF, KBTF_VOLATILE,
	KBTF_CONST, KBTF_RESTRICT, KBTF_FUNC, KBTF_FUNC_PROTO, KBTF_VAR, KBTF_DATASEC, KBTF_FLOAT, KBTF_DECL_TAG, KBTF_TYPE_TAG,
	KBTF_ENUM64, KBTF_NKINDS
};

struct bml_kbtf {
	uint8_t *raw;
	size_t raw_len;
	int be;
	const uint8_t *types;
	uint32_t types_len;
	const uint8_t *strs;
	uint32_t strs_len;
	uint32_t n;
	uint32_t *off;
	uint32_t *idx;
	uint32_t nidx;
};


struct kbtf_type {
	uint32_t kind, vlen, kflag, size_type;
	const char *name;
	const uint8_t *aux;
};

/* CONTRACT: reads raw (a malloc'd buffer; ownership moves). Failure is *err (malloc) with -1 (errors cilium's loadRawSpec also stops on) or -3 (checked by cilium only
 * when a type is looked up: referenced ids, member names, decl tags). raw is released even on failure */
int bml_kbtf_from_raw(uint8_t *raw, size_t len, struct bml_kbtf *kb, char **err);
int bml_kbtf_from_split_raw(uint8_t *raw, size_t len, const struct bml_kbtf *base, struct bml_kbtf *out, char **err);



int bml_kbtf_load_kernel(struct bml_kbtf *kb, char **err);
void bml_kbtf_free(struct bml_kbtf *kb);

uint32_t bml_kbtf_u32(const struct bml_kbtf *kb, const uint8_t *p);
void bml_kbtf_type(const struct bml_kbtf *kb, uint32_t id, struct kbtf_type *t);


struct kbtf_member {
	const char *name;
	uint32_t type, offset, bitfield_size;
};
void bml_kbtf_member(const struct bml_kbtf *kb, const struct kbtf_type *t, uint32_t i, struct kbtf_member *m);

void bml_kbtf_param(const struct bml_kbtf *kb, const struct kbtf_type *t, uint32_t i, const char **name, uint32_t *type);


const char *bml_kbtf_type_name(const struct kbtf_type *t);

int bml_kbtf_build_index(struct bml_kbtf *kb, char **err);
#ifdef BML_TEST_CAPS

int bml_kbtf_build_index_reference(struct bml_kbtf *kb, char **err);
#endif


const char *bml_kbtf_goname(uint32_t kind);


int bml_kbtf_by_name(const struct bml_kbtf *kb, const char *name, uint32_t kind, uint32_t *id, char **err);

int bml_kbtf_any_by_name(const struct bml_kbtf *kb, const char *name, uint32_t **ids, size_t *n, char **err);


uint32_t bml_kbtf_underlying(const struct bml_kbtf *kb, uint32_t id, int *cycle);

int bml_kbtf_sizeof(const struct bml_kbtf *kb, uint32_t id, int64_t *size, char **err);


void bml_kbtf_format(const struct bml_kbtf *kb, struct bml_buf *b, uint32_t id, int cycle, char verb);

void bml_kbtf_gotype(const struct bml_kbtf *kb, struct bml_buf *b, uint32_t id, int cycle);

#endif
