

#ifndef BML_REQ_USDT_H
#define BML_REQ_USDT_H

#include <stddef.h>
#include <stdint.h>

#include "elf/elf.h"

#define BML_USDT_SPEC_MAP_PREFIX "__ebpf_usdt_spec_"


struct bml_usdt_point {
	uint64_t pc, base, semaphore;
	char *provider, *name, *args;
};

struct bml_usdt_points {
	struct bml_usdt_point *p;
	size_t n, cap;
};

/* CONTRACT: ReadUSDTPoints: stapsdt notes (owner "stapsdt", type 3) of every SHT_NOTE section in note order. 0 is success (empty if none),
 * -1 is a broken note (*err, the same text as Go, malloc). Free *out with bml_usdt_points_free (also on failure) */
int bml_usdt_read_points(const struct bml_elf *elf, struct bml_usdt_points *out, char **err);
void bml_usdt_points_free(struct bml_usdt_points *v);


struct bml_usdt_arg {
	int size, is_signed;
	const char *kind;
	char reg[8];
	int64_t off;
};


int bml_usdt_parse_arg(const char *s, size_t n, struct bml_usdt_arg *spec, int *size_ok, char **err);


int bml_go_fields(const char *s, size_t n, size_t **starts, size_t **lens, size_t *count);


int bml_usdt_reg_index(const char *r);


#define BML_USDT_SPEC_SIZE 192
#define BML_USDT_ARG_SPEC_SIZE 16
#define BML_USDT_KIND_CONST 1
#define BML_USDT_KIND_REG 2
#define BML_USDT_KIND_DEREF 3

struct bml_usdt_attach_point {
	size_t index;
	uint64_t pc, semaphore;
	uint64_t off, sem_off;
	uint8_t spec[BML_USDT_SPEC_SIZE];
};


int bml_usdt_encode_spec(const char *args, uint8_t spec[BML_USDT_SPEC_SIZE]);

int bml_usdt_attach_points(const uint8_t *data, size_t len, const char *provider, const char *name, struct bml_usdt_attach_point **out, size_t *n,
			   char **err);

#endif
