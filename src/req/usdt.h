/* req/usdt.h — reading USDT (user-space static tracepoint) probe points and parsing argument descriptions (a port of ReadUSDTPoints and
 * ParseUSDTArg in bpf-mlir's go/requirements/usdt.go; see section 8 of requirements_format.md). The check itself (checkUSDT) is in check_v12.c. */
#ifndef BML_REQ_USDT_H
#define BML_REQ_USDT_H

#include <stddef.h>
#include <stdint.h>

#include "elf/elf.h"

#define BML_USDT_SPEC_MAP_PREFIX "__ebpf_usdt_spec_"

/* One probe point of the note. The strings (provider, name, args) are malloc-ed copies, not pointers into the note; they are NUL-terminated
 * and contain no NUL inside. */
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

/* USDTArgSpec (kind is "", "reg", "deref" or "const"; reg is the register name without the %, or "") */
struct bml_usdt_arg {
	int size, is_signed;
	const char *kind;
	char reg[8];
	int64_t off;
};

/* ParseUSDTArg (s has length n and may contain NUL). *size_ok is set when the size could be read. *err is the error (malloc-ed, NULL if none).
 * Returns -1 when memory runs out. */
int bml_usdt_parse_arg(const char *s, size_t n, struct bml_usdt_arg *spec, int *size_ok, char **err);

/* strings.Fields (splits at Go's unicode.IsSpace). The start and length of every field go to *starts / *lens (malloc-ed). Returns -1 when
 * memory runs out. */
int bml_go_fields(const char *s, size_t n, size_t **starts, size_t **lens, size_t *count);

/* The reg number in the spec for a register name of the note (without the %): the index of the usdtreg table of the UAPI table, ax 0 … r15 15.
 * An unknown name gives -1. */
int bml_usdt_reg_index(const char *r);

/* ---- Computing the attach points (usdt_points.c): the ref_ctr contract of section 8, and a port of Points and EncodeUSDTSpec in bpf-mlir's
 * kernel/internal/usdtattach ---- */
#define BML_USDT_SPEC_SIZE 192    /* 12 arguments x 16 bytes */
#define BML_USDT_ARG_SPEC_SIZE 16 /* kind u8 @+0, reg u8 @+1, 6 zero bytes, off i64 @+8 (little endian) */
#define BML_USDT_KIND_CONST 1
#define BML_USDT_KIND_REG 2
#define BML_USDT_KIND_DEREF 3

struct bml_usdt_attach_point {
	size_t index;           /* the key in the spec map and the cookie (the index of the `<provider>:<name>` point in note order) */
	uint64_t pc, semaphore; /* the pc of the note (before adjustment) and the semaphore address (0 if none) */
	uint64_t off, sem_off;  /* the uprobe file offset (after the prelink adjustment, inside the executable PT_LOAD) and the semaphore file offset (0 if none) */
	uint8_t spec[BML_USDT_SPEC_SIZE];
};

/* EncodeUSDTSpec. Returns -1 when memory runs out. */
int bml_usdt_encode_spec(const char *args, uint8_t spec[BML_USDT_SPEC_SIZE]);
/* Points: the `<provider>:<name>` points of the binary (data, len). Returns 0 on success (*out is malloc-ed and holds at least one point) and
 * -1 with *err (malloc-ed). */
int bml_usdt_attach_points(const uint8_t *data, size_t len, const char *provider, const char *name, struct bml_usdt_attach_point **out, size_t *n,
			   char **err);

#endif
