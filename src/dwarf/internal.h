/* dwarf/internal.h — internals of the DWARF reader, a copy of Go's debug/dwarf Data, unit, buf, Entry and Reader.
 * Do not include it from outside this layer. */
#ifndef BML_DWARF_INTERNAL_H
#define BML_DWARF_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "dwarf/dwarf.h"

struct dw_field {
	uint64_t attr, form;
	int64_t val; /* DW_FORM_implicit_const */
};

struct dw_abbrev {
	uint64_t id, tag;
	int children;
	struct dw_field *f;
	size_t n;
};

struct dw_atable {
	uint64_t off;
	struct dw_abbrev *a;
	size_t n;
};

struct dw_unit {
	uint64_t base, off; /* start of the header, start of the entry (offsets within the section) */
	const uint8_t *data;
	size_t len;
	int vers, is64, asize, utype;
	struct dw_atable *at;
	int have5; /* the DWARF 5 bases were collected (Go's unit5 != nil) */
	uint64_t addr_base, str_base, rng_base;
};

struct dw_sect {
	const uint8_t *p;
	size_t n;
};

struct dw {
	int big;
	struct dw_sect abbrev, info, str, line_str, str_offsets, addr, rnglists;
	uint8_t **owned; /* decompressed sections */
	size_t n_owned;
	struct dw_unit *u;
	size_t nu;
	struct dw_atable **tabs; /* each one separately malloc'd (units point at them, so they must not move on realloc) */
	size_t ntabs;
};

/* struct bml_dwarf of dwarf.h (an opened DWARF) */
struct bml_dwarf {
	struct dw d;
};

/* Go's buf (after an error it returns zeros; it keeps only the first error) */
struct dw_buf {
	const struct dw *d;
	const struct dw_unit *u; /* NULL is Go's unknownFormat */
	const char *name;
	uint64_t off;
	const uint8_t *p;
	size_t n;
	char *err; /* the DecodeError message (malloc'd) */
};

enum { DV_NONE, DV_INT, DV_UINT, DV_STR, DV_BOOL, DV_OFF, DV_BYTES };
struct dw_val {
	uint64_t attr;
	int kind;
	int64_t i;     /* INT, BOOL */
	uint64_t u;    /* UINT, OFF */
	const char *s; /* STR (NUL-terminated, inside the section) */
};

struct dw_entry {
	uint64_t off, tag; /* tag 0 ends a list of children */
	int children;
	struct dw_val *v;
	size_t n;
};

/* pointer.c (from bpf-mlir's ptr parameter type): the ptr spelling of requirements format 18 ("" is Unknown, NULL is out of memory; malloc'd) */
char *dw_pointer_spelling(struct dw *d, uint64_t off);

/* open.c */
int dw_open(const struct bml_elf *elf, struct dw *d, char **err);
void dw_close(struct dw *d);

/* entry.c — buf */
void dw_buf_init(struct dw_buf *b, const struct dw *d, const struct dw_unit *u, const char *name, uint64_t off, const uint8_t *p, size_t n);
void dw_buf_error(struct dw_buf *b, const char *s);
uint8_t dw_u8(struct dw_buf *b);
uint16_t dw_u16(struct dw_buf *b);
uint32_t dw_u32(struct dw_buf *b);
uint64_t dw_u64(struct dw_buf *b);
uint64_t dw_uleb(struct dw_buf *b);
int64_t dw_sleb(struct dw_buf *b);
const uint8_t *dw_bytes(struct dw_buf *b, uint64_t n);

/* entry.c — entries and the reader */
int dw_entry_decode(struct dw_buf *b, const struct dw_unit *u, struct dw_entry *e); /* 0 is success (b->err is not set) */
void dw_entry_free(struct dw_entry *e);
const struct dw_val *dw_val(const struct dw_entry *e, uint64_t attr);

struct dw_reader {
	struct dw *d;
	size_t unit;
	struct dw_buf b;
	char *err;
	int last_children, last_unit;
	uint64_t last_sibling;
};
void dw_reader_init(struct dw_reader *r, struct dw *d);
void dw_reader_free(struct dw_reader *r);
/* Next: 1 means an entry was stored in e, 0 means the end, -1 means an error (r->err) */
int dw_next(struct dw_reader *r, struct dw_entry *e);
void dw_skip_children(struct dw_reader *r);
void dw_seek(struct dw_reader *r, uint64_t off);

#endif
