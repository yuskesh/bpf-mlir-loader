/* shim/spinel/internal.h — the internals of the spinel shim (shared by result.c and spinel.c) */
#ifndef BML_SHIM_SPINEL_INTERNAL_H
#define BML_SHIM_SPINEL_INTERNAL_H

#include <stdint.h>

/* CONTRACT: handles of results the shim creates itself (spinel text checks, value copies) are in a range disjoint from bml result handles */
#define SH_BASE ((int64_t)1 << 62)

int64_t sh_result(int64_t kind, int64_t value, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
/* Reads the bml result r (a copy of its kind, value and message) and releases it. */
struct sh_res {
	int64_t kind, value;
	char *msg; /* malloc'd; may contain NUL bytes, so len gives its length */
	int64_t len;
};
struct sh_res sh_take(int64_t r);
void sh_res_free(struct sh_res *x);

struct bml_map_decl;
/* Reads a map declaration (spinel's ParseMapDecl). A failure is an OTHER result; success returns 0. Defined in spinel.c. */
int64_t sh_parse_decl(const char *decl, struct bml_map_decl *d);
/* spinel's hashBytes: turns an array of int64 into bytes; what is "key" or "value". On failure it returns NULL and sets *err (a result). Defined in spinel.c. */
uint8_t *sh_hash_bytes(const int64_t *a, int64_t n, const char *what, int64_t *err);

/* The record size of a reader, which ringbuf_open remembers; -1 if there is no such reader. */
void sh_reader_set(int64_t rb, int64_t size);
int64_t sh_reader_size(int64_t rb);

#endif
