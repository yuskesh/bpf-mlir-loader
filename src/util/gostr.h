/* gostr.h — copies of Go standard-library string rules, so that this C code makes the same decisions as bpf-mlir's
 * Go implementation.
 *
 * Numbers are read exactly as Go's strconv does (decimal only). C's strtol is not used because it accepts leading
 * white space, a 0x prefix and trailing garbage. */
#ifndef BML_GOSTR_H
#define BML_GOSTR_H

#include <stddef.h>
#include <stdint.h>

/* strconv.ParseInt(s, 10, bits): an optional sign (+ or -) followed by one or more decimal digits and nothing else.
 * Out-of-range values, an empty string and any other character give -1. */
int bml_go_parse_int(const char *s, size_t n, int bits, int64_t *out);

/* strconv.ParseUint(s, 10, bits): no sign is accepted. */
int bml_go_parse_uint(const char *s, size_t n, int bits, uint64_t *out);

/* strconv.Atoi (with a 64-bit int): accepts exactly what ParseInt(s, 10, 0) accepts. */
int bml_go_atoi(const char *s, size_t n, int64_t *out);

/* A growing string buffer (malloc'd). Allocation failure does not abort: it sets oom and every later append is
 * dropped. */
struct bml_buf {
	char *p;
	size_t len, cap;
	int oom;
};
void bml_buf_add(struct bml_buf *b, const char *s, size_t n);
void bml_buf_adds(struct bml_buf *b, const char *s);
void bml_buf_addf(struct bml_buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* A copy of Go's %q (strconv.Quote): printable ASCII is kept as is; \a \b \f \n \r \t \v \\ and \" are escaped;
 * any other byte that belongs to a valid multi-byte UTF-8 character is kept as is (a detail of Go's IsPrint is not
 * copied: Go escapes unprintable multi-byte characters as \u, this does not); an invalid byte becomes \xNN. */
void bml_buf_add_goquote(struct bml_buf *b, const char *s, size_t n);
/* Take the contents as a NUL-terminated string and empty b (NULL if oom is set). */
char *bml_buf_take(struct bml_buf *b);
/* The text of a Go syscall.Errno: glibc's strerror with the first letter lower-cased, which gives the same spelling
 * as Go's table. The result is malloc'd, not a static buffer. */
char *bml_go_errno_str(int err);
void bml_buf_free(struct bml_buf *b);

#endif
