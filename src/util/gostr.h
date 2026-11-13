#ifndef BML_GOSTR_H
#define BML_GOSTR_H

#include <stddef.h>
#include <stdint.h>


int bml_go_parse_int(const char *s, size_t n, int bits, int64_t *out);


int bml_go_parse_uint(const char *s, size_t n, int bits, uint64_t *out);


int bml_go_atoi(const char *s, size_t n, int64_t *out);


struct bml_buf {
	char *p;
	size_t len, cap;
	int oom;
};
void bml_buf_add(struct bml_buf *b, const char *s, size_t n);
void bml_buf_adds(struct bml_buf *b, const char *s);
void bml_buf_addf(struct bml_buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));



void bml_buf_add_goquote(struct bml_buf *b, const char *s, size_t n);

char *bml_buf_take(struct bml_buf *b);

char *bml_go_errno_str(int err);
void bml_buf_free(struct bml_buf *b);

#endif
