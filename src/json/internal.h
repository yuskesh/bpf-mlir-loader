
#ifndef BML_JSON_INTERNAL_H
#define BML_JSON_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "json/json.h"

struct parser {
	const unsigned char *s;
	size_t len, pos;
	int depth, lenient;
	char *err;
	enum bml_json_rule rule;
};

int json_fail(struct parser *p, enum bml_json_rule rule, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
void json_skip_ws(struct parser *p);

size_t json_utf8_seq(const unsigned char *s, size_t n);
void json_put_utf8(struct bml_buf *b, uint32_t cp);

int json_parse_string(struct parser *p, char **out, size_t *out_len);
int json_parse_number(struct parser *p, struct bml_json *j);
int json_lit(struct parser *p, const char *w);

#endif
