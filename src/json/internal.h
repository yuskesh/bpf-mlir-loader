/* json/internal.h — internals of the JSON parser (shared only inside json/; json.c was split into several files
 * before the map-declaration records work). */
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
/* The length of one UTF-8 character (1 for ASCII; 0 for an overlong form, a surrogate or a value out of range). */
size_t json_utf8_seq(const unsigned char *s, size_t n);
void json_put_utf8(struct bml_buf *b, uint32_t cp);
/* p->pos is just after the opening " */
int json_parse_string(struct parser *p, char **out, size_t *out_len);
int json_parse_number(struct parser *p, struct bml_json *j);
int json_lit(struct parser *p, const char *w);

#endif
