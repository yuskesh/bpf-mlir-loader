







#ifndef BML_JSON_H
#define BML_JSON_H

#include <stddef.h>
#include <stdint.h>

#include "util/gostr.h"

#define BML_JSON_MAX_DEPTH 128

enum bml_json_type { BML_JSON_NULL, BML_JSON_BOOL, BML_JSON_NUMBER, BML_JSON_STRING, BML_JSON_ARRAY, BML_JSON_OBJECT };


enum bml_json_rule {
	BML_JR_NONE,
	BML_JR_SYNTAX,
	BML_JR_DUPLICATE_KEY,
	BML_JR_KEY_CASE,
	BML_JR_INVALID_UTF8,
	BML_JR_UNPAIRED_SURROGATE,
	BML_JR_TRAILING_DATA,
	BML_JR_NESTING_TOO_DEEP,
	BML_JR_NUL,
	BML_JR_UNKNOWN_KEY,
	BML_JR_TYPE,
	BML_JR_OOM,

	BML_JR_CAPS_KEY_NEWER_FORMAT,
	BML_JR_CAPS_FORMAT_UNKNOWN,
};
const char *bml_json_rule_name(enum bml_json_rule r);


struct bml_json_desc;
struct bml_json_field {
	const char *name;
	const struct bml_json_desc *desc;
};
struct bml_json_desc {
	enum { BML_JD_SCALAR, BML_JD_STRUCT, BML_JD_MAP, BML_JD_ARRAY, BML_JD_STRING, BML_JD_BOOL, BML_JD_UINT, BML_JD_INT } kind;
	int bits;
	const struct bml_json_field *fields;
	size_t n_fields;
	const struct bml_json_desc *child;
};

struct bml_json;

struct bml_json_member {
	char *key; /* CONTRACT: unescaped and NUL-terminated, but \u0000 can put a NUL inside the key, so read its length from key_len */
	size_t key_len;
	struct bml_json *value;
};

struct bml_json {
	enum bml_json_type type;
	int boolean;
	char *str;
	size_t len;
	struct bml_json **items;
	struct bml_json_member *members;
	size_t n;
};


int bml_json_parse(const char *data, size_t len, struct bml_json **out, char **err);

int bml_json_parse_ex(const char *data, size_t len, const struct bml_json_desc *desc, int lenient, struct bml_json **out,
		      char **err, enum bml_json_rule *rule);
void bml_json_free(struct bml_json *j);




int bml_json_validate(struct bml_json *j, const struct bml_json_desc *desc, char **err, enum bml_json_rule *rule);


const struct bml_json *bml_json_get(const struct bml_json *obj, const char *key);

int bml_json_uint64(const struct bml_json *j, uint64_t *out);
int bml_json_int64(const struct bml_json *j, int64_t *out);



void bml_json_write_string(struct bml_buf *b, const char *s, size_t n);

void bml_json_write_string_html(struct bml_buf *b, const char *s, size_t n);

#endif
