/* json.h — a strict JSON parser, and a writer that escapes strings exactly as Go's encoding/json does. The parser
 * follows the strict decoding rules that bpf-mlir's Go code applies (requirements.DecodeStrictJSON).
 *
 * The rules are section 13 of bpf-mlir's docs/requirements_format.md (the same as Go's requirements.DecodeStrictJSON).
 * Byte-level rules (duplicate_key, key_case, invalid_utf8, unpaired_surrogate, trailing_data, nesting_too_deep,
 * syntax) stop at the first one met when scanning from the start of the input. Reading into types (unknown_key and
 * type) is left to the reader (recorded.c and mapdecl.c). key_case is checked only inside the objects that the type
 * description (desc) declares as structs (map keys are free), in the same scan order as Go's strictScanner.
 * lenient follows the permissiveness of Go's json.Unmarshal (the last duplicate wins; invalid UTF-8 and an unpaired
 * surrogate become U+FFFD; nesting depth up to 10000). It is used only for the look-ahead that reads the format of
 * an ebpf-caps 1 file. */
#ifndef BML_JSON_H
#define BML_JSON_H

#include <stddef.h>
#include <stdint.h>

#include "util/gostr.h"

#define BML_JSON_MAX_DEPTH 128

enum bml_json_type { BML_JSON_NULL, BML_JSON_BOOL, BML_JSON_NUMBER, BML_JSON_STRING, BML_JSON_ARRAY, BML_JSON_OBJECT };

/* The rules of section 13 (Go's requirements.JSONRule* constants) */
enum bml_json_rule {
	BML_JR_NONE,
	BML_JR_SYNTAX,
	BML_JR_DUPLICATE_KEY,
	BML_JR_KEY_CASE,
	BML_JR_INVALID_UTF8,
	BML_JR_UNPAIRED_SURROGATE,
	BML_JR_TRAILING_DATA,
	BML_JR_NESTING_TOO_DEEP,
	BML_JR_NUL, /* a \u0000 inside a string (a rule added in bpf-mlir v0.13.0) */
	BML_JR_UNKNOWN_KEY,
	BML_JR_TYPE,
	BML_JR_OOM,
	/* Not a JSON rule but a caps.json format rule (CapsFormatError), from bpf-mlir: a key or query that is newer than
	 * the file's declared format. */
	BML_JR_CAPS_KEY_NEWER_FORMAT,
	BML_JR_CAPS_FORMAT_UNKNOWN, /* an unknown format (found before the typed decode), from bpf-mlir */
};
const char *bml_json_rule_name(enum bml_json_rule r);

/* A type description (it replaces Go's reflect.Type and bounds where key_case is checked). NULL means "a place
 * whose type is unknown". */
struct bml_json_desc;
struct bml_json_field {
	const char *name;
	const struct bml_json_desc *desc;
};
struct bml_json_desc {
	enum { BML_JD_SCALAR, BML_JD_STRUCT, BML_JD_MAP, BML_JD_ARRAY, BML_JD_STRING, BML_JD_BOOL, BML_JD_UINT, BML_JD_INT } kind;
	int bits; /* the width of UINT and INT */
	const struct bml_json_field *fields; /* STRUCT */
	size_t n_fields;
	const struct bml_json_desc *child; /* the value of a MAP, the element of an ARRAY */
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
	char *str; /* STRING: the unescaped bytes (NUL-terminated); NUMBER: the original spelling */
	size_t len;
	struct bml_json **items; /* ARRAY */
	struct bml_json_member *members; /* OBJECT (in document order) */
	size_t n;
};

/* Success is 0 with *out set (free it with bml_json_free). Failure is -1 with *err set to a malloc'd message of the
 * form "offset N: ...". */
int bml_json_parse(const char *data, size_t len, struct bml_json **out, char **err);
/* The same, with a type description and a rule result. lenient is described in the header comment above. */
int bml_json_parse_ex(const char *data, size_t len, const struct bml_json_desc *desc, int lenient, struct bml_json **out,
		      char **err, enum bml_json_rule *rule);
void bml_json_free(struct bml_json *j);

/* The check that Go's standard decoder applies when it reads into a type (with DisallowUnknownFields), done in
 * document order: the first unknown_key or type error is reported. Field names are matched with encoding/json's
 * case folding (ASCII case, U+017F "ſ" -> s, U+212A "K" -> k); a key that matches after folding is rewritten to the
 * field's name. (key_case is already stopped by the parse scan, so only characters like "ſ" reach this point.)
 * null means "not set" wherever it appears. */
int bml_json_validate(struct bml_json *j, const struct bml_json_desc *desc, char **err, enum bml_json_rule *rule);

/* The value of an object key (NULL if absent; if the key occurs several times the last one is used, as in Go) */
const struct bml_json *bml_json_get(const struct bml_json *obj, const char *key);
/* Read a NUMBER with the same rules as Go's json decoding into uint64 / int64 (a fraction, an exponent or an
 * out-of-range value gives -1). */
int bml_json_uint64(const struct bml_json *j, uint64_t *out);
int bml_json_int64(const struct bml_json *j, int64_t *out);

/* Write a string exactly as Go's encoding/json does with SetEscapeHTML(false): \" \\ \n \r \t are escaped, other
 * control characters become \u00XX,
 * U+2028 and U+2029 become the six-character escapes \u2028 / \u2029, and an invalid UTF-8 byte becomes the replacement-character escape \ufffd. */
void bml_json_write_string(struct bml_buf *b, const char *s, size_t n);
/* The same, but with Go's json.Marshal default, which escapes the HTML characters < > & (as the
 * six-character escapes of U+003C, U+003E and U+0026).
 * It is used for bpf-mlir's KfuncLoadKey and ContextIdentity. */
void bml_json_write_string_html(struct bml_buf *b, const char *s, size_t n);

#endif
