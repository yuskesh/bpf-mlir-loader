/* bml/build.h — build-time C for the bpf-mlir Go names a build calls (libbml_build.a, linked together with libbml.a).
 *
 * Every function here runs on files only: none loads, attaches or asks the kernel. Each one is the C form of one Go name of
 * bpf-mlir, and a differential compares the two on the same inputs:
 *
 *   bml_build_json_check_any      requirements.DecodeStrictJSON(data, &v) with v of type any (the value is not kept)
 *   bml_build_json_decode         requirements.DecodeStrictJSON(data, &v) with v of a declared shape
 *   bml_build_map_decls_validate  bindrt.ParseMapDecls (the error only)
 *   bml_build_schema_sha256       bindrt.Parse(elf), then Requirements().SchemaSHA256
 *   bml_build_check_offline       bindrt.Parse(elf), then CheckTarget with the fixed offline capabilities below
 *   bml_build_map_symbols         layout.MapSymbols
 *   bml_build_sha256(_hex)        crypto/sha256
 *   bml_build_json_string         encoding/json's encoding of a string, with or without HTML escaping
 *
 * Errors. code BML_BUILD_FAIL: text is byte for byte the Go error's Error(). BML_BUILD_UNSUPPORTED: Go fails (or, in rare cases,
 * succeeds) where bml does not reproduce Go's text; text is bml's own and starts with "unsupported: <class>:". A caller that
 * must print Go's exact text treats UNSUPPORTED as its own error. BML_BUILD_NOMEM: out of memory.
 * The JSON functions also fill rule, offset and detail (Go's requirements.JSONError parts; offset -1 where not reproduced). */
#ifndef BML_BUILD_H
#define BML_BUILD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BML_BUILD_OK 0
#define BML_BUILD_FAIL 1
#define BML_BUILD_UNSUPPORTED 2
#define BML_BUILD_NOMEM 3

struct bml_build_error {
	int code;
	char *text;    /* malloc, NULL for OK */
	char rule[24]; /* JSON functions: Go's rule name ("syntax", "duplicate_key", ..., "unknown_key", "type"), else "" */
	int64_t offset; /* JSON functions: Go's byte offset, -1 where not reproduced or not JSON */
	char *detail;  /* JSON functions: Go's detail (malloc), NULL where not reproduced */
};
void bml_build_error_free(struct bml_build_error *err);

/* ---- strict JSON ---- */

/* Validation only: the scan rules and the float64 range of numbers. */
int bml_build_json_check_any(const void *data, size_t len, struct bml_build_error *err);

/* A shape is the Go type the document decodes into. No float and no `any` kind: numbers are read only as declared integers. */
enum bml_build_shape_kind {
	BML_BUILD_SHAPE_STRING = 1,
	BML_BUILD_SHAPE_BOOL,
	BML_BUILD_SHAPE_INT,    /* bits 8, 16, 32 or 64 */
	BML_BUILD_SHAPE_UINT,   /* bits 8, 16, 32 or 64 */
	BML_BUILD_SHAPE_ARRAY,  /* elem */
	BML_BUILD_SHAPE_MAP,    /* string keys, elem values */
	BML_BUILD_SHAPE_STRUCT, /* fields (JSON names); a Go pointer field has the same shape as its target */
};
struct bml_build_field;
struct bml_build_shape {
	int kind;
	int bits;
	const struct bml_build_shape *elem;
	const struct bml_build_field *fields;
	size_t n_fields;
};
struct bml_build_field {
	const char *name;
	const struct bml_build_shape *shape;
};

/* A decoded document: a read-only tree. Nodes stay valid until bml_build_json_free. */
struct bml_build_json;
struct bml_build_json_node;
enum bml_build_json_type {
	BML_BUILD_JSON_NULL,
	BML_BUILD_JSON_BOOL,
	BML_BUILD_JSON_NUMBER,
	BML_BUILD_JSON_STRING,
	BML_BUILD_JSON_ARRAY,
	BML_BUILD_JSON_OBJECT,
};
int bml_build_json_decode(const void *data, size_t len, const struct bml_build_shape *shape, struct bml_build_json **doc,
			  struct bml_build_error *err);
void bml_build_json_free(struct bml_build_json *doc);
const struct bml_build_json_node *bml_build_json_root(const struct bml_build_json *doc);
int bml_build_json_type(const struct bml_build_json_node *n);
int bml_build_json_bool(const struct bml_build_json_node *n);
/* The string's bytes (NUL-terminated; JSON strings here never contain NUL) and length; NULL for another type. */
const char *bml_build_json_string_value(const struct bml_build_json_node *n, size_t *len);
/* 0 and *out for a number Go decodes into int64 / uint64; -1 otherwise. */
int bml_build_json_int64(const struct bml_build_json_node *n, int64_t *out);
int bml_build_json_uint64(const struct bml_build_json_node *n, uint64_t *out);
/* Elements of an array, members of an object (document order); 0 for another type. */
size_t bml_build_json_count(const struct bml_build_json_node *n);
const struct bml_build_json_node *bml_build_json_index(const struct bml_build_json_node *n, size_t i);
/* The i-th member's key (a struct member's key is the field's name, as Go matched it) and value. */
const char *bml_build_json_member(const struct bml_build_json_node *n, size_t i, size_t *key_len,
				  const struct bml_build_json_node **value);
/* The member with this key, or NULL. */
const struct bml_build_json_node *bml_build_json_get(const struct bml_build_json_node *n, const char *key, size_t key_len);

/* ---- bindrt.ParseMapDecls ---- */
int bml_build_map_decls_validate(const void *data, size_t len, struct bml_build_error *err);

/* ---- bindrt.Parse ---- */
/* out receives the 64 hex digits and a NUL. */
int bml_build_schema_sha256(const void *elf, size_t len, char out[65], struct bml_build_error *err);

/* ---- the offline check ----
 * The fixed capabilities of a build machine (tied to bml_policy_version()): every program type and map type answers "not
 * supported", every helper "cannot be determined on this target", the uprobe binary of a program is what the caller gives,
 * the split DWARF of a uprobe binary is read from <debug_root>/.build-id/ (NULL or "" does not look it up), every other
 * question is absent. Every Unmet comes back, unfiltered, in Go's order.
 * targets: per program, either the file's bytes (data, len) or the caller's own error text (error, for example the text of the
 * read that failed); a program missing from the list reads as "no target file for <program>". */
struct bml_build_target {
	const char *program;
	const void *data;
	size_t len;
	const char *error;
};
struct bml_build_unmet {
	char *kind, *program, *name;
	int64_t id;
	char *detail;
};
int bml_build_check_offline(const void *elf, size_t len, const struct bml_build_target *targets, size_t n_targets,
			    const char *debug_root, struct bml_build_unmet **unmets, size_t *n_unmets, struct bml_build_error *err);
void bml_build_unmets_free(struct bml_build_unmet *unmets, size_t n);

/* ---- layout.MapSymbols ---- */
int bml_build_map_symbols(const void *elf, size_t len, char ***names, size_t *n, struct bml_build_error *err);
void bml_build_strs_free(char **names, size_t n);

/* ---- crypto/sha256 ---- */
void bml_build_sha256(const void *data, size_t len, unsigned char out[32]);
void bml_build_sha256_hex(const void *data, size_t len, char out[65]);

/* ---- encoding/json string ----
 * html 1: json.Marshal of a Go string; html 0: an Encoder with SetEscapeHTML(false), without the Encoder's newline.
 * Returns the quoted string (malloc, NUL-terminated; *out_len when not NULL), NULL when out of memory. */
char *bml_build_json_string(const char *s, size_t n, int html, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif
