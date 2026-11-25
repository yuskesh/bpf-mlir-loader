/* mapdecl.h — the map-declaration and record check (bpf-mlir's docs/requirements_format.md section 12). This is a C
 * copy of go/bindrt/mapdecl.go and of BTFRecords, parseBTF and spell in go/layout. */
#ifndef BML_MAPDECL_H
#define BML_MAPDECL_H

#include <stddef.h>
#include <stdint.h>

#include "json/json.h"
#include "req/req.h"

struct bml_map_decl {
	char *name, *kind, *key, *value;
	uint64_t max_entries;
	int has_flags; /* Go's *uint64 is not nil */
	uint64_t flags;
	int has_map_extra;
	uint64_t map_extra; /* arena maps only; an absent value and an explicit zero are distinct. */
	/* The innermap template from bpf-mlir's map-in-map support (optional: Go's *InnerDecl is not nil). An omitted flags
 * or max_entries is 0. */
	int has_inner;
	char *inner_kind, *inner_key, *inner_value;
	uint64_t inner_max_entries, inner_flags;
	char *struct_ops; /* the declaration's struct_ops spelling, from bpf-mlir (NULL means none, and it is not checked) */
};

struct bml_record_member {
	char *name;
	uint32_t offset;
	char *type;
};

struct bml_record_decl {
	char *name;
	uint32_t size;
	struct bml_record_member *members;
	size_t n_members;
};

/* A global variable declaration: section "rodata" or "bss" with a type u8 … i64 (a be suffix is allowed), or (bpf-mlir's
 * record globals) section "data" with record, a key of the same document's records. type_key / record_key: the key was present
 * in maps.json, whatever its value (Go's presence read of ParseMapDecls). */
struct bml_global_decl {
	char *name, *section, *type, *record;
	int type_key, record_key;
};

struct bml_map_decls {
	int allow_undeclared;
	int has_maps; /* the "maps" key is present and not null (Go's Maps is not nil; a downstream load treats nil as an error) */
	struct bml_map_decl *maps;
	size_t n_maps;
	struct bml_record_decl *records;
	size_t n_records;
	/* has_globals means Go's Globals is not nil: the "globals" key is present and not null, and `[]` declares that there
	 * are no globals. If it is 0 the globals are not checked. */
	int has_globals;
	struct bml_global_decl *globals;
	size_t n_globals;
	int allow_undeclared_globals;
};

struct bml_map_problem {
	char *map;
	const char *field; /* missing_in_elf, undeclared, kind, key, value, max_entries, flags, decl, format, record, record_missing,
			      global, global_missing_in_elf, global_undeclared (the last three come from the globals check) */
	char *declared, *elf;
};

struct bml_map_problems {
	struct bml_map_problem *p;
	size_t n, cap;
};

/* Read maps.json (the decode rules of Go's MapDecls with DisallowUnknownFields, plus the strict JSON rules of the
 * offline check). Failure is -1 with *err set. */
int bml_map_decls_parse(const char *data, size_t len, struct bml_map_decls *out, char **err);
/* The same, with the rule names of section 13 of the requirements-format specification */
int bml_map_decls_parse_rule(const char *data, size_t len, struct bml_map_decls *out, char **err, enum bml_json_rule *rule);
void bml_map_decls_free(struct bml_map_decls *d);
/* The type description of Go's MapDecls (the target of ParseMapDecls's DecodeStrictJSON) */
const struct bml_json_desc *bml_map_decls_desc(void);
/* One declaration (Go's DecodeStrictJSON(&MapDecl), the per-map operation declaration). Failure is -1 with *err set. */
int bml_map_decl_parse_one(const char *data, size_t len, struct bml_map_decl *out, char **err);
void bml_map_decl_free(struct bml_map_decl *x);
/* A records document (map[string]RecordDecl); *is_null is set for a null document. Only records are filled in. */
int bml_record_decls_parse(const char *data, size_t len, struct bml_map_decls *out, int *is_null, char **err);

/* Parsed.CheckMapDecls. elf is NULL when only the requirements section is available (records then become a
 * "format" problem). The problems are returned in *out and the caller frees them.
 * Return value: 0 for a match (out is empty), 1 for a mismatch, -1 for out of memory. */
int bml_check_map_decls(const struct bml_requirements *req, const void *elf, size_t elf_len, const struct bml_map_decls *d,
			struct bml_map_problems *out);
void bml_map_problems_free(struct bml_map_problems *v);
/* MapDeclProblem.String (malloc) */
char *bml_map_problem_string(const struct bml_map_problem *p);

#endif
