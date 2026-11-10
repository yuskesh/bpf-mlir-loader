

#ifndef BML_MAPDECL_H
#define BML_MAPDECL_H

#include <stddef.h>
#include <stdint.h>

#include "json/json.h"
#include "req/req.h"

struct bml_map_decl {
	char *name, *kind, *key, *value;
	uint64_t max_entries;
	int has_flags;
	uint64_t flags;
	int has_map_extra;
	uint64_t map_extra;

	int has_inner;
	char *inner_kind, *inner_key, *inner_value;
	uint64_t inner_max_entries, inner_flags;
	char *struct_ops;
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


struct bml_global_decl {
	char *name, *section, *type;
};

struct bml_map_decls {
	int allow_undeclared;
	int has_maps;
	struct bml_map_decl *maps;
	size_t n_maps;
	struct bml_record_decl *records;
	size_t n_records;
	

	int has_globals;
	struct bml_global_decl *globals;
	size_t n_globals;
	int allow_undeclared_globals;
};

struct bml_map_problem {
	char *map;
	const char *field; 

	char *declared, *elf;
};

struct bml_map_problems {
	struct bml_map_problem *p;
	size_t n, cap;
};


int bml_map_decls_parse(const char *data, size_t len, struct bml_map_decls *out, char **err);

int bml_map_decls_parse_rule(const char *data, size_t len, struct bml_map_decls *out, char **err, enum bml_json_rule *rule);
void bml_map_decls_free(struct bml_map_decls *d);

int bml_map_decl_parse_one(const char *data, size_t len, struct bml_map_decl *out, char **err);
void bml_map_decl_free(struct bml_map_decl *x);

int bml_record_decls_parse(const char *data, size_t len, struct bml_map_decls *out, int *is_null, char **err);



int bml_check_map_decls(const struct bml_requirements *req, const void *elf, size_t elf_len, const struct bml_map_decls *d,
			struct bml_map_problems *out);
void bml_map_problems_free(struct bml_map_problems *v);

char *bml_map_problem_string(const struct bml_map_problem *p);

#endif
