
#ifndef BML_MAPS_INTERNAL_H
#define BML_MAPS_INTERNAL_H

#include <stddef.h>

#include "maps/mapdecl.h"

int md_json_is_arena(const struct bml_json *j);
int md_map_decls_parse(const char *, size_t, struct bml_map_decls *, char **, enum bml_json_rule *, int);
int md_map_decl_parse_one(const char *, size_t, struct bml_map_decl *, char **, int);
int md_check_arena_decl(const struct bml_requirements *req, const struct bml_map_decl *m,
	const void *elf, size_t len, struct bml_map_problems *out);
int md_validate_map_json(struct bml_json *j, const struct bml_json_desc *top, const struct bml_json_desc *base,
	const struct bml_json_desc *arena, int one, char **err, enum bml_json_rule *rule);

char *md_xstrdup(const char *s);
char *md_fmts(const char *f, ...) __attribute__((format(printf, 1, 2)));
/* CONTRACT: adds a problem; ownership of the strings moves (NULL means ""). Out of memory is -1 */
int md_add(struct bml_map_problems *v, char *map, const char *field, char *declared, char *elf);

int md_check_records(const void *elf, size_t elf_len, const struct bml_map_decls *d, struct bml_map_problems *out);

int md_check_globals(const void *elf, size_t elf_len, const struct bml_map_decls *d, struct bml_map_problems *out);

#endif
