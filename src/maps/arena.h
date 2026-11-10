
#ifndef BML_MAPS_ARENA_H
#define BML_MAPS_ARENA_H
#include <stddef.h>
#include <stdint.h>

struct bml_arena_spec { uint64_t address, length; uint32_t pages, flags; };
struct bml_requirements;
struct bml_map_decls;
struct bml_map_decl;
struct bml_map_problems;
int bml_arena_map_decls_parse(const char *,size_t,struct bml_map_decls *,char **);
int bml_arena_map_decl_parse_one(const char *,size_t,struct bml_map_decl *,char **);

int bml_check_arena_decls(const struct bml_requirements *,const void *,size_t,
	const struct bml_map_decls *,int require_all,struct bml_map_problems *);
int bml_arena_shape(uint64_t pages, uint64_t flags, uint64_t address,
	struct bml_arena_spec *out, char **err);
int bml_arena_elf(const void *elf, size_t len, const char *name,
	struct bml_arena_spec *out, char **err);
#endif
