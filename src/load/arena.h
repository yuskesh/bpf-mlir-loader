#ifndef BML_LOAD_ARENA_H
#define BML_LOAD_ARENA_H
#include "load/load.h"
struct lb_arena;
struct bpf_map;
int lb_arena_prepare(struct bml_obj *o, const void *elf, size_t len, struct bml_load_result *r);
void lb_arena_observe(struct bml_obj *o);
int lb_arena_check(struct bml_obj *o, struct bml_load_result *r);
void lb_arena_cleanup(struct bml_obj *o);
int bml_obj_arena_span(struct bml_obj *o, struct bpf_map *map, void **base, size_t *length, char **err);
#endif
