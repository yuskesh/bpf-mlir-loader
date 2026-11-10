
#ifndef BML_LOAD_ARENA_RESERVE_H
#define BML_LOAD_ARENA_RESERVE_H
#include <stddef.h>
#include <stdint.h>
struct lb_arena_reservation { void *base; size_t length; };
int lb_arena_reserve(struct lb_arena_reservation *r, uint64_t address, uint64_t length, char **err);
int lb_arena_release(struct lb_arena_reservation *r, char **err);
#endif
