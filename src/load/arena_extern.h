
#ifndef BML_LOAD_ARENA_EXTERN_H
#define BML_LOAD_ARENA_EXTERN_H
#include "elf/elf.h"
#include "load/load.h"
int lb_arena_extern(const struct bml_elf *,const struct bml_elf_sym *,size_t,size_t,struct bml_load_result *);
#endif
