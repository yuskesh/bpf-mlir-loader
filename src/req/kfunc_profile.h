
#ifndef BML_REQ_KFUNC_PROFILE_H
#define BML_REQ_KFUNC_PROFILE_H

#include "elf/elf.h"
#include "req/req.h"
#include "util/gostr.h"


void bml_req_attach_json(struct bml_buf *b, const struct bml_attach *a, int blank_program);

int bml_req_kfunc_profiles_derive(const struct bml_elf *elf, struct bml_requirements *r);
void bml_req_kfunc_profiles_free(struct bml_requirements *r);

const struct bml_kfunc_profile_entry *bml_req_kfunc_profile_for(const struct bml_requirements *r, const char *program, char **why);

#endif
