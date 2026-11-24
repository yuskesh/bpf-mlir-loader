/* req/kfunc_profile.h — the initial profile that says which kfuncs (kernel functions callable from BPF) a program may use. */
#ifndef BML_REQ_KFUNC_PROFILE_H
#define BML_REQ_KFUNC_PROFILE_H

#include "elf/elf.h"
#include "req/req.h"
#include "util/gostr.h"

/* Same output as Go's json.Marshal(Attach), including the HTML escaping of <, > and &. With blank_program the Program field is written as ""
 * (ContextIdentity). */
void bml_req_attach_json(struct bml_buf *b, const struct bml_attach *a, int blank_program);
/* deriveKfuncProfiles (part of FromELF). Returns -1 when memory runs out. */
int bml_req_kfunc_profiles_derive(const struct bml_elf *elf, struct bml_requirements *r);
void bml_req_kfunc_profiles_free(struct bml_requirements *r);
/* kfuncProfileFor: returns the profile if there is one; otherwise NULL and a malloc-ed *why (the text of Go's err.Error()). */
const struct bml_kfunc_profile_entry *bml_req_kfunc_profile_for(const struct bml_requirements *r, const char *program, char **why);

#endif
