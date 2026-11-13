#ifndef BML_REQ_CHECK_INTERNAL_H
#define BML_REQ_CHECK_INTERNAL_H

#include <stdint.h>

#include "req/check.h"

struct ck {
	const struct bml_requirements *req;
	const struct bml_caps *caps;
	struct bml_unmets *out;
	char **err;
	int oom;

	char **asked;
	size_t n_asked, cap_asked;
};

char *ck_dupn(const char *s);
char *ck_fmtd(const char *f, ...) __attribute__((format(printf, 1, 2)));
/* CONTRACT: adds an Unmet; ownership of detail moves (NULL means "") */
void ck_add(struct ck *c, const char *kind, const char *program, const char *name, int64_t id, char *detail);
int ck_has(const struct ck *c, void *fnptr, const char *q);
#define HAS(c, f, q) ck_has((c), (void *)(c)->caps->f, (q))
const struct bml_loader_decl *ck_loader_of(const struct ck *c);
/* CONTRACT: stops with a check error (ownership of msg moves to *err) */
int ck_fail(struct ck *c, char *msg);
void ck_add_diffs(struct ck *c, const char *kind, const char *program, const char *name, struct bml_strs *d);
const char *ck_tracing_attach(const struct bml_requirements *r, const char *prog);
int ck_may_hold_field(const struct bml_map *m);
int ck_in_list(const char **l, size_t n, const char *s);
const char *ck_btf_rewrite_name(const char *f);
int ck_has_nul(const struct bml_requirements *r);
int ck_check_enum_values(struct ck *c);
int ck_check_struct_sizes(struct ck *c);
int ck_check_fib_flags(struct ck *c);
void ck_check_loader_rows(struct ck *c);
int ck_guards_state(struct ck *c, const struct bml_guard_list *gs, int *state, char **why);
int ck_check_kfields_guarded(struct ck *c);
int ck_check_ksym_vars(struct ck *c);
int ck_check_kconfigs(struct ck *c);
int bml_unmet_kernel_string(const struct bml_unmet *u, char **out);

int ck_needs_helper_target(const struct bml_program *p, const struct bml_helper *h);
int ck_check_helper_targets(struct ck *c);
int ck_check_netkit(struct ck *c, const struct bml_attach *a);
int ck_check_sleepable(struct ck *c, const struct bml_attach *a);


int ck_check_nullable(struct ck *c, const struct bml_attach *a);
int ck_check_arch_ctx(struct ck *c, const struct bml_attach *a, char **target_arch);

int ck_check_kprobe_target(struct ck *c, const struct bml_attach *a, const char *target_arch, int ask_alias);
int ck_check_uprobe(struct ck *c, const struct bml_attach *a);

struct bml_elf;
int ck_uprobe_open(struct ck *c, const struct bml_attach *a, const char *name, uint8_t **bin, struct bml_elf *elf);

#include "elf/elf.h"
struct bml_dwarf;
struct bml_dwarf_sub;
struct ck_dsrc {
	const struct bml_elf *body;
	const char *program;
	int resolved, split_open;
	struct bml_dwarf *d;
	uint8_t *raw;
	size_t rawn;
	struct bml_elf split;
	char *err;
	const char *kind;
};
void ck_dsrc_init(struct ck_dsrc *s, const struct bml_elf *body, const char *program);
void ck_dsrc_free(struct ck_dsrc *s);
void ck_dsrc_read(struct ck *c, struct ck_dsrc *s);
int ck_dsrc_subprogram(const struct ck_dsrc *s, const char *target, int parameters, const uint8_t *raw, size_t n_raw, struct bml_dwarf_sub *out,
		       char **err);
void ck_uprobe_target(struct ck *c, const struct bml_attach *a, struct bml_elf *elf, const char *target, int ret, struct ck_dsrc *src);

int ck_check_generic_attach(struct ck *c, const struct bml_attach *a);

int ck_check_attach_type(struct ck *c, const char *program, const char *at);

int ck_check_multi(struct ck *c, const struct bml_attach *a);
int ck_check_usdt(struct ck *c, const struct bml_attach *a);
int ck_check_innermaps(struct ck *c);

int ck_check_prog_loader(struct ck *c, const struct bml_attach *a);
int ck_check_kfuncs(struct ck *c);
int ck_check_v13(struct ck *c, const struct bml_attach *a);
int ck_check_tpbuf(struct ck *c, const struct bml_attach *a);
int ck_check_ctx_accesses(struct ck *c);
int ck_check_fmod_ret(struct ck *c, const struct bml_attach *a);

int ck_check_v11(struct ck *c, const struct bml_attach *a);
int ck_lsm_args(struct ck *c, const struct bml_attach *a);
int ck_fentry_args(struct ck *c, const struct bml_attach *a);

int ck_int_spelling(const char *s);
void ck_asked_free(struct ck *c);

#endif
