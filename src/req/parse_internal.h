#ifndef BML_REQ_PARSE_INTERNAL_H
#define BML_REQ_PARSE_INTERNAL_H

#include <stdarg.h>
#include <stddef.h>

#include "req/req.h"
#include "util/gostr.h"


#define SCAN_MAX 65536

#define MAXF SCAN_MAX
#define Q(f) (f).p, (f).n
#define SEC BML_REQ_SECTION

struct field {
	const char *p;
	size_t n;
};

struct scanner {
	const char *data;
	size_t len, pos;
	int too_long;
	struct field tok;
};

int req_eq(struct field f, const char *lit);
int req_field_cmp(struct field a, struct field b);
int req_valid_kfield_path(const char *p, size_t n);
int req_guard_number(struct field f, int64_t *out);
int req_parse_guard_list(struct field *f, size_t count, int n, const char *row, struct field line, struct bml_guard_list *out, struct bml_parse_error *e);
int req_note_guarded_row(struct bml_requirements *r, int n, long ksym, long kfield);
int req_parse_guard(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e);
int req_check_guard_bindings(const struct bml_requirements *r, struct bml_parse_error *e);
int req_parse_extern(struct bml_requirements *r, struct field *f, struct field *guarded, size_t ng, int has_guarded, struct field line, int n, struct bml_parse_error *e);
int req_parse_loader_row(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e);
int req_parse_kernel_value(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e);
int req_check_arena_rows(const struct bml_requirements *r, struct bml_parse_error *e);
int req_str_eq(const struct bml_str *s, struct field f);
int req_str_eq_lit(const struct bml_str *s, const char *lit);
const struct bml_row_kind *req_row_kind(struct field f);
int req_known_attach_type(struct field f);
int req_valid_int_spelling(struct field f);
int req_enum_bits(struct field f);

int req_kfield_type_ok(struct field f);

int req_kfield_struct_type(struct field t);
int req_kfield_path_row(const struct bml_requirements *r, struct field *f, int n, const char *row, struct bml_parse_error *e);
int req_kfield_prefixes(const struct bml_requirements *r, struct bml_parse_error *e);
int req_mkstr(struct bml_str *s, struct field f);
int req_grow_array(void **arr, size_t *cap, size_t elem, size_t need);
#define GROW(arr, n, cap) ((n) < (cap) ? 0 : req_grow_array((void **)&(arr), &(cap), sizeof(*(arr)), (n) + 1))
int req_perr(struct bml_parse_error *e, int line, const char *row, const char *rule, const char *fmt, ...);
int req_scan(struct scanner *s);
size_t req_split(struct field line, struct field *f);
int req_find_program(const struct bml_requirements *r, struct field name);

int req_v9_attach(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e);
int req_v9_ctxaccess(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e);
int req_valid_attach_type_name(struct field f);

int req_v11_attach_type(struct field t);
int req_valid_cname(struct field f);
int req_v11_companion(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e);


int req_multi_attach_type(struct field t);
int req_v12_attach_type(struct field t);
int req_multi_str(const struct bml_str *t);
int req_uprobe_family(const struct bml_str *t);
int req_v12_pending(const struct bml_requirements *r, int n, const char *row, long after_map, struct bml_parse_error *e);
int req_v12_companion(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e);
int req_v12_innermap(struct bml_requirements *r, struct field *f, struct field line, int n, long after_map, struct bml_parse_error *e);


int req_v13_attach_type(struct field t);
int req_btf_feature_min_version(struct field f);
int req_probe_companion(struct bml_requirements *r, struct field *f, struct field line, int n, const char *row, struct bml_parse_error *e);
int req_v13_kfunc(struct bml_requirements *r, struct field *f, size_t nf, struct field line, int n, struct bml_parse_error *e);
int req_v13_companion(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e);

int req_v14_tpbuf(struct bml_requirements *r, struct field *f, struct field line, int n, int after_attach, struct bml_parse_error *e);

int req_parse_target_row(struct bml_requirements *r, struct field *f, struct field line, int n, int after_attach, struct bml_parse_error *e);
int req_helper_target_bound(const struct bml_requirements *r, const struct bml_str *program, const struct bml_str *helper, int64_t helper_id,
			    const struct bml_str *attach_type, const struct bml_str *target, int64_t arg_index, const struct bml_str *arg_type);

#endif
