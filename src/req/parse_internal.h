/* req/parse_internal.h — internal parts of the requirements parser (Parse); used inside req/ only. The parser was split out of req_parse.c into several files. */
#ifndef BML_REQ_PARSE_INTERNAL_H
#define BML_REQ_PARSE_INTERNAL_H

#include <stdarg.h>
#include <stddef.h>

#include "req/req.h"
#include "util/gostr.h"

/* bufio.MaxScanTokenSize */
#define SCAN_MAX 65536
/* Upper bound on the number of fields kept from a strings.Split result (all of them are still counted). */
#define MAXF SCAN_MAX /* the guarded suffix, including empty fields; the array is allocated on the heap, once per document */
#define Q(f) (f).p, (f).n
#define SEC BML_REQ_SECTION

struct field {
	const char *p;
	size_t n;
};

struct scanner {
	const char *data;
	size_t len, pos;
	int too_long; /* sc.Err() == bufio.ErrTooLong */
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
/* the spelling of kfield types (as of v0.17.0) */
int req_kfield_type_ok(struct field f);
/* kfield_path.c: whether a type is struct:T, the format version and spelling of path rows and struct:T rows, and the last prefix check of
 * the parser. Returns 0 for good and -1 for an error. */
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
/* parse_v9.c: the attach rows and the ctxaccess rows. Returns 0 when the row was read, -1 for an error and -2 when memory runs out. */
int req_v9_attach(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e);
int req_v9_ctxaccess(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e);
int req_valid_attach_type_name(struct field f);
/* Format 11: whether a type belongs to the companion-row families and whether a string is a C identifier; and the tpfield, extret, extarg
 * and structop rows of parse_v11.c. */
int req_v11_attach_type(struct field t);
int req_valid_cname(struct field f);
int req_v11_companion(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e);
/* Format 12: the type test of parse_v9.c, and from parse_v12.c the pending check, mtarget / usdtsem / usdtarg and innermap (after_map is the
 * index of the previous map row, or -1). */
int req_multi_attach_type(struct field t);
int req_v12_attach_type(struct field t);
int req_multi_str(const struct bml_str *t);
int req_uprobe_family(const struct bml_str *t);
int req_v12_pending(const struct bml_requirements *r, int n, const char *row, long after_map, struct bml_parse_error *e);
int req_v12_companion(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e);
int req_v12_innermap(struct bml_requirements *r, struct field *f, struct field line, int n, long after_map, struct bml_parse_error *e);
/* Format 13: the type test (parse_v9.c), the minimum version of a BTF feature (requirements.c), the companion rows of the probe families
 * (parse_probe.c), and from parse_v13.c the kfunc rows (tied to a program by name) and the sysarg / mtargetarg rows (tied to the preceding
 * attach by position). The return values 0 / -1 / -2 are as for req_v9_attach. */
int req_v13_attach_type(struct field t);
int req_btf_feature_min_version(struct field f);
int req_probe_companion(struct bml_requirements *r, struct field *f, struct field line, int n, const char *row, struct bml_parse_error *e);
int req_v13_kfunc(struct bml_requirements *r, struct field *f, size_t nf, struct field line, int n, struct bml_parse_error *e);
int req_v13_companion(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e);
/* Format 14: tpbuf (after_attach tells whether the physically preceding row is an attach row). The return values 0 / -1 / -2 are as for
 * req_v9_attach. */
int req_v14_tpbuf(struct bml_requirements *r, struct field *f, struct field line, int n, int after_attach, struct bml_parse_error *e);
/* parse_target_rows.c: the helper_target and sleepable rows. The return values 0 / -1 / -2 are as for req_v9_attach. */
int req_parse_target_row(struct bml_requirements *r, struct field *f, struct field line, int n, int after_attach, struct bml_parse_error *e);
int req_helper_target_bound(const struct bml_requirements *r, const struct bml_str *program, const struct bml_str *helper, int64_t helper_id,
			    const struct bml_str *attach_type, const struct bml_str *target, int64_t arg_index, const struct bml_str *arg_type);

#endif
