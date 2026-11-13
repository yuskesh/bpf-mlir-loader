#include "req/parse_internal.h"

#include <stdint.h>
#include <string.h>

int req_v14_tpbuf(struct bml_requirements *r, struct field *f, struct field line, int n, int after_attach, struct bml_parse_error *e)
{
	long idx = req_find_program(r, f[1]);
	struct bml_attach *a = r->n_attaches ? &r->attaches[r->n_attaches - 1] : NULL;
	if (!after_attach || idx < 0 || !a || !req_str_eq(&a->program, f[1]) || !a->generic || !req_str_eq_lit(&a->attach_type, "raw_tp_writable") ||
	    a->tpbuf_type.len != 0)
		return req_perr(e, n, "tpbuf", "order", "%s line %d: tpbuf row out of order %q", SEC, (int64_t)n, Q(line));
	const struct bml_program *p = &r->programs[idx];
	struct field tv = {a->tval.p, a->tval.len};
	if (!req_eq(f[2], "i32") || !req_str_eq_lit(&p->prog_type, "raw_tracepoint_writable") || p->prog_type_id != 24 ||
	    !req_str_eq_lit(&a->tkind, "rawtp") || !req_valid_cname(tv))
		return req_perr(e, n, "tpbuf", "value", "%s line %d: bad tpbuf row %q (needs raw_tracepoint_writable/24, rawtp:<IDENT>, i32)", SEC,
				(int64_t)n, Q(line));
	return req_mkstr(&a->tpbuf_type, f[2]) ? -2 : 0;
}
