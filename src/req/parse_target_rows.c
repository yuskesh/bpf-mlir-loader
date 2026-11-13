#include "req/parse_internal.h"

#include <stdlib.h>
#include <string.h>

#include "util/mutation.h"


static int valid_symbol(struct field s)
{
	if (s.n == 0)
		return 0;
	for (size_t i = 0; i < s.n; i++) {
		unsigned char c = (unsigned char)s.p[i];
		if (c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
			continue;
		if (i > 0 && (c == '.' || (c >= '0' && c <= '9')))
			continue;
		return 0;
	}
	return 1;
}


int req_helper_target_bound(const struct bml_requirements *r, const struct bml_str *program, const struct bml_str *helper, int64_t helper_id,
			    const struct bml_str *attach_type, const struct bml_str *target, int64_t arg_index, const struct bml_str *arg_type)
{
	int present = 0;
	for (size_t i = 0; i < r->n_programs; i++) {
		const struct bml_program *p = &r->programs[i];
		if (p->symbol.len != program->len || memcmp(p->symbol.p, program->p, program->len) ||
		    !req_str_eq_lit(&p->prog_type, "tracing") || p->prog_type_id != 26)
			continue;
		for (size_t j = 0; j < p->n_helpers; j++)
			if (p->helpers[j].id == helper_id && p->helpers[j].name.len == helper->len &&
			    !memcmp(p->helpers[j].name.p, helper->p, helper->len))
				present = 1;
	}
	if (BML_MUT("parse.helper_target_no_program"))
		present = 1;
	if (!present)
		return 0;
	for (size_t i = 0; i < r->n_attaches; i++) {
		const struct bml_attach *a = &r->attaches[i];
		struct field pf = {program->p, program->len}, af = {attach_type->p, attach_type->len}, tf = {target->p, target->len};
		if (req_str_eq(&a->program, pf) && req_str_eq(&a->attach_type, af) && req_str_eq(&a->target, tf) &&
		    (BML_MUT("parse.helper_target_no_farg") ||
		     ((size_t)arg_index < a->n_fargs && a->fargs[arg_index].len == arg_type->len &&
		      !memcmp(a->fargs[arg_index].p, arg_type->p, arg_type->len))))
			return 1;
	}
	return 0;
}


static char *order_key(struct field *f, size_t *n)
{
	struct field parts[] = {f[1], f[3], f[4], f[5], f[6], f[7]};
	size_t total = 0;
	for (size_t i = 0; i < 6; i++)
		total += parts[i].n + 1;
	char *s = malloc(total);
	if (!s)
		return NULL;
	size_t at = 0;
	for (size_t i = 0; i < 6; i++) {
		if (parts[i].n)
			memcpy(s + at, parts[i].p, parts[i].n);
		at += parts[i].n;
		s[at++] = 0;
	}
	*n = total - 1;
	return s;
}

static int helper_target_row(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e)
{

	if (!(req_eq(f[2], "d_path") && req_eq(f[3], "147") && req_eq(f[4], "trace_fentry") && req_eq(f[6], "0") && req_eq(f[7], "path") &&
	      valid_symbol(f[5])) && !BML_MUT("parse.helper_target_any_value"))
		return req_perr(e, n, "helper_target", "value", "%s line %d: unsupported helper_target row %q", SEC, (int64_t)n, Q(line));
	struct bml_helper_target h = {0};
	if (req_mkstr(&h.program, f[1]) || req_mkstr(&h.helper, f[2]) || req_mkstr(&h.attach_type, f[4]) || req_mkstr(&h.target, f[5]) ||
	    req_mkstr(&h.arg_type, f[7]))
		goto oom;
	h.helper_id = 147;
	if (!req_helper_target_bound(r, &h.program, &h.helper, 147, &h.attach_type, &h.target, 0, &h.arg_type)) {
		req_perr(e, n, "helper_target", "document", "%s line %d: helper_target is not bound to preceding program/helper/attach/farg rows", SEC, (int64_t)n);
		goto bad;
	}
	if (r->n_helper_targets && !BML_MUT("parse.helper_target_any_order")) {
		const struct bml_helper_target *l = &r->helper_targets[r->n_helper_targets - 1];
		struct field prev[8] = {{0}};
		prev[1] = (struct field){l->program.p, l->program.len};
		prev[3] = (struct field){"147", 3};
		prev[4] = (struct field){l->attach_type.p, l->attach_type.len};
		prev[5] = (struct field){l->target.p, l->target.len};
		prev[6] = (struct field){"0", 1};
		prev[7] = (struct field){l->arg_type.p, l->arg_type.len};
		size_t na = 0, nb = 0;
		char *a = order_key(prev, &na), *b = order_key(f, &nb);
		if (!a || !b) {
			free(a);
			free(b);
			goto oom;
		}
		size_t m = na < nb ? na : nb;
		int c = memcmp(a, b, m);
		int ge = c > 0 || (c == 0 && na >= nb);
		free(a);
		free(b);
		if (ge) {
			req_perr(e, n, "helper_target", "order", "%s line %d: helper_target out of order or repeated", SEC, (int64_t)n);
			goto bad;
		}
	}
	if (GROW(r->helper_targets, r->n_helper_targets, r->cap_helper_targets))
		goto oom;
	r->helper_targets[r->n_helper_targets++] = h;
	return 0;
oom:
	free(h.program.p); free(h.helper.p); free(h.attach_type.p); free(h.target.p); free(h.arg_type.p);
	return -2;
bad:
	free(h.program.p); free(h.helper.p); free(h.attach_type.p); free(h.target.p); free(h.arg_type.p);
	return -1;
}


static int sleepable_row(struct bml_requirements *r, struct field *f, struct field line, int n, int after_attach, struct bml_parse_error *e)
{
	struct bml_attach *a = r->n_attaches ? &r->attaches[r->n_attaches - 1] : NULL;
	if (!BML_MUT("parse.sleepable_any_position") &&
	    (!a || !after_attach || !req_str_eq(&a->program, f[1]) || !req_str_eq_lit(&a->attach_type, "trace_fentry") || a->sleepable || a->n_fargs > 0))
		return req_perr(e, n, "sleepable", "order",
				"%s line %d: sleepable row out of order or malformed %q (want one row directly after the program's trace_fentry attach row)",
				SEC, (int64_t)n, Q(line));
	if (a)
		a->sleepable = 1;
	return 0;
}

int req_parse_target_row(struct bml_requirements *r, struct field *f, struct field line, int n, int after_attach, struct bml_parse_error *e)
{
	return req_eq(f[0], "helper_target") ? helper_target_row(r, f, line, n, e) : sleepable_row(r, f, line, n, after_attach, e);
}
