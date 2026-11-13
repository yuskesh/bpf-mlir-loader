#include "req/parse_internal.h"

#include <stdint.h>
#include <string.h>

#include "util/mutation.h"


int req_probe_companion(struct bml_requirements *r, struct field *f, struct field line, int n, const char *row, struct bml_parse_error *e)
{
	struct bml_attach *a = r->n_attaches ? &r->attaches[r->n_attaches - 1] : NULL;
	int probe = a && (req_str_eq_lit(&a->attach_type, "kprobe") || req_str_eq_lit(&a->attach_type, "uprobe") ||
			  req_str_eq_lit(&a->attach_type, "kretprobe") || req_str_eq_lit(&a->attach_type, "uretprobe") ||
			  req_multi_str(&a->attach_type) || req_str_eq_lit(&a->attach_type, "usdt") || req_str_eq_lit(&a->attach_type, "ksyscall"));
	if (!a || !req_str_eq(&a->program, f[1]) || !probe || (req_eq(f[0], "binary") && !req_uprobe_family(&a->attach_type)) ||
	    (req_eq(f[0], "uprobearg") && !req_str_eq_lit(&a->attach_type, "uprobe") && !req_str_eq_lit(&a->attach_type, "uprobe_multi")) ||
	    (req_eq(f[0], "kprobearg") && !req_str_eq_lit(&a->attach_type, "kprobe") && !req_str_eq_lit(&a->attach_type, "kprobe_multi"))) {
		req_perr(e, n, row, "order", "%s line %d: %s row out of order %q", SEC, (int64_t)n, row, Q(line));
		return -1;
	}

	int v12before = a->n_mtargets == 0 && a->usdt_sem.len == 0 && a->n_usdt_args == 0 && a->n_sys_args == 0;
	int mt_complete = (!req_multi_str(&a->attach_type) || (int64_t)a->n_mtargets == a->multi_n) && a->n_mtarget_args == 0;
	int in_order = 0;
	if (req_eq(f[0], "arch"))
		in_order = a->n_ctxfields == 0 && a->n_kprobe_args == 0 && a->binary_sha256.len == 0 && a->n_uprobe_args == 0 && v12before;
	else if (req_eq(f[0], "ctxfield"))
		in_order = BML_MUT("parse.ctxfield_any_order") ||
			   (a->arch.len != 0 && a->n_kprobe_args == 0 && a->binary_sha256.len == 0 && a->n_uprobe_args == 0 && v12before);
	else if (req_eq(f[0], "binary"))
		in_order = a->arch.len != 0 && a->n_uprobe_args == 0 && v12before;
	else if (req_eq(f[0], "kprobearg"))
		in_order = a->arch.len != 0 && mt_complete;
	else
		in_order = a->binary_sha256.len != 0 && mt_complete;
	if (!in_order) {
		req_perr(e, n, row, "order", "%s line %d: %s row out of order %q", SEC, (int64_t)n, row, Q(line));
		return -1;
	}
	if (req_eq(f[0], "binary")) {
		if (a->binary_sha256.len != 0) {
			req_perr(e, n, row, "order", "%s line %d: bad binary row %q", SEC, (int64_t)n, Q(line));
			return -1;
		}
		if (!req_eq(f[2], "sha256") || f[3].n != 64) {
			req_perr(e, n, row, "value", "%s line %d: bad binary row %q", SEC, (int64_t)n, Q(line));
			return -1;
		}
		if (req_mkstr(&a->binary_sha256, f[3]))
			return -2;
	} else if (req_eq(f[0], "uprobearg")) {
		int64_t na;
		if (bml_go_atoi(f[2].p, f[2].n, &na) || na < 1 || (!req_valid_int_spelling(f[3]) && !req_eq(f[3], "strptr") && !req_eq(f[3], "ptr"))) {
			req_perr(e, n, row, "value", "%s line %d: bad uprobearg row %q", SEC, (int64_t)n, Q(line));
			return -1;
		}

		if (req_eq(f[3], "ptr") && r->version < 18 && !BML_MUT("parse.v18_rows_any_version")) {
			req_perr(e, n, row, "min_version", "%s line %d: uprobearg type ptr needs version 18", SEC, (int64_t)n);
			return -1;
		}
		if (a->n_uprobe_args > 0 && na <= a->uprobe_args[a->n_uprobe_args - 1].n) {
			req_perr(e, n, row, "order", "%s line %d: %s row out of order %q", SEC, (int64_t)n, row, Q(line));
			return -1;
		}
		if (GROW(a->uprobe_args, a->n_uprobe_args, a->cap_uprobe_args))
			return -2;
		a->uprobe_args[a->n_uprobe_args].n = na;
		if (req_mkstr(&a->uprobe_args[a->n_uprobe_args].type, f[3]))
			return -2;
		a->n_uprobe_args++;
	} else if (req_eq(f[0], "arch")) {
		if (a->arch.len != 0) {
			req_perr(e, n, row, "order", "%s line %d: bad arch row %q", SEC, (int64_t)n, Q(line));
			return -1;
		}
		if (f[2].n == 0) {
			req_perr(e, n, row, "value", "%s line %d: bad arch row %q", SEC, (int64_t)n, Q(line));
			return -1;
		}
		if (req_mkstr(&a->arch, f[2]))
			return -2;
	} else if (req_eq(f[0], "ctxfield")) {
		int64_t off, size;
		int e1 = bml_go_atoi(f[4].p, f[4].n, &off);
		int e2 = bml_go_atoi(f[5].p, f[5].n, &size);
		if (e1 || e2 || off < 0 || size <= 0 || f[2].n == 0 || f[3].n == 0) {
			req_perr(e, n, row, "value", "%s line %d: bad ctxfield row %q", SEC, (int64_t)n, Q(line));
			return -1;
		}
		if (GROW(a->ctxfields, a->n_ctxfields, a->cap_ctxfields))
			return -2;
		struct bml_ctxfield *c = &a->ctxfields[a->n_ctxfields];
		c->offset = off;
		c->size = size;
		if (req_mkstr(&c->strct, f[2]) || req_mkstr(&c->field, f[3]))
			return -2;
		a->n_ctxfields++;
	} else {
		int64_t na;

		if (bml_go_atoi(f[2].p, f[2].n, &na) || na < 1 || !(req_valid_int_spelling(f[3]) || req_eq(f[3], "ptr"))) {
			req_perr(e, n, row, "value", "%s line %d: bad kprobearg row %q", SEC, (int64_t)n, Q(line));
			return -1;
		}
		if (a->n_kprobe_args > 0 && na <= a->kprobe_args[a->n_kprobe_args - 1].n) {
			req_perr(e, n, row, "order", "%s line %d: %s row out of order %q", SEC, (int64_t)n, row, Q(line));
			return -1;
		}
		if (GROW(a->kprobe_args, a->n_kprobe_args, a->cap_kprobe_args))
			return -2;
		a->kprobe_args[a->n_kprobe_args].n = na;
		if (req_mkstr(&a->kprobe_args[a->n_kprobe_args].type, f[3]))
			return -2;
		a->n_kprobe_args++;
	}
	return 0;
}
