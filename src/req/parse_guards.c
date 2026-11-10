
#include "req/parse_internal.h"

#include <stdlib.h>
#include <string.h>

int req_guard_number(struct field f, int64_t *out)
{
	if (!f.n || (f.n > 1 && f.p[0] == '0')) return 0;
	for (size_t i = 0; i < f.n; i++)
		if (f.p[i] < '0' || f.p[i] > '9') return 0;
	return !bml_go_atoi(f.p, f.n, out);
}

int req_parse_guard_list(struct field *f, size_t count, int n, const char *row,
	struct field line, struct bml_guard_list *out, struct bml_parse_error *e)
{
	if (!count)
		return req_perr(e, n, row, "fields", "%s line %d: guarded needs one or more guard numbers, got %q", SEC, (int64_t)n, Q(line));
	out->numbers = calloc(count, sizeof(*out->numbers));
	if (!out->numbers) return -2;
	for (size_t i = 0; i < count; i++) {
		int64_t g;
		if (!req_guard_number(f[i], &g))
			return req_perr(e, n, row, "value", "%s line %d: bad guard number %q in %q", SEC, (int64_t)n, Q(f[i]), Q(line));
		if (i && g <= out->numbers[i - 1])
			return req_perr(e, n, row, "guard_order", "%s line %d: guarded numbers must be strictly increasing, got %d after %d", SEC,
				(int64_t)n, g, out->numbers[i - 1]);
		out->numbers[out->count++] = g;
	}
	return 0;
}

int req_note_guarded_row(struct bml_requirements *r, int n, long ksym, long kfield)
{
	if (GROW(r->guarded_rows, r->n_guarded_rows, r->cap_guarded_rows)) return -2;
	r->guarded_rows[r->n_guarded_rows++] = (struct bml_guarded_row){n, ksym, kfield};
	return 0;
}

static int guard_target(struct field kind, struct field target)
{
	if (req_eq(kind, "ksym") || req_eq(kind, "type"))
		return req_valid_cname(target);
	if (!req_eq(kind, "field")) return 0;
	const char *dot = memchr(target.p, '.', target.n);
	return dot && req_valid_cname((struct field){target.p, (size_t)(dot - target.p)}) &&
		req_valid_kfield_path(dot + 1, target.n - (size_t)(dot + 1 - target.p));
}

int req_parse_guard(struct bml_requirements *r, struct field *f,
	struct field line, int n, struct bml_parse_error *e)
{
	int64_t g;
	if (!req_guard_number(f[1], &g))
		return req_perr(e, n, "guard", "value", "%s line %d: bad guard number %q", SEC, (int64_t)n, Q(f[1]));
	if ((uint64_t)g != r->n_guards)
		return req_perr(e, n, "guard", "guard_order", "%s line %d: guard rows are numbered 0, 1, … in row order — want %d, got %d", SEC,
			(int64_t)n, (int64_t)r->n_guards, g);
	if (!guard_target(f[2], f[3]))
		return req_perr(e, n, "guard", "value", "%s line %d: bad guard row %q (want guard <g> ksym <name> | type <struct> | field <struct>.<path>)", SEC,
			(int64_t)n, Q(line));
	if (r->n_guards) {
		const struct bml_guard *p = &r->guards[r->n_guards - 1];
		int c = req_field_cmp((struct field){p->kind.p, p->kind.len}, f[2]);
		if (c > 0 || (!c && req_field_cmp((struct field){p->target.p, p->target.len}, f[3]) >= 0)) {
			struct bml_str kind = {0}, target = {0};
			if (req_mkstr(&kind, f[2]) || req_mkstr(&target, f[3])) { free(kind.p); free(target.p); return -2; }
			int rc = req_perr(e, n, "guard", "guard_order", "%s line %d: guard rows must be strictly increasing by (kind, target), got %s %s after %s %s",
				SEC, (int64_t)n, kind.p, target.p, p->kind.p, p->target.p);
			free(kind.p); free(target.p); return rc;
		}
	}
	if (GROW(r->guards, r->n_guards, r->cap_guards)) return -2;
	struct bml_guard *p = &r->guards[r->n_guards++];
	return req_mkstr(&p->kind, f[2]) || req_mkstr(&p->target, f[3]) ? -2 : 0;
}

int req_check_guard_bindings(const struct bml_requirements *r, struct bml_parse_error *e)
{
	unsigned char *used = calloc(r->n_guards ? r->n_guards : 1, 1);
	if (!used) return -2;
	int rc = 0;
	for (size_t i = 0; i < r->n_guarded_rows; i++) {
		const struct bml_guarded_row *gr = &r->guarded_rows[i];
		int ks = gr->ksym >= 0;
		const struct bml_ksym_var *v = ks ? &r->ksym_vars[gr->ksym] : NULL;
		const struct bml_kfield *kf = ks ? NULL : &r->kfields[gr->kfield];
		const struct bml_guard_list *gs = ks ? &v->guards : &kf->guards;
		const char *row = ks ? "ksymvar" : "kfield";
		struct bml_buf b = {0};
		if (ks) bml_buf_addf(&b, "ksymvar %s", v->name.p);
		else bml_buf_addf(&b, "kfield %s %s.%s", kf->program.p, kf->strct.p, kf->field.p);
		char *what = bml_buf_take(&b);
		if (!what) { rc = -2; break; }
		for (size_t j = 0; j < gs->count; j++) {
			int64_t g = gs->numbers[j];
			if ((uint64_t)g >= r->n_guards) {
				rc = req_perr(e, 0, row, "guard_orphan", "%s: %s (line %d) is guarded by %d, which has no guard row", SEC,
					what, (int64_t)gr->line, g); break;
			}
			const struct bml_guard *gd = &r->guards[g];
			int ok = ks ? req_str_eq_lit(&gd->kind, "ksym") && !strcmp(gd->target.p, v->name.p) :
				req_str_eq_lit(&gd->kind, "type") && !strcmp(gd->target.p, kf->strct.p);
			if (!ks && req_str_eq_lit(&gd->kind, "field")) {
				ok = gd->target.len == kf->strct.len + 1 + kf->field.len &&
					!memcmp(gd->target.p, kf->strct.p, kf->strct.len) && gd->target.p[kf->strct.len] == '.' &&
					!memcmp(gd->target.p + kf->strct.len + 1, kf->field.p, kf->field.len);
			}
			if (!ok) {
				rc = req_perr(e, 0, row, "guard_target", "%s: %s (line %d) is guarded by %d (%s %s), which guards another target", SEC,
					what, (int64_t)gr->line, g, gd->kind.p, gd->target.p); break;
			}
			used[g] = 1;
		}
		free(what);
		if (rc) break;
	}
	if (!rc)
		for (size_t i = 0; i < r->n_guards; i++)
			if (!used[i]) {
				rc = req_perr(e, 0, "guard", "guard_unused", "%s: guard %d (%s %s) marks no row", SEC, (int64_t)i,
					r->guards[i].kind.p, r->guards[i].target.p); break;
			}
	free(used);
	return rc;
}
