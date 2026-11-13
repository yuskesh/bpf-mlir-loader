#include "req/parse_internal.h"

#include <string.h>

static int extern_order(const struct bml_requirements *r, int n, int ksym, struct bml_parse_error *e)
{
	const char *late = r->n_guards ? "guard" : ksym && r->n_kconfigs ? "kconfig" : NULL;
	return late ? req_perr(e, n, ksym ? "ksymvar" : "kconfig", "order", "%s line %d: %s rows come before %s rows", SEC,
		(int64_t)n, ksym ? "ksymvar" : "kconfig", late) : 0;
}

static int kconfig_name(struct field f)
{
	if (f.n <= 7 || memcmp(f.p, "CONFIG_", 7)) return 0;
	for (size_t i = 7; i < f.n; i++) {
		unsigned char c = (unsigned char)f.p[i];
		if (!(c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) return 0;
	}
	return 1;
}

int req_parse_extern(struct bml_requirements *r, struct field *f, struct field *guarded,
	size_t ng, int has_guarded, struct field line, int n, struct bml_parse_error *e)
{
	int ks = req_eq(f[0], "ksymvar");
	const char *row = ks ? "ksymvar" : "kconfig";
	if (extern_order(r, n, ks, e)) return -1;
	if (ks) {
		int slot = req_valid_int_spelling(f[3]) || (f[3].n > 4 && !memcmp(f[3].p, "ptr:", 4) &&
			req_valid_cname((struct field){f[3].p + 4, f[3].n - 4}));
		if (!req_valid_cname(f[1]) || !req_eq(f[2], "percpu") || !slot || (!req_eq(f[4], "weak") && !req_eq(f[4], "strong")))
			return req_perr(e, n, row, "value", "%s line %d: bad ksymvar row %q (want ksymvar <name> percpu <i8…u64|ptr:<struct>> <weak|strong>)", SEC,
				(int64_t)n, Q(line));
	} else {
		int type = req_eq(f[2], "bool") || req_eq(f[2], "tristate") || req_eq(f[2], "char") ||
			(req_valid_int_spelling(f[2]) && !req_eq(f[2], "i8") && !req_eq(f[2], "u8"));
		if (!kconfig_name(f[1]) || !type || (!req_eq(f[3], "weak") && !req_eq(f[3], "strong")))
			return req_perr(e, n, row, "value", "%s line %d: bad kconfig row %q (want kconfig CONFIG_<name> <bool|tristate|char|i16|u16|i32|u32|i64|u64> <weak|strong>)",
				SEC, (int64_t)n, Q(line));
	}
	const struct bml_str *prev = ks ? (r->n_ksym_vars ? &r->ksym_vars[r->n_ksym_vars - 1].name : NULL) :
		(r->n_kconfigs ? &r->kconfigs[r->n_kconfigs - 1].name : NULL);
	if (prev && req_field_cmp((struct field){prev->p, prev->len}, f[1]) >= 0)
		return req_perr(e, n, row, "order", "%s line %d: %s rows must be in strictly increasing name order, got %q after %q", SEC,
			(int64_t)n, row, Q(f[1]), prev->p, prev->len);
	if (!ks) {
		if (GROW(r->kconfigs, r->n_kconfigs, r->cap_kconfigs)) return -2;
		struct bml_kconfig *v = &r->kconfigs[r->n_kconfigs++];
		return req_mkstr(&v->name, f[1]) || req_mkstr(&v->type, f[2]) || req_mkstr(&v->bind, f[3]) ? -2 : 0;
	}
	if (GROW(r->ksym_vars, r->n_ksym_vars, r->cap_ksym_vars)) return -2;
	long idx = (long)r->n_ksym_vars;
	struct bml_ksym_var *v = &r->ksym_vars[r->n_ksym_vars++];
	if (req_mkstr(&v->name, f[1]) || req_mkstr(&v->cls, f[2]) || req_mkstr(&v->slot, f[3]) || req_mkstr(&v->bind, f[4])) return -2;
	if (has_guarded) {
		int rc = req_parse_guard_list(guarded, ng, n, row, line, &v->guards, e);
		if (rc) return rc;
		if (req_eq(f[4], "strong"))
			return req_perr(e, n, row, "guard_strong", "%s line %d: strong ksymvar %s is guarded — a strong extern must resolve whatever its guards say",
				SEC, (int64_t)n, v->name.p);
	} else if (req_eq(f[4], "weak")) {
		return req_perr(e, n, row, "guard_missing", "%s line %d: weak ksymvar %s has no guarded list — the compiler reads a weak VAR only under its own ksym guard",
			SEC, (int64_t)n, v->name.p);
	}
	return req_note_guarded_row(r, n, idx, -1);
}
