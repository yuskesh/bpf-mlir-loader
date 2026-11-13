#include "req/parse_internal.h"

#include <string.h>
#include "util/mutation.h"

static int data_section(struct field f)
{
	if (f.n <= 6 || memcmp(f.p, ".data.", 6))
		return 0;
	for (size_t i = 6; i < f.n; i++) {
		unsigned char c = (unsigned char)f.p[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '_'))
			return 0;
	}
	return 1;
}

int req_parse_loader_row(struct bml_requirements *r, struct field *f,
	struct field line, int n, struct bml_parse_error *e)
{
	int arena = req_eq(f[0], "arena");
	struct bml_str **arr = arena ? &r->arenas : &r->data_kptrs;
	size_t *count = arena ? &r->n_arenas : &r->n_data_kptrs;
	size_t *cap = arena ? &r->cap_arenas : &r->cap_data_kptrs;
	const char *row = arena ? "arena" : "datakptr";
	if (arena) {
		const struct bml_map *m = NULL;
		for (size_t i = 0; i < r->n_maps; i++)
			if (req_str_eq(&r->maps[i].symbol, f[1]))
				m = &r->maps[i];
		if (!m)
			return req_perr(e, n, row, "order", "%s line %d: arena row for %q, which is not an earlier map row", SEC, (int64_t)n, Q(f[1]));
		if (!req_str_eq_lit(&m->map_type, "arena"))
			return req_perr(e, n, row, "value", "%s line %d: arena row for %q, which is a %s map, not an arena map (%q)", SEC,
				(int64_t)n, Q(f[1]), m->map_type.p, Q(line));
	} else if (!data_section(f[1])) {
		return req_perr(e, n, row, "value", "%s line %d: bad datakptr row %q (want .data.<name>, a name of letters, digits and '_')", SEC,
			(int64_t)n, Q(line));
	}
	if (*count) {
		struct bml_str *prev = &(*arr)[*count - 1];
		if (req_field_cmp((struct field){prev->p, prev->len}, f[1]) >= 0)
			return req_perr(e, n, row, "order", "%s line %d: %s rows must be in strictly increasing %s order, got %q after %q", SEC,
				(int64_t)n, row, arena ? "map" : "section", Q(f[1]), prev->p, prev->len);
	}
	if (req_grow_array((void **)arr, cap, sizeof(**arr), *count + 1))
		return -2;

	struct bml_str *s = &(*arr)[(*count)++];
	return req_mkstr(s, f[1]) ? -2 : 0;
}

int req_check_arena_rows(const struct bml_requirements *r, struct bml_parse_error *e)
{
	if (r->version < 29 || BML_MUT("parse.arena_no_reverse"))
		return 0;
	for (size_t i = 0; i < r->n_maps; i++) {
		const struct bml_map *m = &r->maps[i];
		if (!req_str_eq_lit(&m->map_type, "arena"))
			continue;
		int found = 0;
		for (size_t j = 0; j < r->n_arenas; j++)
			if (m->symbol.len == r->arenas[j].len && !memcmp(m->symbol.p, r->arenas[j].p, m->symbol.len))
				found = 1;
		if (!found)
			return req_perr(e, 0, "arena", "document", "%s: map %q is an arena map but has no arena row (format 29 and later)", SEC,
				m->symbol.p, m->symbol.len);
	}
	return 0;
}
