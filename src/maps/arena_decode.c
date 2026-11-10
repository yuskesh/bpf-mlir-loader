

#include "maps/internal.h"

#include <stdlib.h>
#include <string.h>

int md_json_is_arena(const struct bml_json *j)
{
	const struct bml_json *kind = NULL;
	if (!j || j->type != BML_JSON_OBJECT) return 0;
	for (size_t i = 0; i < j->n; i++) {
		const struct bml_json_member *m = &j->members[i];

		if ((m->key_len == 4 && !memcmp(m->key, "kind", 4)) ||
		    (m->key_len == 6 && !memcmp(m->key, "\xe2\x84\xaaind", 6))) kind = m->value;
	}
	return kind && kind->type == BML_JSON_STRING && kind->len == 5 && !memcmp(kind->str, "arena", 5);
}

static int validate_one(struct bml_json *j, const struct bml_json_desc *base,
	const struct bml_json_desc *arena, char **err, enum bml_json_rule *rule)
{
	if (!md_json_is_arena(j)) return bml_json_validate(j, base, err, rule);
	for (size_t i = 0; i < j->n; i++) {
		const struct bml_json_member *m = &j->members[i];
		if (m->key_len != 9) continue;
		char key[10];
		for (size_t k = 0; k < 9; k++) key[k] = m->key[k] >= 'A' && m->key[k] <= 'Z' ? m->key[k] + ('a' - 'A') : m->key[k];
		key[9] = 0;
		if (!strcmp(key, "map_extra") && memcmp(m->key, key, 9)) {
			if (rule) *rule = BML_JR_KEY_CASE;
			*err = md_xstrdup("key differs only in case from \"map_extra\""); return -1;
		}
	}
	return bml_json_validate(j, arena, err, rule);
}

int md_validate_map_json(struct bml_json *j, const struct bml_json_desc *top,
	const struct bml_json_desc *base, const struct bml_json_desc *arena, int one,
	char **err, enum bml_json_rule *rule)
{
	if (one) return validate_one(j, base, arena, err, rule);
	if (j->type != BML_JSON_OBJECT) return bml_json_validate(j, top, err, rule);
	struct bml_json_field fields[8];
	if (!top || top->n_fields > 8) { *err = md_xstrdup("unsupported map declaration descriptor"); return -1; }
	memcpy(fields, top->fields, top->n_fields * sizeof(*fields));
	const struct bml_json_desc any = {.kind = BML_JD_SCALAR};
	const struct bml_json_desc array = {.kind = BML_JD_ARRAY, .child = &any};
	for (size_t i = 0; i < top->n_fields; i++) if (!strcmp(fields[i].name, "maps")) fields[i].desc = &array;
	struct bml_json_desc selected = *top; selected.fields = fields;
	for (size_t i = 0; i < j->n; i++) {
		struct bml_json mini = *j; mini.members = &j->members[i]; mini.n = 1;
		if (bml_json_validate(&mini, &selected, err, rule)) return -1;
		struct bml_json_member *m = &j->members[i];
		if (strcmp(m->key, "maps") || m->value->type != BML_JSON_ARRAY) continue;
		for (size_t k = 0; k < m->value->n; k++)
			if (validate_one(m->value->items[k], base, arena, err, rule)) return -1;
	}
	return 0;
}
