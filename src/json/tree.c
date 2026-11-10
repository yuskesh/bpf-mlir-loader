
#include "json/internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *bml_json_rule_name(enum bml_json_rule r)
{
	switch (r) {
	case BML_JR_NONE: return "";
	case BML_JR_SYNTAX: return "syntax";
	case BML_JR_DUPLICATE_KEY: return "duplicate_key";
	case BML_JR_KEY_CASE: return "key_case";
	case BML_JR_INVALID_UTF8: return "invalid_utf8";
	case BML_JR_UNPAIRED_SURROGATE: return "unpaired_surrogate";
	case BML_JR_TRAILING_DATA: return "trailing_data";
	case BML_JR_NESTING_TOO_DEEP: return "nesting_too_deep";
	case BML_JR_NUL: return "nul";
	case BML_JR_UNKNOWN_KEY: return "unknown_key";
	case BML_JR_TYPE: return "type";
	case BML_JR_OOM: return "out_of_memory";
	case BML_JR_CAPS_KEY_NEWER_FORMAT: return "caps_key_newer_format";
	case BML_JR_CAPS_FORMAT_UNKNOWN: return "caps_format_unknown";
	}
	return "";
}

void bml_json_free(struct bml_json *j)
{
	if (!j)
		return;
	free(j->str);
	for (size_t i = 0; j->type == BML_JSON_ARRAY && i < j->n; i++)
		bml_json_free(j->items[i]);
	free(j->items);
	for (size_t i = 0; j->type == BML_JSON_OBJECT && i < j->n; i++) {
		free(j->members[i].key);
		bml_json_free(j->members[i].value);
	}
	free(j->members);
	free(j);
}

const struct bml_json *bml_json_get(const struct bml_json *obj, const char *key)
{
	if (!obj || obj->type != BML_JSON_OBJECT)
		return NULL;
	size_t n = strlen(key);
	const struct bml_json *v = NULL;
	for (size_t i = 0; i < obj->n; i++)
		if (obj->members[i].key_len == n && memcmp(obj->members[i].key, key, n) == 0)
			v = obj->members[i].value;
	return v;
}

int bml_json_uint64(const struct bml_json *j, uint64_t *out)
{
	if (!j || j->type != BML_JSON_NUMBER)
		return -1;
	return bml_go_parse_uint(j->str, j->len, 64, out);
}

int bml_json_int64(const struct bml_json *j, int64_t *out)
{
	if (!j || j->type != BML_JSON_NUMBER || (j->len > 0 && j->str[0] == '+'))
		return -1;
	return bml_go_parse_int(j->str, j->len, 64, out);
}
