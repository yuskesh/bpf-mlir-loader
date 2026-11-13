#include "caps/recorded_internal.h"

#include <stdio.h>
#include <string.h>

int rc_format_version(const char *format)
{
	if (!format) return 0;
	for (int i = 1; i <= 20; i++) {
		char s[20];
		snprintf(s, sizeof(s), "ebpf-caps %d", i);
		if (!strcmp(format, s)) return i;
	}
	return 0;
}

int rc_added_loader_version(const struct bml_recorded *r, int version, char **err)
{
	const struct { const char *key, *value; int min; } keys[] = {
		{"hidden_data_vars", r->loader.hidden_data_vars, 13},
		{"typed_ksym", r->loader.typed_ksym, 14}, {"kconfig", r->loader.kconfig, 14},
		{"arena_cast", r->loader.arena_cast, 17}, {"arena_premmap", r->loader.arena_premmap, 17},
	};
	for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
		if (version < keys[i].min && keys[i].value && keys[i].value[0]) {
			*err = rc_fmts("caps: loader key \"%s\" is new in \"ebpf-caps %d\", but the format is \"%s\"", keys[i].key, keys[i].min, r->format);
			return -1;
		}
	return 0;
}

int rc_added_query_version(const struct bml_recorded *r, int version, char **err)
{
	const struct { const char *name; int min; } qs[] = {
		{BML_QUERY_ENUM_VALUES, 11}, {BML_QUERY_FIB_FLAGS, 12},
		{BML_QUERY_KSYM_VARS, 14}, {BML_QUERY_KCONFIG, 14}, {BML_QUERY_BTF_PRESENCE, 14},
		{BML_QUERY_FUNC_RET, 15}, {BML_QUERY_STRUCT_SIZE, 16},
	};
	for (size_t k = 0; k < sizeof(qs) / sizeof(qs[0]); k++)
		if (version < qs[k].min)
			for (size_t i = 0; i < r->n_q; i++)
				if (!strcmp(r->q[i].name, qs[k].name)) {
					*err = rc_fmts("caps: query \"%s\" is new in \"ebpf-caps %d\", but the format is \"%s\"", qs[k].name, qs[k].min, r->format);
					return -1;
				}
	return 0;
}
