#include "req/parse_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "req/kfunc_profile.h"
#include "util/mutation.h"

const struct bml_row_kind bml_row_kinds[] = {
	{"schema", 3, 2},   {"program", 4, 1},  {"helper", 4, 1},    {"map", 8, 1},
	{"kfield", 5, 3},   {"attach", 4, 4},   {"arg", 4, 4},       {"retsig", 4, 4},
	{"arch", 3, 4},     {"ctxfield", 6, 4}, {"kprobearg", 4, 4}, {"binary", 4, 4},
	{"uprobearg", 4, 4}, {"btf", 2, 5},     {"argtag", 4, 6},    {"tailslot", 4, 7},
	{"farg", 4, 8},
	{"ctxaccess", 7, 9},
	{"tpfield", 6, 11},  {"extret", 4, 11}, {"extarg", 4, 11}, {"structop", 4, 11},
	{"mtarget", 4, 12},  {"usdtsem", 3, 12}, {"usdtarg", 4, 12}, {"innermap", 8, 12},
	{"kfunc", 4, 13},    {"sysarg", 4, 13},  {"mtargetarg", 5, 13},
	{"tpbuf", 3, 14},
	{"enumval", 5, 20}, {"fibflags", 4, 21}, {"datakptr", 2, 23},
	{"ksymvar", 5, 24}, {"kconfig", 4, 24}, {"guard", 4, 24},
	{"coreenum", 4, 26}, {"funcret", 3, 27}, {"kstructsize", 3, 28}, {"arena", 2, 29},
	{"helper_target", 8, 31}, {"sleepable", 2, 32},
};
const size_t bml_n_row_kinds = sizeof(bml_row_kinds) / sizeof(bml_row_kinds[0]);

static const char *const btf_features[] = {"int",  "ptr",        "const",       "array",    "struct", "func",
					   "func_proto", "func_global", "decl_tag", "var",    "datasec", "type_tag", "enum", "enum64"};


int req_btf_feature_min_version(struct field f)
{
	return req_eq(f, "type_tag") ? 13 : (req_eq(f, "enum") || req_eq(f, "enum64")) ? 22 : 5;
}

int bml_known_btf_feature(const char *s, size_t n)
{
	struct field f = {s, n};
	for (size_t i = 0; i < sizeof(btf_features) / sizeof(btf_features[0]); i++)
		if (req_eq(f, btf_features[i]))
			return 1;
	return 0;
}

static void freestr(struct bml_str *s)
{
	free(s->p);
	s->p = NULL;
	s->len = 0;
}

void bml_requirements_free(struct bml_requirements *r)
{
	if (!r)
		return;
	freestr(&r->schema_sha256);
	for (size_t i = 0; i < r->n_programs; i++) {
		struct bml_program *p = &r->programs[i];
		freestr(&p->symbol);
		freestr(&p->prog_type);
		for (size_t j = 0; j < p->n_helpers; j++)
			freestr(&p->helpers[j].name);
		free(p->helpers);
	}
	free(r->programs);
	for (size_t i = 0; i < r->n_helper_targets; i++) {
		struct bml_helper_target *h = &r->helper_targets[i];
		freestr(&h->program); freestr(&h->helper); freestr(&h->attach_type); freestr(&h->target); freestr(&h->arg_type);
	}
	free(r->helper_targets);
	for (size_t i = 0; i < r->n_maps; i++) {
		freestr(&r->maps[i].symbol);
		freestr(&r->maps[i].map_type);
		freestr(&r->maps[i].key);
		freestr(&r->maps[i].value);
	}
	free(r->maps);
	for (size_t i = 0; i < r->n_kfields; i++) {
		freestr(&r->kfields[i].program);
		freestr(&r->kfields[i].strct);
		freestr(&r->kfields[i].field);
		freestr(&r->kfields[i].type);
		free(r->kfields[i].guards.numbers);
	}
	free(r->kfields);
	for (size_t i = 0; i < r->n_attaches; i++) {
		struct bml_attach *a = &r->attaches[i];
		freestr(&a->program);
		freestr(&a->attach_type);
		freestr(&a->target);
		for (size_t j = 0; j < a->n_args; j++)
			freestr(&a->args[j]);
		for (size_t j = 0; j < a->n_fargs; j++)
			freestr(&a->fargs[j]);
		free(a->fargs);
		free(a->args);
		freestr(&a->ret_type);
		freestr(&a->func_ret);
		freestr(&a->arch);
		for (size_t j = 0; j < a->n_ctxfields; j++) {
			freestr(&a->ctxfields[j].strct);
			freestr(&a->ctxfields[j].field);
		}
		free(a->ctxfields);
		for (size_t j = 0; j < a->n_kprobe_args; j++)
			freestr(&a->kprobe_args[j].type);
		free(a->kprobe_args);
		freestr(&a->binary_sha256);
		for (size_t j = 0; j < a->n_uprobe_args; j++)
			freestr(&a->uprobe_args[j].type);
		free(a->uprobe_args);
		freestr(&a->tkind);
		freestr(&a->tval);
		for (size_t j = 0; j < a->n_tpfields; j++) {
			freestr(&a->tpfields[j].field);
			freestr(&a->tpfields[j].sign);
		}
		free(a->tpfields);
		freestr(&a->ext_ret);
		for (size_t j = 0; j < a->n_ext_args; j++)
			freestr(&a->ext_args[j]);
		free(a->ext_args);
		freestr(&a->sop_struct);
		freestr(&a->sop_member);
		for (size_t j = 0; j < a->n_mtargets; j++)
			freestr(&a->mtargets[j]);
		free(a->mtargets);
		freestr(&a->usdt_sem);
		for (size_t j = 0; j < a->n_usdt_args; j++)
			freestr(&a->usdt_args[j].type);
		free(a->usdt_args);
		for (size_t j = 0; j < a->n_sys_args; j++)
			freestr(&a->sys_args[j].type);
		free(a->sys_args);
		for (size_t j = 0; j < a->n_mtarget_args; j++)
			freestr(&a->mtarget_args[j].type);
		free(a->mtarget_args);
		freestr(&a->tpbuf_type);
	}
	bml_req_kfunc_profiles_free(r);
	free(r->attaches);
	for (size_t i = 0; i < r->n_kfuncs; i++) {
		struct bml_kfunc *k = &r->kfuncs[i];
		freestr(&k->program);
		freestr(&k->name);
		freestr(&k->ret);
		for (size_t j = 0; j < k->n_args; j++)
			freestr(&k->args[j]);
		free(k->args);
	}
	free(r->kfuncs);
	for (size_t i = 0; i < r->n_innermaps; i++) {
		struct bml_innermap *m = &r->innermaps[i];
		freestr(&m->outer);
		freestr(&m->map_type);
		freestr(&m->key);
		freestr(&m->value);
	}
	free(r->innermaps);
	for (size_t i = 0; i < r->n_ctxaccesses; i++) {
		struct bml_ctxaccess *c = &r->ctxaccesses[i];
		freestr(&c->program);
		freestr(&c->attach_type);
		freestr(&c->strct);
		freestr(&c->field);
		freestr(&c->mode);
	}
	free(r->ctxaccesses);
	for (size_t i = 0; i < r->n_btf_features; i++)
		freestr(&r->btf_features[i]);
	free(r->btf_features);
	for (size_t i = 0; i < r->n_argtags; i++) {
		freestr(&r->argtags[i].program);
		freestr(&r->argtags[i].tag);
		freestr(&r->argtags[i].cls);
	}
	free(r->argtags);
	for (size_t i = 0; i < r->n_tailslots; i++) {
		freestr(&r->tailslots[i].map);
		freestr(&r->tailslots[i].program);
	}
	free(r->tailslots);
	for (size_t i = 0; i < r->n_arenas; i++)
		freestr(&r->arenas[i]);
	free(r->arenas);
	for (size_t i = 0; i < r->n_data_kptrs; i++)
		freestr(&r->data_kptrs[i]);
	free(r->data_kptrs);
	for (size_t i = 0; i < r->n_fib_flags; i++) {
		freestr(&r->fib_flags[i].program);
		freestr(&r->fib_flags[i].name);
	}
	free(r->fib_flags);
	for (size_t i = 0; i < r->n_enum_values; i++) {
		freestr(&r->enum_values[i].program);
		freestr(&r->enum_values[i].enumeration);
		freestr(&r->enum_values[i].name);
	}
	free(r->enum_values);
	for (size_t i = 0; i < r->n_core_enums; i++) {
		freestr(&r->core_enums[i].program);
		freestr(&r->core_enums[i].enumeration);
		freestr(&r->core_enums[i].name);
	}
	free(r->core_enums);
	for (size_t i = 0; i < r->n_struct_sizes; i++)
		freestr(&r->struct_sizes[i].strct);
	free(r->struct_sizes);
	for (size_t i = 0; i < r->n_ksym_vars; i++) {
		struct bml_ksym_var *v = &r->ksym_vars[i];
		freestr(&v->name); freestr(&v->cls); freestr(&v->slot); freestr(&v->bind);
		free(v->guards.numbers);
	}
	free(r->ksym_vars);
	for (size_t i = 0; i < r->n_kconfigs; i++) {
		freestr(&r->kconfigs[i].name); freestr(&r->kconfigs[i].type); freestr(&r->kconfigs[i].bind);
	}
	free(r->kconfigs);
	for (size_t i = 0; i < r->n_guards; i++) {
		freestr(&r->guards[i].kind); freestr(&r->guards[i].target);
	}
	free(r->guards);
	free(r->guarded_rows);
	bml_map_fields_free(&r->map_fields);
	free(r);
}

void bml_parse_error_free(struct bml_parse_error *e)
{
	free(e->msg);
	e->msg = NULL;
}
