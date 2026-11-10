
#include "req/check_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "req/parse_internal.h"
#include "req/uprobe.h"
#include "util/gostr.h"
#include "util/mutation.h"



static int is_ptr_arg(const struct bml_str *t)
{
	if (BML_MUT("check.nullable_all_args"))
		return 1;
	struct field f = {t->p, t->len};
	return !req_eq(f, "-") && !req_valid_int_spelling(f);
}

int ck_check_nullable(struct ck *c, const struct bml_attach *a)
{
	size_t nptr = 0;
	for (size_t i = 0; i < a->n_args; i++)
		nptr += is_ptr_arg(&a->args[i]);
	if (nptr == 0)
		return 0;
	const char *P = a->program.p, *T = a->target.p;
	const char *kind = NULL;
	char *msg = NULL;
	if (!HAS(c, nullable_args, BML_QUERY_NULLABLE_ARGS)) {
		kind = "arg_nullable_mark_unknown";
		msg = ck_dupn("no nullable-argument probe");
	} else {
		int marks = 0;
		int st = c->caps->nullable_args(c->caps->ctx, &marks, &msg);
		if (st == BML_Q_UNKNOWN)
			kind = "arg_nullable_mark_unknown";
		else if (st != BML_Q_OK)
			return ck_fail(c, msg);
		else if (!marks) {
			free(msg);
			kind = "arg_nullable";
			msg = ck_dupn("probe: an unchecked read of a NULL-able argument is accepted");
		} else {
			free(msg);
			msg = NULL;
			kind = "arg_nullable_unknown";
		}
	}
	int single = BML_MUT("check.nullable_single_unmet") && strcmp(kind, "arg_nullable_unknown") != 0;
	for (size_t i = 0; i < a->n_args; i++) {
		if (!is_ptr_arg(&a->args[i]))
			continue;
		ck_add(c, kind, P, T, single ? 0 : (int64_t)i, msg ? ck_dupn(msg) : NULL);
		if (single)
			break;
	}
	free(msg);
	return 0;
}


int ck_check_arch_ctx(struct ck *c, const struct bml_attach *a, char **target_arch)
{
	*target_arch = ck_dupn("");
	const char *P = a->program.p;
	if (a->arch.len == 0)
		return ck_fail(c, ck_fmtd("program %s: %s attach row without an arch row", P, a->attach_type.p));
	if (!HAS(c, arch, BML_QUERY_ARCH)) {
		ck_add(c, "arch_unknown", P, a->arch.p, 0, ck_dupn("no arch probe"));
	} else {
		char *arch = NULL, *msg = NULL;
		int st = c->caps->arch(c->caps->ctx, &arch, &msg);
		if (st == BML_Q_UNKNOWN) {
			ck_add(c, "arch_unknown", P, a->arch.p, 0, msg);
		} else if (st != BML_Q_OK) {
			return ck_fail(c, msg);
		} else {
			free(*target_arch);
			*target_arch = arch;
			if (strcmp(arch, a->arch.p) != 0)
				ck_add(c, "arch", P, a->arch.p, 0,
				    ck_fmtd("the object reads pt_regs with the calling convention of %s, but the target is %s", a->arch.p, arch));
		}
	}
	for (size_t i = 0; i < a->n_ctxfields; i++) {
		const struct bml_ctxfield *cf = &a->ctxfields[i];
		char *name = ck_fmtd("%s.%s (offset %lld, %lld bytes)", cf->strct.p, cf->field.p, (long long)cf->offset, (long long)cf->size);
		if (!name)
			return ck_fail(c, ck_dupn("out of memory"));
		if (!HAS(c, struct_field, BML_QUERY_STRUCT_FIELD)) {
			ck_add(c, "ctxfield_unknown", P, name, 0, ck_dupn("no BTF probe"));
			free(name);
			continue;
		}
		struct bml_strs d = {0};
		char *msg = NULL;
		int st = c->caps->struct_field(c->caps->ctx, cf->strct.p, cf->field.p, cf->offset, cf->size, &d, &msg);
		if (st == BML_Q_UNKNOWN) {
			ck_add(c, "ctxfield_unknown", P, name, 0, msg);
			free(name);
			continue;
		}
		if (st != BML_Q_OK) {
			free(name);
			return ck_fail(c, msg);
		}
		ck_add_diffs(c, "ctxfield", P, name, &d);
		free(name);
	}
	return 0;
}

int ck_check_kprobe_target(struct ck *c, const struct bml_attach *a, const char *target_arch, int ask_alias)
{
	const char *P = a->program.p, *T = a->target.p;
	if (!HAS(c, kernel_symbol, BML_QUERY_KERNEL_SYM)) {
		ck_add(c, "attach_symbol_unknown", P, T, 0, ck_dupn("no kallsyms probe"));
	} else {
		int found = 0;
		char *msg = NULL;
		int st = c->caps->kernel_symbol(c->caps->ctx, T, &found, &msg);
		if (st == BML_Q_UNKNOWN) {
			ck_add(c, "attach_symbol_unknown", P, T, 0, msg);
		} else if (st != BML_Q_OK) {
			return ck_fail(c, msg);
		} else {
			if (!found)
				ck_add(c, "attach", P, T, 0, ck_fmtd("kprobe target %s is not a kernel symbol on the target (kallsyms)", T));
			const struct bml_loader_decl *d = ck_loader_of(c);
			const char *alias = bml_kv_get(d->kprobe_alias_prefix, d->n_kprobe_alias_prefix, target_arch);
			if (!ask_alias) {

			} else if (!alias) {
				struct bml_buf b = {0};
				bml_buf_adds(&b, "no fallback prefix known for the target arch ");
				bml_buf_add_goquote(&b, target_arch, strlen(target_arch));
				ck_add(c, "attach_alias_unknown", P, T, 0, bml_buf_take(&b));
			} else if (alias[0] == 0) {

			} else {
				char *full = ck_fmtd("%s%s", alias, T);
				int afound = 0;
				char *amsg = NULL;
				int ast = c->caps->kernel_symbol(c->caps->ctx, full, &afound, &amsg);
				free(full);
				if (ast == BML_Q_UNKNOWN) {
					ck_add(c, "attach_alias_unknown", P, T, 0, amsg);
				} else if (ast != BML_Q_OK) {
					return ck_fail(c, amsg);
				} else if (afound && !BML_MUT("check.alias_found_ignored")) {
					const char *label = strcmp(d->name, bml_loader_cilium022.name) != 0 ? d->name : "cilium/ebpf link.Kprobe";
					ck_add(c, "attach_alias", P, T, 0,
					    ck_fmtd("the target also has %s%s; the loader (%s) retries with that syscall-wrapper name when attaching to %s fails, and would read another calling convention — not loading without an exact attach",
						 alias, T, label, T));
				}
			}
		}
	}
	for (size_t i = 0; i < a->n_kprobe_args; i++) {
		const struct bml_intarg *k = &a->kprobe_args[i];
		char *name = ck_fmtd("%lld of %s (%s)", (long long)k->n, T, k->type.p);
		if (!name)
			return ck_fail(c, ck_dupn("out of memory"));
		if (!HAS(c, func_param, BML_QUERY_FUNC_PARAM)) {
			ck_add(c, "kprobearg_unknown", P, name, 0, ck_dupn("no BTF probe"));
			free(name);
			continue;
		}
		struct bml_strs d = {0};
		char *msg = NULL;
		int st = c->caps->func_param(c->caps->ctx, T, k->n, k->type.p, &d, &msg);
		if (st == BML_Q_UNKNOWN) {
			ck_add(c, "kprobearg_unknown", P, name, 0, msg);
			free(name);
			continue;
		}
		if (st != BML_Q_OK) {
			free(name);
			return ck_fail(c, msg);
		}
		ck_add_diffs(c, "kprobearg", P, name, &d);
		free(name);
	}
	return 0;
}



static int uprobe_abi(const char *target, const struct bml_dwarf_sub *sp, char **detail)
{
	static const int64_t sysv[] = {0x01, 0x02, 0x0c, 0x1d, 0x2c, 0x04, 0x19, 0x1a, 0x21, 0x2a, 0x2b};
	*detail = NULL;
	if (sp->cc >= 0 && sp->cc != 1) {
		*detail = ck_fmtd("%s has DW_AT_calling_convention %lld (not DW_CC_normal) — uprobe.arg reads the SysV argument registers", target,
				  (long long)sp->cc);
		return 1;
	}
	if (BML_MUT("dwarf.lang_always_c"))
		return 0;
	for (size_t i = 0; i < sizeof sysv / sizeof sysv[0]; i++)
		if (sp->lang == sysv[i])
			return 0;
	struct bml_buf prod = {0};
	if (sp->producer && sp->producer[0]) {
		bml_buf_adds(&prod, " (producer ");
		bml_buf_add_goquote(&prod, sp->producer, strlen(sp->producer));
		bml_buf_adds(&prod, ")");
	}
	char *pr = bml_buf_take(&prod);
	const char *p = pr ? pr : "";
	int v = 2;
	if (sp->lang == 0x16) {
		*detail = ck_fmtd("%s is a Go function%s — Go's ABIInternal passes arguments in registers that uprobe.arg (SysV) does not read; target a cgo //export C entry instead",
				  target, p);
		v = 1;
	} else if (sp->lang < 0)
		*detail = ck_fmtd("the compilation unit of %s has no DW_AT_language%s — the calling convention cannot be told", target, p);
	else
		*detail = ck_fmtd("the compilation unit of %s has DW_AT_language 0x%llx%s, which is not C or C++ — the calling convention cannot be told", target,
				  (unsigned long long)sp->lang, p);
	free(pr);
	return v;
}


static int uretprobe_abi(const char *target, const struct bml_dwarf_sub *sp, char **detail)
{
	char *ud = NULL;
	int v = uprobe_abi(target, sp, &ud);
	free(ud);
	*detail = NULL;
	if (v == 0)
		return 0;
	struct bml_buf prod = {0};
	if (sp->producer && sp->producer[0]) {
		bml_buf_adds(&prod, " (producer ");
		bml_buf_add_goquote(&prod, sp->producer, strlen(sp->producer));
		bml_buf_adds(&prod, ")");
	}
	char *pr = bml_buf_take(&prod);
	const char *p = pr ? pr : "";
	if (sp->cc >= 0 && sp->cc != 1)
		*detail = ck_fmtd("%s has DW_AT_calling_convention %lld (not DW_CC_normal) — probe.retval reads the SysV return value register", target,
				  (long long)sp->cc);
	else if (sp->lang == 0x16)
		*detail = ck_fmtd("%s is a Go function%s — Go's ABIInternal returns results in RAX, RBX, … (probe.retval reads the SysV return value register only); target a cgo //export C entry instead",
				  target, p);
	else if (sp->lang < 0)
		*detail = ck_fmtd("the compilation unit of %s has no DW_AT_language%s — the calling convention cannot be told", target, p);
	else
		*detail = ck_fmtd("the compilation unit of %s has DW_AT_language 0x%llx%s, which is not C or C++ — the calling convention cannot be told", target,
				  (unsigned long long)sp->lang, p);
	free(pr);
	return v;
}



int ck_uprobe_open(struct ck *c, const struct bml_attach *a, const char *name, uint8_t **bin, struct bml_elf *elf)
{
	const char *P = a->program.p;
	size_t blen = 0;
	*bin = NULL;
	if (a->binary_sha256.len == 0)
		return ck_fail(c, ck_fmtd("program %s: %s attach row without a binary row", P, a->attach_type.p));
	if (!HAS(c, uprobe_binary, BML_QUERY_UPROBE_BIN)) {
		ck_add(c, "binary_unknown", P, name, 0, ck_dupn("no binary given"));
		return 0;
	}
	char *msg = NULL;
	if (c->caps->uprobe_binary(c->caps->ctx, P, bin, &blen, &msg) != BML_Q_OK) {
		ck_add(c, "binary_unknown", P, name, 0, msg);
		return 0;
	}
	char hex[65];
	bml_sha256_hex(*bin, blen, hex);
	if (strcmp(hex, a->binary_sha256.p) != 0) {
		ck_add(c, "binary", P, name, 0, ck_fmtd("the binary's SHA-256 is %s, but the object was built for %s", hex, a->binary_sha256.p));
		free(*bin);
		*bin = NULL;
		return 0;
	}
	char *eerr = NULL;
	if (bml_elf_open(*bin, blen, elf, &eerr)) {
		ck_add(c, "binary_unknown", P, name, 0, eerr);
		free(*bin);
		*bin = NULL;
		return 0;
	}
	return 1;
}

int ck_check_uprobe(struct ck *c, const struct bml_attach *a)
{
	char *ta;
	if (ck_check_arch_ctx(c, a, &ta)) {
		free(ta);
		return -1;
	}
	free(ta);
	uint8_t *bin;
	struct bml_elf elf;
	int o = ck_uprobe_open(c, a, a->target.p, &bin, &elf);
	if (o <= 0)
		return o;
	struct ck_dsrc src;
	ck_dsrc_init(&src, &elf, a->program.p);
	ck_uprobe_target(c, a, &elf, a->target.p, !strcmp(a->attach_type.p, "uretprobe"), &src);
	ck_dsrc_free(&src);
	bml_elf_close(&elf);
	free(bin);
	return 0;
}



void ck_uprobe_target(struct ck *c, const struct bml_attach *a, struct bml_elf *elfp, const char *T, int ret, struct ck_dsrc *src)
{
	const char *P = a->program.p;
	char *sd = bml_uprobe_symbol(elfp, T);
	if (sd)
		ck_add(c, "uprobe_symbol", P, T, 0, sd);
	if (ret || a->n_uprobe_args > 0) {
		ck_dsrc_read(c, src);
		if (src->kind) {
			ck_add(c, src->kind, P, T, 0, ck_dupn(src->err));
			return;
		}
	}

	if (ret && !BML_MUT("check.uretprobe_abi_skip")) {
		struct bml_dwarf_sub sp;
		char *derr = NULL;
		if (ck_dsrc_subprogram(src, T, 0, NULL, 0, &sp, &derr) != 0) {
			ck_add(c, "uretprobe_abi_unknown", P, T, 0, ck_fmtd("the calling convention of %s cannot be told (%s)", T, derr ? derr : ""));
			free(derr);
		} else {
			char *detail = NULL;
			int v = uretprobe_abi(T, &sp, &detail);
			if (v != 0)
				ck_add(c, v == 1 ? "uretprobe_abi" : "uretprobe_abi_unknown", P, T, 0, detail);
			bml_dwarf_sub_free(&sp);
		}
		return;
	}
	if (a->n_uprobe_args > 0) {
		struct bml_dwarf_sub sp;
		char *derr = NULL;

		size_t nraw = 0;
		for (size_t i = 0; i < a->n_uprobe_args; i++)
			if (!strcmp(a->uprobe_args[i].type.p, "ptr") && (uint64_t)a->uprobe_args[i].n > nraw && a->uprobe_args[i].n <= 4096)
				nraw = (size_t)a->uprobe_args[i].n;
		uint8_t *raw = nraw ? calloc(nraw, 1) : NULL;
		for (size_t i = 0; raw && i < a->n_uprobe_args; i++)
			if (!strcmp(a->uprobe_args[i].type.p, "ptr") && a->uprobe_args[i].n <= (int64_t)nraw)
				raw[a->uprobe_args[i].n - 1] = 1;
		if (nraw && !raw)
			c->oom = 1;
		int drc = ck_dsrc_subprogram(src, T, 1, raw, nraw, &sp, &derr);
		free(raw);

		if (drc == 0) {
			char *detail = NULL;
			int v = uprobe_abi(T, &sp, &detail);
			if (v != 0) {
				ck_add(c, v == 1 ? "uprobearg_abi" : "uprobearg_abi_unknown", P, T, 0, detail);
				bml_dwarf_sub_free(&sp);
				return;
			}
		}
		const struct bml_dwarf_param *ps = drc == 0 ? sp.params : NULL;
		size_t nps = drc == 0 ? sp.n : 0;
		for (size_t i = 0; i < a->n_uprobe_args; i++) {
			const struct bml_intarg *k = &a->uprobe_args[i];
			char *name = ck_fmtd("%lld of %s (%s)", (long long)k->n, T, k->type.p);
			if (drc) {
				ck_add(c, "uprobearg_unknown", P, name, 0, ck_dupn(derr));
			} else if ((uint64_t)k->n > nps) {
				ck_add(c, "uprobearg", P, name, 0,
				    ck_fmtd("%s takes %zu arguments in the binary's DWARF, but the object reads argument %lld", T, nps, (long long)k->n));
			} else {
				const struct bml_dwarf_param *p = &ps[k->n - 1];

				const char *pt = !strcmp(k->type.p, "ptr") ? (p->pointer ? p->pointer : "") : p->type;
				if (pt[0] == 0)
					ck_add(c, "uprobearg_unknown", P, name, 0, ck_fmtd("argument %s has a type this check cannot read", p->name));
				else if (strcmp(pt, k->type.p) != 0)
					ck_add(c, "uprobearg", P, name, 0,
					    ck_fmtd("argument %lld (%s) of %s is %s in the binary's DWARF, but the object reads it as %s", (long long)k->n,
						 p->name[0] ? p->name : "unnamed", T, pt, k->type.p));
			}
			free(name);
		}
		free(derr);
		if (drc == 0)
			bml_dwarf_sub_free(&sp);
	}
}
