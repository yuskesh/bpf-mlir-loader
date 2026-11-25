/* load/pre.c — the guards before the load: the shape of the ELF (the narrow shape of the ELFs bpf-mlir produces, as
 * tallied over 673 ELFs of the repository), and the comparison with
 * libbpf's feature decisions (feat_supported). */
#include "load/internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btf/kernel.h"
#include "elf/elf.h"
#include "maps/arena.h"
#include "load/arena_extern.h"
#include "load/kfunc_extern.h"
#include "util/errtext.h"
#include "util/mutation.h"

int lb_fail(struct bml_load_result *r, int stage, const char *fmt, ...)
{
	struct bml_buf b = {0};
	char tmp[1024];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(tmp, sizeof tmp, fmt, ap);
	va_end(ap);
	bml_buf_adds(&b, tmp);
	r->stage = stage;
	free(r->msg);
	r->msg = bml_buf_take(&b);
	return -1;
}

const char *lb_feat_name(int f)
{
	switch (f) {
	case LBF_PROG_NAME: return "FEAT_PROG_NAME";
	case LBF_GLOBAL_DATA: return "FEAT_GLOBAL_DATA";
	case LBF_BTF: return "FEAT_BTF";
	case LBF_BTF_FUNC: return "FEAT_BTF_FUNC";
	case LBF_BTF_DATASEC: return "FEAT_BTF_DATASEC";
	case LBF_BTF_GLOBAL_FUNC: return "FEAT_BTF_GLOBAL_FUNC";
	case LBF_ARRAY_MMAP: return "FEAT_ARRAY_MMAP";
	case LBF_EXP_ATTACH_TYPE: return "FEAT_EXP_ATTACH_TYPE";
	case LBF_PROBE_READ_KERN: return "FEAT_PROBE_READ_KERN";
	case LBF_BTF_FLOAT: return "FEAT_BTF_FLOAT";
	case LBF_BTF_DECL_TAG: return "FEAT_BTF_DECL_TAG";
	case LBF_BTF_TYPE_TAG: return "FEAT_BTF_TYPE_TAG";
	case LBF_BTF_ENUM64: return "FEAT_BTF_ENUM64";
	case LBF_BTF_QMARK_DATASEC: return "FEAT_BTF_QMARK_DATASEC";
	}
	return "FEAT_?";
}

/* ---- the shape of the ELF ---- */

/* The program sections are the table of load/sections.c (lb_prog_section). */

/* content sections (a relocation may target them: debug, BTF and eh_frame) */
static int meta_section(const char *n)
{
	return strcmp(n, ".BTF") == 0 || strcmp(n, ".BTF.ext") == 0 || strcmp(n, ".eh_frame") == 0 || strncmp(n, ".debug_", 7) == 0;
}

static int data_section(const char *n)
{
	static const char *const exact[] = {"", ".symtab", ".strtab", ".shstrtab", "license", ".maps", ".rodata", ".bss",
					    ".ebpf_requirements", ".ebpf_records",
					    /* struct_ops: the struct_ops link table, and .data (libbpf's ordinary internal map; loaded, no bml read yet) */
					    ".struct_ops.link", ".data"};
	for (size_t i = 0; i < sizeof exact / sizeof *exact; i++)
		if (strcmp(n, exact[i]) == 0)
			return 1;
	return BML_MUT("load.struct_ops_plain_ok") && strcmp(n, ".struct_ops") == 0; /* mutant: G1 off */
}

/* struct_ops: the struct_ops table sections; their relocations may only be R_BPF_64_ABS64 (a program in a slot) */
static int table_section(const char *n)
{
	return strcmp(n, ".struct_ops.link") == 0 || (BML_MUT("load.struct_ops_plain_ok") && strcmp(n, ".struct_ops") == 0);
}

/* The members of the struct of a var in the .maps DATASEC may be only the libbpf map-definition names that bpf-mlir uses (pinning, values and inner maps are rejected) */
static int check_maps_defs(const struct bml_elf *e, struct bml_load_result *r)
{
	const struct bml_elf_shdr *s = bml_elf_section(e, ".BTF");
	const uint8_t *p;
	size_t n;
	char *err = NULL;
	if (!s || bml_elf_section_data(e, s, &p, &n, &err) != 0) {
		free(err);
		return lb_fail(r, BML_LOAD_SHAPE, "the ELF has no readable .BTF");
	}
	uint8_t *raw = malloc(n ? n : 1);
	if (!raw)
		return lb_fail(r, BML_LOAD_SHAPE, "out of memory");
	memcpy(raw, p, n);
	struct bml_kbtf kb;
	if (bml_kbtf_from_raw(raw, n, &kb, &err) != 0) {
		int rc = lb_fail(r, BML_LOAD_SHAPE, "the ELF .BTF cannot be read: %s", err ? err : "?");
		free(err);
		return rc;
	}
	static const char *const allowed[] = {"type", "key", "value", "key_size", "value_size", "max_entries", "map_flags"};
	int rc = 0;
	for (uint32_t id = 1; id < kb.n && !rc; id++) {
		struct kbtf_type ds;
		bml_kbtf_type(&kb, id, &ds);
		if (ds.kind != KBTF_DATASEC || strcmp(ds.name, ".maps") != 0)
			continue;
		for (uint32_t i = 0; i < ds.vlen && !rc; i++) {
			struct kbtf_type var, st;
			bml_kbtf_type(&kb, bml_kbtf_u32(&kb, ds.aux + 12 * (size_t)i), &var);
			int cyc;
			bml_kbtf_type(&kb, bml_kbtf_underlying(&kb, var.size_type, &cyc), &st);
			if (var.kind != KBTF_VAR || cyc || st.kind != KBTF_STRUCT) {
				rc = lb_fail(r, BML_LOAD_SHAPE, "a .maps definition is not a struct variable");
				break;
			}
			for (uint32_t j = 0; j < st.vlen; j++) {
				struct kbtf_member m;
				bml_kbtf_member(&kb, &st, j, &m);
				int ok = 0;
				for (size_t k = 0; k < sizeof allowed / sizeof *allowed; k++)
					ok |= strcmp(m.name, allowed[k]) == 0;
				if (!ok && strcmp(m.name, "map_extra") == 0) {
					struct bml_arena_spec spec;
					char *why = NULL;
					ok = bml_arena_elf(e->data, e->len, var.name, &spec, &why) == 0;
					free(why);
				}
				if (!ok) {
					rc = lb_fail(r, BML_LOAD_SHAPE, "map %s has the definition field %s (not in the bpf-mlir ELF form — libbpf would act on it)",
						     var.name, m.name);
					break;
				}
			}
		}
	}
	bml_kbtf_free(&kb);
	return rc;
}

int lb_check_shape(const uint8_t *elf, size_t len, struct bml_load_result *r)
{
	struct bml_elf e;
	char *err = NULL;
	if (bml_elf_open(elf, len, &e, &err) != 0) {
		int rc = lb_fail(r, BML_LOAD_SHAPE, "the ELF cannot be read: %s", err ? err : "?");
		free(err);
		return rc;
	}
	int rc = 0;
	if (!e.is64 || e.big_endian || e.machine != 247 /* EM_BPF */)
		rc = lb_fail(r, BML_LOAD_SHAPE, "not a little-endian 64-bit BPF ELF");
	for (size_t i = 0; i < e.n_sections && !rc; i++) {
		const struct bml_elf_shdr *s = &e.sections[i];
		if (s->type == 4 /* SHT_RELA */) {
			rc = lb_fail(r, BML_LOAD_SHAPE, "section %s is RELA (bpf-mlir emits REL only)", s->name);
			break;
		}
		if (s->type != BML_SHT_REL) {
			if (strcmp(s->name, ".struct_ops") == 0 && !BML_MUT("load.struct_ops_plain_ok")) { /* struct_ops guard G1 */
				rc = lb_fail(r, BML_LOAD_SHAPE, "struct_ops table section .struct_ops registers at load (only .struct_ops.link is accepted)");
				break;
			}
			if (!lb_prog_section(s->name) && !meta_section(s->name) && !data_section(s->name))
				rc = lb_fail(r, BML_LOAD_SHAPE, "section %s is not in the bpf-mlir ELF form", s->name);
			continue;
		}
		/* relocations: program sections allow R_BPF_64_64 (1) and R_BPF_64_32 (10); BTF and debug sections allow ABS64 (2), ABS32 (3) and NODYLD32 (4) */
		const char *target = strncmp(s->name, ".rel", 4) == 0 ? s->name + 4 : "";
		int prog = lb_prog_section(target), meta = meta_section(target), table = table_section(target);
		if (!prog && !meta && !table) {
			rc = lb_fail(r, BML_LOAD_SHAPE, "relocation section %s targets a section outside the form", s->name);
			break;
		}
		const uint8_t *p;
		size_t n;
		if (bml_elf_section_data(&e, s, &p, &n, &err) != 0 || n % 16 != 0) {
			rc = lb_fail(r, BML_LOAD_SHAPE, "relocation section %s cannot be read", s->name);
			break;
		}
		for (size_t k = 0; k < n / 16; k++) {
			uint32_t type = (uint32_t)bml_elf_u64(&e, p + 16 * k + 8);
			int ok = prog ? (type == 1 || type == 10) : table ? type == 2 : (type == 2 || type == 3 || type == 4);
			if (!ok) {
				rc = lb_fail(r, BML_LOAD_SHAPE, "relocation type %u in %s is outside the bpf-mlir ELF form", type, s->name);
				break;
			}
		}
	}
	free(err);
	if (!rc) {
		struct bml_elf_sym *syms = NULL;
		size_t ns = 0;
		err = NULL;
		if (bml_elf_symbols(&e, BML_SHT_SYMTAB, &syms, &ns, &err) != 0)
			rc = lb_fail(r, BML_LOAD_SHAPE, "the ELF has no symbol table");
		int other_externs = 0;
		for (size_t i = 0; i < ns && !rc; i++) {
			if (syms[i].shndx == BML_SHN_UNDEF) { /* the arena kfuncs keep their proof; the others are proved once, below */
				int proof = lb_kfunc_is_arena_name(syms[i].name) ? lb_arena_extern(&e,syms,ns,i,r) : (other_externs = 1);
				if(proof<0)rc=-1;
				else if(!proof)rc = lb_fail(r, BML_LOAD_SHAPE, "symbol %s is undefined (extern — libbpf would resolve it)", syms[i].name);
			}
			else if ((syms[i].other & 3) != 0)
				rc = lb_fail(r, BML_LOAD_SHAPE, "symbol %s is not STV_DEFAULT (libbpf would make it static — B5)", syms[i].name);
		}
		if (!rc && other_externs) rc = lb_kfunc_externs(&e, syms, ns, NULL, r);
		free(syms);
		free(err);
	}
	if (!rc)
		rc = check_maps_defs(&e, r);
	bml_elf_close(&e);
	return rc;
}

/* ---- libbpf's feature decisions ---- */

/* a feature of a btf row -> libbpf's feature (in one place a single libbpf feature decides two of these features, as found in the loader design survey) */
static int feat_of(const char *f)
{
	static const struct {
		const char *name;
		int feat;
	} t[] = {
		{"int", LBF_BTF}, {"ptr", LBF_BTF}, {"const", LBF_BTF}, {"array", LBF_BTF}, {"struct", LBF_BTF},
		{"func", LBF_BTF_FUNC}, {"func_proto", LBF_BTF_FUNC}, {"func_global", LBF_BTF_GLOBAL_FUNC},
		{"var", LBF_BTF_DATASEC}, {"datasec", LBF_BTF_DATASEC}, {"decl_tag", LBF_BTF_DECL_TAG},
		{"type_tag", LBF_BTF_TYPE_TAG}, {"enum", LBF_BTF}, {"enum64", LBF_BTF_ENUM64},
	};
	for (size_t i = 0; i < sizeof t / sizeof *t; i++)
		if (strcmp(t[i].name, f) == 0)
			return t[i].feat;
	return -1;
}

/* Apply libbpf's sanitize rules to the ELF's .BTF (before libbpf's finalize; the kind, linkage, kflag and name of the
 * types, which are what the sanitize decision depends on, do not change in finalize). The result is the missing
 * feature (LBF_*) if there is a type that would be rewritten, -1 if there is none, and -2 if the BTF cannot be read. */
int lb_btf_rewrite(const uint8_t *elf, size_t len)
{
	struct bml_elf e;
	char *err = NULL;
	const struct bml_elf_shdr *s;
	const uint8_t *p;
	size_t n;
	if (bml_elf_open(elf, len, &e, &err) != 0) {
		free(err);
		return -2;
	}
	s = bml_elf_section(&e, ".BTF");
	if (!s || bml_elf_section_data(&e, s, &p, &n, &err) != 0) {
		free(err);
		bml_elf_close(&e);
		return -2;
	}
	uint8_t *raw = malloc(n ? n : 1);
	if (!raw) {
		bml_elf_close(&e);
		return -2;
	}
	memcpy(raw, p, n);
	bml_elf_close(&e);
	struct bml_kbtf kb;
	if (bml_kbtf_from_raw(raw, n, &kb, &err) != 0) {
		free(err);
		return -2;
	}
	int has_datasec = feat_supported(NULL, LBF_BTF_DATASEC), has_decl_tag = feat_supported(NULL, LBF_BTF_DECL_TAG),
	    has_qmark = feat_supported(NULL, LBF_BTF_QMARK_DATASEC), has_func = feat_supported(NULL, LBF_BTF_FUNC),
	    has_func_global = feat_supported(NULL, LBF_BTF_GLOBAL_FUNC), has_float = feat_supported(NULL, LBF_BTF_FLOAT),
	    has_type_tag = feat_supported(NULL, LBF_BTF_TYPE_TAG), has_enum64 = feat_supported(NULL, LBF_BTF_ENUM64);
	int out = -1;
	for (uint32_t id = 1; id < kb.n && out < 0; id++) {
		struct kbtf_type t;
		bml_kbtf_type(&kb, id, &t);
		/* keep libbpf's if / else if order */
		if ((!has_datasec && t.kind == KBTF_VAR) || (!has_decl_tag && t.kind == KBTF_DECL_TAG))
			out = !has_datasec && t.kind == KBTF_VAR ? LBF_BTF_DATASEC : LBF_BTF_DECL_TAG;
		else if (!has_datasec && t.kind == KBTF_DATASEC)
			out = LBF_BTF_DATASEC;
		else if (!has_qmark && t.kind == KBTF_DATASEC && t.name[0] == '?')
			out = LBF_BTF_QMARK_DATASEC;
		else if (!has_func && (t.kind == KBTF_FUNC_PROTO || t.kind == KBTF_FUNC))
			out = LBF_BTF_FUNC;
		else if (!has_func_global && t.kind == KBTF_FUNC && t.vlen != 0)
			out = LBF_BTF_GLOBAL_FUNC; /* if the linkage (vlen) is not static (0), it is rewritten to static */
		else if (!has_float && t.kind == KBTF_FLOAT)
			out = LBF_BTF_FLOAT;
		else if (!has_type_tag && t.kind == KBTF_TYPE_TAG)
			out = LBF_BTF_TYPE_TAG;
		else if (!has_enum64 && t.kind == KBTF_ENUM && t.kflag)
			out = LBF_BTF_ENUM64; /* the kflag is cleared; if it was not set, the bytes are the same */
		else if (!has_enum64 && t.kind == KBTF_ENUM64)
			out = LBF_BTF_ENUM64;
	}
	bml_kbtf_free(&kb);
	return out;
}

int lb_check_features(const uint8_t *elf, size_t len, const struct bml_requirements *req, const struct bml_caps *caps,
		      struct bml_load_result *r)
{
	if (BML_MUT("load.no_pre_features")) /* mutant control: see whether the guards after the load alone stop it */
		return 0;
	/* 1. Compare the prediction (the check's btf_feature answer) with libbpf's actual decision; a mismatch is Unknown */
	for (size_t i = 0; i < req->n_btf_features && !BML_MUT("load.no_predict"); i++) { /* mutant control: exercise the sanitize stage */
		const char *f = req->btf_features[i].p;
		int feat = feat_of(f);
		if (feat < 0)
			return lb_fail(r, BML_LOAD_PREDICT, "BTF feature %s has no libbpf feature to cross-check", f);
		int v = 0;
		char *m = NULL;
		int rc = caps && caps->btf_feature ? caps->btf_feature(caps->ctx, f, &v, &m) : BML_Q_UNKNOWN;
		free(m);
		if (rc != BML_Q_OK)
			return lb_fail(r, BML_LOAD_PREDICT, "BTF feature %s: the check has no answer to cross-check libbpf against", f);
		bool lb = feat_supported(NULL, feat);
		if (lb != (v != 0))
			return lb_fail(r, BML_LOAD_PREDICT,
				       "BTF feature %s: the check says %s but libbpf says %s %s — the prediction of the loader's rewrite cannot be trusted",
				       f, v ? "accepted" : "not accepted", lb_feat_name(feat), lb ? "supported" : "missing");
	}
	/* 2. Whether libbpf loads the BTF at all, and whether libbpf's sanitize really rewrites the ELF's BTF
	 * (bpf_object__sanitize_btf; this copies the per-type rules of libbpf.c lines 3146-3244). Sanitize runs if any of 8
	 * features is missing (btf_needs_sanitization), but if the BTF has no type that needs a missing feature, the copy is
	 * byte-identical (for example FEAT_BTF_QMARK_DATASEC on 6.6). The guard stops on the predicted rewrite, and the byte
	 * comparison after the load is the backstop. */
	if (!feat_supported(NULL, LBF_BTF))
		return lb_fail(r, BML_LOAD_SANITIZE, "libbpf says FEAT_BTF is missing — it would not load the BTF (B3)");
	int rw = lb_btf_rewrite(elf, len);
	if (rw >= 0)
		return lb_fail(r, BML_LOAD_SANITIZE, "libbpf says %s is missing and the BTF has types it would rewrite without saying so (B1)",
			       lb_feat_name(rw));
	if (rw == -2)
		return lb_fail(r, BML_LOAD_SANITIZE, "the ELF BTF cannot be read to predict libbpf's rewrite");
	/* 3. Rewrites of programs and maps (program and map attributes), and the replacement of helpers (when a program uses probe_read_{kernel,user}[_str]) */
	static const int attr_feats[] = {LBF_PROG_NAME, LBF_GLOBAL_DATA, LBF_ARRAY_MMAP};
	for (size_t i = 0; i < sizeof attr_feats / sizeof *attr_feats; i++)
		if (!feat_supported(NULL, attr_feats[i]))
			return lb_fail(r, BML_LOAD_REWRITE, "libbpf says %s is missing — it would change the programs or maps without saying so",
				       lb_feat_name(attr_feats[i]));
	/* When FEAT_EXP_ATTACH_TYPE is missing, libbpf rewrites (sets expected_attach_type to 0) only programs whose section has a
	 * SEC_EXP_ATTACH_OPT definition. libbpf's probe (a load of a cgroup_sock program) fails with EPERM when the process
	 * lacks CAP_NET_ADMIN and is read as "missing"; stopping whatever the ELF contains would stop an fentry program run
	 * with {bpf, perfmon} (this broke a downstream mojo program). So stop only when a matching section exists (and stop
	 * if the ELF cannot be read: fail closed). */
	if (!feat_supported(NULL, LBF_EXP_ATTACH_TYPE)) {
		const char *hit = NULL;
		struct bml_elf e;
		char *err = NULL;
		int open_ok = bml_elf_open(elf, len, &e, &err) == 0;
		free(err);
		for (size_t i = 0; open_ok && !hit && i < e.n_sections; i++)
			if ((e.sections[i].flags & BML_SHF_EXECINSTR) && lb_sec_exp_attach_opt(e.sections[i].name))
				hit = e.sections[i].name;
		char name[128] = "";
		if (hit)
			snprintf(name, sizeof name, "%s", hit);
		if (open_ok)
			bml_elf_close(&e);
		if (!open_ok || hit)
			return lb_fail(r, BML_LOAD_REWRITE,
				       "libbpf says FEAT_EXP_ATTACH_TYPE is missing — it would clear the expected attach type of the program in section %s without saying so",
				       open_ok ? name : "(the ELF cannot be read)");
	}
	for (size_t i = 0; i < req->n_programs; i++)
		for (size_t j = 0; j < req->programs[i].n_helpers; j++) {
			int64_t h = req->programs[i].helpers[j].id;
			if (h >= 112 && h <= 115 && !feat_supported(NULL, LBF_PROBE_READ_KERN))
				return lb_fail(r, BML_LOAD_REWRITE,
					       "program %s calls helper %lld but libbpf says FEAT_PROBE_READ_KERN is missing — it would replace the helper (P1)",
					       req->programs[i].symbol.p, (long long)h);
		}
	return 0;
}

const char *lb_errno(int e) /* class B (the errno tables): bml's load messages, never compared with Go's text */
{
	static __thread char buf[256];
	char *s = bml_errno_text(e);
	snprintf(buf, sizeof buf, "%s", s ? s : "unknown error");
	free(s);
	return buf;
}
