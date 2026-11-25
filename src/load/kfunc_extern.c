/* The shape guard's proof for kfunc externs other than the two arena kfuncs.
 *
 * libbpf resolves an undefined symbol that names a kfunc at load time: it looks the name up in vmlinux BTF and, if the
 * name is not there, silently in every loaded module's BTF (find_ksym_btf_id). It also accepts weak externs that it
 * cannot resolve. This proof lets an extern through only when libbpf has nothing to decide silently:
 *   K1 the symbol is a unique, non-weak GLOBAL NOTYPE UNDEF symbol of default visibility, value 0 and size 0;
 *   K2 the ELF's BTF has exactly one extern-linkage FUNC of that name, a member (offset 0, size 0) of the single .ksyms;
 *   K3 the only relocations naming it are one .rel.BTF record at that member's offset field and at least one call;
 *   K4 every program that reaches a call has a kfunc row for it whose signature matches the ELF's BTF prototype;
 *   K5 the target's vmlinux BTF has a FUNC of that name.
 * The target's prototype and whether the program type may call it are the requirements check's (kfunc_sig, kfunc_loads),
 * which every supported load path runs before this guard. */
#include "load/kfunc_extern.h"
#include "load/internal.h"
#include "caps/live.h"
#include "caps/live_internal.h"
#include "req/from_elf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REL_ABS32 3 /* R_BPF_64_ABS32: the .rel.BTF record of an extern */
#define REL_CALL 10 /* R_BPF_64_32: a call */
#define REL_LDIMM64 1

static int is_name(const struct bml_str *a, const char *b)
{
	return a->len == strlen(b) && !memcmp(a->p, b, a->len);
}

static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

int lb_kfunc_is_arena_name(const char *name)
{
	return !strcmp(name, "bpf_arena_alloc_pages") || !strcmp(name, "bpf_arena_free_pages");
}

struct fn {
	const char *name;
	size_t sec;
	uint64_t start, size;
	size_t *callees;
	size_t n_callees, cap_callees;
};

struct st {
	const struct bml_elf *e;
	const struct bml_elf_sym *syms;
	size_t ns, symtab;
	struct fn *fns;
	size_t n_fns;
	struct bml_requirements *req;
	struct bml_live ebtf; /* a view of the ELF's own BTF, to compare a row with the extern's prototype */
	uint64_t ksyms_aux;   /* offset in .BTF of the .ksyms secinfo array */
	uint32_t ksyms_n;
	size_t *roots;        /* fn index of each requirements program (SIZE_MAX if the program has no FUNC) */
	unsigned char *reach; /* reach[p * n_fns + f]: program p reaches function f */
};

static const struct bml_elf_sym *reloc_sym(const struct st *s, size_t sec, uint64_t off, uint32_t *type)
{
	for (size_t i = 0; i < s->e->n_sections; i++) {
		const struct bml_elf_shdr *rs = &s->e->sections[i];
		if (rs->type != BML_SHT_REL || rs->info != sec)
			continue;
		const uint8_t *p;
		size_t n;
		char *err = NULL;
		if (bml_elf_section_data(s->e, rs, &p, &n, &err)) {
			free(err);
			return NULL;
		}
		for (size_t j = 0; j + 16 <= n; j += 16) {
			uint64_t info = bml_elf_u64(s->e, p + j + 8), idx = info >> 32;
			if (bml_elf_u64(s->e, p + j) == off && idx && idx <= s->ns) {
				*type = (uint32_t)info;
				return &s->syms[idx - 1];
			}
		}
	}
	return NULL;
}

static size_t fn_at(const struct st *s, size_t sec, uint64_t off)
{
	for (size_t i = 0; i < s->n_fns; i++)
		if (s->fns[i].sec == sec && s->fns[i].start == off)
			return i;
	return SIZE_MAX;
}

static int add_edge(struct fn *f, size_t to)
{
	if (f->n_callees == f->cap_callees) {
		size_t cap = f->cap_callees ? 2 * f->cap_callees : 4;
		size_t *n = realloc(f->callees, cap * sizeof *n);
		if (!n)
			return -1;
		f->callees = n;
		f->cap_callees = cap;
	}
	f->callees[f->n_callees++] = to;
	return 0;
}

/* The functions and their edges: BPF-to-BPF calls and function addresses loaded by ld_imm64 (callbacks). */
static int scan(struct st *s, struct bml_load_result *r)
{
	const struct bml_elf *e = s->e;
	for (size_t i = 0; i < s->ns; i++) {
		const struct bml_elf_sym *y = &s->syms[i];
		if (BML_ST_TYPE(y->info) != BML_STT_FUNC || y->shndx == BML_SHN_UNDEF || y->shndx >= e->n_sections ||
		    !(e->sections[y->shndx].flags & BML_SHF_EXECINSTR))
			continue;
		struct fn *n = realloc(s->fns, (s->n_fns + 1) * sizeof *n);
		if (!n)
			return lb_fail(r, BML_LOAD_ENV, "out of memory");
		s->fns = n;
		s->fns[s->n_fns++] = (struct fn){.name = y->name, .sec = y->shndx, .start = y->value, .size = y->size};
	}
	for (size_t fi = 0; fi < s->n_fns; fi++) {
		struct fn *x = &s->fns[fi];
		const uint8_t *code;
		size_t len;
		char *err = NULL;
		if (bml_elf_section_data(e, &e->sections[x->sec], &code, &len, &err) || x->start > len || x->size > len - x->start) {
			free(err);
			return lb_fail(r, BML_LOAD_SHAPE, "function %s cannot be read", x->name);
		}
		for (uint64_t i = 0; i + 8 <= x->size; i += 8) {
			const uint8_t *in = code + x->start + i;
			uint64_t at = x->start + i;
			uint32_t type = 0;
			const struct bml_elf_sym *y = reloc_sym(s, x->sec, at, &type);
			size_t to = SIZE_MAX;
			if (in[0] == 0x18) {
				if (y && type == REL_LDIMM64 && y->shndx != BML_SHN_UNDEF && y->shndx < e->n_sections &&
				    (e->sections[y->shndx].flags & BML_SHF_EXECINSTR))
					to = fn_at(s, y->shndx, y->value + le32(in + 4));
				i += 8;
			} else if (in[0] == 0x85 && (in[1] >> 4) == 1) {
				int32_t imm = (int32_t)le32(in + 4);
				if (y && y->shndx == BML_SHN_UNDEF)
					continue; /* a kfunc call, not an edge */
				if (y)
					to = fn_at(s, y->shndx, (uint64_t)((int64_t)y->value + ((int64_t)imm + 1) * 8));
				else
					to = fn_at(s, x->sec, (uint64_t)((int64_t)at + ((int64_t)imm + 1) * 8));
				if (to == SIZE_MAX)
					return lb_fail(r, BML_LOAD_SHAPE, "%s: the call at +%#llx does not land on a function", x->name,
						       (unsigned long long)i);
			}
			if (to != SIZE_MAX && add_edge(x, to))
				return lb_fail(r, BML_LOAD_ENV, "out of memory");
		}
	}
	size_t np = s->req->n_programs;
	s->roots = malloc((np ? np : 1) * sizeof *s->roots);
	s->reach = calloc((np ? np : 1) * (s->n_fns ? s->n_fns : 1), 1);
	size_t *stack = malloc((s->n_fns ? s->n_fns : 1) * sizeof *stack);
	if (!s->roots || !s->reach || !stack) {
		free(stack);
		return lb_fail(r, BML_LOAD_ENV, "out of memory");
	}
	/* The roots are the ELF's loadable programs (libbpf: every FUNC in an executable section other than .text), bound
	 * one-to-one to the requirements' program rows, so no program can reach a call without being checked. */
	for (size_t f = 0; f < s->n_fns; f++) {
		if (!strcmp(e->sections[s->fns[f].sec].name, ".text"))
			continue;
		unsigned rows = 0;
		for (size_t p = 0; p < np; p++)
			rows += is_name(&s->req->programs[p].symbol, s->fns[f].name);
		if (rows != 1) {
			free(stack);
			return lb_fail(r, BML_LOAD_SHAPE, "kfunc externs: program %s (section %s) has %u requirements program rows, "
				       "not 1", s->fns[f].name, e->sections[s->fns[f].sec].name, rows);
		}
	}
	for (size_t p = 0; p < np; p++) {
		const struct bml_str *name = &s->req->programs[p].symbol;
		unsigned found = 0;
		s->roots[p] = SIZE_MAX;
		for (size_t f = 0; f < s->n_fns; f++)
			if (is_name(name, s->fns[f].name) && strcmp(e->sections[s->fns[f].sec].name, ".text"))
				s->roots[p] = f, found++;
		if (found != 1) {
			free(stack);
			return lb_fail(r, BML_LOAD_SHAPE, "kfunc externs: the requirements program %.*s names %u programs of the "
				       "ELF, not 1", (int)name->len, name->p, found);
		}
		unsigned char *seen = s->reach + p * s->n_fns;
		size_t sp = 0;
		stack[sp++] = s->roots[p];
		seen[s->roots[p]] = 1;
		while (sp) {
			struct fn *g = &s->fns[stack[--sp]];
			for (size_t k = 0; k < g->n_callees; k++)
				if (!seen[g->callees[k]]) {
					seen[g->callees[k]] = 1;
					stack[sp++] = g->callees[k];
				}
		}
	}
	free(stack);
	return 0;
}

/* The ELF's BTF and its single .ksyms DATASEC. */
static int elf_btf(struct st *s, struct bml_load_result *r)
{
	const struct bml_elf_shdr *sec = NULL;
	for (size_t i = 0; i < s->e->n_sections; i++)
		if (!strcmp(s->e->sections[i].name, ".BTF")) {
			if (sec)
				return lb_fail(r, BML_LOAD_SHAPE, "kfunc externs: the ELF has more than one .BTF section");
			sec = &s->e->sections[i];
		}
	const uint8_t *raw;
	size_t len;
	char *err = NULL;
	if (!sec || bml_elf_section_data(s->e, sec, &raw, &len, &err)) {
		free(err);
		return lb_fail(r, BML_LOAD_SHAPE, "kfunc externs: the ELF has no readable .BTF section");
	}
	uint8_t *copy = malloc(len ? len : 1);
	if (!copy)
		return lb_fail(r, BML_LOAD_ENV, "out of memory");
	memcpy(copy, raw, len);
	if (bml_kbtf_from_raw(copy, len, &s->ebtf.kb, &err)) {
		int rc = lb_fail(r, BML_LOAD_SHAPE, "kfunc externs: the ELF's .BTF cannot be read: %s", err ? err : "");
		free(err);
		return rc;
	}
	s->ebtf.kb_done = 1;
	unsigned found = 0;
	for (uint32_t i = 1; i < s->ebtf.kb.n; i++) {
		struct kbtf_type t;
		bml_kbtf_type(&s->ebtf.kb, i, &t);
		if (t.kind == KBTF_DATASEC && !strcmp(t.name, ".ksyms")) {
			found++;
			s->ksyms_aux = (uint64_t)(t.aux - s->ebtf.kb.raw);
			s->ksyms_n = t.vlen;
		}
	}
	if (found != 1)
		return lb_fail(r, BML_LOAD_SHAPE, "kfunc externs: the ELF's BTF has %u .ksyms DATASECs, not 1", found);
	return 0;
}

static int only_overlap(const struct st *s, size_t target, uint64_t off, uint64_t width)
{
	unsigned n = 0;
	for (size_t i = 0; i < s->e->n_sections; i++) {
		const struct bml_elf_shdr *rs = &s->e->sections[i];
		if (rs->type != BML_SHT_REL || rs->info != target)
			continue;
		const uint8_t *p;
		size_t len;
		char *err = NULL;
		if (bml_elf_section_data(s->e, rs, &p, &len, &err)) {
			free(err);
			return 0;
		}
		for (size_t j = 0; j + 16 <= len; j += 16) {
			uint64_t at = bml_elf_u64(s->e, p + j);
			uint32_t type = (uint32_t)bml_elf_u64(s->e, p + j + 8);
			uint64_t span = type == REL_LDIMM64 || type == 2 || type == REL_CALL ? 8 : 4;
			n += at < off + width && off < at + span;
		}
	}
	return n == 1;
}

#define FAIL(fmt, ...) return lb_fail(r, BML_LOAD_SHAPE, "kfunc extern %s: " fmt, name, ##__VA_ARGS__)

/* K4 for one call: every program that reaches the calling function has a matching row. */
static int callers(struct st *s, const char *name, size_t fn, uint64_t off, struct bml_load_result *r)
{
	unsigned reached = 0;
	for (size_t p = 0; p < s->req->n_programs; p++) {
		if (s->roots[p] == SIZE_MAX || !s->reach[p * s->n_fns + fn])
			continue;
		reached++;
		const struct bml_str *prog = &s->req->programs[p].symbol;
		unsigned rows = 0;
		for (size_t k = 0; k < s->req->n_kfuncs; k++) {
			const struct bml_kfunc *row = &s->req->kfuncs[k];
			if (!is_name(&row->name, name) || row->program.len != prog->len || memcmp(row->program.p, prog->p, prog->len))
				continue;
			rows++;
			struct bml_strs d = {0};
			char *msg = NULL;
			int q = bml_live_kfunc(&s->ebtf, name, row->ret.p, row->args, row->n_args, &d, &msg);
			int ok = q == BML_Q_OK && !d.n;
			char first[256];
			snprintf(first, sizeof first, "%s", d.n ? d.s[0] : msg ? msg : "");
			bml_strs_free(&d);
			free(msg);
			if (!ok)
				FAIL("the kfunc row of program %.*s does not match the prototype in the ELF's BTF (%s)", (int)prog->len,
				     prog->p, first);
		}
		if (!rows)
			FAIL("program %.*s reaches a call of it but has no kfunc row for it", (int)prog->len, prog->p);
	}
	if (!reached)
		FAIL("the call in function %s at +%#llx is not reachable from any program", s->fns[fn].name, (unsigned long long)off);
	return 0;
}

static int one(struct st *s, size_t idx, struct bml_live *vm, struct bml_load_result *r)
{
	const struct bml_elf_sym *y = &s->syms[idx];
	const char *name = y->name;
	unsigned same = 0;
	for (size_t i = 0; i < s->ns; i++)
		same += !strcmp(s->syms[i].name, name);
	/* K1 */
	if ((y->info >> 4) == 2)
		FAIL("a weak extern is refused (libbpf resolves a missing weak extern to zero)");
	if (BML_ST_TYPE(y->info) != 0)
		FAIL("a data extern is refused (symbol type %u, not NOTYPE)", BML_ST_TYPE(y->info));
	if (y->info != 0x10 || y->other || y->value || y->size || same != 1)
		FAIL("the symbol is not a unique GLOBAL NOTYPE extern of default visibility, value 0 and size 0");
	/* K2 */
	uint32_t func = 0;
	unsigned funcs = 0, vars = 0;
	for (uint32_t i = 1; i < s->ebtf.kb.n; i++) {
		struct kbtf_type t;
		bml_kbtf_type(&s->ebtf.kb, i, &t);
		if (strcmp(t.name, name))
			continue;
		if (t.kind == KBTF_FUNC)
			funcs++, func = i;
		vars += t.kind == KBTF_VAR;
	}
	if (vars)
		FAIL("a data extern is refused (the ELF's BTF has a VAR of this name)");
	struct kbtf_type ft;
	if (funcs == 1)
		bml_kbtf_type(&s->ebtf.kb, func, &ft);
	if (funcs != 1 || ft.vlen != 2)
		FAIL("the ELF's BTF does not have exactly one extern-linkage FUNC of this name");
	uint64_t meta = UINT64_MAX;
	unsigned members = 0;
	for (uint32_t j = 0; j < s->ksyms_n; j++) {
		const uint8_t *m = s->ebtf.kb.raw + s->ksyms_aux + 12 * j;
		if (bml_kbtf_u32(&s->ebtf.kb, m) != func)
			continue;
		members++;
		if (bml_kbtf_u32(&s->ebtf.kb, m + 4) || bml_kbtf_u32(&s->ebtf.kb, m + 8))
			FAIL("its .ksyms member has a nonzero offset or size");
		meta = s->ksyms_aux + 12 * j + 4;
	}
	if (members != 1)
		FAIL("its FUNC is a member of .ksyms %u times, not once", members);
	/* K3 and K4 */
	unsigned metas = 0, calls = 0;
	for (size_t i = 0; i < s->e->n_sections; i++) {
		const struct bml_elf_shdr *rs = &s->e->sections[i];
		if (rs->type != BML_SHT_REL)
			continue;
		const uint8_t *p;
		size_t len;
		char *err = NULL;
		if (rs->link != s->symtab || rs->info >= s->e->n_sections || bml_elf_section_data(s->e, rs, &p, &len, &err)) {
			free(err);
			FAIL("relocation section %s cannot be read against the symbol table", rs->name);
		}
		const struct bml_elf_shdr *target = &s->e->sections[rs->info];
		for (size_t k = 0; k + 16 <= len; k += 16) {
			uint64_t off = bml_elf_u64(s->e, p + k), info = bml_elf_u64(s->e, p + k + 8);
			if ((info >> 32) != idx + 1)
				continue;
			uint32_t type = (uint32_t)info;
			if (!strcmp(target->name, ".BTF")) {
				if (type != REL_ABS32 || off != meta || !only_overlap(s, rs->info, off, 4))
					FAIL("it is referenced other than by a kfunc call (the %s record at +%#llx, type %u, is not the "
					     ".ksyms offset field at +%#llx)", rs->name, (unsigned long long)off, type,
					     (unsigned long long)meta);
				metas++;
				continue;
			}
			const uint8_t *code;
			size_t clen;
			err = NULL;
			if (type != REL_CALL || !(target->flags & BML_SHF_EXECINSTR) || off % 8 ||
			    bml_elf_section_data(s->e, target, &code, &clen, &err) || clen < 8 || off > clen - 8 ||
			    memcmp(code + off, "\x85\x10\x00\x00\xff\xff\xff\xff", 8) || !only_overlap(s, rs->info, off, 8)) {
				free(err);
				FAIL("it is referenced other than by a kfunc call (the %s record at +%#llx, type %u)", rs->name,
				     (unsigned long long)off, type);
			}
			size_t fn = SIZE_MAX;
			unsigned in = 0;
			for (size_t f = 0; f < s->n_fns; f++)
				if (s->fns[f].sec == rs->info && s->fns[f].start <= off && s->fns[f].size >= 8 &&
				    off - s->fns[f].start <= s->fns[f].size - 8)
					fn = f, in++;
			if (in != 1)
				FAIL("the call at %s+%#llx (8 bytes) is not inside exactly one function", target->name, (unsigned long long)off);
			if (callers(s, name, fn, off - s->fns[fn].start, r))
				return -1;
			calls++;
		}
	}
	if (metas != 1)
		FAIL("it is referenced other than by a kfunc call (%u .rel.BTF records for its .ksyms member, not 1)", metas);
	if (!calls)
		FAIL("it is referenced other than by a kfunc call (no call)");
	/* K5 */
	uint32_t id;
	char *err = NULL;
	if (bml_live_func_btf_id(vm, name, &id, &err)) {
		char why[256];
		snprintf(why, sizeof why, "%s", err ? err : "");
		free(err);
		if (vm->kb_done && vm->kb_rc != 0)
			FAIL("the target's vmlinux BTF cannot be read (%s)", why);
		/* Name the kind that holds the name instead, if any (a plain scan: this runs only on the way to a stop). */
		const char *verr = NULL;
		const struct bml_kbtf *kb = lv_kb(vm, &verr);
		const char *other = NULL;
		for (uint32_t i = 1; kb && i < kb->n && !other; i++) {
			struct kbtf_type t;
			bml_kbtf_type(kb, i, &t);
			if (!strcmp(t.name, name))
				other = bml_kbtf_goname(t.kind);
		}
		if (other)
			FAIL("it has no FUNC in the target's vmlinux BTF, only a %s of this name; libbpf would look in module BTF, "
			     "and module kfuncs are not supported", other);
		FAIL("it has no FUNC in the target's vmlinux BTF (%s); libbpf would look in module BTF, and module kfuncs are "
		     "not supported", why);
	}
	return 0;
}

int lb_kfunc_externs(const struct bml_elf *e, const struct bml_elf_sym *syms, size_t ns, struct bml_live *vmlinux,
		     struct bml_load_result *r)
{
	struct st s = {.e = e, .syms = syms, .ns = ns};
	struct bml_live own = {0};
	struct bml_req_elf_error re = {0};
	struct bml_live *vm = vmlinux ? vmlinux : &own;
	int rc = 0;
	unsigned tables = 0;
	for (size_t i = 0; i < e->n_sections; i++)
		if (e->sections[i].type == BML_SHT_SYMTAB)
			tables++, s.symtab = i;
	if (tables != 1) {
		rc = lb_fail(r, BML_LOAD_SHAPE, "kfunc externs: the ELF has %u symbol tables, not 1", tables);
		goto out;
	}
	if (bml_req_from_elf(e->data, e->len, &s.req, &re)) {
		rc = lb_fail(r, BML_LOAD_SHAPE, "kfunc externs: the ELF's requirements cannot be read");
		goto out;
	}
	if ((rc = elf_btf(&s, r)) || (rc = scan(&s, r)))
		goto out;
	for (size_t i = 0; i < ns && !rc; i++)
		if (syms[i].shndx == BML_SHN_UNDEF && !lb_kfunc_is_arena_name(syms[i].name))
			rc = one(&s, i, vm, r);
out:
	for (size_t i = 0; i < s.n_fns; i++)
		free(s.fns[i].callees);
	free(s.fns);
	free(s.roots);
	free(s.reach);
	bml_requirements_free(s.req);
	bml_req_elf_error_free(&re);
	bml_live_free(&s.ebtf);
	bml_live_free(&own);
	return rc ? -1 : 0;
}
