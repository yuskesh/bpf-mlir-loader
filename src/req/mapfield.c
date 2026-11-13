#include "req/mapfield.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"
#include "btf/map_values.h"

struct loc {
	int sec;
	uint64_t off;
};

struct fn {
	const char *name;
	int sec;
	uint64_t start, size;
	const char **maps;
	size_t n_maps, cap_maps;
	struct loc *callees;
	size_t n_callees, cap_callees;
	char *map_err;
};

struct rel {
	uint64_t off;
	size_t sym;
};

struct relmap {
	struct rel *e;
	size_t n;
	int set;
};

struct scan {
	const struct bml_elf *elf;
	struct bml_elf_sym *syms;
	size_t n_syms;
	struct fn *fns;
	size_t n_fns;
	struct relmap *relocs;
};

static char *fmt(const char *f, ...) __attribute__((format(printf, 1, 2)));
static char *fmt(const char *f, ...)
{
	char tmp[512];
	va_list ap;
	va_start(ap, f);
	vsnprintf(tmp, sizeof(tmp), f, ap);
	va_end(ap);
	struct bml_buf b = {0};
	bml_buf_adds(&b, tmp);
	return bml_buf_take(&b);
}

static int cmp_cstr(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int push(void **arr, size_t *n, size_t *cap, size_t elem, const void *v)
{
	if (*n == *cap) {
		size_t c = *cap ? *cap * 2 : 4;
		void *p = realloc(*arr, c * elem);
		if (!p)
			return -1;
		*arr = p;
		*cap = c;
	}
	memcpy((char *)*arr + *n * elem, v, elem);
	(*n)++;
	return 0;
}

static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t le64(const uint8_t *p)
{
	return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32;
}

static struct fn *by_start(struct scan *s, struct loc l)
{
	for (size_t i = s->n_fns; i-- > 0;)
		if (s->fns[i].sec == l.sec && s->fns[i].start == l.off)
			return &s->fns[i];
	return NULL;
}

static const struct bml_elf_sym *reloc_at(struct scan *s, int sec, uint64_t off)
{
	if (sec < 0 || (size_t)sec >= s->elf->n_sections || !s->relocs[sec].set)
		return NULL;
	struct relmap *m = &s->relocs[sec];
	for (size_t i = m->n; i-- > 0;)
		if (m->e[i].off == off)
			return &s->syms[m->e[i].sym];
	return NULL;
}

static int sym_in_section(const struct scan *s, const struct bml_elf_sym *y)
{
	return y->shndx < s->elf->n_sections && y->shndx != BML_SHN_UNDEF;
}


static int record_map_ref(struct scan *s, struct fn *x, uint64_t at, uint8_t regs, const uint8_t *immb)
{
	const struct bml_elf_sym *y = reloc_at(s, x->sec, at);
	if (!y) {
		unsigned src = regs >> 4;
		if ((src == 1 || src == 2) && !x->map_err)
			x->map_err = fmt("%s: ld_imm64 at +%#llx refers to a map (src_reg %u) without a relocation", x->name,
					 (unsigned long long)(at - x->start), src);
		return 0;
	}
	if (!sym_in_section(s, y) || strcmp(s->elf->sections[y->shndx].name, ".maps") != 0)
		return 0;
	if (BML_ST_TYPE(y->info) == BML_STT_OBJECT)
		return push((void **)&x->maps, &x->n_maps, &x->cap_maps, sizeof(char *), &y->name);
	uint64_t off = y->value + (uint64_t)le32(immb);
	for (size_t i = 0; i < s->n_syms; i++) {
		const struct bml_elf_sym *o = &s->syms[i];
		if (o->shndx == y->shndx && BML_ST_TYPE(o->info) == BML_STT_OBJECT && o->value == off)
			return push((void **)&x->maps, &x->n_maps, &x->cap_maps, sizeof(char *), &o->name);
	}
	if (!x->map_err)
		x->map_err = fmt("%s: ld_imm64 at +%#llx refers to .maps offset %#llx, which no map symbol starts at", x->name,
				 (unsigned long long)(at - x->start), (unsigned long long)off);
	return 0;
}


static int scan_funcs(struct scan *s, char **err)
{
	const struct bml_elf *e = s->elf;
	if (bml_elf_symbols(e, BML_SHT_SYMTAB, &s->syms, &s->n_syms, err))
		return -1;
	for (size_t i = 0; i < s->n_syms; i++) {
		const struct bml_elf_sym *y = &s->syms[i];
		if (BML_ST_TYPE(y->info) != BML_STT_FUNC || !sym_in_section(s, y))
			continue;
		if (!(e->sections[y->shndx].flags & BML_SHF_EXECINSTR))
			continue;
		struct fn x = {.name = y->name, .sec = y->shndx, .start = y->value, .size = y->size};
		size_t cap = s->n_fns;
		if (push((void **)&s->fns, &s->n_fns, &cap, sizeof(x), &x))
			return (*err = fmt("out of memory"), -1);

	}
	s->relocs = calloc(e->n_sections ? e->n_sections : 1, sizeof(*s->relocs));
	if (!s->relocs)
		return (*err = fmt("out of memory"), -1);
	for (size_t si = 0; si < e->n_sections; si++) {
		const struct bml_elf_shdr *rs = &e->sections[si];
		if (rs->type != BML_SHT_REL || rs->info >= e->n_sections)
			continue;
		const uint8_t *data;
		size_t len;
		if (bml_elf_section_data(e, rs, &data, &len, err))
			return -1;
		struct relmap m = {.set = 1};
		size_t cap = 0;
		for (size_t i = 0; i + 16 <= len; i += 16) {
			uint64_t off = le64(data + i);
			uint64_t info = le64(data + i + 8);
			uint64_t idx = info >> 32;
			if (idx == 0 || idx > s->n_syms) {
				free(m.e);
				*err = fmt("relocation at %s+%#llx names symbol %llu outside the symbol table", e->sections[rs->info].name,
					   (unsigned long long)off, (unsigned long long)idx);
				return -1;
			}
			struct rel r = {off, (size_t)(idx - 1)};
			if (push((void **)&m.e, &m.n, &cap, sizeof(r), &r)) {
				free(m.e);
				return (*err = fmt("out of memory"), -1);
			}
		}
		free(s->relocs[rs->info].e);
		s->relocs[rs->info] = m;
	}
	for (size_t fi = 0; fi < s->n_fns; fi++) {
		struct fn *x = &s->fns[fi];
		const uint8_t *data;
		size_t len;
		if (bml_elf_section_data(e, &e->sections[x->sec], &data, &len, err))
			return -1;
		if (x->start > len || x->size > len - x->start)
			return (*err = fmt("symbol %s runs past its section", x->name), -1);
		const uint8_t *code = data + x->start;
		size_t clen = (size_t)x->size;
		for (size_t i = 0; i + 8 <= clen; i += 8) {
			uint8_t op = code[i], regs = code[i + 1];
			if (op == 0x18) {
				uint64_t at = x->start + i;
				if (record_map_ref(s, x, at, regs, code + i + 4))
					return (*err = fmt("out of memory"), -1);
				const struct bml_elf_sym *y = reloc_at(s, x->sec, at);
				if (y && sym_in_section(s, y) && (e->sections[y->shndx].flags & BML_SHF_EXECINSTR)) {
					struct loc to = {y->shndx, y->value + (uint64_t)le32(code + i + 4)};
					if (!by_start(s, to))
						return (*err = fmt("%s: the function address loaded at +%#zx does not point at the start of a function (section %d offset %#llx)",
								   x->name, i, to.sec, (unsigned long long)to.off), -1);
					if (push((void **)&x->callees, &x->n_callees, &x->cap_callees, sizeof(to), &to))
						return (*err = fmt("out of memory"), -1);
				}
				i += 8;
				continue;
			}
			if (op != 0x85)
				continue;
			int64_t imm = (int32_t)le32(code + i + 4);
			switch (regs >> 4) {
			case 0:
				break;
			case 1: {
				uint64_t at = x->start + i;
				struct loc to;
				const struct bml_elf_sym *y = reloc_at(s, x->sec, at);

				if (y && y->shndx == BML_SHN_UNDEF)
					break;
				if (y)
					to = (struct loc){y->shndx, (uint64_t)((int64_t)y->value + (imm + 1) * 8)};
				else
					to = (struct loc){x->sec, (uint64_t)((int64_t)at + (imm + 1) * 8)};
				if (!by_start(s, to))
					return (*err = fmt("%s: the BPF-to-BPF call at +%#zx does not land on the start of a function (section %d offset %#llx)",
							   x->name, i, to.sec, (unsigned long long)to.off), -1);
				if (push((void **)&x->callees, &x->n_callees, &x->cap_callees, sizeof(to), &to))
					return (*err = fmt("out of memory"), -1);
				break;
			}
			}
		}
	}
	return 0;
}


static int cmpstr(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}



static int uses(const struct bml_elf *e, struct bml_map_fields *out, char **err)
{
	struct scan s = {.elf = e};
	int rc = -1;
	const char **needed = NULL;
	size_t n_needed = 0, cap_needed = 0;
	struct mapfields *fields = NULL;
	size_t n_fields = 0;

	struct usedp {
		const char *name;
		const char **maps;
		size_t n, cap;
	} *used = NULL;
	size_t n_used = 0, cap_used = 0;
	char *visited = NULL;
	size_t *stack = NULL;
	char *seen = NULL;

	if (scan_funcs(&s, err))
		goto out;
	visited = calloc(s.n_fns ? s.n_fns : 1, 1);
	stack = calloc(s.n_fns ? s.n_fns : 1, sizeof(*stack));
	if (!visited || !stack) {
		*err = fmt("out of memory");
		goto out;
	}
	for (size_t ri = 0; ri < s.n_fns; ri++) {
		memset(visited, 0, s.n_fns);

		const char **set = NULL;
		size_t n_set = 0, cap_set = 0;
		size_t sp = 0;
		stack[sp++] = ri;
		visited[ri] = 1;
		while (sp) {
			struct fn *g = &s.fns[stack[--sp]];
			if (g->map_err) {
				*err = fmt("%s", g->map_err);
				free(set);
				goto out;
			}
			for (size_t k = 0; k < g->n_maps; k++) {
				int dup = 0;
				for (size_t j = 0; j < n_set; j++)
					if (strcmp(set[j], g->maps[k]) == 0)
						dup = 1;
				if (!dup && push((void **)&set, &n_set, &cap_set, sizeof(char *), &g->maps[k])) {
					free(set);
					*err = fmt("out of memory");
					goto out;
				}
			}
			for (size_t k = g->n_callees; k-- > 0;) {
				struct fn *c = by_start(&s, g->callees[k]);
				size_t ci = (size_t)(c - s.fns);
				if (!visited[ci]) {
					visited[ci] = 1;
					stack[sp++] = ci;
				}
			}
		}
		if (n_set) {
			struct usedp *u = NULL;
			for (size_t j = 0; j < n_used; j++)
				if (strcmp(used[j].name, s.fns[ri].name) == 0)
					u = &used[j];
			if (!u) {
				struct usedp z = {.name = s.fns[ri].name};
				if (push((void **)&used, &n_used, &cap_used, sizeof(z), &z)) {
					free(set);
					*err = fmt("out of memory");
					goto out;
				}
				u = &used[n_used - 1];
			}
			for (size_t j = 0; j < n_set; j++) {
				if (push((void **)&u->maps, &u->n, &u->cap, sizeof(char *), &set[j]) ||
				    push((void **)&needed, &n_needed, &cap_needed, sizeof(char *), &set[j])) {
					free(set);
					*err = fmt("out of memory");
					goto out;
				}
			}
		}
		free(set);
	}

	if (n_needed)
		qsort(needed, n_needed, sizeof *needed, cmp_cstr);
	if (n_needed && btf_map_value_fields(e, needed, n_needed, &fields, &n_fields, err))
		goto out;
	for (size_t j = 0; j < n_used; j++) {
		struct usedp *u = &used[j];
		qsort(u->maps, u->n, sizeof(char *), cmpstr);
		struct bml_mf_prog p = {0};
		size_t cap_uses = 0;
		for (size_t k = 0; k < u->n; k++) {
			for (size_t f = 0; f < n_fields; f++) {
				if (strcmp(fields[f].map, u->maps[k]) != 0)
					continue;
				for (size_t q = 0; q < fields[f].n; q++) {
					struct bml_mf_use use = {strdup(u->maps[k]), fields[f].fields[q]};
					if (!use.map || push((void **)&p.uses, &p.n_uses, &cap_uses, sizeof(use), &use)) {
						free(use.map);
						for (size_t z = 0; z < p.n_uses; z++)
							free(p.uses[z].map);
						free(p.uses);
						*err = fmt("out of memory");
						goto out;
					}
				}
			}
		}
		if (p.n_uses) {
			p.program = strdup(u->name);
			size_t cap = out->n_progs;
			if (!p.program || push((void **)&out->progs, &out->n_progs, &cap, sizeof(p), &p)) {
				free(p.program);
				for (size_t z = 0; z < p.n_uses; z++)
					free(p.uses[z].map);
				free(p.uses);
				*err = fmt("out of memory");
				goto out;
			}
		}
	}
	rc = 0;
out:
	for (size_t j = 0; j < n_used; j++)
		free(used[j].maps);
	free(used);
	free(needed);
	free(fields);
	free(visited);
	free(stack);
	free(seen);
	for (size_t i = 0; i < s.n_fns; i++) {
		free(s.fns[i].maps);
		free(s.fns[i].callees);
		free(s.fns[i].map_err);
	}
	free(s.fns);
	if (s.relocs)
		for (size_t i = 0; i < e->n_sections; i++)
			free(s.relocs[i].e);
	free(s.relocs);
	free(s.syms);
	return rc;
}

void bml_map_fields_free(struct bml_map_fields *mf)
{
	for (size_t i = 0; i < mf->n_progs; i++) {
		free(mf->progs[i].program);
		for (size_t j = 0; j < mf->progs[i].n_uses; j++)
			free(mf->progs[i].uses[j].map);
		free(mf->progs[i].uses);
	}
	free(mf->progs);
	free(mf->reason);
	memset(mf, 0, sizeof(*mf));
}

void bml_map_fields_derive(const struct bml_elf *e, struct bml_map_fields *out)
{
	char *err = NULL;
	memset(out, 0, sizeof(*out));
	if (uses(e, out, &err)) {
		bml_map_fields_free(out);
		out->state = BML_MF_FAILED;
		out->reason = err ? err : fmt("map-field derivation failed");
		return;
	}
	out->state = BML_MF_DERIVED;
}

const struct bml_mf_prog *bml_map_fields_uses(const struct bml_map_fields *mf, const char *program)
{
	for (size_t i = 0; i < mf->n_progs; i++)
		if (strcmp(mf->progs[i].program, program) == 0)
			return &mf->progs[i];
	return NULL;
}
