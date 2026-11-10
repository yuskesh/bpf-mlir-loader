
#include "btf/layout.h"


#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf/elf.h"
#include "util/gostr.h"
#include "util/mutation.h"

static char *xstrdup(const char *s)
{
	return strdup(s ? s : "");
}

static char *fmts(const char *f, ...) __attribute__((format(printf, 1, 2)));
static char *fmts(const char *f, ...)
{
	va_list ap;
	va_start(ap, f);
	int k = vsnprintf(NULL, 0, f, ap);
	va_end(ap);
	char *p = k >= 0 ? malloc((size_t)k + 1) : NULL;
	if (!p)
		return NULL;
	va_start(ap, f);
	vsnprintf(p, (size_t)k + 1, f, ap);
	va_end(ap);
	return p;
}
void btf_layout_free(struct lbtf *b)
{
	for (size_t i = 0; i < b->n; i++) {
		free(b->t[i].members);
		free(b->t[i].secinfo);
	}
	free(b->t);
}

static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}


#define PANIC_MSG "the ELF BTF is corrupt (a read past its data — bpf-mlir-loader stops here)"


static int rd32(const uint8_t *raw, size_t len, uint32_t off, uint32_t *out)
{
	if ((uint64_t)off + 4 > len)
		return -1;
	*out = le32(raw + off);
	return 0;
}


static int lstr(const uint8_t *strs, size_t slen, uint32_t off, const char **out)
{
	if (off >= slen) {
		*out = "";
		return 0;
	}
	if (!memchr(strs + off, 0, slen - off))
		return -1;
	*out = (const char *)strs + off;
	return 0;
}


static uint64_t record_tail(uint32_t kind, uint32_t vlen)
{
	switch (kind) {
	case 1: case 14: case 17: return 4;
	case 3: return 12;
	case 4: case 5: case 19: case 15: return 12ull * vlen;
	case 6: case 13: return 8ull * vlen;
	}
	return 0;
}

int btf_layout_parse(const void *elf_data, size_t elf_len, struct lbtf *b, char **err)
{
	memset(b, 0, sizeof(*b));
	struct bml_elf e;
	char *eerr = NULL;
	if (bml_elf_open(elf_data, elf_len, &e, &eerr)) {
		*err = eerr;
		return -1;
	}
	int rc = -1;
	const struct bml_elf_shdr *sec = bml_elf_section(&e, ".BTF");
	const uint8_t *raw;
	size_t len;
	if (!sec) {
		*err = xstrdup("the ELF has no .BTF section");
		goto out;
	}
	if (bml_elf_section_data(&e, sec, &raw, &len, err))
		goto out;
	if (len < 24 || (raw[0] | raw[1] << 8) != 0xeb9f) {
		*err = xstrdup("the .BTF header cannot be read");
		goto out;
	}
	uint32_t hdr = le32(raw + 4), toff = le32(raw + 8), tlen = le32(raw + 12), soff = le32(raw + 16), sl = le32(raw + 20);

	uint64_t n = len;
	if ((uint64_t)hdr < 24 || (uint64_t)hdr > n || (uint64_t)hdr + toff + tlen > n || (uint64_t)hdr + soff + sl > n) {
		*err = fmts("the .BTF is corrupt: the header (length %u, types %u+%u, strings %u+%u) is outside the %llu-byte section", hdr,
			    toff, tlen, soff, sl, (unsigned long long)n);
		goto out;
	}
	const uint8_t *strs = raw + hdr + soff;
	size_t slen = sl;
	if (slen > 0 && strs[slen - 1] != 0) {
		*err = xstrdup("the .BTF is corrupt: the string table does not end with NUL");
		goto out;
	}
	size_t cap = 1;
	b->t = calloc(1, sizeof(*b->t));
	if (!b->t) {
		*err = xstrdup("out of memory");
		goto out;
	}
	b->t[0].name = "";
	b->n = 1;
	uint32_t p = hdr + toff, end = hdr + toff + tlen;
	if ((end - p) % 4 != 0) {
		*err = fmts("the .BTF is corrupt: the type section length %u is not a multiple of 4", end - p);
		goto out;
	}
	while (p < end) {
		uint32_t info, nameoff, st;
		if ((uint64_t)p + 12 > end) {
			*err = fmts("the .BTF is corrupt: a type record ends inside the type section (offset %u)", p - hdr - toff);
			goto out;
		}
		info = le32(raw + p + 4);
		if ((uint64_t)p + 12 + record_tail(info >> 24 & 0x1f, info & 0xffff) > end) {
			*err = fmts("the .BTF is corrupt: a type record (kind %u, vlen %u) runs past the type section (offset %u)", info >> 24 & 0x1f,
				    info & 0xffff, p - hdr - toff);
			goto out;
		}
		if (rd32(raw, len, p + 4, &info) || rd32(raw, len, p, &nameoff) || rd32(raw, len, p + 8, &st)) {
			*err = xstrdup(PANIC_MSG);
			goto out;
		}
		struct ltype t = {.kind = (info >> 24) & 0x1f};
		if (lstr(strs, slen, nameoff, &t.name)) {
			*err = xstrdup(PANIC_MSG);
			goto out;
		}
		uint32_t vlen = info & 0xffff;
		int kflag = info >> 31 == 1;
		p += 12;
		switch (t.kind) {
		case 1: case 14: case 17:
			t.size = st;
			if (t.kind == 14)
				t.type_id = st;
			if (t.kind == 1) {
				uint32_t enc;
				if (rd32(raw, len, p, &enc)) {
					*err = xstrdup(PANIC_MSG);
					goto out;
				}
				t.is_signed = (enc >> 24) & 1;
			}
			p += 4;
			break;
		case 3: {
			uint32_t e0, e2;
			if (rd32(raw, len, p, &e0) || rd32(raw, len, p + 8, &e2)) {
				*err = xstrdup(PANIC_MSG);
				goto out;
			}
			t.type_id = e0;
			t.nelems = e2;
			p += 12;
			break;
		}
		case 4: case 5:
			t.size = st;
			if (vlen) {
				t.members = calloc(vlen, sizeof(*t.members));
				if (!t.members) {
					*err = xstrdup("out of memory");
					goto out;
				}
			}
			for (uint32_t i = 0; i < vlen; i++) {
				uint32_t m = p + 12 * i, mn, mt, off;
				if (rd32(raw, len, m, &mn) || rd32(raw, len, m + 4, &mt) || rd32(raw, len, m + 8, &off) ||
				    lstr(strs, slen, mn, &t.members[i].name)) {
					free(t.members);
					*err = xstrdup(PANIC_MSG);
					goto out;
				}
				if (kflag) {
					if (off >> 24 != 0)
						t.bitfield = 1;
					off &= 0xffffff;
				}
				t.members[i].type_id = mt;
				t.members[i].offset = off / 8;
				t.n_members++;
			}
			p += 12 * vlen;
			break;
		case 6:
			t.size = st;
			p += 8 * vlen;
			break;
		case 19:
			t.size = st;
			p += 12 * vlen;
			break;
		case 15:
			t.size = st;
			if (vlen) {
				t.secinfo = calloc(vlen, sizeof(*t.secinfo));
				if (!t.secinfo) {
					*err = xstrdup("out of memory");
					goto out;
				}
			}
			for (uint32_t i = 0; i < vlen; i++) {
				uint32_t m = p + 12 * i;
				struct lsecinfo *v = &t.secinfo[i];
				if (rd32(raw, len, m, &v->type_id) || rd32(raw, len, m + 4, &v->offset) || rd32(raw, len, m + 8, &v->size)) {
					free(t.secinfo);
					*err = xstrdup(PANIC_MSG);
					goto out;
				}
				v->pos = m + 4;
				t.n_secinfo++;
			}
			p += 12 * vlen;
			break;
		case 13:
			p += 8 * vlen;
			break;
		case 2: case 8: case 9: case 10: case 11: case 18: case 7: case 12: case 16:
			t.type_id = st;
			if (t.kind == 16)
				t.size = st;
			break;
		default:
			*err = fmts("the .BTF has a type of kind %u that cannot be read", t.kind);
			goto out;
		}
		if (b->n == cap) {
			size_t nc = cap * 2;
			struct ltype *nt = realloc(b->t, nc * sizeof(*nt));
			if (!nt) {
				free(t.members);
				free(t.secinfo);
				*err = xstrdup("out of memory");
				goto out;
			}
			b->t = nt;
			cap = nc;
		}
		b->t[b->n++] = t;
		if (t.kind == 4 && t.name[0]) {
			for (size_t i = 0; i + 1 < b->n; i++) {
				if (b->t[i].kind == 4 && !strcmp(b->t[i].name, t.name)) {
					struct bml_buf m = {0};
					bml_buf_adds(&m, "the .BTF has two structs named ");
					bml_buf_add_goquote(&m, t.name, strlen(t.name));
					bml_buf_adds(&m, " — the layout cannot be checked by name");
					*err = bml_buf_take(&m);
					goto out;
				}
			}
		}
	}
	rc = 0;
out:
	bml_elf_close(&e);
	if (rc)
		btf_layout_free(b);
	return rc;
}


static const struct ltype *find_struct(const struct lbtf *b, const char *name)
{
	for (size_t i = 0; i < b->n; i++)
		if (b->t[i].kind == 4 && b->t[i].name[0] && !strcmp(b->t[i].name, name))
			return &b->t[i];
	return NULL;
}

static const struct ltype void_type = {.name = ""};

const struct ltype *btf_layout_resolve(const struct lbtf *b, uint32_t id)
{
	for (int i = 0; i < 32 && id < b->n; i++) {
		const struct ltype *t = &b->t[id];
		switch (t->kind) {
		case 8: case 9: case 10: case 11: case 18:
			id = t->type_id;
			break;
		default:
			return t;
		}
	}
	return &void_type;
}

static void spell(const struct lbtf *b, uint32_t id, struct bml_buf *o, int depth)
{
	const struct ltype *t = depth > 64 ? &void_type : btf_layout_resolve(b, id);
	switch (t->kind) {
	case 1:
		bml_buf_addf(o, "%s%u", t->is_signed ? "i" : "u", (uint32_t)(t->size * 8));
		return;
	case 3:
		bml_buf_addf(o, "[%u]", t->nelems);
		spell(b, t->type_id, o, depth + 1);
		return;
	case 4:
		if (!t->name[0])
			bml_buf_adds(o, "?anonymous_struct");
		else if (!strcmp(t->name, "bpf_spin_lock") || !strcmp(t->name, "bpf_timer"))
			bml_buf_adds(o, t->name);
		else {
			bml_buf_adds(o, "record:");
			bml_buf_adds(o, t->name);
		}
		return;
	case 5:
		bml_buf_adds(o, "?union");
		return;
	case 2: {
		const struct ltype *s = NULL;
		if (t->type_id < b->n && b->t[t->type_id].kind == 18 && !strcmp(b->t[t->type_id].name, "kptr") && !BML_MUT("maps.kptr_as_pointer"))
			s = btf_layout_resolve(b, b->t[t->type_id].type_id);
		if (s && s->kind == 4 && s->name[0]) {
			bml_buf_adds(o, "kptr:");
			bml_buf_adds(o, s->name);
		} else
			bml_buf_adds(o, "?pointer");
		return;
	}
	case 6: case 19:
		bml_buf_adds(o, "?enum");
		return;
	}
	bml_buf_addf(o, "?btf_kind_%u", t->kind);
}
static int cmp_indexed(const void *a, const void *b)
{
	const struct btf_indexed *x = a, *y = b;
	if (x->m.offset != y->m.offset)
		return x->m.offset < y->m.offset ? -1 : 1;
	return x->idx < y->idx ? -1 : (x->idx > y->idx);
}

char *btf_shape_string(uint32_t size, struct btf_indexed *ms, size_t n)
{
	qsort(ms, n, sizeof(*ms), cmp_indexed);
	struct bml_buf b = {0};
	bml_buf_addf(&b, "size=%u;", size);
	for (size_t i = 0; i < n; i++)
		bml_buf_addf(&b, "%s:%u:%s;", ms[i].m.name, ms[i].m.offset, ms[i].m.type);
	return bml_buf_take(&b);
}


char *btf_layout_record(const struct lbtf *b, const char *name, int *missing)
{
	*missing = 0;
	const struct ltype *t = find_struct(b, name);
	if (!t) {
		*missing = 1;
		return NULL;
	}
	struct btf_indexed *ms = calloc(t->n_members + 1, sizeof(*ms));
	if (!ms)
		return NULL;
	for (uint32_t i = 0; i < t->n_members; i++) {
		struct bml_buf ty = {0};
		if (t->bitfield)
			bml_buf_adds(&ty, "?bitfield");
		else
			spell(b, t->members[i].type_id, &ty, 0);
		ms[i].m.name = t->members[i].name;
		ms[i].m.offset = t->members[i].offset;
		ms[i].m.type = bml_buf_take(&ty);
		ms[i].idx = i;
	}
	char *s = btf_shape_string(t->size, ms, t->n_members);
	for (uint32_t i = 0; i < t->n_members; i++)
		free(ms[i].m.type);
	free(ms);
	return s;
}
