#include "dwarf/internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void dw_buf_init(struct dw_buf *b, const struct dw *d, const struct dw_unit *u, const char *name, uint64_t off, const uint8_t *p, size_t n)
{
	*b = (struct dw_buf){d, u, name, off, p, n, NULL};
}

void dw_buf_error(struct dw_buf *b, const char *s)
{
	if (b->err)
		return;
	b->p = NULL;
	b->n = 0;
	size_t len = strlen(s) + strlen(b->name) + 64;
	b->err = malloc(len);
	if (b->err)
		snprintf(b->err, len, "decoding dwarf section %s at offset 0x%llx: %s", b->name, (unsigned long long)b->off, s);
}

const uint8_t *dw_bytes(struct dw_buf *b, uint64_t n)
{
	if (b->n < n) {
		dw_buf_error(b, "underflow");
		return NULL;
	}
	const uint8_t *p = b->p;
	b->p += n;
	b->n -= (size_t)n;
	b->off += n;
	return p;
}

static uint64_t fixed(struct dw_buf *b, int size)
{
	const uint8_t *p = dw_bytes(b, (uint64_t)size);
	if (!p)
		return 0;
	uint64_t v = 0;
	for (int i = 0; i < size; i++)
		v |= (uint64_t)p[b->d->big ? size - 1 - i : i] << (8 * i);
	return v;
}

uint8_t dw_u8(struct dw_buf *b)
{
	return (uint8_t)fixed(b, 1);
}
uint16_t dw_u16(struct dw_buf *b)
{
	return (uint16_t)fixed(b, 2);
}
uint32_t dw_u32(struct dw_buf *b)
{
	return (uint32_t)fixed(b, 4);
}
uint64_t dw_u64(struct dw_buf *b)
{
	return fixed(b, 8);
}


static uint64_t varint(struct dw_buf *b, unsigned *bits)
{
	uint64_t c = 0;
	*bits = 0;
	for (size_t i = 0; i < b->n; i++) {
		uint8_t x = b->p[i];
		if (*bits < 64)
			c |= (uint64_t)(x & 0x7f) << *bits;
		*bits += 7;
		if (!(x & 0x80)) {
			b->p += i + 1;
			b->n -= i + 1;
			b->off += i + 1;
			return c;
		}
	}
	*bits = 0;
	return 0;
}



uint64_t dw_uleb(struct dw_buf *b)
{
	unsigned bits;
	uint64_t x = varint(b, &bits);
	if (bits == 0)
		dw_buf_error(b, "underflow");
	return x;
}

int64_t dw_sleb(struct dw_buf *b)
{
	unsigned bits;
	uint64_t ux = varint(b, &bits);
	if (bits > 0 && bits <= 64 && (ux >> (bits - 1) & 1))
		ux |= bits >= 64 ? 0 : ~0ull << bits;
	if (bits == 0)
		dw_buf_error(b, "underflow");
	return (int64_t)ux;
}


static const char *cstring(struct dw_buf *b)
{
	const uint8_t *z = b->n ? memchr(b->p, 0, b->n) : NULL;
	if (!z) {
		dw_buf_error(b, "underflow");
		return "";
	}
	const char *s = (const char *)b->p;
	dw_bytes(b, (uint64_t)(z - b->p) + 1);
	return s;
}

static uint64_t addr(struct dw_buf *b)
{
	int sz = b->u ? b->u->asize : 0;
	if (sz == 1 || sz == 2 || sz == 4 || sz == 8)
		return fixed(b, sz);
	dw_buf_error(b, "unknown address size");
	return 0;
}


static const char *str_at(struct dw_buf *b, const char *name, struct dw_sect s, uint64_t off)
{
	struct dw_buf b1;
	dw_buf_init(&b1, b->d, b->u, name, 0, s.p, s.n);
	dw_bytes(&b1, off);
	const char *v = cstring(&b1);
	if (b1.err) {
		if (!b->err) {
			b->err = b1.err;
			b->p = NULL;
			b->n = 0;
		} else
			free(b1.err);
		return "";
	}
	return v;
}

static uint64_t off_sized(struct dw_buf *b, const char *what)
{
	if (!b->u) {
		char m[64];
		snprintf(m, sizeof m, "unknown size for %s", what);
		dw_buf_error(b, m);
		return 0;
	}
	return b->u->is64 ? dw_u64(b) : dw_u32(b);
}

static int known_form(uint64_t f)
{
	return (f >= 0x01 && f <= 0x2c && f != 0x02) || f == 0x1f20 || f == 0x1f21;
}

const struct dw_val *dw_val(const struct dw_entry *e, uint64_t attr)
{
	for (size_t i = 0; i < e->n; i++)
		if (e->v[i].attr == attr)
			return &e->v[i];
	return NULL;
}

void dw_entry_free(struct dw_entry *e)
{
	free(e->v);
	memset(e, 0, sizeof *e);
}

static void one_val(struct dw_buf *b, const struct dw_unit *u, const struct dw_field *f, struct dw_val *v)
{
	uint64_t fm = f->form;
	*v = (struct dw_val){.attr = f->attr};
	if (fm == 0x16) {
		fm = dw_uleb(b);
		if (!known_form(fm)) {
			dw_buf_error(b, "cannot determine class of unknown attribute form");
			return;
		}
	}
	int is64 = u->is64;
	uint64_t o;
	switch (fm) {
	case 0x01: v->kind = DV_UINT, v->u = addr(b); break;
	case 0x1b: case 0x29: case 0x2a: case 0x2b: case 0x2c:
		o = fm == 0x1b ? dw_uleb(b) : fixed(b, fm == 0x29 ? 1 : fm == 0x2a ? 2 : fm == 0x2b ? 3 : 4);
		if (!b->d->addr.p)
			dw_buf_error(b, "DW_FORM_addrx with no .debug_addr section");
		if (b->err)
			return;
		{
			struct dw_buf b1;
			dw_buf_init(&b1, b->d, u, "addr", 0, b->d->addr.p, b->d->addr.n);
			dw_bytes(&b1, o * (uint64_t)u->asize + u->addr_base);
			v->kind = DV_UINT, v->u = addr(&b1);
			if (b1.err) {
				b->err = b1.err;
				b->p = NULL;
				b->n = 0;
			}
		}
		break;
	case 0x0a: v->kind = DV_BYTES, dw_bytes(b, dw_u8(b)); break;
	case 0x03: v->kind = DV_BYTES, dw_bytes(b, dw_u16(b)); break;
	case 0x04: v->kind = DV_BYTES, dw_bytes(b, dw_u32(b)); break;
	case 0x09: case 0x18: v->kind = DV_BYTES, dw_bytes(b, dw_uleb(b)); break;
	case 0x0b: v->kind = DV_INT, v->i = dw_u8(b); break;
	case 0x05: v->kind = DV_INT, v->i = dw_u16(b); break;
	case 0x06: v->kind = DV_INT, v->i = dw_u32(b); break;
	case 0x07: v->kind = DV_INT, v->i = (int64_t)dw_u64(b); break;
	case 0x1e: v->kind = DV_BYTES, dw_bytes(b, 16); break;
	case 0x0d: v->kind = DV_INT, v->i = dw_sleb(b); break;
	case 0x0f: v->kind = DV_INT, v->i = (int64_t)dw_uleb(b); break;
	case 0x21: v->kind = DV_INT, v->i = f->form == 0x21 ? f->val : 0; break;
	case 0x0c: v->kind = DV_BOOL, v->i = dw_u8(b) == 1; break;
	case 0x19: v->kind = DV_BOOL, v->i = 1; break;
	case 0x10:
		if (u->vers == 2)
			v->kind = DV_OFF, v->u = addr(b);
		else
			v->kind = DV_OFF, v->u = is64 ? dw_u64(b) : dw_u32(b);
		break;
	case 0x11: v->kind = DV_OFF, v->u = dw_u8(b) + u->base; break;
	case 0x12: v->kind = DV_OFF, v->u = dw_u16(b) + u->base; break;
	case 0x13: v->kind = DV_OFF, v->u = dw_u32(b) + u->base; break;
	case 0x14: v->kind = DV_OFF, v->u = dw_u64(b) + u->base; break;
	case 0x15: v->kind = DV_OFF, v->u = dw_uleb(b) + u->base; break;
	case 0x08: v->kind = DV_STR, v->s = cstring(b); break;
	case 0x0e: case 0x1f:
		o = off_sized(b, "DW_FORM_strp/line_strp");
		if (b->err)
			return;
		if (fm == 0x1f && !b->d->line_str.n) {
			dw_buf_error(b, "DW_FORM_line_strp with no .debug_line_str section");
			return;
		}
		v->kind = DV_STR, v->s = str_at(b, fm == 0x0e ? "str" : "line_str", fm == 0x0e ? b->d->str : b->d->line_str, o);
		break;
	case 0x1a: case 0x25: case 0x26: case 0x27: case 0x28: {
		o = fm == 0x1a ? dw_uleb(b) : fixed(b, fm - 0x24);
		if (!b->d->str_offsets.n)
			dw_buf_error(b, "DW_FORM_strx with no .debug_str_offsets section");
		if (b->err)
			return;
		struct dw_buf b1;
		dw_buf_init(&b1, b->d, u, "str_offsets", 0, b->d->str_offsets.p, b->d->str_offsets.n);
		dw_bytes(&b1, o * (is64 ? 8 : 4) + u->str_base);
		uint64_t so = is64 ? dw_u64(&b1) : dw_u32(&b1);
		if (b1.err) {
			b->err = b1.err;
			b->p = NULL;
			b->n = 0;
			return;
		}
		v->kind = DV_STR, v->s = str_at(b, "str", b->d->str, so);
		break;
	}
	case 0x1d: v->kind = DV_UINT, v->u = off_sized(b, "DW_FORM_strp_sup"); break;
	case 0x17: case 0x1f20: case 0x1f21: v->kind = DV_INT, v->i = (int64_t)off_sized(b, "form"); break;
	case 0x20: case 0x24: v->kind = DV_UINT, v->u = dw_u64(b); break;
	case 0x1c: v->kind = DV_UINT, v->u = dw_u32(b); break;
	case 0x22: v->kind = DV_UINT, v->u = dw_uleb(b); break;
	case 0x23: {
		o = dw_uleb(b) * (is64 ? 8 : 4) + u->rng_base;
		struct dw_buf b1;
		dw_buf_init(&b1, b->d, u, "rnglists", 0, b->d->rnglists.p, b->d->rnglists.n);
		dw_bytes(&b1, o);
		uint64_t r = is64 ? dw_u64(&b1) : dw_u32(&b1);
		if (b1.err) {
			if (!b->err)
				b->err = b1.err;
			else
				free(b1.err);
			b->p = NULL;
			b->n = 0;
			return;
		}
		v->kind = DV_UINT, v->u = u->rng_base + r;
		break;
	}
	default: {
		char m[64];
		snprintf(m, sizeof m, "unknown entry attr format 0x%llx", (unsigned long long)fm);
		dw_buf_error(b, m);
	}
	}
}

int dw_entry_decode(struct dw_buf *b, const struct dw_unit *u, struct dw_entry *e)
{
	memset(e, 0, sizeof *e);
	uint64_t off = b->off, id = dw_uleb(b);
	if (id == 0)
		return b->err ? -1 : 0;
	const struct dw_abbrev *a = NULL;
	for (size_t i = u->at ? u->at->n : 0; i-- > 0;)
		if (u->at->a[i].id == id) {
			a = &u->at->a[i];
			break;
		}
	if (!a) {
		dw_buf_error(b, "unknown abbreviation table index");
		return -1;
	}
	e->off = off;
	e->tag = a->tag;
	e->children = a->children;
	e->v = calloc(a->n ? a->n : 1, sizeof *e->v);
	if (!e->v) {
		dw_buf_error(b, "out of memory");
		return -1;
	}
	e->n = a->n;
	for (size_t i = 0; i < a->n && !b->err; i++)
		one_val(b, u, &a->f[i], &e->v[i]);
	if (b->err) {
		dw_entry_free(e);
		return -1;
	}
	return 0;
}



static void set_err(struct dw_reader *r, char *e)
{
	if (!r->err)
		r->err = e;
	else
		free(e);
}


static void collect_bases(struct dw_reader *r, struct dw_unit *u)
{
	if (u->vers < 5 || u->have5)
		return;
	u->have5 = 1;
	struct dw_buf b;
	dw_buf_init(&b, r->d, u, "info", u->off, u->data, u->len);
	struct dw_entry e;
	if (dw_entry_decode(&b, u, &e) != 0) {
		set_err(r, b.err);
		return;
	}
	const struct dw_val *v;
	if ((v = dw_val(&e, 0x73)) && v->kind == DV_INT)
		u->addr_base = (uint64_t)v->i;
	if ((v = dw_val(&e, 0x72)) && v->kind == DV_INT)
		u->str_base = (uint64_t)v->i;
	if ((v = dw_val(&e, 0x74)) && v->kind == DV_INT)
		u->rng_base = (uint64_t)v->i;
	dw_entry_free(&e);
}

static void next_unit(struct dw_reader *r)
{
	struct dw_unit *u = &r->d->u[++r->unit];
	dw_buf_init(&r->b, r->d, u, "info", u->off, u->data, u->len);
	collect_bases(r, u);
}

void dw_seek(struct dw_reader *r, uint64_t off)
{
	free(r->err);
	r->err = NULL;
	r->last_children = 0;
	if (off == 0) {
		if (!r->d->nu)
			return;
		struct dw_unit *u = &r->d->u[0];
		r->unit = 0;
		dw_buf_init(&r->b, r->d, u, "info", u->off, u->data, u->len);
		collect_bases(r, u);
		return;
	}
	for (size_t i = 0; i < r->d->nu; i++) {
		struct dw_unit *u = &r->d->u[i];
		if (u->off <= off && off < u->off + u->len) {
			r->unit = i;
			dw_buf_init(&r->b, r->d, u, "info", off, u->data + (off - u->off), u->len - (size_t)(off - u->off));
			collect_bases(r, u);
			return;
		}
	}
	set_err(r, strdup("offset out of range"));
}

void dw_reader_init(struct dw_reader *r, struct dw *d)
{
	memset(r, 0, sizeof *r);
	r->d = d;
	dw_buf_init(&r->b, d, NULL, "info", 0, NULL, 0);
	dw_seek(r, 0);
}

void dw_reader_free(struct dw_reader *r)
{
	free(r->err);
	free(r->b.err);
	r->err = r->b.err = NULL;
}

int dw_next(struct dw_reader *r, struct dw_entry *e)
{
	memset(e, 0, sizeof *e);
	if (r->err)
		return -1;
	while (r->b.n == 0 && r->unit + 1 < r->d->nu)
		next_unit(r);
	if (r->err)
		return -1;
	if (r->b.n == 0)
		return 0;
	if (dw_entry_decode(&r->b, &r->d->u[r->unit], e) != 0) {
		set_err(r, r->b.err);
		r->b.err = NULL;
		return -1;
	}
	r->last_unit = 0;
	r->last_children = e->children;
	r->last_sibling = 0;
	if (e->children) {
		const struct dw_val *s = dw_val(e, 0x01);
		r->last_sibling = s && s->kind == DV_OFF ? s->u : 0;
	}
	if (e->tag == 0x11 || e->tag == 0x3c)
		r->last_unit = 1;
	return 1;
}

void dw_skip_children(struct dw_reader *r)
{
	if (r->err || !r->last_children)
		return;
	if (r->last_sibling >= r->b.off) {
		dw_seek(r, r->last_sibling);
		return;
	}
	if (r->last_unit && r->unit + 1 < r->d->nu) {
		next_unit(r);
		return;
	}
	for (;;) {
		struct dw_entry e;
		int rc = dw_next(r, &e);
		int kids = rc == 1 && e.tag != 0 && e.children;
		int stop = rc != 1 || e.tag == 0;
		dw_entry_free(&e);
		if (stop)
			break;
		if (kids)
			dw_skip_children(r);
	}
}
