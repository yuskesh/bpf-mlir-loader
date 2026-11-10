




#include "dwarf/internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#include "util/mutation.h"

static int ferr(char **err, const char *fmt, const char *a)
{
	size_t n = strlen(fmt) + (a ? strlen(a) : 0) + 1;
	*err = malloc(n);
	if (*err)
		snprintf(*err, n, fmt, a ? a : "");
	return -1;
}


static uint8_t *inflate_all(const uint8_t *src, size_t n, uint64_t want, char **err)
{
	if (want > (1ull << 32)) {
		ferr(err, "the decompressed section is too large%s", NULL);
		return NULL;
	}
	uint8_t *out = malloc(want ? want : 1);
	if (!out) {
		ferr(err, "out of memory%s", NULL);
		return NULL;
	}
	z_stream z;
	memset(&z, 0, sizeof z);
	z.next_in = (Bytef *)src;
	z.avail_in = (uInt)n;
	z.next_out = out;
	z.avail_out = (uInt)want;
	int rc = inflateInit(&z);
	if (rc == Z_OK)
		rc = inflate(&z, Z_FINISH);
	uLong got = z.total_out;
	inflateEnd(&z);
	if ((rc != Z_STREAM_END && rc != Z_BUF_ERROR && rc != Z_OK) || got != want) {
		free(out);
		ferr(err, "zlib: the compressed section is corrupt or short%s", NULL);
		return NULL;
	}
	return out;
}


static int section_data(const struct bml_elf *e, const struct bml_elf_shdr *s, struct dw_sect *out, uint8_t **owned, char **err)
{
	*owned = NULL;
	if (s->type == BML_SHT_NOBITS) {
		if (s->size > (1ull << 30))
			return ferr(err, "section %s is too large", s->name);
		*owned = calloc(1, s->size ? s->size : 1);
		if (!*owned)
			return ferr(err, "out of memory%s", NULL);
		out->p = *owned;
		out->n = (size_t)s->size;
		return 0;
	}
	if (s->offset > e->len || s->size > e->len - s->offset)
		return ferr(err, "unexpected EOF reading section %s", s->name);
	const uint8_t *raw = e->data + s->offset;
	size_t n = (size_t)s->size;
	if (s->flags & BML_SHF_COMPRESSED) {
		size_t hl = e->is64 ? 24 : 12;
		if (n < hl)
			return ferr(err, "section %s: short compression header", s->name);
		uint32_t type = bml_elf_u32(e, raw);
		uint64_t size = e->is64 ? bml_elf_u64(e, raw + 8) : bml_elf_u32(e, raw + 4);
		if (type != 1)
			return ferr(err, type == 2 ? "section %s is zstd-compressed (bpf-mlir-loader decompresses only zlib)"
						   : "section %s has an unknown compression type",
				    s->name);
		*owned = inflate_all(raw + hl, n - hl, size, err);
		if (!*owned)
			return -1;
		out->p = *owned;
		out->n = (size_t)size;
		return 0;
	}
	if (!strncmp(s->name, ".zdebug", 7) && n >= 12 && !memcmp(raw, "ZLIB", 4)) {
		uint64_t size = 0;
		for (int i = 4; i < 12; i++)
			size = size << 8 | raw[i];
		*owned = inflate_all(raw + 12, n - 12, size, err);
		if (!*owned)
			return -1;
		out->p = *owned;
		out->n = (size_t)size;
		return 0;
	}
	out->p = raw;
	out->n = n;
	return 0;
}

static const char *suffix(const char *name)
{
	return !strncmp(name, ".debug_", 7) ? name + 7 : !strncmp(name, ".zdebug_", 8) ? name + 8 : NULL;
}


static int known_form(uint64_t f)
{
	return (f >= 0x01 && f <= 0x2c && f != 0x02) || f == 0x1f20 || f == 0x1f21;
}

static struct dw_atable *parse_abbrev(struct dw *d, uint64_t off, char **err)
{
	for (size_t i = 0; i < d->ntabs; i++)
		if (d->tabs[i]->off == off)
			return d->tabs[i];
	struct dw_buf b;
	dw_buf_init(&b, d, NULL, "abbrev", 0, off > d->abbrev.n ? NULL : d->abbrev.p + off, off > d->abbrev.n ? 0 : d->abbrev.n - (size_t)off);
	struct dw_atable t = {off, NULL, 0};
	for (;;) {
		uint64_t id = dw_uleb(&b);
		if (id == 0 || b.err)
			break;
		struct dw_abbrev a = {.id = id};
		a.tag = dw_uleb(&b);
		a.children = dw_u8(&b) != 0;
		for (;;) {
			uint64_t at = dw_uleb(&b), fm = dw_uleb(&b);
			if (at == 0 && fm == 0)
				break;
			if (!known_form(fm)) {
				dw_buf_error(&b, "cannot determine class of unknown attribute form");
				break;
			}
			int64_t v = fm == 0x21 ? dw_sleb(&b) : 0;
			struct dw_field *nf = realloc(a.f, (a.n + 1) * sizeof *nf);
			if (!nf) {
				dw_buf_error(&b, "out of memory");
				break;
			}
			a.f = nf;
			a.f[a.n++] = (struct dw_field){at, fm, v};
			if (b.err)
				break;
		}
		struct dw_abbrev *na = b.err ? NULL : realloc(t.a, (t.n + 1) * sizeof *na);
		if (!na) {
			free(a.f);
			break;
		}
		t.a = na;
		t.a[t.n++] = a;
	}
	if (b.err) {
		*err = b.err;
		for (size_t i = 0; i < t.n; i++)
			free(t.a[i].f);
		free(t.a);
		return NULL;
	}
	struct dw_atable **nt = realloc(d->tabs, (d->ntabs + 1) * sizeof *nt), *p = malloc(sizeof *p);
	if (nt)
		d->tabs = nt;
	if (!nt || !p) {
		for (size_t i = 0; i < t.n; i++)
			free(t.a[i].f);
		free(t.a);
		free(p);
		ferr(err, "out of memory%s", NULL);
		return NULL;
	}
	*p = t;
	d->tabs[d->ntabs++] = p;
	return p;
}


static int parse_units(struct dw *d, char **err)
{
	const uint8_t *in = d->info.p;
	size_t n = d->info.n;
	char off_s[32];
	if (n < 6)
		return snprintf(off_s, sizeof off_s, "%zx", n), ferr(err, "decoding dwarf section info at offset 0x%s: too short", off_s);
	size_t o = 4;
	if (in[0] == 0xff && in[1] == 0xff && in[2] == 0xff && in[3] == 0xff) {
		if (n < 14)
			return snprintf(off_s, sizeof off_s, "%zx", n), ferr(err, "decoding dwarf section info at offset 0x%s: too short", off_s);
		o = 12;
	}
	uint8_t x = in[o], y = in[o + 1];
	if (x == 0 && y == 0)
		return ferr(err, "decoding dwarf section info at offset 0x4: unsupported version 0%s", NULL);
	if (x != 0 && y != 0)
		return ferr(err, "decoding dwarf section info at offset 0x4: cannot determine byte order%s", NULL);
	d->big = x == 0;

	struct dw_buf b;
	size_t cnt = 0;
	dw_buf_init(&b, d, NULL, "info", 0, in, n);
	while (b.n > 0 && !b.err) {
		int is64 = 0;
		uint64_t len = dw_u32(&b);
		if (len == 0xffffffff) {
			is64 = 1;
			len = dw_u64(&b);
		} else if (len >= 0xfffffff0)
			dw_buf_error(&b, "unit length has reserved value");
		(void)is64;
		if (len != (uint32_t)len) {
			dw_buf_error(&b, "unit length overflow");
			break;
		}
		dw_bytes(&b, len);
		cnt += len > 0;
	}
	if (b.err)
		return (*err = b.err, -1);
	d->u = calloc(cnt ? cnt : 1, sizeof *d->u);
	if (!d->u)
		return ferr(err, "out of memory%s", NULL);

	dw_buf_init(&b, d, NULL, "info", 0, in, n);
	for (size_t i = 0; i < cnt; i++) {
		struct dw_unit *u = &d->u[i];
		u->base = b.off;
		if (b.err)
			break;
		uint64_t len = 0;
		while (len == 0 && !b.err) {
			len = dw_u32(&b);
			u->is64 = 0;
			if (len == 0xffffffff) {
				u->is64 = 1;
				len = dw_u64(&b);
			} else if (len >= 0xfffffff0)
				dw_buf_error(&b, "unit length has reserved value");
		}
		uint64_t data_off = b.off;
		uint16_t vers = dw_u16(&b);
		if (vers < 2 || vers > 5) {
			char m[48];
			snprintf(m, sizeof m, "unsupported DWARF version %u", vers);
			dw_buf_error(&b, m);
			break;
		}
		u->vers = vers;
		if (vers >= 5) {
			u->utype = dw_u8(&b);
			u->asize = dw_u8(&b);
		}
		uint64_t aoff = u->is64 ? dw_u64(&b) : dw_u32(&b);
		char *aerr = NULL;
		u->at = parse_abbrev(d, aoff, &aerr);
		if (!u->at) {
			if (!b.err)
				b.err = aerr;
			else
				free(aerr);
			break;
		}
		if (vers < 5)
			u->asize = dw_u8(&b);
		if (u->utype == 4 || u->utype == 5)
			dw_u64(&b);
		else if (u->utype == 2 || u->utype == 6) {
			dw_u64(&b);
			if (u->is64)
				dw_u64(&b);
			else
				dw_u32(&b);
		}
		u->off = b.off;
		uint64_t rest = len - (b.off - data_off);
		u->data = dw_bytes(&b, rest);
		u->len = u->data ? (size_t)rest : 0;
	}
	if (b.err)
		return (*err = b.err, -1);
	d->nu = cnt;
	return 0;
}

int dw_open(const struct bml_elf *elf, struct dw *d, char **err)
{
	memset(d, 0, sizeof *d);
	*err = NULL;
	for (size_t i = 0; i < elf->n_sections; i++) {
		const struct bml_elf_shdr *r = &elf->sections[i];
		if (elf->type != 2               && (r->type == BML_SHT_REL || r->type == 4               ) && r->info < elf->n_sections &&
		    suffix(elf->sections[r->info].name))
			return ferr(err, "relocations of the DWARF section %s are not supported (bpf-mlir-loader reads linked binaries)",
				    elf->sections[r->info].name);
	}

	for (size_t i = 0; i < elf->n_sections; i++) {
		const struct bml_elf_shdr *s = &elf->sections[i];
		const char *sfx = suffix(s->name);
		if (!sfx)
			continue;
		struct dw_sect sd;
		uint8_t *own = NULL;
		char *serr = NULL;
		if (section_data(elf, s, &sd, &own, &serr) != 0) {
			ferr(err, "%s", serr);
			free(serr);
			dw_close(d);
			return -1;
		}
		if (own) {
			uint8_t **no = realloc(d->owned, (d->n_owned + 1) * sizeof *no);
			if (!no) {
				free(own);
				dw_close(d);
				return ferr(err, "out of memory%s", NULL);
			}
			d->owned = no;
			d->owned[d->n_owned++] = own;
		}
		struct dw_sect *slot = !strcmp(sfx, "abbrev") ? &d->abbrev : !strcmp(sfx, "info") ? &d->info : !strcmp(sfx, "str") ? &d->str
				      : !strcmp(sfx, "line_str") ? &d->line_str : !strcmp(sfx, "str_offsets") ? &d->str_offsets
				      : !strcmp(sfx, "addr") ? &d->addr : !strcmp(sfx, "rnglists") ? &d->rnglists : NULL;
		if (slot)
			*slot = sd;
	}
	char *perr = NULL;
	if (parse_units(d, &perr) != 0) {
		ferr(err, "%s", perr);
		free(perr);
		dw_close(d);
		return -1;
	}
	return 0;
}

void dw_close(struct dw *d)
{
	for (size_t i = 0; i < d->n_owned; i++)
		free(d->owned[i]);
	free(d->owned);
	for (size_t i = 0; i < d->ntabs; i++) {
		for (size_t k = 0; k < d->tabs[i]->n; k++)
			free(d->tabs[i]->a[k].f);
		free(d->tabs[i]->a);
		free(d->tabs[i]);
	}
	free(d->tabs);
	free(d->u);
	memset(d, 0, sizeof *d);
}
