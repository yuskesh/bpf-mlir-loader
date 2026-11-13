#include "elf/elf.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"

static int ferr(char **err, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int ferr(char **err, const char *fmt, ...)
{
	struct bml_buf b = {0};
	char tmp[256];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	bml_buf_adds(&b, tmp);
	*err = bml_buf_take(&b);
	return -1;
}

uint16_t bml_elf_u16(const struct bml_elf *e, const uint8_t *p)
{
	return e->big_endian ? (uint16_t)(p[0] << 8 | p[1]) : (uint16_t)(p[1] << 8 | p[0]);
}

uint32_t bml_elf_u32(const struct bml_elf *e, const uint8_t *p)
{
	return e->big_endian ? (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]
			     : (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0];
}

uint64_t bml_elf_u64(const struct bml_elf *e, const uint8_t *p)
{
	uint64_t hi = bml_elf_u32(e, p + (e->big_endian ? 0 : 4)), lo = bml_elf_u32(e, p + (e->big_endian ? 4 : 0));
	return hi << 32 | lo;
}


static int in_file(const struct bml_elf *e, uint64_t off, uint64_t n)
{
	return off <= e->len && n <= e->len - off;
}

void bml_elf_close(struct bml_elf *e)
{
	free(e->sections);
	free(e->progs);
	memset(e, 0, sizeof(*e));
}

int bml_elf_open(const void *data, size_t len, struct bml_elf *e, char **err)
{
	memset(e, 0, sizeof(*e));
	*err = NULL;
	e->data = data;
	e->len = len;
	const uint8_t *d = data;
	if (len < 16)
		return ferr(err, "cannot read ELF identifier");
	if (memcmp(d, "\x7f" "ELF", 4) != 0)
		return ferr(err, "bad magic number");
	if (d[4] != 1 && d[4] != 2)
		return ferr(err, "unknown ELF class %u", d[4]);
	e->is64 = d[4] == 2;
	if (d[5] != 1 && d[5] != 2)
		return ferr(err, "unknown ELF data encoding %u", d[5]);
	e->big_endian = d[5] == 2;
	if (d[6] != 1)
		return ferr(err, "unknown ELF version %u", d[6]);
	size_t hsz = e->is64 ? 64 : 52;
	if (len < hsz)
		return ferr(err, "unexpected EOF reading the ELF header");
	uint64_t phoff, shoff;
	unsigned phentsize, phnum, shentsize, shnum, shstrndx;
	e->type = bml_elf_u16(e, d + 16);
	e->machine = bml_elf_u16(e, d + 18);
	

	if (bml_elf_u32(e, d + 20) != 1)
		return ferr(err, "mismatched ELF version");
	if (e->is64) {
		phoff = bml_elf_u64(e, d + 32);
		shoff = bml_elf_u64(e, d + 40);
		phentsize = bml_elf_u16(e, d + 54);
		phnum = bml_elf_u16(e, d + 56);
		shentsize = bml_elf_u16(e, d + 58);
		shnum = bml_elf_u16(e, d + 60);
		shstrndx = bml_elf_u16(e, d + 62);
	} else {
		phoff = bml_elf_u32(e, d + 28);
		shoff = bml_elf_u32(e, d + 32);
		phentsize = bml_elf_u16(e, d + 42);
		phnum = bml_elf_u16(e, d + 44);
		shentsize = bml_elf_u16(e, d + 46);
		shnum = bml_elf_u16(e, d + 48);
		shstrndx = bml_elf_u16(e, d + 50);
	}
	if ((int64_t)shoff < 0)
		return ferr(err, "invalid shoff");
	if ((int64_t)phoff < 0)
		return ferr(err, "invalid phoff");
	if (shoff == 0 && shnum != 0)
		return ferr(err, "invalid ELF shnum for shoff=0");
	if (shnum > 0 && shstrndx >= shnum)
		return ferr(err, "invalid ELF shstrndx");
	unsigned want_ph = e->is64 ? 56 : 32, want_sh = e->is64 ? 64 : 40;
	if (phnum > 0 && phentsize < want_ph)
		return ferr(err, "invalid ELF phentsize");
	uint64_t n_sh = shnum, n_ph = phnum;
	if (shoff > 0 && (shnum == 0 || phnum == 0xffff)) {

		if (!in_file(e, shoff, want_sh))
			return ferr(err, "unexpected EOF reading section 0");
		const uint8_t *s0 = d + shoff;
		uint32_t typ = bml_elf_u32(e, s0 + 4);
		uint32_t link = e->is64 ? bml_elf_u32(e, s0 + 40) : bml_elf_u32(e, s0 + 24);
		uint32_t info = e->is64 ? bml_elf_u32(e, s0 + 44) : bml_elf_u32(e, s0 + 28);
		uint64_t size = e->is64 ? bml_elf_u64(e, s0 + 32) : bml_elf_u32(e, s0 + 20);
		if (typ != BML_SHT_NULL)
			return ferr(err, "invalid type of the initial section");
		if (shnum == 0) {
			if (size < 0xff00)
				return ferr(err, "invalid ELF shnum contained in sh_size");
			n_sh = size;
		}
		if (phnum == 0xffff) {
			if (info < 0xffff)
				return ferr(err, "invalid ELF phnum contained in sh_info");
			n_ph = info;
		}
		if (shstrndx == 0xffff) {
			shstrndx = link;
			if (shstrndx < 0xff00 || shstrndx >= n_sh)
				return ferr(err, "invalid ELF shstrndx contained in sh_link");
		}
	}

	if (n_ph > 0 && UINT64_MAX / n_ph < phentsize)
		return ferr(err, "segment header overflow");
	if (n_ph * phentsize > 0 && !in_file(e, phoff, n_ph * phentsize))
		return ferr(err, "unexpected EOF reading program headers");
	if (n_ph) {
		e->progs = calloc(n_ph, sizeof(*e->progs));
		if (!e->progs)
			return ferr(err, "out of memory");
	}
	for (uint64_t i = 0; i < n_ph; i++) {
		const uint8_t *p = d + phoff + i * phentsize;
		struct bml_elf_phdr *ph = &e->progs[i];
		if (e->is64) {
			ph->type = bml_elf_u32(e, p);
			ph->flags = bml_elf_u32(e, p + 4);
			ph->offset = bml_elf_u64(e, p + 8);
			ph->vaddr = bml_elf_u64(e, p + 16);
			ph->paddr = bml_elf_u64(e, p + 24);
			ph->filesz = bml_elf_u64(e, p + 32);
			ph->memsz = bml_elf_u64(e, p + 40);
			ph->align = bml_elf_u64(e, p + 48);
		} else {
			ph->type = bml_elf_u32(e, p);
			ph->offset = bml_elf_u32(e, p + 4);
			ph->vaddr = bml_elf_u32(e, p + 8);
			ph->paddr = bml_elf_u32(e, p + 12);
			ph->filesz = bml_elf_u32(e, p + 16);
			ph->memsz = bml_elf_u32(e, p + 20);
			ph->flags = bml_elf_u32(e, p + 24);
			ph->align = bml_elf_u32(e, p + 28);
		}
		if ((int64_t)ph->offset < 0 || (int64_t)ph->filesz < 0) {
			bml_elf_close(e);
			return ferr(err, "invalid program header offset or file size");
		}
		e->n_progs++;
	}
	if (n_sh > 0 && shentsize < want_sh) {
		bml_elf_close(e);
		return ferr(err, "invalid ELF shentsize");
	}
	if (n_sh > 0 && UINT64_MAX / n_sh < shentsize) {
		bml_elf_close(e);
		return ferr(err, "section header overflow");
	}
	if (n_sh * shentsize > 0 && !in_file(e, shoff, n_sh * shentsize)) {
		bml_elf_close(e);
		return ferr(err, "unexpected EOF reading section headers");
	}
	uint32_t *names = NULL;
	if (n_sh) {
		e->sections = calloc(n_sh, sizeof(*e->sections));
		names = calloc(n_sh, sizeof(*names));
		if (!e->sections || !names) {
			free(names);
			bml_elf_close(e);
			return ferr(err, "out of memory");
		}
	}
	for (uint64_t i = 0; i < n_sh; i++) {
		const uint8_t *p = d + shoff + i * shentsize;
		struct bml_elf_shdr *s = &e->sections[i];
		s->name = "";
		names[i] = bml_elf_u32(e, p);
		s->type = bml_elf_u32(e, p + 4);
		if (e->is64) {
			s->flags = bml_elf_u64(e, p + 8);
			s->addr = bml_elf_u64(e, p + 16);
			s->offset = bml_elf_u64(e, p + 24);
			s->size = bml_elf_u64(e, p + 32);
			s->link = bml_elf_u32(e, p + 40);
			s->info = bml_elf_u32(e, p + 44);
			s->addralign = bml_elf_u64(e, p + 48);
			s->entsize = bml_elf_u64(e, p + 56);
		} else {
			s->flags = bml_elf_u32(e, p + 8);
			s->addr = bml_elf_u32(e, p + 12);
			s->offset = bml_elf_u32(e, p + 16);
			s->size = bml_elf_u32(e, p + 20);
			s->link = bml_elf_u32(e, p + 24);
			s->info = bml_elf_u32(e, p + 28);
			s->addralign = bml_elf_u32(e, p + 32);
			s->entsize = bml_elf_u32(e, p + 36);
		}
		if ((int64_t)s->offset < 0 || (int64_t)s->size < 0) {
			free(names);
			bml_elf_close(e);
			return ferr(err, "invalid section offset or size");
		}

		if (s->flags & BML_SHF_COMPRESSED) {
			uint64_t ch = e->is64 ? 24 : 12;
			if (s->size < ch || !in_file(e, s->offset, ch)) {
				free(names);
				bml_elf_close(e);
				return ferr(err, "unexpected EOF reading a compression header");
			}
		}
		e->n_sections++;
	}
	if (n_sh == 0 || shstrndx == 0) {
		free(names);
		return 0;
	}
	const struct bml_elf_shdr *st = &e->sections[shstrndx];
	if (st->type != BML_SHT_STRTAB) {
		free(names);
		bml_elf_close(e);
		return ferr(err, "invalid ELF section name string table type");
	}
	const uint8_t *tab;
	size_t tlen;
	char *derr = NULL;
	if (bml_elf_section_data(e, st, &tab, &tlen, &derr)) {
		free(names);
		bml_elf_close(e);
		*err = derr;
		return -1;
	}
	for (uint64_t i = 0; i < n_sh; i++) {

		if (names[i] >= tlen || !memchr(tab + names[i], 0, tlen - names[i])) {
			free(names);
			bml_elf_close(e);
			return ferr(err, "bad section name index");
		}
		e->sections[i].name = (const char *)tab + names[i];
	}
	free(names);
	return 0;
}

const struct bml_elf_shdr *bml_elf_section(const struct bml_elf *e, const char *name)
{
	for (size_t i = 0; i < e->n_sections; i++)
		if (strcmp(e->sections[i].name, name) == 0)
			return &e->sections[i];
	return NULL;
}

int bml_elf_section_data(const struct bml_elf *e, const struct bml_elf_shdr *s, const uint8_t **out, size_t *out_len,
			 char **err)
{
	*err = NULL;
	if (s->type == BML_SHT_NOBITS)
		return ferr(err, "unexpected read from SHT_NOBITS section");
	if (s->flags & BML_SHF_COMPRESSED)
		return ferr(err, "compressed section %s is not supported (bpf-mlir-loader reads only uncompressed sections)",
			    s->name);
	if (!in_file(e, s->offset, s->size))
		return ferr(err, "unexpected EOF reading section %s", s->name);
	*out = e->data + s->offset;
	*out_len = (size_t)s->size;
	return 0;
}

int bml_elf_symbols(const struct bml_elf *e, uint32_t type, struct bml_elf_sym **out, size_t *n, char **err)
{
	*out = NULL;
	*n = 0;
	*err = NULL;
	const struct bml_elf_shdr *st = NULL;
	for (size_t i = 0; i < e->n_sections; i++) {
		if (e->sections[i].type == type) {
			st = &e->sections[i];
			break;
		}
	}
	if (!st)
		return ferr(err, "no symbol section");
	const uint8_t *data;
	size_t len;
	char *derr;
	if (bml_elf_section_data(e, st, &data, &len, &derr)) {
		ferr(err, "cannot load symbol section: %s", derr);
		free(derr);
		return -1;
	}
	if (len == 0)
		return ferr(err, "no symbol section");
	size_t sz = e->is64 ? 24 : 16;
	if (len % sz != 0)
		return ferr(err, "length of symbol section is not a multiple of %s", e->is64 ? "Sym64Size" : "Sym32Size");
	if (st->link == 0 || st->link >= e->n_sections)
		return ferr(err, "cannot load string table section: section has invalid string table link");
	const uint8_t *strs;
	size_t slen;
	if (bml_elf_section_data(e, &e->sections[st->link], &strs, &slen, &derr)) {
		ferr(err, "cannot load string table section: %s", derr);
		free(derr);
		return -1;
	}
	size_t cnt = len / sz - 1;
	struct bml_elf_sym *s = cnt ? calloc(cnt, sizeof(*s)) : NULL;
	if (cnt && !s)
		return ferr(err, "out of memory");
	for (size_t i = 0; i < cnt; i++) {
		const uint8_t *p = data + (i + 1) * sz;
		uint32_t name;
		if (e->is64) {
			name = bml_elf_u32(e, p);
			s[i].info = p[4];
			s[i].other = p[5];
			s[i].shndx = bml_elf_u16(e, p + 6);
			s[i].value = bml_elf_u64(e, p + 8);
			s[i].size = bml_elf_u64(e, p + 16);
		} else {
			name = bml_elf_u32(e, p);
			s[i].value = bml_elf_u32(e, p + 4);
			s[i].size = bml_elf_u32(e, p + 8);
			s[i].info = p[12];
			s[i].other = p[13];
			s[i].shndx = bml_elf_u16(e, p + 14);
		}
		s[i].name = "";
		if (name < slen && memchr(strs + name, 0, slen - name))
			s[i].name = (const char *)strs + name;
	}
	*out = s;
	*n = cnt;
	return 0;
}
