#include "dwarf/split.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int reason(char **out, const char *s)
{
	*out = strdup(s);
	return -1;
}


static int unique(const struct bml_elf *e, const char *name, const struct bml_elf_shdr **s)
{
	*s = NULL;
	for (size_t i = 0; i < e->n_sections; i++) {
		if (strcmp(e->sections[i].name, name) != 0)
			continue;
		if (*s)
			return -1;
		*s = &e->sections[i];
	}
	return 0;
}

int bml_debug_build_id(const struct bml_elf *e, const char *owner, uint8_t **id, size_t *n, char **why)
{
	*id = NULL, *n = 0;
	char invalid[96], none[96];
	snprintf(invalid, sizeof invalid, "%s has an invalid GNU build ID note", owner);
	snprintf(none, sizeof none, "%s has no GNU build ID", owner);
	const struct bml_elf_shdr *s;
	if (unique(e, ".note.gnu.build-id", &s))
		return reason(why, invalid);
	if (!s)
		return reason(why, none);
	const uint8_t *b;
	size_t len;
	char *err = NULL;
	if (s->type != 7                || (s->flags & BML_SHF_COMPRESSED) || s->size > 4096 || bml_elf_section_data(e, s, &b, &len, &err)) {
		free(err);
		return reason(why, invalid);
	}
	const uint8_t *got = NULL;
	uint64_t gn = 0;
	while (len > 0) {
		if (len < 12)
			return reason(why, invalid);
		uint64_t nsz = bml_elf_u32(e, b), dsz = bml_elf_u32(e, b + 4);
		uint32_t type = bml_elf_u32(e, b + 8);
		uint64_t na = (nsz + 3) & ~3ull, da = (dsz + 3) & ~3ull;
		if (na + da + 12 > len)
			return reason(why, invalid);
		if (nsz == 4 && !memcmp(b + 12, "GNU", 4) && type == 3) {
			if (got || dsz < 1 || dsz > 64)
				return reason(why, invalid);
			got = b + 12 + na, gn = dsz;
		}
		b += 12 + na + da, len -= (size_t)(12 + na + da);
	}
	if (!got)
		return reason(why, invalid);
	*id = malloc(gn);
	if (!*id)
		return reason(why, "out of memory");
	memcpy(*id, got, gn);
	*n = (size_t)gn;
	return 0;
}

int bml_debug_link_crc(const struct bml_elf *e, uint32_t *crc, int *has, char **why)
{
	*crc = 0, *has = 0;
	const char *invalid = "the binary has an invalid GNU debuglink";
	const struct bml_elf_shdr *s;
	if (unique(e, ".gnu_debuglink", &s))
		return reason(why, invalid);
	if (!s)
		return 0;
	const uint8_t *b;
	size_t len;
	char *err = NULL;
	if (s->type != 1                    || (s->flags & BML_SHF_COMPRESSED) || s->size > 4096 || bml_elf_section_data(e, s, &b, &len, &err)) {
		free(err);
		return reason(why, invalid);
	}
	const uint8_t *nul = memchr(b, 0, len);
	if (!nul || nul == b)
		return reason(why, invalid);
	size_t off = ((size_t)(nul - b) + 1 + 3) & ~(size_t)3;
	if (off + 4 != len)
		return reason(why, invalid);
	*crc = bml_elf_u32(e, b + off);
	*has = 1;
	return 0;
}


uint32_t bml_crc32_ieee(const uint8_t *p, size_t n)
{
	uint32_t t[256];
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t c = i;
		for (int k = 0; k < 8; k++)
			c = c & 1 ? 0xedb88320u ^ (c >> 1) : c >> 1;
		t[i] = c;
	}
	uint32_t c = 0xffffffffu;
	for (size_t i = 0; i < n; i++)
		c = t[(c ^ p[i]) & 0xff] ^ (c >> 8);
	return c ^ 0xffffffffu;
}

int bml_debug_has_info(const struct bml_elf *e)
{
	return bml_elf_section(e, ".debug_info") || bml_elf_section(e, ".zdebug_info");
}

static int is_debug(const char *name)
{
	return !strncmp(name, ".debug_", 7) || !strncmp(name, ".zdebug_", 8);
}

int bml_debug_open_checks(const struct bml_elf *f, char **why)
{

	size_t hl = f->is64 ? 24 : 12;
	for (size_t i = 0; i < f->n_sections; i++) {
		const struct bml_elf_shdr *s = &f->sections[i];
		if ((s->flags & BML_SHF_COMPRESSED) && (s->size < hl || s->offset > f->len || hl > f->len - s->offset))
			return reason(why, "separate DWARF ELF is unreadable");
	}
	return 0;
}

int bml_debug_split_checks(const struct bml_elf *f, char **why)
{
	if (bml_elf_section(f, ".gnu_debugaltlink"))
		return reason(why, "separate DWARF contains unsupported .gnu_debugaltlink");
	for (size_t i = 0; i < f->n_sections; i++) {
		const struct bml_elf_shdr *s = &f->sections[i];
		if ((s->type == BML_SHT_REL || s->type == 4               ) && s->info < f->n_sections && is_debug(f->sections[s->info].name))
			return reason(why, "separate DWARF contains unsupported relocations");
	}
	if (bml_elf_section(f, ".debug_types") || bml_elf_section(f, ".zdebug_types"))
		return reason(why, "separate DWARF contains unsupported type units");

	const char *invalid = "separate DWARF has an invalid compression header";
	uint64_t total = 0;
	for (size_t i = 0; i < f->n_sections; i++) {
		const struct bml_elf_shdr *s = &f->sections[i];
		if (!is_debug(s->name))
			continue;
		if (s->type == BML_SHT_NOBITS)
			return reason(why, "separate DWARF has a NOBITS debug section");
		if (s->offset > f->len || s->size > f->len - s->offset)
			return reason(why, invalid);
		const uint8_t *b = f->data + s->offset;
		uint64_t n = s->size, expanded = s->size;
		if (s->flags & BML_SHF_COMPRESSED) {
			uint64_t need = f->is64 ? 24 : 12;
			if (n < need)
				return reason(why, invalid);
			uint32_t type = bml_elf_u32(f, b);
			if (type == 2)
				return reason(why, "separate DWARF contains unsupported zstd compression");
			if (type != 1)
				return reason(why, invalid);
			expanded = f->is64 ? bml_elf_u64(f, b + 8) : bml_elf_u32(f, b + 4);
		} else if (!strncmp(s->name, ".zdebug_", 8)) {
			if (n < 12 || memcmp(b, "ZLIB", 4) != 0)
				return reason(why, invalid);
			expanded = 0;
			for (int k = 4; k < 12; k++)
				expanded = expanded << 8 | b[k];
		}
		if (expanded > BML_DEBUG_EXPANDED_LIMIT - total)
			return reason(why, "separate DWARF expanded sections exceed 536870912 bytes");
		total += expanded;
	}
	if (!bml_debug_has_info(f))
		return reason(why, "separate DWARF has no debug information");
	return 0;
}
