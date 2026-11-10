


#include "req/check_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "caps/caps.h"
#include "dwarf/split.h"
#include "req/uprobe.h"
#include "util/mutation.h"

void ck_dsrc_init(struct ck_dsrc *s, const struct bml_elf *body, const char *program)
{
	memset(s, 0, sizeof *s);
	s->body = body;
	s->program = program;
}

void ck_dsrc_free(struct ck_dsrc *s)
{
	bml_dwarf_close(s->d);
	if (s->split_open)
		bml_elf_close(&s->split);
	free(s->raw);
	free(s->err);
	memset(s, 0, sizeof *s);
}

static void hexs(char *out, const uint8_t *b, size_t n)
{
	for (size_t i = 0; i < n; i++)
		snprintf(out + 2 * i, 3, "%02x", b[i]);
	out[2 * n] = 0;
}


static void select_source(struct ck *c, struct ck_dsrc *s)
{
	const struct bml_elf *body = s->body;
	if (bml_elf_section(body, ".gnu_debugaltlink")) {
		s->err = strdup("the binary contains unsupported .gnu_debugaltlink");
		return;
	}
	if (bml_debug_has_info(body)) {
		bml_dwarf_open(body, &s->d, &s->err);
		return;
	}
	uint8_t *id = NULL, *gid = NULL;
	size_t idn = 0, gn = 0;
	uint32_t crc;
	int has_crc;
	if (bml_debug_build_id(body, "the binary", &id, &idn, &s->err) || bml_debug_link_crc(body, &crc, &has_crc, &s->err))
		goto done;
	if (!HAS(c, uprobe_debug, BML_QUERY_UPROBE_DEBUG)) {
		s->err = strdup("no separate DWARF capability");
		goto done;
	}
	char *path = NULL, *msg = NULL;
	int st = c->caps->uprobe_debug(c->caps->ctx, s->program, id, idn, &s->raw, &s->rawn, &path, &msg);
	free(path);
	if (st != BML_Q_OK) {
		s->err = st == BML_Q_UNKNOWN ? msg : (free(msg), strdup("separate DWARF query failed"));
		goto done;
	}
	free(msg);
	if (s->rawn > BML_DEBUG_RAW_LIMIT) {
		s->err = strdup("separate DWARF file exceeds 268435456 bytes");
		goto done;
	}
	char *oerr = NULL;
	if (bml_elf_open(s->raw ? s->raw : (const uint8_t *)"", s->rawn, &s->split, &oerr) != 0) {
		free(oerr);
		s->err = strdup("separate DWARF ELF is unreadable");
		goto done;
	}
	s->split_open = 1;
	const struct bml_elf *f = &s->split;
	if (bml_debug_open_checks(f, &s->err))
		goto done;
	if (f->is64 != body->is64 || f->big_endian != body->big_endian || f->machine != body->machine) {
		s->err = strdup("separate DWARF ELF class, data or machine differs from the binary");
		goto done;
	}
	if (bml_debug_build_id(f, "separate DWARF", &gid, &gn, &s->err))
		goto done;
	if ((gn != idn || memcmp(gid, id, idn) != 0) && !BML_MUT("check.debug_build_id_skip")) {
		char g[129], w[129];
		hexs(g, gid, gn), hexs(w, id, idn);
		s->err = ck_fmtd("separate DWARF build ID is %s, want %s", g, w);
		s->kind = "uprobe_debug_build_id";
		goto done;
	}
	if (has_crc && !BML_MUT("check.debug_crc_skip")) {
		uint32_t got = bml_crc32_ieee(s->raw, s->rawn);
		if (got != crc) {
			s->err = ck_fmtd("separate DWARF CRC32 is %08x, want %08x", got, crc);
			s->kind = "uprobe_debug_crc";
			goto done;
		}
	}
	if (bml_debug_split_checks(f, &s->err))
		goto done;
	bml_dwarf_open(f, &s->d, &s->err);
done:
	free(id);
	free(gid);
	if (!s->d && !s->err)
		s->err = strdup("out of memory");
}

void ck_dsrc_read(struct ck *c, struct ck_dsrc *s)
{
	if (s->resolved)
		return;
	s->resolved = 1;
	select_source(c, s);
}


int ck_dsrc_subprogram(const struct ck_dsrc *s, const char *T, int parameters, const uint8_t *raw, size_t n_raw, struct bml_dwarf_sub *out,
		       char **err)
{
	memset(out, 0, sizeof *out);
	if (s->err)
		return (*err = strdup(s->err), -1);
	return bml_uprobe_dwarf_at(s->body, s->d, T, parameters, raw, n_raw, out, err);
}

int bml_uprobe_dwarf_at(const struct bml_elf *body, struct bml_dwarf *d, const char *T, int parameters, const uint8_t *raw, size_t n_raw,
			struct bml_dwarf_sub *out, char **err)
{
	memset(out, 0, sizeof *out);
	char *detail = bml_uprobe_symbol(body, T);
	if (detail) {
		*err = ck_fmtd("cannot resolve DWARF address: %s", detail);
		free(detail);
		return -1;
	}

	uint64_t address = 0;
	int found = 0;
	for (uint32_t t = 0; t < 2 && !found; t++) {
		struct bml_elf_sym *syms = NULL;
		size_t n = 0;
		char *e = NULL;
		if (bml_elf_symbols(body, t ? BML_SHT_DYNSYM : BML_SHT_SYMTAB, &syms, &n, &e) != 0) {
			free(e);
			continue;
		}
		for (size_t i = 0; i < n && !found; i++)
			if (!strcmp(syms[i].name, T) && BML_ST_TYPE(syms[i].info) == BML_STT_FUNC)
				address = syms[i].value, found = 1;
		free(syms);
	}
	return bml_dwarf_subprogram_at_ptr(d, address, T, parameters, raw, n_raw, out, err);
}
