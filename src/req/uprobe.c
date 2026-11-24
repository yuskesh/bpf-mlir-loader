/* uprobe.c — a port of uprobeSymbol in go/requirements/uprobe.go. dwarfParams is in src/dwarf/, and the calling convention check is in check_attach.c. */
#include "req/uprobe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"
#include "util/mutation.h"

#define PT_LOAD 1
#define PF_X 1

char *bml_uprobe_symbol(const struct bml_elf *elf, const char *name)
{
	/* Go: syms, _ := f.Symbols(); dyn, _ := f.DynamicSymbols(); an error is ignored and treated as empty */
	struct bml_elf_sym *syms = NULL, *dyn = NULL;
	size_t ns = 0, nd = 0;
	char *err = NULL;
	if (bml_elf_symbols(elf, BML_SHT_SYMTAB, &syms, &ns, &err))
		free(err), ns = 0;
	err = NULL;
	if (bml_elf_symbols(elf, BML_SHT_DYNSYM, &dyn, &nd, &err))
		free(err), nd = 0;
	uint64_t *vals = malloc((ns + nd + 1) * sizeof(*vals));
	size_t nv = 0;
	if (!vals) {
		free(syms);
		free(dyn);
		return strdup("out of memory");
	}
	for (size_t i = 0; i < ns + nd; i++) {
		const struct bml_elf_sym *s = i < ns ? &syms[i] : &dyn[i - ns];
		if (strcmp(s->name, name) != 0 || BML_ST_TYPE(s->info) != BML_STT_FUNC)
			continue;
		int seen = 0;
		for (size_t k = 0; k < nv; k++)
			if (vals[k] == s->value)
				seen = 1;
		if (seen)
			continue;
		vals[nv++] = s->value;
	}
	free(syms);
	free(dyn);
	struct bml_buf b = {0};
	if (nv != 1) {
		free(vals);
		bml_buf_addf(&b, "the binary has %zu FUNC symbols named %s (want exactly one)", nv, name);
		return bml_buf_take(&b);
	}
	for (size_t i = 0; i < elf->n_progs; i++) {
		const struct bml_elf_phdr *p = &elf->progs[i];
		if (p->type == PT_LOAD && (p->flags & PF_X) && p->vaddr <= vals[0] && vals[0] < p->vaddr + p->memsz)
			return free(vals), NULL;
	}
	bml_buf_addf(&b, "%s (0x%llx) is not in an executable PT_LOAD of the binary", name, (unsigned long long)vals[0]);
	free(vals);
	return bml_buf_take(&b);
}

/* The file offset of an attach. It uses the same symbol table and rules as the check (bml_uprobe_symbol): the first STT_FUNC with a matching name in
 * .symtab, then .dynsym; unique by address; inside the memsz of a PF_X PT_LOAD segment. The offset is v - p_vaddr + p_offset, as in cilium/ebpf's
 * Executable.load (using the first PF_X PT_LOAD that contains the address). The mutation uprobe.attach_symtab_only reproduces the earlier attach rule
 * (only FUNCs defined in .symtab, and neither filesz nor size is looked at). */
int bml_uprobe_file_offset(const struct bml_elf *elf, const char *name, uint64_t *off, uint64_t *value, uint64_t *seg_vaddr, char **why)
{
	*why = NULL;
	int legacy = BML_MUT("uprobe.attach_symtab_only");
	if (!legacy && (*why = bml_uprobe_symbol(elf, name)))
		return -1;
	uint64_t v = 0, size = 0;
	size_t n = 0;
	for (uint32_t t = 0; t < 2 && (legacy || !n); t++) {
		struct bml_elf_sym *syms = NULL;
		size_t ns = 0;
		char *err = NULL;
		if (legacy && t == 1)
			break;
		if (bml_elf_symbols(elf, t ? BML_SHT_DYNSYM : BML_SHT_SYMTAB, &syms, &ns, &err) != 0) {
			free(err);
			continue;
		}
		for (size_t i = 0; i < ns && (legacy || !n); i++)
			if (!strcmp(syms[i].name, name) && BML_ST_TYPE(syms[i].info) == BML_STT_FUNC && (!legacy || syms[i].shndx != BML_SHN_UNDEF))
				v = syms[i].value, size = syms[i].size, n++;
		free(syms);
	}
	struct bml_buf b = {0};
	if (legacy && n != 1) {
		bml_buf_addf(&b, "the target has %zu FUNC symbols named %s (want exactly one)", n, name);
		return (*why = bml_buf_take(&b), -1);
	}
	for (size_t i = 0; i < elf->n_progs; i++) {
		const struct bml_elf_phdr *p = &elf->progs[i];
		if (p->type == PT_LOAD && (p->flags & PF_X) && p->vaddr <= v && v < p->vaddr + (legacy ? p->filesz : p->memsz)) {
			/* cilium/ebpf's Executable.address rejects an offset (always 0 in bml) that is >= the symbol size, which happens for a FUNC of size 0 (a
			 * hand-written asm function without .size, or a crt stub). The check does not look at size, so as with the Go loader the check passes and the
			 * attach stops. This was a deliberate decision. */
			if (!legacy && size == 0) {
				bml_buf_addf(&b, "offset 0 is out of range of symbol %s", name);
				return (*why = bml_buf_take(&b), -1);
			}
			*off = v - p->vaddr + p->offset;
			if (value)
				*value = v;
			if (seg_vaddr)
				*seg_vaddr = p->vaddr;
			return 0;
		}
	}
	bml_buf_addf(&b, "%s (0x%llx) is not in an executable PT_LOAD of the binary", name, (unsigned long long)v);
	return (*why = bml_buf_take(&b), -1);
}

