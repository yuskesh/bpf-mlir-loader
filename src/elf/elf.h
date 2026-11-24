/* elf.h — a minimal ELF reader. It makes the same checks as Go's debug/elf.NewFile when opening, and checks a section's
 * range when its contents are read (the same stage as Go, so a corrupt offset in an unrelated section does not make
 * the open fail). It reads ELF32 and ELF64, little and big endian.
 *
 * Difference from Go (on the fail-closed side): the contents of an SHF_COMPRESSED section are not read (Go inflates
 * zlib / zstd data), so reading one is an error.
 * libelf is not used, to keep the checking reader independent of the libbpf path that loads the object (see the
 * loader design survey, question 3, section 1.1). */
#ifndef BML_ELF_H
#define BML_ELF_H

#include <stddef.h>
#include <stdint.h>

struct bml_elf_shdr {
	const char *name; /* inside shstrtab (NUL-terminated); "" if there is no shstrtab */
	uint32_t type, link, info;
	uint64_t flags, addr, offset, size, addralign, entsize;
};

struct bml_elf_phdr {
	uint32_t type, flags;
	uint64_t offset, vaddr, paddr, filesz, memsz, align;
};

struct bml_elf {
	const uint8_t *data;
	size_t len;
	int is64, big_endian;
	uint16_t type, machine;
	struct bml_elf_shdr *sections;
	size_t n_sections;
	struct bml_elf_phdr *progs;
	size_t n_progs;
};

/* Open. The caller owns data, which must stay alive until bml_elf_close. Failure is -1 with *err set to a malloc'd message. */
int bml_elf_open(const void *data, size_t len, struct bml_elf *elf, char **err);
void bml_elf_close(struct bml_elf *elf);

/* The first section with the name (Go's File.Section); NULL if there is none */
const struct bml_elf_shdr *bml_elf_section(const struct bml_elf *elf, const char *name);

/* The contents of a section (Go's Section.Data). The result points into the file (no copy). NOBITS, out-of-range and
 * compressed sections give -1 with *err set. */
int bml_elf_section_data(const struct bml_elf *elf, const struct bml_elf_shdr *s, const uint8_t **out, size_t *out_len,
			 char **err);

/* Read helpers (they use the ELF's byte order; the caller checks the range) */
uint16_t bml_elf_u16(const struct bml_elf *elf, const uint8_t *p);
uint32_t bml_elf_u32(const struct bml_elf *elf, const uint8_t *p);
uint64_t bml_elf_u64(const struct bml_elf *elf, const uint8_t *p);

#define BML_SHT_NULL 0
#define BML_SHT_SYMTAB 2
#define BML_SHT_STRTAB 3
#define BML_SHT_REL 9
#define BML_SHT_NOBITS 8
#define BML_SHT_DYNSYM 11
#define BML_SHF_COMPRESSED 0x800


/* A symbol (Go's elf.Symbol; the empty symbol at index 0 is not included) */
struct bml_elf_sym {
	const char *name; /* inside the string table (NUL-terminated); "" for an index that cannot be read (as when Go's getString fails) */
	uint8_t info, other;
	uint16_t shndx;
	uint64_t value, size;
};
#define BML_STT_OBJECT 1
#define BML_STT_FUNC 2
#define BML_ST_TYPE(i) ((i) & 0xf)
#define BML_SHN_UNDEF 0
#define BML_SHF_EXECINSTR 0x4

/* CONTRACT: reads the symbols of type BML_SHT_SYMTAB or BML_SHT_DYNSYM from the first section of that type (version information is not read).
 * A missing or empty section returns -1 and sets *err = "no symbol section". *out is malloc'd (release with free) */
int bml_elf_symbols(const struct bml_elf *elf, uint32_t type, struct bml_elf_sym **out, size_t *n, char **err);

#endif
