




#ifndef BML_ELF_H
#define BML_ELF_H

#include <stddef.h>
#include <stdint.h>

struct bml_elf_shdr {
	const char *name;
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


int bml_elf_open(const void *data, size_t len, struct bml_elf *elf, char **err);
void bml_elf_close(struct bml_elf *elf);


const struct bml_elf_shdr *bml_elf_section(const struct bml_elf *elf, const char *name);


int bml_elf_section_data(const struct bml_elf *elf, const struct bml_elf_shdr *s, const uint8_t **out, size_t *out_len,
			 char **err);


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



struct bml_elf_sym {
	const char *name;
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
