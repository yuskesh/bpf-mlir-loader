/* req_elf.h — reading `.ebpf_requirements` from an ELF file (the section-reading part of Go's requirements.FromELF). */
#ifndef BML_REQ_ELF_H
#define BML_REQ_ELF_H

#include "elf/elf.h"
#include "req/req.h"

enum bml_req_elf_stage {
	BML_REQ_ELF_OK,
	BML_REQ_ELF_OPEN,       /* cannot be opened as an ELF (the error of Go's elf.NewFile) */
	BML_REQ_ELF_NO_SECTION, /* there is no such section */
	BML_REQ_ELF_DATA,       /* the contents of the section cannot be read */
	BML_REQ_ELF_PARSE,      /* a Parse error (the details are in parse) */
};

struct bml_req_elf_error {
	enum bml_req_elf_stage stage;
	char *msg; /* the text for OPEN, NO_SECTION and DATA */
	/* 1 when an OPEN text is checkELFVersion's own (Go's text byte for byte — "ELF header: EOF" and the e_version text);
	 * 0 for bml_elf_open's texts, which are not debug/elf's FormatError texts */
	int go_text;
	struct bml_parse_error parse;
};

int bml_req_from_elf(const void *data, size_t len, struct bml_requirements **out, struct bml_req_elf_error *e);
void bml_req_elf_error_free(struct bml_req_elf_error *e);
/* bpf-mlir's checkSleepableSections (from_elf_sleepable.c): 0 for good, -1 with *err (malloc-ed). */
int bml_req_check_sleepable_sections(const struct bml_elf *elf, const struct bml_requirements *r, char **err);

#endif
