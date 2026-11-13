#ifndef BML_REQ_ELF_H
#define BML_REQ_ELF_H

#include "elf/elf.h"
#include "req/req.h"

enum bml_req_elf_stage {
	BML_REQ_ELF_OK,
	BML_REQ_ELF_OPEN,
	BML_REQ_ELF_NO_SECTION,
	BML_REQ_ELF_DATA,
	BML_REQ_ELF_PARSE,
};

struct bml_req_elf_error {
	enum bml_req_elf_stage stage;
	char *msg;
	

	int go_text;
	struct bml_parse_error parse;
};

int bml_req_from_elf(const void *data, size_t len, struct bml_requirements **out, struct bml_req_elf_error *e);
void bml_req_elf_error_free(struct bml_req_elf_error *e);

int bml_req_check_sleepable_sections(const struct bml_elf *elf, const struct bml_requirements *r, char **err);

#endif
