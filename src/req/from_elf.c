#include "req/from_elf.h"

#include <stdlib.h>
#include <string.h>

#include "req/kfunc_profile.h"
#include "util/gostr.h"

int bml_req_from_elf(const void *data, size_t len, struct bml_requirements **out, struct bml_req_elf_error *e)
{
	*out = NULL;
	memset(e, 0, sizeof(*e));
	e->parse.row = "";
	e->parse.rule = "";
	


	if (len < 24) {
		e->stage = BML_REQ_ELF_OPEN;
		e->msg = strdup("ELF header: EOF");
		e->go_text = 1;
		return -1;
	}
	const uint8_t *h = data;
	if (h[5] == 1 || h[5] == 2) {
		uint32_t v = h[5] == 1 ? (uint32_t)h[20] | (uint32_t)h[21] << 8 | (uint32_t)h[22] << 16 | (uint32_t)h[23] << 24
				       : (uint32_t)h[23] | (uint32_t)h[22] << 8 | (uint32_t)h[21] << 16 | (uint32_t)h[20] << 24;
		if (v != 1) {
			e->stage = BML_REQ_ELF_OPEN;
			struct bml_buf b = {0};
			bml_buf_addf(&b, "ELF e_version is %#x, want 1 (EV_CURRENT — all 4 bytes)", v);
			e->msg = bml_buf_take(&b);
			e->go_text = 1;
			return -1;
		}
	}
	struct bml_elf elf;
	char *err = NULL;
	if (bml_elf_open(data, len, &elf, &err)) {
		e->stage = BML_REQ_ELF_OPEN;
		e->msg = err;
		return -1;
	}
	const struct bml_elf_shdr *s = bml_elf_section(&elf, BML_REQ_SECTION);
	if (!s) {
		bml_elf_close(&elf);
		struct bml_buf b = {0};
		bml_buf_adds(&b, "the object has no " BML_REQ_SECTION " section (built by an older compiler?)");
		e->stage = BML_REQ_ELF_NO_SECTION;
		e->msg = bml_buf_take(&b);
		return -1;
	}
	const uint8_t *sec;
	size_t slen;
	if (bml_elf_section_data(&elf, s, &sec, &slen, &err)) {
		bml_elf_close(&elf);
		e->stage = BML_REQ_ELF_DATA;
		e->msg = err;
		return -1;
	}
	int rc = bml_req_parse((const char *)sec, slen, out, &e->parse);
	if (rc == 0) {
		char *serr = NULL;
		if (bml_req_check_sleepable_sections(&elf, *out, &serr)) {
			bml_elf_close(&elf);
			bml_requirements_free(*out);
			*out = NULL;
			e->stage = BML_REQ_ELF_PARSE;
			e->parse.msg = serr;
			return -1;
		}
		bml_map_fields_derive(&elf, &(*out)->map_fields);
		if (bml_req_kfunc_profiles_derive(&elf, *out)) {
			bml_elf_close(&elf);
			bml_requirements_free(*out);
			*out = NULL;
			e->stage = BML_REQ_ELF_PARSE;
			e->parse.msg = strdup("out of memory");
			return -1;
		}
	}
	bml_elf_close(&elf);
	if (rc) {

		bml_requirements_free(*out);
		*out = NULL;
		e->stage = BML_REQ_ELF_PARSE;
		return -1;
	}
	return 0;
}

void bml_req_elf_error_free(struct bml_req_elf_error *e)
{
	free(e->msg);
	e->msg = NULL;
	if (e->stage == BML_REQ_ELF_PARSE)
		bml_parse_error_free(&e->parse);
}
