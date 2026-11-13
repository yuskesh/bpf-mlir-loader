#ifndef BML_SHIM_BUILD_ELF_INTERNAL_H
#define BML_SHIM_BUILD_ELF_INTERNAL_H

#include "req/from_elf.h"
#include "req/req.h"
#include "shim/build/internal.h"



static inline int bb_read_requirements(const void *elf, size_t len, struct bml_requirements **req, struct bml_build_error *err)
{
	struct bml_req_elf_error ee;
	*req = NULL;
	if (bml_req_from_elf(elf ? elf : "", len, req, &ee) == 0)
		return 0;
	const char *m = ee.stage == BML_REQ_ELF_PARSE ? ee.parse.msg : ee.msg;
	int go = ee.stage == BML_REQ_ELF_NO_SECTION || ee.stage == BML_REQ_ELF_PARSE || (ee.stage == BML_REQ_ELF_OPEN && ee.go_text);
	if (!m) {
		bb_nomem(err);
	} else if (go) {
		struct bml_buf b = {0};
		bml_buf_addf(&b, "cannot read requirements from the embedded ELF: %s", m);
		char *t = bml_buf_take(&b);
		bb_fail(err, t);
		free(t);
	} else {
		bb_unsupported(err, ee.stage == BML_REQ_ELF_OPEN ? "elf-header" : "elf-data", m);
	}
	bml_req_elf_error_free(&ee);
	return err->code;
}

#endif
