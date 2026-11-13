#ifndef BML_SHIM_BUILD_INTERNAL_H
#define BML_SHIM_BUILD_INTERNAL_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "shim/build/build.h"
#include "util/gostr.h"


static inline void bb_init(struct bml_build_error *err)
{
	memset(err, 0, sizeof *err);
	err->offset = -1;
}

static inline int bb_nomem(struct bml_build_error *err)
{
	free(err->text);
	err->text = NULL;
	err->code = BML_BUILD_NOMEM;
	return err->code;
}


static inline int bb_fail(struct bml_build_error *err, const char *text)
{
	if (!text || !(err->text = strdup(text)))
		return bb_nomem(err);
	err->code = BML_BUILD_FAIL;
	return err->code;
}


static inline int bb_unsupported(struct bml_build_error *err, const char *cls, const char *what)
{
	struct bml_buf b = {0};
	bml_buf_addf(&b, "unsupported: %s: %s", cls, what ? what : "");
	if (!(err->text = bml_buf_take(&b)))
		return bb_nomem(err);
	err->code = BML_BUILD_UNSUPPORTED;
	return err->code;
}

#endif
