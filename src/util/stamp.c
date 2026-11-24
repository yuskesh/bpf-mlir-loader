/* util/stamp.c — the version facts stamped at build time (source form, source commit, dirty flag and the pinned bpf-mlir commit).
 * scripts/build-libs.sh generates bml_stamp.h (scripts/stamp-lib.sh) on the include path of this object only in the product build.
 * Other builds (test tools, fuzzing) have no such header and get the "none" form. No other object refers to this one, so a
 * program that does not call these functions does not link it (the rest of libbml.a stays byte-comparable across commits). */
#include "bml/bml.h"

#if __has_include("bml_stamp.h")
#include "bml_stamp.h"
#else
#define BML_STAMP_FORM "none"
#define BML_STAMP_SOURCE_COMMIT "unknown"
#define BML_STAMP_DIRTY (-1)
#define BML_STAMP_BPF_MLIR_COMMIT "unknown"
#endif

const char *bml_source_form(void)
{
	return BML_STAMP_FORM;
}

const char *bml_source_commit(void)
{
	return BML_STAMP_SOURCE_COMMIT;
}

int bml_source_dirty(void)
{
	return BML_STAMP_DIRTY;
}

const char *bml_bpf_mlir_commit(void)
{
	return BML_STAMP_BPF_MLIR_COMMIT;
}
