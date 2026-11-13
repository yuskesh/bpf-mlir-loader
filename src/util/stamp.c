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
