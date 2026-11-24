/* caps/live_caps.h — live caps (they ask the target kernel) in the shape of the matching caps. This is a C port of ebpf-precheck's
 * `--live` and `--binary`. */
#ifndef BML_CAPS_LIVE_CAPS_H
#define BML_CAPS_LIVE_CAPS_H

#include "caps/caps.h"
#include "caps/live.h"

struct bml_live_bin {
	char *program, *path;
	int fd;
};

/* `--ext-target program=target`: either the BTF that was read, or the sentence saying why it could not be read (matching then
 * reports ext_target_unknown) */
struct bml_live_ext {
	char *program;
	int ok;
	struct bml_kbtf kb;
	char *err;
};

struct bml_live_caps {
	struct bml_live live;
	struct bml_live_bin *bins; /* `--binary program=path` (the fd stays open for the duration of matching) */
	size_t n_bins;
	struct bml_live_ext *exts; /* the ext_targets query exists only when this is present (the live caps of the C ABI do not have it) */
	size_t n_exts;
	const struct bml_loader_decl *decl; /* the declared loader (ebpf-precheck's liveCaps.Loader; NULL means Cilium022) */
	/* Separated DWARF: a NULL debug_root means /usr/lib/debug and "" means do not search (LiveCaps.UprobeDebugRoot). debugs holds the
	 * per-program overrides (UprobeDebugPaths); an override takes priority and a failing override does not fall back to the root. */
	char *debug_root;
	struct bml_live_debug {
		char *program, *path;
	} *debugs;
	size_t n_debugs;
};

/* CONTRACT: caps valid while c is alive (the loader declaration is c->decl; NULL means Cilium022) */
void bml_live_caps(struct bml_live_caps *c, struct bml_caps *out);
void bml_live_caps_free(struct bml_live_caps *c);

#endif
