
#ifndef BML_CAPS_LIVE_CAPS_H
#define BML_CAPS_LIVE_CAPS_H

#include "caps/caps.h"
#include "caps/live.h"

struct bml_live_bin {
	char *program, *path;
	int fd;
};


struct bml_live_ext {
	char *program;
	int ok;
	struct bml_kbtf kb;
	char *err;
};

struct bml_live_caps {
	struct bml_live live;
	struct bml_live_bin *bins;
	size_t n_bins;
	struct bml_live_ext *exts;
	size_t n_exts;
	const struct bml_loader_decl *decl;
	

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
