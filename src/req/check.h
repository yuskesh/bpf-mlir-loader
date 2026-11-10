

#ifndef BML_CHECK_H
#define BML_CHECK_H

#include <stddef.h>
#include <stdint.h>

#include "caps/caps.h"
#include "req/req.h"

#define BML_POLICY_VERSION 27

struct bml_unmet {
	const char *kind;
	char *program, *name;
	int64_t id;
	char *detail;
};

struct bml_unmets {
	struct bml_unmet *u;
	size_t n, cap;
};


int bml_unmet_unknown(const struct bml_unmet *u);
int bml_unmet_blocks_load(const struct bml_unmet *u);

char *bml_unmet_string(const struct bml_unmet *u);
void bml_unmets_free(struct bml_unmets *v);


int bml_check(const struct bml_requirements *req, const struct bml_caps *caps, struct bml_unmets *out, char **err);


#endif
