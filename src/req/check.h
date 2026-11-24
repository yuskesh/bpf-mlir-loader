/* check.h — checking of requirements (sections 5, 6 and 9 of bpf-mlir's docs/requirements_format.md). A port of Check and Unmet in
 * go/requirements/requirements.go and of classify in go/bindrt; the port started at judgement version 3. */
#ifndef BML_CHECK_H
#define BML_CHECK_H

#include <stddef.h>
#include <stdint.h>

#include "caps/caps.h"
#include "req/req.h"

/* Judgement versions added: enumval 17, fibflags 18, datakptr 19, extern/guard 20, coreenum 21, funcret 22, kstructsize 23, arena 24,
 * netkit 25, helper_target 26, sleepable 27. */
#define BML_POLICY_VERSION 27

struct bml_unmet {
	const char *kind; /* one of UnmetKinds (a static string) */
	char *program, *name;
	int64_t id;
	char *detail;
};

struct bml_unmets {
	struct bml_unmet *u;
	size_t n, cap;
};

/* Go's Unmet.Unknown / BlocksLoad */
int bml_unmet_unknown(const struct bml_unmet *u);
int bml_unmet_blocks_load(const struct bml_unmet *u);
/* Go's Unmet.String (malloc-ed) */
char *bml_unmet_string(const struct bml_unmet *u);
void bml_unmets_free(struct bml_unmets *v);

/* Go's Check. Success is 0 with every Unmet in *out, in checking order; a checking error is -1 with *err (malloc-ed). */
int bml_check(const struct bml_requirements *req, const struct bml_caps *caps, struct bml_unmets *out, char **err);


#endif
