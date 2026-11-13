#ifndef BML_CAPS_RECORDER_H
#define BML_CAPS_RECORDER_H

#include "caps/caps.h"

struct bml_recorder;


struct bml_recorder *bml_recorder_new(const struct bml_caps *under);
void bml_recorder_free(struct bml_recorder *r);

void bml_recorder_caps(struct bml_recorder *r, struct bml_caps *out);

int bml_recorder_set_binary(struct bml_recorder *r, const char *program, const char *path);

char *bml_recorder_json(const struct bml_recorder *r, long long uid, const char *cap_eff, const struct bml_loader_decl *loader,
			size_t *len);

#endif
