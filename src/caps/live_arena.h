#ifndef BML_CAPS_LIVE_ARENA_H
#define BML_CAPS_LIVE_ARENA_H
#include "caps/live.h"
int lv_arena_kfunc_name(const char *name);
int lv_arena_kfunc_load(struct bml_live *, const struct bml_kfunc_profile *, const char *, const char *,
	const struct bml_str *, size_t, int *, char **);
#endif
