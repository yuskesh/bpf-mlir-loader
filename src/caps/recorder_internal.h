
#ifndef BML_CAPS_RECORDER_INTERNAL_H
#define BML_CAPS_RECORDER_INTERNAL_H

#include "caps/recorder.h"

enum { A_VALUE, A_UNKNOWN, A_ERROR, A_DIFFS, A_TEXT, A_FILE };

struct rec {
	char *query, *key;
	int kind, value;
	char *s;
	struct bml_strs diffs;
};

struct bml_recorder {
	const struct bml_caps *under;
	struct rec *r;
	size_t n;
	struct bml_kv *files;
	size_t n_files;
};

#define R(ctx) ((struct bml_recorder *)(ctx))
#define U(ctx) (R(ctx)->under)

#define slot bml_rr_slot
#define put_err bml_rr_put_err
struct rec *slot(struct bml_recorder *r, const char *q, const char *key);
int put_err(struct rec *e, int rc, const char *msg);
#define rec_bool bml_rr_bool
#define rec_diffs bml_rr_diffs
void rec_bool(struct bml_recorder *r, const char *q, const char *key, int rc, int value, const char *msg);
void rec_diffs(struct bml_recorder *r, const char *q, const char *key, int rc, const struct bml_strs *d, const char *msg);
void rr_caps_kernel_values(const struct bml_caps *u, struct bml_caps *out);

void rr_caps_files(const struct bml_caps *u, struct bml_caps *out);

#endif
