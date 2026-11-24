/* caps/recorder_internal.h — the internals of Recorder (shared by recorder.c and recorder_json.c, which writes caps.json) */
#ifndef BML_CAPS_RECORDER_INTERNAL_H
#define BML_CAPS_RECORDER_INTERNAL_H

#include "caps/recorder.h"

enum { A_VALUE, A_UNKNOWN, A_ERROR, A_DIFFS, A_TEXT, A_FILE };

struct rec {
	char *query, *key;
	int kind, value;
	char *s; /* the sentence of unknown, error, text or file */
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
/* recorder.c: the place of a recording (the same key is overwritten; NULL on out of memory) and recording an answer that is an error (1 means recorded). The names are spelled so that they do not leave the library. */
#define slot bml_rr_slot
#define put_err bml_rr_put_err
struct rec *slot(struct bml_recorder *r, const char *q, const char *key);
int put_err(struct rec *e, int rc, const char *msg);
#define rec_bool bml_rr_bool
#define rec_diffs bml_rr_diffs
void rec_bool(struct bml_recorder *r, const char *q, const char *key, int rc, int value, const char *msg);
void rec_diffs(struct bml_recorder *r, const char *q, const char *key, int rc, const struct bml_strs *d, const char *msg);
void rr_caps_kernel_values(const struct bml_caps *u, struct bml_caps *out);
/* recorder_files.c (split out of recorder.c to stay under its 500-line limit): puts the file-answer queries uprobe_binary and uprobe_debug into out */
void rr_caps_files(const struct bml_caps *u, struct bml_caps *out);

#endif
