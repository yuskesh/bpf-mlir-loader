/* caps/recorder.h — caps that record the answers to queries (a C port of Recorder in go/requirements/recorder.go of bpf-mlir).
 *
 * It asks the caps underneath and records each answer per (query, key); for the same key the later answer wins. kfields asks the caps
 * underneath once per kfield (the recorded key is per kfield, and the mismatch sentences are joined in the order of the kfields). The
 * recording is written as caps.json (format ebpf-caps 3) with the same bytes as Go's json.MarshalIndent (map keys in byte order, HTML escaping, two-space
 * indentation and a trailing newline). */
#ifndef BML_CAPS_RECORDER_H
#define BML_CAPS_RECORDER_H

#include "caps/caps.h"

struct bml_recorder;

/* under must outlive the recorder */
struct bml_recorder *bml_recorder_new(const struct bml_caps *under);
void bml_recorder_free(struct bml_recorder *r);
/* the recording caps (valid while r is alive) */
void bml_recorder_caps(struct bml_recorder *r, struct bml_caps *out);
/* the path recorded for a uprobe binary (Go's SetBinaryPath) */
int bml_recorder_set_binary(struct bml_recorder *r, const char *program, const char *path);
/* the bytes of caps.json (malloc'd). The loader is the declared loader (--loader / --loader-file). */
char *bml_recorder_json(const struct bml_recorder *r, long long uid, const char *cap_eff, const struct bml_loader_decl *loader,
			size_t *len);

#endif
