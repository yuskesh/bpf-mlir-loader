
#ifndef BML_RECORDED_H
#define BML_RECORDED_H

#include "caps/caps.h"
#include "json/json.h"

#define BML_RECORDED_FORMAT "ebpf-caps 20"
#define BML_RECORDED_FORMAT_V19 "ebpf-caps 19"
#define BML_RECORDED_FORMAT_V18 "ebpf-caps 18"
#define BML_RECORDED_FORMAT_V17 "ebpf-caps 17"
#define BML_RECORDED_FORMAT_V16 "ebpf-caps 16"
#define BML_RECORDED_FORMAT_V15 "ebpf-caps 15"
#define BML_RECORDED_FORMAT_V14 "ebpf-caps 14"
#define BML_RECORDED_FORMAT_V13 "ebpf-caps 13"
#define BML_RECORDED_FORMAT_V12 "ebpf-caps 12"
#define BML_RECORDED_FORMAT_V11 "ebpf-caps 11"
#define BML_RECORDED_FORMAT_V10 "ebpf-caps 10"
#define BML_RECORDED_FORMAT_V9 "ebpf-caps 9"
#define BML_RECORDED_FORMAT_V8 "ebpf-caps 8"
#define BML_RECORDED_FORMAT_V7 "ebpf-caps 7"
#define BML_RECORDED_FORMAT_V6 "ebpf-caps 6"
#define BML_RECORDED_FORMAT_V5 "ebpf-caps 5"
#define BML_RECORDED_FORMAT_V4 "ebpf-caps 4"
#define BML_RECORDED_FORMAT_V3 "ebpf-caps 3"
#define BML_RECORDED_FORMAT_V2 "ebpf-caps 2"

struct bml_recorded;


struct bml_recorded *bml_recorded_parse(const char *data, size_t len, const char *dir, char **err);

struct bml_recorded *bml_recorded_parse_rule(const char *data, size_t len, const char *dir, char **err, enum bml_json_rule *rule);

int bml_loader_decl_parse(const char *data, size_t len, struct bml_loader_decl *d, char **err, enum bml_json_rule *rule);

struct bml_recorded *bml_recorded_read(const char *path, char **err);
void bml_recorded_free(struct bml_recorded *r);

void bml_recorded_caps(struct bml_recorded *r, struct bml_caps *out);


char *bml_caps_tpfield_key(const char *event, const char *field, int64_t off, int64_t bytes, const char *sign);
char *bml_caps_kfunc_key(const char *name, const char *ret, const struct bml_str *args, size_t n);
char *bml_caps_proto_key(const char *a, char sep, const char *b, int64_t nargs, const char *ret, const struct bml_str *args, size_t n);

int bml_caps_privilege_dependent(const char *q);

int bml_caps_same_privilege(const char *cap_a, const char *cap_b);
/* CONTRACT: RecordedCaps.ForLoad: uses r with the load privileges (uid and CapEff); when they differ from the recorded probed_as, privilege-dependent queries are reprobed (NULL means Unknown).
 * Modifies r (Go returns a copy; bml uses one record for one check). reprobe must stay alive while r is used. Out of memory is -1 */
int bml_recorded_for_load(struct bml_recorded *r, long long load_uid, const char *load_cap, const struct bml_caps *reprobe);

int bml_caps_parse_load_as(const char *s, long long *uid, char **cap, char **err);

int bml_recorded_probed_as(const struct bml_recorded *r, long long *uid, char **cap);

#endif
