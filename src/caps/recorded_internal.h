#ifndef BML_CAPS_RECORDED_INTERNAL_H
#define BML_CAPS_RECORDED_INTERNAL_H

#include <stddef.h>

#include "caps/recorded.h"
#include "json/json.h"


struct answer {
	int has_value, value;
	char *unknown, *error, *text, *file;
	int has_diffs;
	struct bml_strs diffs;
};

struct entry {
	char *key;
	struct answer a;
};

struct query {
	char *name;
	struct entry *e;
	size_t n;
	int priv;
};


struct rc_scope {
	int set;
	int mismatch;
	long long load_uid;
	char *load_cap;
	const struct bml_caps *reprobe;
};

struct bml_recorded {
	char *format;
	int has_probed;
	long long probed_uid;
	char *probed_cap;
	struct bml_loader_decl loader;
	struct query *q;
	size_t n_q;
	char *dir;
	struct rc_scope scope;
};


int rc_privileged(const struct bml_recorded *r, const char *q, const struct bml_caps **reprobe, char **msg);

int rc_boolean(const struct bml_recorded *r, const char *q, const char *key, int *out, char **msg);

int rc_answer(const struct bml_recorded *r, const char *q, const char *key, const struct answer **out, char **msg);
int rc_diffs(const struct bml_recorded *r, const char *q, const char *key, struct bml_strs *out, char **msg);

void rc_caps_e499(struct bml_caps *c);

void rc_caps_v16(struct bml_caps *c);
int rc_format_version(const char *format);
int rc_added_loader_version(const struct bml_recorded *r, int version, char **err);
int rc_added_query_version(const struct bml_recorded *r, int version, char **err);
void rc_caps_kernel_values(struct bml_caps *c);

int rc_check_target_queries(const struct bml_recorded *r, const struct bml_json *j, int version, char **err);
void rc_caps_target_rows(struct bml_caps *c);
int rc_helper_target_privilege(const struct bml_recorded *r, const struct bml_caps **reprobe, char **msg);

extern const struct bml_json_desc rc_d_caps, rc_d_loader;
char *rc_fmts(const char *f, ...) __attribute__((format(printf, 1, 2)));
void rc_answer_free(struct answer *a);
int rc_check_keys(const struct bml_json *o, const char *const *allowed, size_t n, const char *where, char **err);
int rc_get_str(const struct bml_json *o, const char *key, char **out, char **err);
int rc_get_bool(const struct bml_json *o, const char *key, int *set, int *out, char **err);
int rc_get_kv(const struct bml_json *o, const char *key, struct bml_kv **out, size_t *n, int *has, char **err);
int rc_decode_answer(const struct bml_json *v, struct answer *a, char **err);

struct bml_json *rc_strict(const char *data, size_t len, const struct bml_json_desc *d, const char *prefix, char **err,
			   enum bml_json_rule *rule);

#endif
