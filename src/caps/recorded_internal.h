/* caps/recorded_internal.h — the internals of recorded caps (caps.json), for use inside caps/ only. recorded.c was split up for this. */
#ifndef BML_CAPS_RECORDED_INTERNAL_H
#define BML_CAPS_RECORDED_INTERNAL_H

#include <stddef.h>

#include "caps/recorded.h"
#include "json/json.h"


struct answer {
	int has_value, value;
	char *unknown, *error, *text, *file; /* unknown, error and file are unset when ""; text is unset when NULL */
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
	int priv; /* read from privileged_queries (this matters only for validating the read; afterwards it is the same table as queries) */
};

/* the privilege of the load for ForLoad (recorded_priv.c) */
struct rc_scope {
	int set;           /* set after ForLoad */
	int mismatch;      /* the recorded probed_as differs from the privilege of the load (a missing probed_as counts as different) */
	long long load_uid;
	char *load_cap;
	const struct bml_caps *reprobe; /* the caps used to probe again (NULL means Unknown) */
};

struct bml_recorded {
	char *format;
	int has_probed; /* Go's *ProbedAs is not nil (an empty {} counts as present) */
	long long probed_uid;
	char *probed_cap;
	struct bml_loader_decl loader;
	struct query *q;
	size_t n_q;
	char *dir;
	struct rc_scope scope;
};

/* How a query that depends on privilege is handled (Go's privileged): 0 answers from the recording, 1 answers from *r (the caps that probe again), and -1 is Unknown (*msg, malloc'd) */
int rc_privileged(const struct bml_recorded *r, const char *q, const struct bml_caps **reprobe, char **msg);
/* reading the answers in recorded_query.c (truth values and diffs; shared with recorded_e499.c) */
int rc_boolean(const struct bml_recorded *r, const char *q, const char *key, int *out, char **msg);
/* one answer of the recording (a missing key is ERROR; an unknown / error answer gives UNKNOWN / ERROR with its sentence) */
int rc_answer(const struct bml_recorded *r, const char *q, const char *key, const struct answer **out, char **msg);
int rc_diffs(const struct bml_recorded *r, const char *q, const char *key, struct bml_strs *out, char **msg);
/* recorded_e499.c: puts the callbacks of kfunc_loads and tracepoint_buffer into c */
void rc_caps_e499(struct bml_caps *c);
/* recorded_v16.c: puts the callbacks of tracepoint_fields and syscall_args into c (a missing strptr / strarray key is Unknown) */
void rc_caps_v16(struct bml_caps *c);
int rc_format_version(const char *format);
int rc_added_loader_version(const struct bml_recorded *r, int version, char **err);
int rc_added_query_version(const struct bml_recorded *r, int version, char **err);
void rc_caps_kernel_values(struct bml_caps *c);
/* recorded_target_rows.c: validates the reading of sleepable, netkit and helper_target (0; -1 with *err; 1 with *err for caps_key_newer_format) and puts their callbacks in place */
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
/* The strict reading (section 13): parse (byte-level rules and key_case), then the type check (unknown_key, type) */
struct bml_json *rc_strict(const char *data, size_t len, const struct bml_json_desc *d, const char *prefix, char **err,
			   enum bml_json_rule *rule);

#endif
