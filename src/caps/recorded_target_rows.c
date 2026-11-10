
#include "caps/recorded_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"
#include "util/mutation.h"

#define HT_PREFIX "[\"tracing\",\"26\",\"trace_fentry\",\""
#define HT_SUFFIX "\",\"d_path\",\"147\",\"0\",\"path\"]"

char *bml_caps_helper_target_key(const char *pt, int64_t id, const struct bml_helper_target *h)
{
	struct bml_buf b = {0};
	bml_buf_addf(&b, "[\"%s\",\"%lld\",\"%s\",\"%s\",\"%s\",\"%lld\",\"%lld\",\"%s\"]", pt, (long long)id, h->attach_type.p, h->target.p, h->helper.p,
		     (long long)h->helper_id, (long long)h->arg_index, h->arg_type.p);
	return bml_buf_take(&b);
}


static int blank(const char *s)
{
	const unsigned char *p = (const unsigned char *)s;
	while (*p) {
		if (*p == ' ' || (*p >= 9 && *p <= 13)) { p++; continue; }
		if (p[0] == 0xc2 && (p[1] == 0x85 || p[1] == 0xa0)) { p += 2; continue; }
		if (p[0] == 0xe1 && p[1] == 0x9a && p[2] == 0x80) { p += 3; continue; }
		if (p[0] == 0xe2 && p[1] == 0x80 && ((p[2] >= 0x80 && p[2] <= 0x8a) || p[2] == 0xa8 || p[2] == 0xa9 || p[2] == 0xaf)) { p += 3; continue; }
		if (p[0] == 0xe2 && p[1] == 0x81 && p[2] == 0x9f) { p += 3; continue; }
		if (p[0] == 0xe3 && p[1] == 0x80 && p[2] == 0x80) { p += 3; continue; }
		return 0;
	}
	return 1;
}

static char *quoted(const char *pre, const char *key, const char *post)
{
	struct bml_buf b = {0};
	bml_buf_adds(&b, pre);
	bml_buf_add_goquote(&b, key, strlen(key));
	bml_buf_adds(&b, post);
	return bml_buf_take(&b);
}

static const struct query *q_of(const struct bml_recorded *r, const char *name, int priv)
{
	for (size_t i = 0; i < r->n_q; i++)
		if (r->q[i].priv == priv && !strcmp(r->q[i].name, name))
			return &r->q[i];
	return NULL;
}


static int check_helper_key(const char *key, char **err)
{
	size_t n = strlen(key), pn = sizeof HT_PREFIX - 1, sn = sizeof HT_SUFFIX - 1;
	int ok = n > pn + sn && !strncmp(key, HT_PREFIX, pn) && !strcmp(key + n - sn, HT_SUFFIX);
	if (ok) {
		const char *t = key + pn;
		size_t tn = n - pn - sn;
		ok = (t[0] == '_' || (t[0] >= 'a' && t[0] <= 'z') || (t[0] >= 'A' && t[0] <= 'Z'));
		for (size_t i = 1; ok && i < tn; i++)
			ok = t[i] == '_' || t[i] == '.' || (t[i] >= '0' && t[i] <= '9') || (t[i] >= 'a' && t[i] <= 'z') || (t[i] >= 'A' && t[i] <= 'Z');
	}
	if (ok || BML_MUT("caps.helper_target_key_any"))
		return 0;
	struct bml_json *j = NULL;
	char *perr = NULL;
	int shape = 0;
	if (bml_json_parse(key, n, &j, &perr) == 0 && j && j->type == BML_JSON_ARRAY && j->n == 8) {
		shape = 1;
		for (size_t i = 0; i < 8; i++)
			if (j->items[i]->type != BML_JSON_STRING && j->items[i]->type != BML_JSON_NULL)
				shape = 0;
	}
	bml_json_free(j);
	free(perr);
	*err = shape ? quoted("helper_target: noncanonical or unsupported key ", key, "") : strdup("helper_target: key must be a canonical eight-string JSON array");
	return -1;
}

static int check_sleepable(const struct bml_recorded *r, int version, char **err)
{
	for (int priv = 0; priv < 2; priv++) {
		const struct query *q = q_of(r, BML_QUERY_SLEEPABLE, priv);
		if (!q)
			continue;
		if (version != 20 && !BML_MUT("caps.sleepable_any_format")) {
			*err = rc_fmts("caps: query \"" BML_QUERY_SLEEPABLE "\" is new in \"" BML_RECORDED_FORMAT "\", but the format is \"%s\"", r->format);
			return 1;
		}
		for (size_t i = 0; i < q->n; i++) {
			const char *k = q->e[i].key, *s = strchr(k, '/');
			if (!s || s == k || !s[1] || strpbrk(k, " \t\n") || strchr(s + 1, '/')) {
				*err = quoted("caps: sleepable_types: key ", k, " is not <program type>/<attach type>");
				return -1;
			}
			const struct answer *a = &q->e[i].a;
			if (!a->has_value && (!a->unknown || !a->unknown[0]) && (!a->error || !a->error[0])) {
				*err = quoted("caps: sleepable_types ", k, " is not a value answer");
				return -1;
			}
		}
	}
	return 0;
}

static int check_netkit(const struct bml_recorded *r, int version, char **err)
{
	for (int priv = 0; priv < 2; priv++) {
		const struct query *q = q_of(r, BML_QUERY_NETKIT, priv);
		if (!q)
			continue;
		if (version < 18 && !BML_MUT("caps.netkit_any_format")) {
			*err = rc_fmts("caps: query \"" BML_QUERY_NETKIT "\" is new in \"" BML_RECORDED_FORMAT_V18 "\", but the format is \"%s\"", r->format);
			return 1;
		}
		for (size_t i = 0; i < q->n; i++) {
			const char *d = q->e[i].key;
			if (strcmp(d, "primary") && strcmp(d, "peer") && !BML_MUT("caps.netkit_any_key")) {
				*err = quoted("caps: netkit: unknown direction ", d, "");
				return -1;
			}
			const struct answer *a = &q->e[i].a;
			if (!a->has_value && (!a->unknown || !a->unknown[0]) && (!a->error || !a->error[0])) {
				*err = quoted("caps: netkit ", d, " is not a value answer");
				return -1;
			}
		}
	}
	return 0;
}


static int check_helper_raw(const struct bml_recorded *r, const struct bml_json *root, char **err)
{
	static const char *const objs[2] = {"queries", "privileged_queries"};
	for (int priv = 0; priv < 2; priv++) {
		const struct query *q = q_of(r, BML_QUERY_HELPER_TARGET, priv);
		const struct bml_json *o = bml_json_get(root, objs[priv]);
		const struct bml_json *m = o ? bml_json_get(o, BML_QUERY_HELPER_TARGET) : NULL;
		for (size_t i = 0; q && m && i < q->n; i++) {
			const char *k = q->e[i].key;
			const struct bml_json *v = bml_json_get(m, k);
			if (!v || v->type != BML_JSON_OBJECT || v->n != 1) {
				*err = quoted("caps: helper_target ", k, " needs exactly one answer field");
				return -1;
			}
			const char *name = v->members[0].key;
			const struct bml_json *x = v->members[0].value;
			if (!strcmp(name, "diffs")) {
				int ok = x->type == BML_JSON_ARRAY;
				for (size_t e = 0; ok && e < x->n; e++)
					ok = x->items[e]->type == BML_JSON_STRING || x->items[e]->type == BML_JSON_NULL;
				if (!ok) {
					*err = quoted("caps: helper_target ", k, " needs a non-null diffs array");
					return -1;
				}
			} else if (!strcmp(name, "unknown") || !strcmp(name, "error")) {
				if (x->type != BML_JSON_STRING || blank(x->str)) {
					struct bml_buf b = {0};
					bml_buf_adds(&b, " needs a nonempty ");
					bml_buf_adds(&b, name);
					bml_buf_adds(&b, " reason");
					char *post = bml_buf_take(&b);
					*err = quoted("caps: helper_target ", k, post ? post : "");
					free(post);
					return -1;
				}
			} else {
				struct bml_buf b = {0};
				bml_buf_adds(&b, " does not accept answer ");
				bml_buf_add_goquote(&b, name, strlen(name));
				char *post = bml_buf_take(&b);
				*err = quoted("caps: helper_target ", k, post ? post : "");
				free(post);
				return -1;
			}
		}
	}
	return 0;
}

static int check_helper(const struct bml_recorded *r, const struct bml_json *root, int version, char **err)
{
	if (check_helper_raw(r, root, err))
		return -1;
	for (int priv = 0; priv < 2; priv++) {
		const struct query *q = q_of(r, BML_QUERY_HELPER_TARGET, priv);
		if (!q)
			continue;
		if (version < 19 && !BML_MUT("caps.helper_target_any_format")) {
			*err = rc_fmts("caps: query \"" BML_QUERY_HELPER_TARGET "\" is new in \"" BML_RECORDED_FORMAT_V19 "\", but the format is \"%s\"", r->format);
			return 1;
		}
		for (size_t i = 0; i < q->n; i++) {
			const char *k = q->e[i].key;
			if (check_helper_key(k, err))
				return -1;
			const struct answer *a = &q->e[i].a;
			if (a->has_diffs)
				for (size_t d = 0; d < a->diffs.n; d++)
					if (blank(a->diffs.s[d])) {
						*err = quoted("caps: helper_target ", k, " has empty mismatch text");
						return -1;
					}
		}
	}
	return 0;
}

int rc_check_target_queries(const struct bml_recorded *r, const struct bml_json *j, int version, char **err)
{
	int rc = check_sleepable(r, version, err);
	if (rc)
		return rc;
	rc = check_netkit(r, version, err);
	if (rc)
		return rc;
	return check_helper(r, j, version, err);
}


int rc_helper_target_privilege(const struct bml_recorded *r, const struct bml_caps **reprobe, char **msg)
{
	*reprobe = NULL;
	if (r->scope.set && r->has_probed && r->probed_uid != r->scope.load_uid && !BML_MUT("caps.helper_target_no_uid")) {
		if (r->scope.reprobe) {
			*reprobe = r->scope.reprobe;
			return 1;
		}
		*msg = rc_fmts("recorded helper_target UID %lld differs from load UID %lld: cannot be determined on this target", r->probed_uid, r->scope.load_uid);
		return -1;
	}
	return rc_privileged(r, BML_QUERY_HELPER_TARGET, reprobe, msg);
}

static int has_key(const struct bml_recorded *r, const char *q, const char *key)
{
	for (size_t i = 0; i < r->n_q; i++)
		if (!strcmp(r->q[i].name, q))
			for (size_t j = 0; j < r->q[i].n; j++)
				if (!strcmp(r->q[i].e[j].key, key))
					return 1;
	return 0;
}

#define NO_REPROBE(Q) (*msg = strdup("recorded caps: the re-probing caps has no " Q " query: cannot be determined on this target"), BML_Q_UNKNOWN)

static int rec_netkit(void *ctx, const char *d, int *out, char **msg)
{
	const struct bml_caps *rp;
	int pv = rc_privileged(ctx, BML_QUERY_NETKIT, &rp, msg);
	if (pv < 0)
		return *msg ? BML_Q_UNKNOWN : (*msg = strdup("out of memory"), BML_Q_ERROR);
	if (pv > 0)
		return rp->netkit ? rp->netkit(rp->ctx, d, out, msg) : NO_REPROBE(BML_QUERY_NETKIT);
	return rc_boolean(ctx, BML_QUERY_NETKIT, d, out, msg);
}

static int rec_sleepable(void *ctx, const char *pt, const char *at, int *out, char **msg)
{
	const struct bml_caps *rp;
	int pv = rc_privileged(ctx, BML_QUERY_SLEEPABLE, &rp, msg);
	if (pv < 0)
		return *msg ? BML_Q_UNKNOWN : (*msg = strdup("out of memory"), BML_Q_ERROR);
	if (pv > 0)
		return rp->sleepable ? rp->sleepable(rp->ctx, pt, at, out, msg) : NO_REPROBE(BML_QUERY_SLEEPABLE);
	char *key = rc_fmts("%s/%s", pt, at);
	if (!key)
		return (*msg = strdup("out of memory"), BML_Q_ERROR);
	int st = rc_boolean(ctx, BML_QUERY_SLEEPABLE, key, out, msg);
	free(key);
	return st;
}

static int rec_helper_target(void *ctx, const char *pt, int64_t id, const struct bml_helper_target *h, struct bml_strs *out, char **msg)
{
	const struct bml_caps *rp;
	int pv = rc_helper_target_privilege(ctx, &rp, msg);
	if (pv < 0)
		return *msg ? BML_Q_UNKNOWN : (*msg = strdup("out of memory"), BML_Q_ERROR);
	if (pv > 0)
		return rp->helper_target ? rp->helper_target(rp->ctx, pt, id, h, out, msg) : NO_REPROBE(BML_QUERY_HELPER_TARGET);
	char *key = bml_caps_helper_target_key(pt, id, h);
	if (!key)
		return (*msg = strdup("out of memory"), BML_Q_ERROR);
	int st;
	if (!has_key(ctx, BML_QUERY_HELPER_TARGET, key)) {
		*msg = quoted("recorded caps: no answer for helper_target ", key, ": cannot be determined on this target");
		st = BML_Q_UNKNOWN;
	} else {
		st = rc_diffs(ctx, BML_QUERY_HELPER_TARGET, key, out, msg);
	}
	free(key);
	return st;
}

void rc_caps_target_rows(struct bml_caps *c)
{
	c->netkit = rec_netkit;
	c->sleepable = rec_sleepable;
	c->helper_target = rec_helper_target;
}
