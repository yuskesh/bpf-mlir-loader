#define _GNU_SOURCE
#include "abi/internal.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"
#include "util/mutation.h"

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

void abi_lock(void)
{
	pthread_mutex_lock(&mu);
}

void abi_unlock(void)
{
	pthread_mutex_unlock(&mu);
}



struct rslot {
	int64_t id;
	struct abi_result r;
};

static struct rslot *results;
static size_t n_results, cap_results;
static int64_t next_result = 1;

static void result_clear(struct abi_result *r)
{
	free(r->msg);
	for (size_t i = 0; i < r->n_u; i++)
		for (int k = 0; k < 4; k++)
			free(r->u[i].f[k]);
	free(r->u);
	memset(r, 0, sizeof *r);
}

int64_t abi_put(struct abi_result *r)
{
	if (!r->msg) {
		r->msg = strdup("");
		r->msg_len = 0;
		if (!r->msg) {
			result_clear(r);
			return -1;
		}
	}
	pthread_mutex_lock(&mu);
	if (n_results == cap_results) {
		size_t nc = cap_results ? cap_results * 2 : 16;
		struct rslot *ns = realloc(results, nc * sizeof *ns);
		if (!ns) {
			pthread_mutex_unlock(&mu);
			result_clear(r);
			return -1;
		}
		results = ns;
		cap_results = nc;
	}
	int64_t id = next_result++;
	results[n_results].id = id;
	results[n_results].r = *r;
	n_results++;
	pthread_mutex_unlock(&mu);
	memset(r, 0, sizeof *r);
	return id;
}

int64_t abi_fail(int64_t kind, const char *fmt, ...)
{
	struct abi_result r = {.kind = kind};
	va_list ap;
	va_start(ap, fmt);
	int n = vasprintf(&r.msg, fmt, ap);
	va_end(ap);
	if (n < 0)
		r.msg = NULL;
	else
		r.msg_len = (size_t)n;
	return abi_put(&r);
}

int64_t abi_ok(int64_t value)
{
	struct abi_result r = {.kind = BML_OK, .value = value};
	return abi_put(&r);
}

int abi_set_unmets(struct abi_result *r, const struct bml_unmet *u, size_t n)
{
	if (!n)
		return 0;
	r->u = calloc(n, sizeof *r->u);
	if (!r->u)
		return -1;
	r->n_u = n;
	for (size_t i = 0; i < n; i++) {
		const char *f[4] = {u[i].kind, u[i].program ? u[i].program : "", u[i].name ? u[i].name : "", u[i].detail ? u[i].detail : ""};
		for (int k = 0; k < 4; k++) {
			r->u[i].f[k] = strdup(f[k]);
			if (!r->u[i].f[k])
				return -1;
			r->u[i].len[k] = strlen(f[k]);
		}
	}
	return 0;
}


static struct abi_result *result_get(int64_t id)
{
	for (size_t i = 0; i < n_results; i++)
		if (results[i].id == id)
			return &results[i].r;
	return NULL;
}

int64_t bml_result_kind(int64_t r)
{
	pthread_mutex_lock(&mu);
	struct abi_result *x = result_get(r);
	int64_t k = x ? x->kind : BML_STATE;
	pthread_mutex_unlock(&mu);
	return k;
}

int64_t bml_result_value(int64_t r)
{
	pthread_mutex_lock(&mu);
	struct abi_result *x = result_get(r);
	int64_t v = x ? x->value : 0;
	pthread_mutex_unlock(&mu);
	return v;
}


static const char no_result[] = "bml: no such result (it was never returned or was already freed)";

const char *bml_result_message(int64_t r, int64_t *len)
{
	pthread_mutex_lock(&mu);
	struct abi_result *x = result_get(r);
	const char *m = x ? x->msg : no_result;
	size_t l = x ? x->msg_len : sizeof no_result - 1;
	pthread_mutex_unlock(&mu);
	if (len)
		*len = (int64_t)l;
	return m;
}

static int64_t copy_out(const char *s, size_t l, char *buf, int64_t cap)
{
	if (buf && cap > 0)
		memcpy(buf, s, (size_t)cap < l ? (size_t)cap : l);
	return (int64_t)l;
}

int64_t bml_result_message_copy(int64_t r, char *buf, int64_t cap)
{
	pthread_mutex_lock(&mu);
	struct abi_result *x = result_get(r);
	int64_t n = x ? copy_out(x->msg, x->msg_len, buf, cap) : copy_out(no_result, sizeof no_result - 1, buf, cap);
	pthread_mutex_unlock(&mu);
	return n;
}

int64_t bml_result_unmet_count(int64_t r)
{
	pthread_mutex_lock(&mu);
	struct abi_result *x = result_get(r);
	int64_t n = x ? (int64_t)x->n_u : 0;
	pthread_mutex_unlock(&mu);
	return n;
}

const char *bml_result_unmet_field(int64_t r, int64_t i, int64_t field, int64_t *len)
{
	pthread_mutex_lock(&mu);
	struct abi_result *x = result_get(r);
	const char *s = "";
	size_t l = 0;
	if (x && i >= 0 && (size_t)i < x->n_u && field >= 0 && field < 4) {
		s = x->u[i].f[field];
		l = x->u[i].len[field];
	}
	pthread_mutex_unlock(&mu);
	if (len)
		*len = (int64_t)l;
	return s;
}

int64_t bml_result_unmet_field_copy(int64_t r, int64_t i, int64_t field, char *buf, int64_t cap)
{
	pthread_mutex_lock(&mu);
	struct abi_result *x = result_get(r);
	int64_t n = 0;
	if (x && i >= 0 && (size_t)i < x->n_u && field >= 0 && field < 4)
		n = copy_out(x->u[i].f[field], x->u[i].len[field], buf, cap);
	pthread_mutex_unlock(&mu);
	return n;
}

void bml_result_free(int64_t r)
{
	pthread_mutex_lock(&mu);
	for (size_t i = 0; i < n_results; i++)
		if (results[i].id == r) {
			result_clear(&results[i].r);
			results[i] = results[--n_results];
			break;
		}
	pthread_mutex_unlock(&mu);
}



struct hslot {
	int64_t id, owner;
	int type;
	void *p;
};

static struct hslot *handles;
static size_t n_handles, cap_handles;
static int64_t next_handle = 1;
int64_t abi_loaded;

int64_t abi_handle_new(int type, void *p, int64_t owner)
{
	if (n_handles == cap_handles) {
		size_t nc = cap_handles ? cap_handles * 2 : 16;
		struct hslot *ns = realloc(handles, nc * sizeof *ns);
		if (!ns)
			return -1;
		handles = ns;
		cap_handles = nc;
	}
	int64_t id = next_handle++;
	handles[n_handles++] = (struct hslot){id, owner, type, p};
	return id;
}

void *abi_handle_get(int64_t h, int type)
{
	for (size_t i = 0; i < n_handles; i++)
		if (handles[i].id == h)
			return handles[i].type == type ? handles[i].p : NULL;
	return NULL;
}

void *abi_handle_take(int64_t h, int type)
{
	for (size_t i = 0; i < n_handles; i++)
		if (handles[i].id == h && handles[i].type == type) {
			void *p = handles[i].p;
			handles[i] = handles[--n_handles];
			return p;
		}
	return NULL;
}

size_t abi_handle_list_owned(int type, int64_t owner, void ***out)
{
	size_t n = 0;
	*out = NULL;
	for (size_t i = 0; i < n_handles; i++)
		n += handles[i].type == type && handles[i].owner == owner;
	if (!n)
		return 0;
	void **v = calloc(n, sizeof *v);
	if (!v)
		return 0;
	size_t k = 0;
	for (size_t i = 0; i < n_handles; i++)
		if (handles[i].type == type && handles[i].owner == owner)
			v[k++] = handles[i].p;
	*out = v;
	return k;
}

struct abi_object *abi_object_get(int64_t h, int64_t *err)
{
	abi_lock();
	struct abi_object *o = abi_handle_get(h, H_OBJECT);
	int closed = o && o->closed;
	abi_unlock();
	if (!o) {
		*err = abi_fail(BML_STATE, "bml: no loaded object %lld (load it first)", (long long)h);
		return NULL;
	}
	if (closed) {
		*err = abi_fail(BML_STATE, "bml: the object %lld is closed", (long long)h);
		return NULL;
	}
	return o;
}

struct abi_object *abi_object_acquire(int64_t h, int64_t *err)
{
	abi_lock();
	struct abi_object *o = abi_handle_get(h, H_OBJECT);
	int closed = o && o->closed;
	if (o && !closed && !BML_MUT("abi.no_inflight"))
		o->inflight++;
	abi_unlock();
	if (!o) {
		*err = abi_fail(BML_STATE, "bml: no loaded object %lld (load it first)", (long long)h);
		return NULL;
	}
	if (closed) {
		*err = abi_fail(BML_STATE, "bml: the object %lld is closed", (long long)h);
		return NULL;
	}
	return o;
}

void abi_object_release(struct abi_object *o)
{
	if (!o || BML_MUT("abi.no_inflight"))
		return;
	abi_lock();
	o->inflight--;
	abi_unlock();
}



const char *abi_errno(int e)
{
	static __thread char buf[256];
	char *s = bml_go_errno_str(e);
	snprintf(buf, sizeof buf, "%s", s ? s : "unknown error");
	free(s);
	return buf;
}
