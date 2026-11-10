/* CONTRACT: reads bml results and shim results (SH_BASE and above) through one handle space.
 * Message and unmet rows are C strings owned by the result (a NUL in a message is written as the two characters `\0`); result_free releases them together. */
#define _GNU_SOURCE
#include "shim/spinel/internal.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bml/bml.h"
#include "shim/spinel/spinelbpf.h"

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

struct own {
	int64_t r;
	char *s;
};
struct shres {
	int64_t id, kind, value;
	char *msg;
};
struct rdsz {
	int64_t rb, size;
};

static struct own *owns;
static size_t n_owns, cap_owns;
static struct shres *shs;
static size_t n_shs, cap_shs;
static struct rdsz *rds;
static size_t n_rds, cap_rds;
static int64_t next_id = SH_BASE;


static int grow(void **v, size_t n, size_t *cap, size_t sz)
{
	if (n < *cap)
		return 1;
	size_t nc = *cap ? *cap * 2 : 16;
	void *p = realloc(*v, nc * sz);
	if (!p)
		return 0;
	*v = p;
	*cap = nc;
	return 1;
}
#define GROW(v, n, cap) grow((void **)&(v), (n), &(cap), sizeof *(v))

int64_t sh_result(int64_t kind, int64_t value, const char *fmt, ...)
{
	char *m = NULL;
	va_list ap;
	va_start(ap, fmt);
	if (vasprintf(&m, fmt, ap) < 0)
		m = NULL;
	va_end(ap);
	pthread_mutex_lock(&mu);
	int64_t id = -1;
	if (GROW(shs, n_shs, cap_shs)) {
		id = next_id++;
		shs[n_shs++] = (struct shres){id, kind, value, m ? m : strdup("")};
	} else
		free(m);
	pthread_mutex_unlock(&mu);
	return id;
}

static struct shres *find_sh(int64_t r)
{
	for (size_t i = 0; i < n_shs; i++)
		if (shs[i].id == r)
			return &shs[i];
	return NULL;
}

struct sh_res sh_take(int64_t r)
{
	struct sh_res x = {bml_result_kind(r), bml_result_value(r), NULL, 0};
	const char *m = bml_result_message(r, &x.len);
	x.msg = malloc((size_t)x.len + 1);
	if (x.msg) {
		memcpy(x.msg, m ? m : "", (size_t)x.len);
		x.msg[x.len] = 0;
	} else
		x.len = 0;
	bml_result_free(r);
	return x;
}

void sh_res_free(struct sh_res *x)
{
	free(x->msg);
	x->msg = NULL;
}

void sh_reader_set(int64_t rb, int64_t size)
{
	pthread_mutex_lock(&mu);
	if (GROW(rds, n_rds, cap_rds))
		rds[n_rds++] = (struct rdsz){rb, size};
	pthread_mutex_unlock(&mu);
}

int64_t sh_reader_size(int64_t rb)
{
	int64_t s = -1;
	pthread_mutex_lock(&mu);
	for (size_t i = 0; i < n_rds; i++)
		if (rds[i].rb == rb)
			s = rds[i].size;
	pthread_mutex_unlock(&mu);
	return s;
}

int64_t spinelbpf_result_kind(int64_t r)
{
	if (r >= SH_BASE) {
		pthread_mutex_lock(&mu);
		struct shres *x = find_sh(r);
		int64_t k = x ? x->kind : BML_STATE;
		pthread_mutex_unlock(&mu);
		return k;
	}
	return bml_result_kind(r);
}

int64_t spinelbpf_result_value(int64_t r)
{
	if (r >= SH_BASE) {
		pthread_mutex_lock(&mu);
		struct shres *x = find_sh(r);
		int64_t v = x ? x->value : 0;
		pthread_mutex_unlock(&mu);
		return v;
	}
	return bml_result_value(r);
}


static char *own(int64_t r, const char *s, int64_t n)
{
	size_t k = 0;
	for (int64_t i = 0; i < n; i++)
		k += s[i] ? 1 : 2;
	char *c = malloc(k + 1), *p = c;
	if (!c)
		return NULL;
	for (int64_t i = 0; i < n; i++) {
		if (s[i])
			*p++ = s[i];
		else
			*p++ = '\\', *p++ = '0';
	}
	*p = 0;
	pthread_mutex_lock(&mu);
	if (GROW(owns, n_owns, cap_owns))
		owns[n_owns++] = (struct own){r, c};
	else {
		free(c);
		c = NULL;
	}
	pthread_mutex_unlock(&mu);
	return c;
}

char *spinelbpf_result_message(int64_t r)
{
	if (r >= SH_BASE) {
		pthread_mutex_lock(&mu);
		struct shres *x = find_sh(r);
		char *m = x ? x->msg : NULL;
		pthread_mutex_unlock(&mu);
		if (m)
			return m;
		char buf[64];
		snprintf(buf, sizeof buf, "spinelbpf: no result %lld", (long long)r);
		return own(r, buf, (int64_t)strlen(buf));
	}
	int64_t n = 0;
	const char *m = bml_result_message(r, &n);
	if (m && (int64_t)strlen(m) == n)
		return (char *)m;
	return own(r, m ? m : "", m ? n : 0);
}

int64_t spinelbpf_result_unmet_count(int64_t r)
{
	return r >= SH_BASE ? 0 : bml_result_unmet_count(r);
}


char *spinelbpf_result_unmet(int64_t r, int64_t i)
{
	if (r >= SH_BASE || i < 0 || i >= bml_result_unmet_count(r))
		return own(r, "", 0);
	size_t tot = 0;
	int64_t len[4];
	const char *f[4];
	for (int k = 0; k < 4; k++) {
		f[k] = bml_result_unmet_field(r, i, k, &len[k]);
		tot += (size_t)len[k] + 1;
	}
	char *line = malloc(tot), *p = line;
	if (!line)
		return NULL;
	for (int k = 0; k < 4; k++) {
		memcpy(p, f[k], (size_t)len[k]);
		p += len[k];
		*p++ = k < 3 ? '\t' : 0;
	}
	char *c = own(r, line, (int64_t)(p - line - 1));
	free(line);
	return c;
}

void spinelbpf_result_free(int64_t r)
{
	pthread_mutex_lock(&mu);
	for (size_t i = 0; i < n_owns;) {
		if (owns[i].r == r) {
			free(owns[i].s);
			owns[i] = owns[--n_owns];
		} else
			i++;
	}
	struct shres *x = r >= SH_BASE ? find_sh(r) : NULL;
	if (x) {
		free(x->msg);
		*x = shs[--n_shs];
	}
	pthread_mutex_unlock(&mu);
	if (r < SH_BASE)
		bml_result_free(r);
}

int64_t spinelbpf_policy_version(void)
{
	return bml_policy_version();
}
