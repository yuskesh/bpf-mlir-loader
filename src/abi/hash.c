#define _GNU_SOURCE
#include "abi/map_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "abi/iter.h"

static const char *const hash_kinds[] = {"hash", "lru_hash", NULL};


static int64_t open_hash(int64_t obj, const char *decl, int64_t dl, const char *km, int64_t kl, const char *vm, int64_t vl,
			 int64_t klen, int64_t vlen, struct abi_map *m)
{
	const char *recs[2] = {km, vm};
	int64_t lens[2] = {km ? kl : 0, vm ? vl : 0};
	int64_t e = abi_map_open_kind(obj, decl, dl, hash_kinds, "a hash map", recs, lens, 2, m);
	if (e)
		return e;
	if ((int64_t)m->key_size != klen || (vlen >= 0 && (int64_t)m->value_size != vlen)) {
		e = abi_fail(BML_MAP_MISMATCH,
			     "bml: map %s has %u-byte keys and %u-byte values in the embedded ELF, but this program's are %lld and %lld bytes",
			     m->d.name, m->key_size, m->value_size, (long long)klen, (long long)vlen);
		abi_map_close(m);
	}
	return e;
}

static int bad_buf(const void *p, int64_t n)
{
	return n < 0 || (!p && n);
}

int64_t bml_hash_get(int64_t obj, const char *decl, int64_t dl, const char *km, int64_t kl, const char *vm, int64_t vl,
		     const uint8_t *key, int64_t klen, uint8_t *dst, int64_t dlen)
{
	struct abi_map m;
	if (bad_buf(key, klen) || bad_buf(dst, dlen))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL buffer with a length");
	int64_t e = open_hash(obj, decl, dl, km, kl, vm, vl, klen, dlen, &m);
	if (e)
		return e;
	if (bpf_map_lookup_elem(m.fd, key, dst) != 0)
		e = errno == ENOENT ? abi_fail(BML_NOT_FOUND, "bml: map %s has no such key", m.d.name) : abi_fail(BML_OTHER, "bml: lookup %s: %s", m.d.name, abi_errno(errno));
	else
		e = abi_ok(1);
	abi_map_close(&m);
	return e;
}

int64_t bml_hash_put(int64_t obj, const char *decl, int64_t dl, const char *km, int64_t kl, const char *vm, int64_t vl,
		     const uint8_t *key, int64_t klen, const uint8_t *val, int64_t vlen)
{
	struct abi_map m;
	if (bad_buf(key, klen) || bad_buf(val, vlen))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL buffer with a length");
	int64_t e = open_hash(obj, decl, dl, km, kl, vm, vl, klen, vlen, &m);
	if (e)
		return e;
	e = bpf_map_update_elem(m.fd, key, val, BPF_ANY) != 0 ? abi_fail(BML_OTHER, "bml: update %s: %s", m.d.name, abi_errno(errno))
							       : abi_ok(0);
	abi_map_close(&m);
	return e;
}

int64_t bml_hash_delete(int64_t obj, const char *decl, int64_t dl, const char *km, int64_t kl, const uint8_t *key, int64_t klen)
{
	struct abi_map m;
	if (bad_buf(key, klen))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL buffer with a length");
	int64_t e = open_hash(obj, decl, dl, km, kl, NULL, 0, klen, -1, &m);
	if (e)
		return e;
	if (bpf_map_delete_elem(m.fd, key) != 0)
		e = errno == ENOENT ? abi_fail(BML_NOT_FOUND, "bml: map %s has no such key", m.d.name) : abi_fail(BML_OTHER, "bml: delete %s: %s", m.d.name, abi_errno(errno));
	else
		e = abi_ok(1);
	abi_map_close(&m);
	return e;
}



int64_t abi_iter_open(struct abi_map *m, int64_t obj, int64_t klen, int64_t vlen, int percpu)
{
	struct abi_iter *it = calloc(1, sizeof *it);
	if (!it)
		return abi_fail(BML_OTHER, "bml: out of memory");
	pthread_mutex_init(&it->mu, NULL);
	it->obj = obj;
	it->fd = fcntl(m->fd, F_DUPFD_CLOEXEC, 3); /* CONTRACT: the map fd is copied so the iterator stays safe until its own close, even after the object closes (next checks closed first) */
	it->name = strdup(m->d.name);
	it->klen = (size_t)klen;
	it->vlen = (size_t)vlen;
	it->percpu = percpu;
	it->elem = percpu ? (size_t)vlen / (size_t)percpu : 0;
	it->max_entries = bpf_map__max_entries(m->map);
	it->cursor = calloc(1, (size_t)klen ? (size_t)klen : 1);
	if (it->fd < 0 || !it->name || !it->cursor) {
		abi_iter_free(it);
		return abi_fail(BML_OTHER, "bml: out of memory");
	}
	abi_lock();
	int64_t id = abi_handle_new(H_ITER, it, obj);
	abi_unlock();
	if (id < 0) {
		abi_iter_free(it);
		return abi_fail(BML_OTHER, "bml: out of memory");
	}
	return abi_ok(id);
}

int64_t bml_hash_iter_open(int64_t obj, const char *decl, int64_t dl, const char *km, int64_t kl, const char *vm, int64_t vl,
			   int64_t klen, int64_t vlen)
{
	struct abi_map m;
	if (klen < 0 || vlen < 0)
		return abi_fail(BML_OTHER, "bml: a negative length");
	int64_t e = open_hash(obj, decl, dl, km, kl, vm, vl, klen, vlen, &m);
	if (e)
		return e;
	e = abi_iter_open(&m, obj, klen, vlen, 0);
	abi_map_close(&m);
	return e;
}


static int iter_step(struct abi_iter *it, uint8_t *k, uint8_t *v, int *err)
{
	size_t stride = (it->elem + 7) / 8 * 8;
	uint8_t *raw = it->percpu ? calloc((size_t)it->percpu, stride ? stride : 1) : v;
	if (it->percpu && !raw) {
		*err = ENOMEM;
		return -1;
	}
	int rc = -2;
	for (; it->count <= it->max_entries; it->count++) {
		if (it->done) {
			rc = 0;
			break;
		}
		if (bpf_map_get_next_key(it->fd, it->started ? it->cursor : NULL, k) != 0) {
			if (errno == ENOENT) {
				it->done = 1;
				rc = 0;
				break;
			}
			*err = errno;
			rc = -1;
			break;
		}
		it->started = 1;
		memcpy(it->cursor, k, it->klen);
		if (bpf_map_lookup_elem(it->fd, k, raw) != 0) {
			if (errno == ENOENT)
				continue;
			*err = errno;
			rc = -1;
			break;
		}
		if (it->percpu)
			for (int c = 0; c < it->percpu; c++)
				memcpy(v + (size_t)c * it->elem, raw + (size_t)c * stride, it->elem);
		it->count++;
		rc = 1;
		break;
	}
	if (it->percpu)
		free(raw);
	return rc;
}

int64_t bml_hash_iter_next(int64_t iter, uint8_t *kdst, int64_t klen, uint8_t *vdst, int64_t vlen)
{
	abi_lock();
	struct abi_iter *it = abi_handle_get(iter, H_ITER);
	abi_unlock();
	if (!it)
		return abi_fail(BML_STATE, "bml: no map iterator %lld", (long long)iter);
	int64_t e;
	struct abi_object *o = abi_object_acquire(it->obj, &e);
	if (!o)
		return e;
	pthread_mutex_lock(&it->mu);
	if (it->closed)
		e = abi_fail(BML_STATE, "bml: the map iterator %lld (%s) is closed", (long long)iter, it->name);
	else if (bad_buf(kdst, klen) || bad_buf(vdst, vlen) || (size_t)klen != it->klen || (size_t)vlen != it->vlen)
		e = abi_fail(BML_OTHER, "bml: map iterator %s: buffer sizes %lld / %lld, want %zu / %zu", it->name, (long long)klen, (long long)vlen,
			     it->klen, it->vlen);
	else {
		uint8_t *k = malloc(it->klen ? it->klen : 1), *v = malloc(it->vlen ? it->vlen : 1);
		int err = 0, rc = k && v ? iter_step(it, k, v, &err) : (err = ENOMEM, -1);
		if (rc == 1) {
			memcpy(kdst, k, it->klen);
			memcpy(vdst, v, it->vlen);
			e = abi_ok(1);
		} else if (rc == 0)
			e = abi_ok(0);
		else if (rc == -2)
			e = abi_fail(BML_OTHER, "bml: iterate %s: iteration aborted (more than %u steps — the map changed while iterating)", it->name,
				     it->max_entries);
		else
			e = abi_fail(BML_OTHER, "bml: iterate %s: %s", it->name, abi_errno(err));
		free(k);
		free(v);
	}
	pthread_mutex_unlock(&it->mu);
	abi_object_release(o);
	return e;
}


static void iter_close_locked(struct abi_iter *it)
{
	if (!it->closed) {
		it->closed = 1;
		if (it->fd >= 0)
			close(it->fd);
		it->fd = -1;
	}
}

static void iter_close(struct abi_iter *it)
{
	pthread_mutex_lock(&it->mu);
	iter_close_locked(it);
	pthread_mutex_unlock(&it->mu);
}

int64_t bml_hash_iter_close(int64_t iter)
{
	abi_lock();
	struct abi_iter *it = abi_handle_get(iter, H_ITER);
	abi_unlock();
	if (!it)
		return abi_fail(BML_STATE, "bml: no map iterator %lld", (long long)iter);
	if (pthread_mutex_trylock(&it->mu) != 0)
		return abi_fail(BML_STATE, "bml: the map iterator %lld (%s) has a next in flight on another thread — close it again after it returns",
				(long long)iter, it->name);
	iter_close_locked(it);
	pthread_mutex_unlock(&it->mu);
	return abi_ok(0);
}


void abi_iter_free(void *p)
{
	iter_close(p);
}
