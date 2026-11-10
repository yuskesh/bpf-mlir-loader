/* CONTRACT: ring buffer reader.
 * - Pull style: open, then read(timeout) repeatedly by the caller, then close. A per-reader mutex serializes read and close. **close does not wait**:
 *   read counts as a running call of the object (an object close during it is STATE), and a reader close during a read on another thread
 *   only tries the mutex and returns STATE (the caller retries)
 * - **The mmap region is never given to the caller**: libbpf's ring_buffer callback copies the sample into the reader's buffer, then into the caller's buffer
 * - **A read on a closed reader is STATE** (the mapping is not touched, since downstream languages cannot handle SEGV). A second close is OK. Closing the object closes readers
 *   first (owned.c)
 * - A timeout is OK with value 0. One read is made after the deadline (the same measure as cilium's against BPF_RB_NO_WAKEUP). Discarded records are
 *   skipped by libbpf. An event size different from the record is MAP_MISMATCH */
#define _GNU_SOURCE
#include "abi/map_internal.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>

#include <bpf/libbpf.h>

#include "btf/layout.h"
#include "util/mutation.h"

struct abi_reader {
	pthread_mutex_t mu;
	int64_t obj;
	struct ring_buffer *rb;
	char *name;
	size_t rec_size;
	int closed;

	uint8_t *buf;
	size_t got_len;
	int got;
};

static int on_sample(void *ctx, void *data, size_t size)
{
	struct abi_reader *r = ctx;
	r->got = 1;
	r->got_len = size;
	memcpy(r->buf, data, size < r->rec_size ? size : r->rec_size);
	return 0;
}



static int64_t record_size_check(const struct abi_map *m, int64_t rec_size)
{
	const char *v = m->d.value;
	if (strncmp(v, "record:", 7) != 0)
		return abi_fail(BML_MAP_MISMATCH, "bml: ring buffer %s: the declared value %s is not a record", m->d.name, v);
	struct lbtf b;
	char *err = NULL;
	if (btf_layout_parse(m->o->elf, m->o->elf_len, &b, &err) != 0) {
		int64_t e = abi_fail(BML_OTHER, "bml: ring buffer %s: the ELF BTF cannot be read: %s", m->d.name, err ? err : "");
		free(err);
		return e;
	}
	int64_t size = -1;
	for (size_t i = 0; i < b.n; i++)
		if (b.t[i].kind == 4 && !strcmp(b.t[i].name, v + 7))
			size = b.t[i].size;
	btf_layout_free(&b);
	if (size < 0)
		return abi_fail(BML_MAP_MISMATCH, "bml: ring buffer %s: the ELF BTF has no struct %s", m->d.name, v + 7);
	if (size != rec_size)
		return abi_fail(BML_MAP_MISMATCH,
				"bml: ring buffer %s: the record %s is %lld bytes in the embedded ELF, but the reader is for %lld-byte records — regenerate the bindings and rebuild",
				m->d.name, v + 7, (long long)size, (long long)rec_size);
	return 0;
}

int64_t bml_ringbuf_open(int64_t obj, const char *decl, int64_t dl, const char *members, int64_t ml, int64_t rec_size)
{
	static const char *const kinds[] = {"ringbuf", NULL};
	struct abi_map m;
	if (rec_size < 0)
		return abi_fail(BML_OTHER, "bml: a negative record size");
	int64_t e = abi_map_open_kind(obj, decl, dl, kinds, "a ring buffer", &members, &ml, 1, &m);
	if (e)
		return e;
	if ((e = record_size_check(&m, rec_size)) != 0) {
		abi_map_close(&m);
		return e;
	}
	struct abi_reader *r = calloc(1, sizeof *r);
	if (!r) {
		abi_map_close(&m);
		return abi_fail(BML_OTHER, "bml: out of memory");
	}
	pthread_mutex_init(&r->mu, NULL);
	r->obj = obj;
	r->name = strdup(m.d.name);
	r->rec_size = (size_t)rec_size;
	r->buf = calloc(1, (size_t)rec_size ? (size_t)rec_size : 1);
	r->rb = r->name && r->buf ? ring_buffer__new(m.fd, on_sample, r, NULL) : NULL;
	if (!r->rb) {
		e = abi_fail(BML_OTHER, "bml: ring buffer reader for %s: %s", m.d.name, abi_errno(errno ? errno : ENOMEM));
		abi_map_close(&m);
		free(r->name);
		free(r->buf);
		free(r);
		return e;
	}
	abi_map_close(&m);
	abi_lock();
	int64_t id = abi_handle_new(H_READER, r, obj);
	abi_unlock();
	if (id < 0) {
		abi_reader_free(r);
		return abi_fail(BML_OTHER, "bml: out of memory");
	}
	return abi_ok(id);
}

static int64_t now_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

int64_t bml_ringbuf_read(int64_t reader, int64_t timeout_ms, uint8_t *dst, int64_t n)
{
	abi_lock();
	struct abi_reader *r = abi_handle_get(reader, H_READER);
	abi_unlock();
	if (!r)
		return abi_fail(BML_STATE, "bml: no ring buffer reader %lld (open it first)", (long long)reader);
	int64_t e;
	struct abi_object *o = NULL;
	if (!BML_MUT("abi.reader_no_inflight") && !(o = abi_object_acquire(r->obj, &e)))
		return e;
	pthread_mutex_lock(&r->mu);
	if (r->closed) {
		e = abi_fail(BML_STATE, "bml: the ring buffer reader %lld (%s) is closed", (long long)reader, r->name);
		goto out;
	}
	if (n < 0 || (!dst && n) || (size_t)n != r->rec_size) {
		e = abi_fail(BML_OTHER, "bml: ring buffer %s: a %lld-byte buffer for %zu-byte records", r->name, (long long)n, r->rec_size);
		goto out;
	}
	r->got = 0;
	int rc = ring_buffer__consume_n(r->rb, 1);
	if (rc == 0 && timeout_ms > 0) {
		int64_t deadline = now_ms() + timeout_ms;
		for (;;) {
			int64_t left = deadline - now_ms();
			if (left <= 0)
				break;
			struct epoll_event ev;
			int w = epoll_wait(ring_buffer__epoll_fd(r->rb), &ev, 1, left > 1000000 ? 1000000 : (int)left);
			if (w < 0 && errno == EINTR)
				continue;
			if (w < 0) {
				rc = -errno;
				break;
			}
			if (w == 0)
				break;
			if ((rc = ring_buffer__consume_n(r->rb, 1)) != 0)
				break;
		}
		if (rc == 0)
			rc = ring_buffer__consume_n(r->rb, 1);
	}
	if (rc < 0)
		e = abi_fail(BML_OTHER, "bml: ring buffer %s: %s", r->name, abi_errno(-rc));
	else if (!r->got)
		e = abi_ok(0);
	else if (r->got_len != r->rec_size)
		e = abi_fail(BML_MAP_MISMATCH, "bml: ring buffer %s: a %zu-byte event, but the record is %zu bytes (regenerate the bindings and rebuild)",
			     r->name, r->got_len, r->rec_size);
	else {
		memcpy(dst, r->buf, r->rec_size);
		e = abi_ok(1);
	}
out:
	pthread_mutex_unlock(&r->mu);
	abi_object_release(o);
	return e;
}


static void reader_close_locked(struct abi_reader *r)
{
	if (!r->closed) {
		r->closed = 1;
		ring_buffer__free(r->rb);
		r->rb = NULL;
	}
}

int64_t bml_ringbuf_close(int64_t reader)
{
	abi_lock();
	struct abi_reader *r = abi_handle_get(reader, H_READER);
	abi_unlock();
	if (!r)
		return abi_fail(BML_STATE, "bml: no ring buffer reader %lld (open it first)", (long long)reader);

	if (BML_MUT("abi.reader_close_waits"))
		pthread_mutex_lock(&r->mu);
	else if (pthread_mutex_trylock(&r->mu) != 0)
		return abi_fail(BML_STATE, "bml: the ring buffer reader %lld (%s) has a read in flight on another thread — close it again after it returns",
				(long long)reader, r->name);
	reader_close_locked(r);
	pthread_mutex_unlock(&r->mu);
	return abi_ok(0);
}

/* CONTRACT: called from the object close (owned.c) only when the object has no running calls, so no thread is inside read: closes, and does not remove it from the table */
void abi_reader_free(void *p)
{
	struct abi_reader *r = p;
	pthread_mutex_lock(&r->mu);
	reader_close_locked(r);
	pthread_mutex_unlock(&r->mu);
}
