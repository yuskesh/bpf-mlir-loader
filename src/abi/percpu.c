


#define _GNU_SOURCE
#include "abi/map_internal.h"

#include <errno.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "abi/iter.h"

static const char *const percpu_kinds[] = {"percpu_array", "percpu_hash", "lru_percpu_hash", NULL};

static size_t stride(size_t n)
{
	return (n + 7) / 8 * 8;
}

int64_t bml_possible_cpus(void)
{
	int n = libbpf_num_possible_cpus();
	if (n <= 0)
		return abi_fail(BML_OTHER, "bml: possible CPUs: %s", abi_errno(-n));
	return abi_ok(n);
}

static int64_t open_percpu(int64_t obj, const char *decl, int64_t dl, const char *km, int64_t kl, const char *vm, int64_t vl, int64_t klen,
			   int64_t vlen, struct abi_map *m, int *ncpu)
{
	const char *recs[2] = {km, vm};
	int64_t lens[2] = {km ? kl : 0, vm ? vl : 0};
	int64_t e = abi_map_open_kind(obj, decl, dl, percpu_kinds, "a per-CPU map", recs, lens, 2, m);
	if (e)
		return e;
	if ((int64_t)m->key_size != klen || (vlen >= 0 && (int64_t)m->value_size != vlen)) {
		e = abi_fail(BML_MAP_MISMATCH,
			     "bml: map %s has %u-byte keys and %u-byte values in the embedded ELF, but this program's are %lld and %lld bytes",
			     m->d.name, m->key_size, m->value_size, (long long)klen, (long long)vlen);
		abi_map_close(m);
		return e;
	}
	*ncpu = libbpf_num_possible_cpus();
	if (*ncpu <= 0) {
		e = abi_fail(BML_OTHER, "bml: possible CPUs: %s", abi_errno(-*ncpu));
		abi_map_close(m);
	}
	return e;
}

static int bad_buf(const void *p, int64_t n)
{
	return n < 0 || (!p && n);
}

int64_t bml_percpu_get(int64_t obj, const char *decl, int64_t dl, const char *km, int64_t kl, const char *vm, int64_t vl, const uint8_t *key,
		       int64_t klen, int64_t vlen, uint8_t *dst, int64_t dlen)
{
	struct abi_map m;
	int n;
	if (bad_buf(key, klen) || bad_buf(dst, dlen) || vlen < 0)
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL buffer with a length");
	int64_t e = open_percpu(obj, decl, dl, km, kl, vm, vl, klen, vlen, &m, &n);
	if (e)
		return e;
	if (dlen != (int64_t)n * vlen) {
		e = abi_fail(BML_OTHER, "bml: map %s: the buffer holds %lld bytes, want %d possible CPUs × %lld", m.d.name, (long long)dlen, n,
			     (long long)vlen);
		abi_map_close(&m);
		return e;
	}
	size_t st = stride((size_t)vlen);
	uint8_t *raw = calloc((size_t)n, st ? st : 1);
	if (!raw)
		e = abi_fail(BML_OTHER, "bml: out of memory");
	else if (bpf_map_lookup_elem(m.fd, key, raw) != 0)
		e = errno == ENOENT ? abi_fail(BML_NOT_FOUND, "bml: map %s has no such key", m.d.name) : abi_fail(BML_OTHER, "bml: lookup %s: %s", m.d.name, abi_errno(errno));
	else {
		for (int c = 0; c < n; c++)
			memcpy(dst + (size_t)c * (size_t)vlen, raw + (size_t)c * st, (size_t)vlen);
		e = abi_ok(1);
	}
	free(raw);
	abi_map_close(&m);
	return e;
}

int64_t bml_percpu_put(int64_t obj, const char *decl, int64_t dl, const char *km, int64_t kl, const char *vm, int64_t vl, const uint8_t *key,
		       int64_t klen, int64_t vlen, const uint8_t *src, int64_t slen)
{
	struct abi_map m;
	int n;
	if (bad_buf(key, klen) || bad_buf(src, slen) || vlen < 0)
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL buffer with a length");
	int64_t e = open_percpu(obj, decl, dl, km, kl, vm, vl, klen, vlen, &m, &n);
	if (e)
		return e;
	if (slen != (int64_t)n * vlen) {
		e = abi_fail(BML_OTHER, "bml: map %s: map_put_percpu needs one value per possible CPU (%d), got %lld", m.d.name, n,
			     (long long)(vlen ? slen / vlen : slen));
		abi_map_close(&m);
		return e;
	}
	size_t st = stride((size_t)vlen);
	uint8_t *raw = calloc((size_t)n, st ? st : 1);
	if (!raw)
		e = abi_fail(BML_OTHER, "bml: out of memory");
	else {
		for (int c = 0; c < n; c++)
			memcpy(raw + (size_t)c * st, src + (size_t)c * (size_t)vlen, (size_t)vlen);
		e = bpf_map_update_elem(m.fd, key, raw, BPF_ANY) != 0 ? abi_fail(BML_OTHER, "bml: update %s: %s", m.d.name, abi_errno(errno))
								      : abi_ok(0);
	}
	free(raw);
	abi_map_close(&m);
	return e;
}

int64_t bml_percpu_delete(int64_t obj, const char *decl, int64_t dl, const char *km, int64_t kl, const uint8_t *key, int64_t klen)
{
	struct abi_map m;
	int n;
	if (bad_buf(key, klen))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL buffer with a length");
	int64_t e = open_percpu(obj, decl, dl, km, kl, NULL, 0, klen, -1, &m, &n);
	if (e)
		return e;
	if (bpf_map_delete_elem(m.fd, key) != 0)
		e = errno == ENOENT ? abi_fail(BML_NOT_FOUND, "bml: map %s has no such key", m.d.name) : abi_fail(BML_OTHER, "bml: delete %s: %s", m.d.name, abi_errno(errno));
	else
		e = abi_ok(1);
	abi_map_close(&m);
	return e;
}

int64_t bml_percpu_iter_open(int64_t obj, const char *decl, int64_t dl, const char *km, int64_t kl, const char *vm, int64_t vl, int64_t klen,
			     int64_t vlen)
{
	struct abi_map m;
	int n;
	if (klen < 0 || vlen < 0)
		return abi_fail(BML_OTHER, "bml: a negative length");
	int64_t e = open_percpu(obj, decl, dl, km, kl, vm, vl, klen, vlen, &m, &n);
	if (e)
		return e;
	e = abi_iter_open(&m, obj, klen, vlen * n, n);
	abi_map_close(&m);
	return e;
}

static int getcpu_now(unsigned *cpu)
{
	unsigned node;
	return (int)syscall(SYS_getcpu, cpu, &node, NULL);
}

int64_t bml_test_run_xdp_data_on_cpu(int64_t obj, const char *prog, int64_t prog_len, const uint8_t *data, int64_t n, int64_t cpu)
{
	int np = libbpf_num_possible_cpus();
	if (np <= 0)
		return abi_fail(BML_OTHER, "bml: possible CPUs: %s", abi_errno(-np));
	if (cpu < 0 || cpu >= np)
		return abi_fail(BML_OTHER, "bml: test run on CPU %lld: the machine has %d possible CPUs", (long long)cpu, np);

	cpu_set_t old, one, now;
	if (sched_getaffinity(0, sizeof old, &old) != 0)
		return abi_fail(BML_OTHER, "bml: sched_getaffinity: %s", abi_errno(errno));
	CPU_ZERO(&one);
	CPU_SET((int)cpu, &one);
	if (sched_setaffinity(0, sizeof one, &one) != 0)
		return abi_fail(BML_OTHER, "bml: cannot pin the thread to CPU %lld (offline or not allowed): %s", (long long)cpu, abi_errno(errno));
	unsigned c;
	int64_t r;
	if (getcpu_now(&c) != 0 || (int64_t)c != cpu)
		r = abi_fail(BML_OTHER, "bml: pinned to CPU %lld but running on CPU %u", (long long)cpu, c);
	else {
		r = bml_test_run_xdp_data(obj, prog, prog_len, data, n);
		if (getcpu_now(&c) != 0 || (int64_t)c != cpu) {
			bml_result_free(r);
			r = abi_fail(BML_OTHER, "bml: the test run on CPU %lld ended on CPU %u", (long long)cpu, c);
		}
	}
	if (sched_setaffinity(0, sizeof old, &old) != 0 || sched_getaffinity(0, sizeof now, &now) != 0 || !CPU_EQUAL(&now, &old)) {
		bml_result_free(r);
		r = abi_fail(BML_OTHER, "bml: the thread's CPU affinity was not restored after the test run on CPU %lld", (long long)cpu);
	}
	return r;
}
