#define _GNU_SOURCE
#include "shim/spinel/internal.h"

#include <stdlib.h>
#include <string.h>

#include "bml/bml.h"
#include "maps/mapdecl.h"
#include "shim/spinel/spinelbpf.h"
#include "util/gostr.h"

#define S(x) (x), (int64_t)((x) ? strlen(x) : 0)
#define U20 ((int64_t)1 << 20)

static int key32_bad(int64_t k)
{
	return k < 0 || k > 0xffffffffLL;
}


static uint8_t *to_bytes(const int64_t *a, int64_t n, int64_t *bad)
{
	*bad = -1;
	uint8_t *b = calloc(n > 0 ? (size_t)n : 1, 1);
	if (!b)
		return NULL;
	for (int64_t i = 0; i < n; i++) {
		if (a[i] < 0 || a[i] > 255) {
			*bad = i;
			free(b);
			return NULL;
		}
		b[i] = (uint8_t)a[i];
	}
	*bad = -1;
	return b;
}

static void from_bytes(int64_t *out, const uint8_t *b, int64_t n)
{
	for (int64_t i = 0; i < n; i++)
		out[i] = b[i];
}


int64_t sh_parse_decl(const char *decl, struct bml_map_decl *d)
{
	char *err = NULL;
	if (bml_map_decl_parse_one(decl ? decl : "", decl ? strlen(decl) : 0, d, &err) != 0) {
		int64_t r = sh_result(BML_OTHER, 0, "spinelbpf: unreadable map declaration: %s", err ? err : "");
		free(err);
		return r;
	}
	return 0;
}

int64_t spinelbpf_load_checked(uint8_t *elf, int64_t n, char *sha, char *maps, int64_t capsKind)
{
	if (!elf || n <= 0)
		return sh_result(BML_PRECHECK_FAILED, 0, "spinelbpf: no embedded ELF (build with spinelbpf build)");
	return bml_load_checked(elf, n, S(sha), S(maps), capsKind);
}

int64_t spinelbpf_attach_xdp(int64_t obj, char *prog, char *ifname)
{
	return bml_attach_xdp(obj, S(prog), S(ifname));
}

int64_t spinelbpf_detach(int64_t l)
{
	return bml_detach(l);
}

int64_t spinelbpf_map_get(int64_t obj, char *decl, int64_t key)
{
	if (key32_bad(key))
		return sh_result(BML_OTHER, 0, "spinelbpf: key %lld is outside u32", (long long)key);
	return bml_map_get_int(obj, S(decl), key);
}

int64_t spinelbpf_map_put(int64_t obj, char *decl, int64_t key, int64_t value)
{
	if (key32_bad(key))
		return sh_result(BML_OTHER, 0, "spinelbpf: key %lld is outside u32", (long long)key);
	return bml_map_put_int(obj, S(decl), key, value);
}


static int64_t record_only(const struct bml_map_decl *d)
{
	if (!strncmp(d->value, "record:", 7))
		return 0;
	struct bml_buf b = {0};
	bml_buf_addf(&b, "spinelbpf: map %s is declared with value ", d->name);
	bml_buf_add_goquote(&b, d->value, strlen(d->value));
	bml_buf_adds(&b, " — the bytes get / put is for record maps (record:<S>)");
	char *m = bml_buf_take(&b);
	int64_t r = sh_result(BML_OTHER, 0, "%s", m ? m : "");
	free(m);
	return r;
}

int64_t spinelbpf_map_get_bytes(int64_t obj, char *decl, int64_t key, int64_t *buf, int64_t n)
{
	if (key32_bad(key))
		return sh_result(BML_OTHER, 0, "spinelbpf: key %lld is outside u32", (long long)key);
	if (n <= 0 || n > U20)
		return sh_result(BML_OTHER, 0, "spinelbpf: record size %lld is outside 1..2^20", (long long)n);
	struct bml_map_decl d;
	int64_t e = sh_parse_decl(decl, &d);
	if (e)
		return e;
	e = record_only(&d);
	bml_map_decl_free(&d);
	if (e)
		return e;
	uint8_t *b = malloc((size_t)n);
	if (!b)
		return sh_result(BML_OTHER, 0, "spinelbpf: out of memory");
	int64_t r = bml_map_get_bytes(obj, S(decl), NULL, 0, key, b, n);
	if (bml_result_kind(r) == BML_OK)
		from_bytes(buf, b, n);
	free(b);
	return r;
}

int64_t spinelbpf_map_put_bytes(int64_t obj, char *decl, int64_t key, int64_t *buf, int64_t n)
{
	if (key32_bad(key))
		return sh_result(BML_OTHER, 0, "spinelbpf: key %lld is outside u32", (long long)key);
	if (n <= 0 || n > U20)
		return sh_result(BML_OTHER, 0, "spinelbpf: record size %lld is outside 1..2^20", (long long)n);
	struct bml_map_decl d;
	int64_t e = sh_parse_decl(decl, &d);
	if (e)
		return e;
	int64_t bad;
	uint8_t *b = to_bytes(buf, n, &bad);
	if (!b) {
		bml_map_decl_free(&d);
		return bad >= 0 ? sh_result(BML_VALUE_RANGE, 0, "spinelbpf: record byte %lld is %lld, outside 0..255", (long long)bad, (long long)buf[bad])
				: sh_result(BML_OTHER, 0, "spinelbpf: out of memory");
	}
	e = record_only(&d);
	bml_map_decl_free(&d);
	int64_t r = e ? e : bml_map_put_bytes(obj, S(decl), NULL, 0, key, b, n);
	free(b);
	return r;
}


uint8_t *sh_hash_bytes(const int64_t *a, int64_t n, const char *what, int64_t *err)
{
	*err = 0;
	if (n <= 0 || n > U20) {
		*err = sh_result(BML_OTHER, 0, "spinelbpf: %s size %lld is outside 1..2^20", what, (long long)n);
		return NULL;
	}
	int64_t bad;
	uint8_t *b = to_bytes(a, n, &bad);
	if (!b)
		*err = bad >= 0 ? sh_result(BML_VALUE_RANGE, 0, "spinelbpf: %s byte %lld is %lld, outside 0..255", what, (long long)bad, (long long)a[bad])
				: sh_result(BML_OTHER, 0, "spinelbpf: out of memory");
	return b;
}

int64_t spinelbpf_hash_get(int64_t obj, char *decl, int64_t *key, int64_t klen, int64_t *val, int64_t vlen)
{
	struct bml_map_decl d;
	int64_t e = sh_parse_decl(decl, &d);
	if (e)
		return e;
	bml_map_decl_free(&d);
	uint8_t *k = sh_hash_bytes(key, klen, "key", &e);
	if (!k)
		return e;
	if (vlen <= 0 || vlen > U20) {
		free(k);
		return sh_result(BML_OTHER, 0, "spinelbpf: value size %lld is outside 1..2^20", (long long)vlen);
	}
	uint8_t *v = malloc((size_t)vlen);
	int64_t r = v ? bml_hash_get(obj, S(decl), NULL, 0, NULL, 0, k, klen, v, vlen) : sh_result(BML_OTHER, 0, "spinelbpf: out of memory");
	if (v && bml_result_kind(r) == BML_OK) {
		from_bytes(val, v, vlen);
		bml_result_free(r);
		r = sh_result(BML_OK, vlen, "%s", "");
	}
	free(k);
	free(v);
	return r;
}

int64_t spinelbpf_hash_put(int64_t obj, char *decl, int64_t *key, int64_t klen, int64_t *val, int64_t vlen)
{
	struct bml_map_decl d;
	int64_t e = sh_parse_decl(decl, &d);
	if (e)
		return e;
	uint8_t *k = sh_hash_bytes(key, klen, "key", &e), *v = NULL;
	if (k)
		v = sh_hash_bytes(val, vlen, "value", &e);
	int64_t r = e;
	if (k && v) {
		r = bml_hash_put(obj, S(decl), NULL, 0, NULL, 0, k, klen, v, vlen);
		if (bml_result_kind(r) == BML_OTHER) {
			struct sh_res x = sh_take(r);
			if (x.msg && strstr(x.msg, "argument list too long"))
				r = sh_result(BML_OTHER, 0, "spinelbpf: update %s: E2BIG — map is full (%llu entries): %s", d.name, (unsigned long long)d.max_entries,
					      x.msg);
			else
				r = sh_result(x.kind, x.value, "%s", x.msg ? x.msg : "");
			sh_res_free(&x);
		}
	}
	bml_map_decl_free(&d);
	free(k);
	free(v);
	return r;
}

int64_t spinelbpf_hash_delete(int64_t obj, char *decl, int64_t *key, int64_t klen)
{
	struct bml_map_decl d;
	int64_t e = sh_parse_decl(decl, &d);
	if (e)
		return e;
	int percpu = !strcmp(d.kind, "percpu_hash");
	bml_map_decl_free(&d);
	uint8_t *k = sh_hash_bytes(key, klen, "key", &e);
	if (!k)
		return e;
	int64_t r = percpu ? bml_percpu_delete(obj, S(decl), NULL, 0, k, klen) : bml_hash_delete(obj, S(decl), NULL, 0, k, klen);
	free(k);
	if (bml_result_kind(r) == BML_NOT_FOUND) {
		bml_result_free(r);
		return sh_result(BML_OK, 0, "%s", "");
	}
	return r;
}

int64_t spinelbpf_hash_keys(int64_t obj, char *decl, int64_t klen, int64_t *out, int64_t capacity)
{
	struct bml_map_decl d;
	int64_t e = sh_parse_decl(decl, &d);
	if (e)
		return e;
	if (klen <= 0 || klen > U20 || capacity <= 0 || capacity * klen > ((int64_t)1 << 26)) {
		bml_map_decl_free(&d);
		return sh_result(BML_OTHER, 0, "spinelbpf: key size %lld × capacity %lld is outside the accepted range (at most 2^26 bytes)", (long long)klen,
				 (long long)capacity);
	}

	int64_t vlen = 0, dr = bml_map_describe(obj, S(d.name));
	if (bml_result_kind(dr) == BML_OK)
		vlen = bml_result_value(dr);
	bml_result_free(dr);

	int percpu = !strcmp(d.kind, "percpu_hash");
	int64_t r = percpu ? bml_percpu_iter_open(obj, S(decl), NULL, 0, NULL, 0, klen, vlen) : bml_hash_iter_open(obj, S(decl), NULL, 0, NULL, 0, klen, vlen);
	if (percpu && bml_result_kind(r) == BML_OK) {
		int64_t pc = bml_possible_cpus();
		vlen *= bml_result_kind(pc) == BML_OK ? bml_result_value(pc) : 0;
		bml_result_free(pc);
	}
	if (bml_result_kind(r) != BML_OK) {
		bml_map_decl_free(&d);
		return r;
	}
	int64_t it = bml_result_value(r);
	bml_result_free(r);
	uint8_t *k = malloc((size_t)klen), *v = malloc(vlen > 0 ? (size_t)vlen : 1), *all = NULL;
	int64_t n = 0, cap = 0, res = 0;
	while (k && v) {
		int64_t x = bml_hash_iter_next(it, k, klen, v, vlen);
		if (bml_result_kind(x) != BML_OK) {
			res = x;
			break;
		}
		int64_t more = bml_result_value(x);
		bml_result_free(x);
		if (!more)
			break;
		if (n == cap) {
			cap = cap ? cap * 2 : 16;
			uint8_t *na = realloc(all, (size_t)(cap * klen));
			if (!na) {
				res = sh_result(BML_OTHER, 0, "spinelbpf: out of memory");
				break;
			}
			all = na;
		}
		memcpy(all + n * klen, k, (size_t)klen);
		n++;
	}
	bml_result_free(bml_hash_iter_close(it));
	if (!res && (!k || !v))
		res = sh_result(BML_OTHER, 0, "spinelbpf: out of memory");
	if (!res && n > capacity)
		res = sh_result(BML_OTHER, 0, "spinelbpf: %s has %lld keys, more than the caller's capacity %lld", d.name, (long long)n, (long long)capacity);
	if (!res) {
		from_bytes(out, all, n * klen);
		res = sh_result(BML_OK, n, "%s", "");
	}
	bml_map_decl_free(&d);
	free(k);
	free(v);
	free(all);
	return res;
}

int64_t spinelbpf_ringbuf_open(int64_t obj, char *name)
{
	int64_t dr = bml_map_describe(obj, S(name));
	if (bml_result_kind(dr) != BML_OK)
		return dr;
	int64_t size = bml_result_value(dr), dl = 0;
	const char *decl = bml_result_message(dr, &dl);
	struct bml_map_decl d;
	char *err = NULL;
	int64_t r;
	if (bml_map_decl_parse_one(decl, (size_t)dl, &d, &err) != 0) {
		r = sh_result(BML_OTHER, 0, "spinelbpf: the map %s has an unreadable declaration: %s", name, err ? err : "");
		free(err);
	} else {
		if (strcmp(d.kind, "ringbuf") != 0)
			r = sh_result(BML_MAP_MISMATCH, 0, "spinelbpf: map %s is a %s, not a ring buffer", name, d.kind);
		else
			r = bml_ringbuf_open(obj, decl, dl, NULL, 0, size);
		bml_map_decl_free(&d);
	}
	bml_result_free(dr);
	if (bml_result_kind(r) == BML_OK && r < SH_BASE)
		sh_reader_set(bml_result_value(r), size);
	return r;
}

int64_t spinelbpf_ringbuf_read(int64_t rb, int64_t timeoutMs, int64_t *buf, int64_t n)
{
	if (n <= 0 || n > U20 || timeoutMs < 0 || timeoutMs > ((int64_t)1 << 31))
		return sh_result(BML_OTHER, 0, "spinelbpf: ring buffer read with size %lld and timeout %lld ms is outside the accepted range", (long long)n,
				 (long long)timeoutMs);
	int64_t size = sh_reader_size(rb);
	if (size < 0)
		return bml_ringbuf_read(rb, 0, NULL, 0);
	uint8_t *b = malloc(size > 0 ? (size_t)size : 1);
	if (!b)
		return sh_result(BML_OTHER, 0, "spinelbpf: out of memory");
	int64_t r = bml_ringbuf_read(rb, timeoutMs, b, size);
	if (bml_result_kind(r) == BML_OK && bml_result_value(r) == 1) {
		bml_result_free(r);
		if (n != size)
			r = sh_result(BML_MAP_MISMATCH, 0, "spinelbpf: the ring buffer event is %lld bytes but the caller's record layout is %lld — rebuild with spinelbpf build",
				      (long long)size, (long long)n);
		else {
			from_bytes(buf, b, n);
			r = sh_result(BML_OK, n, "%s", "");
		}
	}
	free(b);
	return r;
}

int64_t spinelbpf_ringbuf_close(int64_t rb)
{
	return bml_ringbuf_close(rb);
}

int64_t spinelbpf_test_run_xdp(int64_t obj, char *prog, int64_t repeat)
{
	if (repeat < 0 || repeat > 0xffffffffLL)
		return sh_result(BML_OTHER, 0, "spinelbpf: repeat is outside u32");
	return bml_test_run_xdp(obj, S(prog), repeat);
}

int64_t spinelbpf_test_run_xdp_packet(int64_t obj, char *prog, int64_t *bytes, int64_t n)
{
	if (n < 0 || n > 0xffff)
		return sh_result(BML_OTHER, 0, "spinelbpf: packet length %lld is outside 0..65535", (long long)n);
	int64_t bad = -1;
	uint8_t *b = to_bytes(bytes, n, &bad);
	if (!b) {
		if (bad < 0)
			return sh_result(BML_OTHER, 0, "spinelbpf: out of memory");
		int64_t u = bml_object_unmet(obj);
		if (bml_result_kind(u) != BML_OK)
			return u;
		bml_result_free(u);
		return sh_result(BML_VALUE_RANGE, 0, "spinelbpf: packet byte %lld is %lld, outside 0..255", (long long)bad, (long long)bytes[bad]);
	}
	int64_t r = bml_test_run_xdp_data(obj, S(prog), b, n);
	free(b);
	if (n < 14 && bml_result_kind(r) == BML_OTHER) {
		struct sh_res x = sh_take(r);
		int einval = x.msg && x.len >= 16 && !strcmp(x.msg + x.len - 16, "invalid argument");
		r = sh_result(x.kind, x.value, "%s%s", x.msg ? x.msg : "",
			      einval ? " — the XDP test run needs at least 14 bytes of data (an Ethernet header; measured on 7.1.8 / 6.12.111 / 6.6.157)" : "");
		sh_res_free(&x);
	}
	return r;
}

int64_t spinelbpf_object_unmet(int64_t obj)
{
	return bml_object_unmet(obj);
}

int64_t spinelbpf_close(int64_t obj)
{
	return bml_close(obj);
}
