#define _GNU_SOURCE
#include "abi/map_internal.h"
#include "maps/arena.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static void record_free(struct bml_record_decl *r)
{
	free(r->name);
	for (size_t q = 0; q < r->n_members; q++) {
		free(r->members[q].name);
		free(r->members[q].type);
	}
	free(r->members);
	memset(r, 0, sizeof *r);
}


static int64_t check_decl(struct abi_object *o, struct bml_map_decl *d, struct bml_map_decls *records)
{
	struct bml_map_decls one = {.allow_undeclared = 1, .has_maps = 1, .maps = d, .n_maps = 1};
	if (records) {
		one.records = records->records;
		one.n_records = records->n_records;
	}
	struct bml_map_problems mp = {0};
	int rc = bml_check_map_decls(o->req, o->elf, o->elf_len, &one, &mp);
	if (!rc)
		rc = bml_check_arena_decls(o->req, o->elf, o->elf_len, &one, 0, &mp);
	if (rc == 0)
		return 0;
	struct bml_buf b = {0};
	bml_buf_adds(&b, "bml: the map declarations differ from the ELF (regenerate the bindings from the same schema):");
	for (size_t i = 0; i < mp.n; i++) {
		char *s = bml_map_problem_string(&mp.p[i]);
		bml_buf_adds(&b, "\n  ");
		bml_buf_adds(&b, s ? s : "");
		free(s);
	}
	bml_buf_adds(&b, " — regenerate the bindings and rebuild");
	bml_map_problems_free(&mp);
	struct abi_result r = {.kind = rc < 0 ? BML_OTHER : BML_MAP_MISMATCH, .msg_len = b.len};
	r.msg = bml_buf_take(&b);
	return abi_put(&r);
}

int64_t abi_map_open(int64_t h, const char *decl, int64_t decl_len, const char *const *records, const int64_t *records_len,
		     size_t n_records, struct abi_map *m)
{
	return abi_map_open_kind(h, decl, decl_len, NULL, NULL, records, records_len, n_records, m);
}

int64_t abi_map_open_kind(int64_t h, const char *decl, int64_t decl_len, const char *const *kinds, const char *what,
			  const char *const *records, const int64_t *records_len, size_t n_records, struct abi_map *m)
{
	memset(m, 0, sizeof *m);
	int64_t err;
	if (decl_len < 0 || (!decl && decl_len))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL string with a length");
	m->o = abi_object_acquire(h, &err);
	if (!m->o)
		return err;
	char *e = NULL;
	if (bml_arena_map_decl_parse_one(decl ? decl : "", (size_t)decl_len, &m->d, &e) != 0) {
		struct bml_buf b = {0};
		bml_buf_adds(&b, "bml: unreadable map declaration ");
		bml_buf_add_goquote(&b, decl ? decl : "", (size_t)decl_len);
		bml_buf_addf(&b, ": %s", e ? e : "");
		free(e);
		struct abi_result r = {.kind = BML_OTHER, .msg_len = b.len};
		r.msg = bml_buf_take(&b);
		abi_map_close(m);
		return abi_put(&r);
	}
	m->has_d = 1;
	if (kinds) {
		int ok = 0;
		for (const char *const *k = kinds; *k; k++)
			ok |= strcmp(m->d.kind, *k) == 0;
		if (!ok) {
			int64_t rr = abi_fail(BML_MAP_MISMATCH, "bml: map %s is declared as %s, not %s", m->d.name, m->d.kind, what);
			abi_map_close(m);
			return rr;
		}
	}

	struct bml_map_decls recs = {0};
	for (size_t i = 0; i < n_records; i++) {
		if (!records[i] || records_len[i] <= 0)
			continue;
		struct bml_map_decls one;
		int is_null;
		if (bml_record_decls_parse(records[i], (size_t)records_len[i], &one, &is_null, &e) != 0 || is_null) {
			int64_t rr = abi_fail(BML_OTHER, "bml: map %s: the record declarations are unreadable: %s", m->d.name, e ? e : "null");
			free(e);
			bml_map_decls_free(&recs);
			abi_map_close(m);
			return rr;
		}
		for (size_t k = 0; k < one.n_records; k++) {
			size_t j = 0;
			while (j < recs.n_records && strcmp(recs.records[j].name, one.records[k].name) != 0)
				j++;
			if (j < recs.n_records) {
				record_free(&recs.records[j]);
				recs.records[j] = one.records[k];
			} else {
				struct bml_record_decl *nr = realloc(recs.records, (recs.n_records + 1) * sizeof *nr);
				if (!nr) {
					bml_map_decls_free(&one);
					bml_map_decls_free(&recs);
					abi_map_close(m);
					return abi_fail(BML_OTHER, "bml: out of memory");
				}
				recs.records = nr;
				recs.records[recs.n_records++] = one.records[k];
			}
			memset(&one.records[k], 0, sizeof one.records[k]);
		}
		bml_map_decls_free(&one);
	}
	int64_t rr = check_decl(m->o, &m->d, n_records ? &recs : NULL);
	bml_map_decls_free(&recs);
	if (rr) {
		abi_map_close(m);
		return rr;
	}
	m->map = bpf_object__find_map_by_name(bml_obj_bpf(m->o->lo), m->d.name);
	if (!m->map) {
		rr = abi_fail(BML_STATE, "bml: the loaded collection has no map %s", m->d.name);
		abi_map_close(m);
		return rr;
	}
	m->fd = bpf_map__fd(m->map);
	m->key_size = bpf_map__key_size(m->map);
	m->value_size = bpf_map__value_size(m->map);
	return 0;
}

void abi_map_close(struct abi_map *m)
{
	if (m->has_d)
		bml_map_decl_free(&m->d);
	abi_object_release(m->o);
	memset(m, 0, sizeof *m);
}


static int64_t u32_key(struct abi_map *m, int64_t key, uint32_t *k)
{
	if (m->key_size != 4)
		return abi_fail(BML_OTHER, "bml: map %s has %u-byte keys; the array entry points read only u32 keys", m->d.name, m->key_size);
	if (key < 0 || key > UINT32_MAX)
		return abi_fail(BML_OTHER, "bml: key %lld of map %s is outside u32", (long long)key, m->d.name);
	*k = (uint32_t)key;
	return 0;
}

static int64_t lookup_u(struct abi_map *m, uint32_t k, uint64_t *v)
{
	if (m->value_size != 4 && m->value_size != 8)
		return abi_fail(BML_OTHER, "bml: map %s has %u-byte values; the integer entry points read 4- and 8-byte integers", m->d.name,
				m->value_size);
	uint64_t buf = 0;
	if (bpf_map_lookup_elem(m->fd, &k, &buf) != 0)
		return abi_fail(BML_OTHER, "bml: lookup %s[%u]: %s", m->d.name, k, abi_errno(errno));
	*v = m->value_size == 4 ? (uint64_t)(uint32_t)buf : buf;
	return 0;
}

static int64_t update_u(struct abi_map *m, uint32_t k, uint64_t v)
{
	if (m->value_size != 4 && m->value_size != 8)
		return abi_fail(BML_OTHER, "bml: map %s has %u-byte values; the integer entry points write 4- and 8-byte integers", m->d.name,
				m->value_size);
	uint64_t buf = v;
	uint32_t b4 = (uint32_t)v;
	if (bpf_map_update_elem(m->fd, &k, m->value_size == 4 ? (void *)&b4 : (void *)&buf, BPF_ANY) != 0)
		return abi_fail(BML_OTHER, "bml: update %s[%u]: %s", m->d.name, k, abi_errno(errno));
	return 0;
}

int64_t bml_map_get_bits(int64_t obj, const char *decl, int64_t decl_len, int64_t key)
{
	struct abi_map m;
	uint32_t k = 0;
	uint64_t v = 0;
	int64_t e = abi_map_open(obj, decl, decl_len, NULL, NULL, 0, &m);
	if (!e && !(e = u32_key(&m, key, &k)) && !(e = lookup_u(&m, k, &v)))
		e = abi_ok((int64_t)v);
	abi_map_close(&m);
	return e;
}

int64_t bml_map_put_bits(int64_t obj, const char *decl, int64_t decl_len, int64_t key, int64_t bits)
{
	struct abi_map m;
	uint32_t k = 0;
	int64_t e = abi_map_open(obj, decl, decl_len, NULL, NULL, 0, &m);
	if (!e && !(e = u32_key(&m, key, &k)) && !(e = update_u(&m, k, (uint64_t)bits)))
		e = abi_ok(0);
	abi_map_close(&m);
	return e;
}


static int is_signed(const struct bml_map_decl *d)
{
	return d->value && d->value[0] == 'i';
}

int64_t bml_map_get_int(int64_t obj, const char *decl, int64_t decl_len, int64_t key)
{
	struct abi_map m;
	uint32_t k = 0;
	uint64_t v = 0;
	int64_t e = abi_map_open(obj, decl, decl_len, NULL, NULL, 0, &m);
	if (!e && !(e = u32_key(&m, key, &k)) && !(e = lookup_u(&m, k, &v))) {
		int64_t x;
		int ok = 1;
		if (m.value_size == 4)
			x = is_signed(&m.d) ? (int64_t)(int32_t)(uint32_t)v : (int64_t)v;
		else if (is_signed(&m.d)) {
			x = (int64_t)v;
			ok = x != INT64_MIN;
		} else {
			x = (int64_t)v;
			ok = v <= (uint64_t)INT64_MAX;
		}
		e = ok ? abi_ok(x)
		       : abi_fail(BML_VALUE_RANGE, "bml: %s[%u] holds a %s value that an Integer cannot represent", m.d.name, k,
				  m.d.value ? m.d.value : "?");
	}
	abi_map_close(&m);
	return e;
}

int64_t bml_map_put_int(int64_t obj, const char *decl, int64_t decl_len, int64_t key, int64_t value)
{
	struct abi_map m;
	uint32_t k = 0;
	int64_t e = abi_map_open(obj, decl, decl_len, NULL, NULL, 0, &m);
	if (!e && !(e = u32_key(&m, key, &k))) {
		int sg = is_signed(&m.d);
		int ok = value != INT64_MIN;
		if (m.value_size == 4)
			ok = ok && (sg ? value >= INT32_MIN && value <= INT32_MAX : value >= 0 && value <= UINT32_MAX);
		else
			ok = ok && (sg || value >= 0);
		if (!ok)
			e = abi_fail(BML_VALUE_RANGE, "bml: %lld does not fit the %s values of map %s", (long long)value, m.d.value ? m.d.value : "?",
				     m.d.name);
		else if (!(e = update_u(&m, k, (uint64_t)value)))
			e = abi_ok(0);
	}
	abi_map_close(&m);
	return e;
}

static int64_t record_size(struct abi_map *m, int64_t n)
{
	if ((int64_t)m->value_size != n)
		return abi_fail(BML_MAP_MISMATCH,
				"bml: map %s has %u-byte values in the embedded ELF but this program's record is %lld bytes — regenerate the bindings and rebuild",
				m->d.name, m->value_size, (long long)n);
	return 0;
}

int64_t bml_map_get_bytes(int64_t obj, const char *decl, int64_t decl_len, const char *members, int64_t members_len, int64_t key,
			  uint8_t *dst, int64_t n)
{
	struct abi_map m;
	uint32_t k = 0;
	if (n < 0 || (!dst && n))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL buffer with a length");
	int64_t e = abi_map_open(obj, decl, decl_len, &members, &members_len, 1, &m);
	if (!e && !(e = u32_key(&m, key, &k)) && !(e = record_size(&m, n))) {
		if (bpf_map_lookup_elem(m.fd, &k, dst) != 0)
			e = abi_fail(BML_OTHER, "bml: lookup %s[%u]: %s", m.d.name, k, abi_errno(errno));
		else
			e = abi_ok(0);
	}
	abi_map_close(&m);
	return e;
}

int64_t bml_map_put_bytes(int64_t obj, const char *decl, int64_t decl_len, const char *members, int64_t members_len, int64_t key,
			  const uint8_t *src, int64_t n)
{
	struct abi_map m;
	uint32_t k = 0;
	if (n < 0 || (!src && n))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL buffer with a length");
	int64_t e = abi_map_open(obj, decl, decl_len, &members, &members_len, 1, &m);
	if (!e && !(e = u32_key(&m, key, &k)) && !(e = record_size(&m, n))) {
		if (bpf_map_update_elem(m.fd, &k, src, BPF_ANY) != 0)
			e = abi_fail(BML_OTHER, "bml: update %s[%u]: %s", m.d.name, k, abi_errno(errno));
		else
			e = abi_ok(0);
	}
	abi_map_close(&m);
	return e;
}
