









#define _GNU_SOURCE
#include "abi/map_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "json/json.h"
#include "util/gostr.h"
#include "util/mutation.h"


static int parse_v4(const char *s, size_t n, uint8_t out[4], const char **why)
{
	int val = 0, pos = 0, dig = 0;
	for (size_t i = 0; i < n; i++) {
		if (s[i] >= '0' && s[i] <= '9') {
			if (dig == 1 && val == 0)
				return *why = "IPv4 field has octet with leading zero", -1;
			val = val * 10 + (s[i] - '0');
			dig++;
			if (val > 255)
				return *why = "IPv4 field has value >255", -1;
		} else if (s[i] == '.') {
			if (i == 0 || i == n - 1 || s[i - 1] == '.')
				return *why = "IPv4 field must have at least one digit", -1;
			if (pos == 3)
				return *why = "IPv4 address too long", -1;
			out[pos++] = (uint8_t)val;
			val = 0;
			dig = 0;
		} else
			return *why = "unexpected character (not an IPv4 address)", -1;
	}
	if (pos < 3)
		return *why = "IPv4 address too short", -1;
	out[3] = (uint8_t)val;
	return 0;
}


static int64_t parse_prefix(const char *what, const char *s, int64_t n, uint8_t addr[4], int *bits)
{
	if (n < 0 || (!s && n))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL string with a length");
	const char *slash = NULL;
	for (int64_t i = n; i-- > 0;)
		if (s[i] == '/') {
			slash = s + i;
			break;
		}
	const char *why = NULL;
	int b = -1;
	if (!slash)
		why = "no '/'";
	else if (parse_v4(s, (size_t)(slash - s), addr, &why) == 0) {
		const char *bs = slash + 1;
		size_t bl = (size_t)(s + n - bs);
		if (bl == 0 || bl > 2 || (bl > 1 && (bs[0] < '1' || bs[0] > '9')))
			why = "bad bits after slash";
		for (size_t i = 0; !why && i < bl; i++)
			if (bs[i] < '0' || bs[i] > '9')
				why = "bad bits after slash";
		if (!why) {
			b = bl == 1 ? bs[0] - '0' : (bs[0] - '0') * 10 + (bs[1] - '0');
			if (b > 32)
				why = "prefix length out of range";
		}
	}
	struct bml_buf m = {0};
	if (why) {
		bml_buf_addf(&m, "bml: %s", what);
		bml_buf_add_goquote(&m, s ? s : "", (size_t)n);
		bml_buf_addf(&m, " is not an IPv4 prefix (a.b.c.d/n): %s", why);
	} else {
		uint32_t a = (uint32_t)addr[0] << 24 | (uint32_t)addr[1] << 16 | (uint32_t)addr[2] << 8 | addr[3];
		uint32_t mask = b == 0 ? 0 : ~0u << (32 - b);
		if ((a & ~mask) && !BML_MUT("lpm.no_host_bits_check")) {
			bml_buf_addf(&m, "bml: %s", what);
			bml_buf_add_goquote(&m, s, (size_t)n);
			bml_buf_addf(&m, " has host bits set — use %u.%u.%u.%u/%d (the kernel would keep the bits outside the prefix length and return them when iterating)",
				     (a & mask) >> 24, (a & mask) >> 16 & 0xff, (a & mask) >> 8 & 0xff, (a & mask) & 0xff, b);
		} else {
			*bits = b;
			return 0;
		}
	}
	struct abi_result r = {.kind = BML_OTHER, .msg_len = m.len};
	r.msg = bml_buf_take(&m);
	return abi_put(&r);
}

int64_t bml_lpm_check_prefix(const char *prefix, int64_t len)
{
	uint8_t a[4];
	int bits = 0;
	int64_t e = parse_prefix("", prefix, len, a, &bits);
	return e ? e : abi_ok(bits);
}

static size_t val_len(const struct abi_map *m)
{
	return !strcmp(m->d.value, "u32") || !strcmp(m->d.value, "i32") ? 4 : 8;
}


static int64_t open_lpm(int64_t obj, const char *decl, int64_t dl, struct abi_map *m)
{
	static const char *const kinds[] = {"lpm_trie", NULL};

	char rec[512] = "";
	struct bml_json *j = NULL;
	char *jerr = NULL;
	if (decl && dl > 0 && bml_json_parse(decl, (size_t)dl, &j, &jerr) == 0) {
		const struct bml_json *k = j->type == BML_JSON_OBJECT ? bml_json_get(j, "key") : NULL;
		if (k && k->type == BML_JSON_STRING && k->len > 7 && k->len < 200 && !strncmp(k->str, "record:", 7)) {
			struct bml_buf nm = {0};
			bml_json_write_string(&nm, k->str + 7, k->len - 7);
			snprintf(rec, sizeof rec,
				 "{%.*s:{\"size\":8,\"members\":[{\"name\":\"prefixlen\",\"offset\":0,\"type\":\"u32\"},{\"name\":\"addr\",\"offset\":4,\"type\":\"[4]u8\"}]}}",
				 (int)nm.len, nm.p ? nm.p : "\"\"");
			bml_buf_free(&nm);
		}
	}
	bml_json_free(j);
	free(jerr);
	const char *recs[1] = {rec};
	int64_t lens[1] = {(int64_t)strlen(rec)};
	int64_t e = abi_map_open_kind(obj, decl, dl, kinds, "an lpm_trie", recs, lens, 1, m);
	if (e)
		return e;
	if (m->key_size != 8 || m->value_size != val_len(m)) {
		e = abi_fail(BML_MAP_MISMATCH, "bml: map %s has %u-byte keys and %u-byte values in the embedded ELF, but an IPv4 lpm_trie of %s has 8 and %zu",
			     m->d.name, m->key_size, m->value_size, m->d.value, val_len(m));
		abi_map_close(m);
	}
	return e;
}

static void key_of(uint8_t k[8], const uint8_t addr[4], int bits)
{
	uint32_t b = (uint32_t)bits;
	memcpy(k, &b, 4);
	memcpy(k + 4, addr, 4);
}

int64_t bml_lpm_put(int64_t obj, const char *decl, int64_t dl, const char *prefix, int64_t pl, int64_t bits)
{
	uint8_t a[4], k[8];
	int b = 0;
	int64_t e = parse_prefix("lpm_put: ", prefix, pl, a, &b);
	struct abi_map m;
	if (e || (e = open_lpm(obj, decl, dl, &m)))
		return e;
	key_of(k, a, b);
	uint64_t v = (uint64_t)bits;
	if (bpf_map_update_elem(m.fd, k, &v, BPF_ANY) == 0)
		e = abi_ok(0);
	else if (errno == ENOSPC)
		e = abi_ok(-ENOSPC);
	else
		e = abi_fail(BML_OTHER, "bml: lpm_put %s %.*s: %s", m.d.name, (int)pl, prefix, abi_errno(errno));
	abi_map_close(&m);
	return e;
}

int64_t bml_lpm_remove(int64_t obj, const char *decl, int64_t dl, const char *prefix, int64_t pl)
{
	uint8_t a[4], k[8];
	int b = 0;
	int64_t e = parse_prefix("lpm_remove: ", prefix, pl, a, &b);
	struct abi_map m;
	if (e || (e = open_lpm(obj, decl, dl, &m)))
		return e;
	key_of(k, a, b);
	if (bpf_map_delete_elem(m.fd, k) == 0)
		e = abi_ok(0);
	else if (errno == ENOENT)
		e = abi_ok(-ENOENT);
	else
		e = abi_fail(BML_OTHER, "bml: lpm_remove %s %.*s: %s", m.d.name, (int)pl, prefix, abi_errno(errno));
	abi_map_close(&m);
	return e;
}

int64_t bml_lpm_match(int64_t obj, const char *decl, int64_t dl, const char *addr, int64_t al)
{
	uint8_t a[4], k[8];
	const char *why = NULL;
	if (al < 0 || (!addr && al))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL string with a length");
	if (parse_v4(addr ? addr : "", (size_t)al, a, &why) != 0) {
		struct bml_buf mb = {0};
		bml_buf_adds(&mb, "bml: lpm_match: ");
		bml_buf_add_goquote(&mb, addr ? addr : "", (size_t)al);
		bml_buf_addf(&mb, " is not an IPv4 address: %s", why);
		struct abi_result r = {.kind = BML_OTHER, .msg_len = mb.len};
		r.msg = bml_buf_take(&mb);
		return abi_put(&r);
	}
	struct abi_map m;
	int64_t e = open_lpm(obj, decl, dl, &m);
	if (e)
		return e;
	key_of(k, a, 32);
	uint64_t v = 0;
	if (bpf_map_lookup_elem(m.fd, k, &v) == 0) {
		struct abi_result r = {.kind = BML_OK, .value = (int64_t)v, .msg = strdup("found"), .msg_len = 5};
		e = r.msg ? abi_put(&r) : abi_fail(BML_OTHER, "bml: out of memory");
	} else if (errno == ENOENT) {
		struct abi_result r = {.kind = BML_OK, .msg = strdup("absent"), .msg_len = 6};
		e = r.msg ? abi_put(&r) : abi_fail(BML_OTHER, "bml: out of memory");
	} else
		e = abi_fail(BML_OTHER, "bml: lpm_match %s %.*s: %s", m.d.name, (int)al, addr, abi_errno(errno));
	abi_map_close(&m);
	return e;
}

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

int64_t bml_lpm_list(int64_t obj, const char *decl, int64_t dl)
{
	struct abi_map m;
	int64_t e = open_lpm(obj, decl, dl, &m);
	if (e)
		return e;
	char **lines = NULL;
	size_t n = 0;
	uint8_t k[8], nk[8];
	int first = 1, err = 0;
	for (uint32_t step = 0;; step++) {
		if (step > bpf_map__max_entries(m.map)) {
			err = -1;
			break;
		}
		if (bpf_map_get_next_key(m.fd, first ? NULL : k, nk) != 0) {
			err = errno == ENOENT ? 0 : errno;
			break;
		}
		first = 0;
		memcpy(k, nk, 8);
		uint64_t v = 0;
		if (bpf_map_lookup_elem(m.fd, k, &v) != 0) {
			if (errno == ENOENT)
				continue;
			err = errno;
			break;
		}
		uint32_t pl;
		memcpy(&pl, k, 4);
		char *line = NULL;
		char **nl = realloc(lines, (n + 1) * sizeof *nl);
		if (!nl || asprintf(&line, "%u.%u.%u.%u/%u %llu", k[4], k[5], k[6], k[7], pl, (unsigned long long)v) < 0) {
			if (nl)
				lines = nl;
			err = ENOMEM;
			break;
		}
		lines = nl;
		lines[n++] = line;
	}
	if (err)
		e = err < 0 ? abi_fail(BML_OTHER, "bml: lpm_iter %s: iteration aborted (the map changed while iterating)", m.d.name)
			    : abi_fail(BML_OTHER, "bml: lpm_iter %s: %s", m.d.name, abi_errno(err));
	else {
		qsort(lines, n, sizeof *lines, cmp_str);
		struct bml_buf b = {0};
		for (size_t i = 0; i < n; i++) {
			if (i)
				bml_buf_adds(&b, "\n");
			bml_buf_adds(&b, lines[i]);
		}
		struct abi_result r = {.kind = BML_OK, .value = (int64_t)n, .msg_len = b.len};
		r.msg = bml_buf_take(&b);
		e = r.msg || !n ? abi_put(&r) : abi_fail(BML_OTHER, "bml: out of memory");
	}
	for (size_t i = 0; i < n; i++)
		free(lines[i]);
	free(lines);
	abi_map_close(&m);
	return e;
}
