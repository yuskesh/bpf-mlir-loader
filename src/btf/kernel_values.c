

#include "btf/kernel_values.h"

#include <stdlib.h>
#include <string.h>


static size_t key_len(const char *s)
{
	const char *last = NULL;
	for (const char *p = strstr(s, "___"); p; p = strstr(p + 1, "___")) last = p;
	return last ? (size_t)(last - s) : strlen(s);
}

static int key_cmp(const struct bml_kbtf *kb, uint32_t id, const char *name, size_t len)
{
	struct kbtf_type t; bml_kbtf_type(kb, id, &t);
	size_t n = key_len(t.name);
	int c = memcmp(t.name, name, n < len ? n : len);
	return c ? c : (n > len) - (n < len);
}

size_t bml_kbtf_exact_kind(const struct bml_kbtf *kb, const char *name, uint32_t kind, uint32_t first, uint32_t *id)
{
	size_t count = 0;
	size_t len = key_len(name);
	uint32_t lo = 0, hi = kb->nidx;
	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2;
		if (key_cmp(kb, kb->idx[mid], name, len) < 0) lo = mid + 1;
		else hi = mid;
	}
	for (uint32_t at = lo; at < kb->nidx && !key_cmp(kb, kb->idx[at], name, len); at++) {
		uint32_t i = kb->idx[at];
		if (i < first) continue;
		struct kbtf_type t;
		bml_kbtf_type(kb, i, &t);
		if ((t.kind == kind || (kind == KBTF_ENUM && t.kind == KBTF_ENUM64)) && !strcmp(t.name, name)) {
			if (!count) *id = i;
			count++;
		}
	}
	return count;
}

int bml_kbtf_enum_constant(const struct bml_kbtf *kb, uint32_t id, const char *name, uint64_t *value)
{
	struct kbtf_type t;
	bml_kbtf_type(kb, id, &t);
	if (t.kind != KBTF_ENUM && t.kind != KBTF_ENUM64) return 0;
	size_t stride = t.kind == KBTF_ENUM64 ? 12 : 8;
	for (uint32_t i = 0; i < t.vlen; i++) {
		const uint8_t *p = t.aux + stride * i;
		uint32_t off = bml_kbtf_u32(kb, p);
		if (off >= kb->strs_len || strcmp((const char *)kb->strs + off, name)) continue;
		uint64_t v = bml_kbtf_u32(kb, p + 4);
		if (t.kind == KBTF_ENUM64) v |= (uint64_t)bml_kbtf_u32(kb, p + 8) << 32;
		else if (t.kflag) v = (uint64_t)(int64_t)(int32_t)v;
		*value = v; return 1;
	}
	return 0;
}

int bml_kbtf_exact_types(const struct bml_kbtf *kb, const char *name, uint32_t **ids, size_t *count)
{
	*ids = NULL; *count = 0;
	size_t len = key_len(name);
	uint32_t lo = 0, hi = kb->nidx;
	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2;
		if (key_cmp(kb, kb->idx[mid], name, len) < 0) lo = mid + 1; else hi = mid;
	}
	for (uint32_t i = lo; i < kb->nidx && !key_cmp(kb, kb->idx[i], name, len); i++) {
		struct kbtf_type t; bml_kbtf_type(kb, kb->idx[i], &t);
		if (strcmp(t.name, name)) continue;
		uint32_t *a = realloc(*ids, (*count + 1) * sizeof(*a));
		if (!a) { free(*ids); *ids = NULL; *count = 0; return -1; }
		*ids = a; a[(*count)++] = kb->idx[i];
	}
	return 0;
}

static void kind_name(struct bml_buf *b, uint32_t kind)
{
	const char *n = kind ? bml_kbtf_goname(kind) : "Void";
	for (const char *p = n; *p; p++) {
		char c = *p >= 'A' && *p <= 'Z' ? (char)(*p - 'A' + 'a') : *p;
		bml_buf_add(b, &c, 1);
	}
}

char *bml_kbtf_var_slot(const struct bml_kbtf *kb, uint32_t id)
{
	struct kbtf_type v, t;
	int cyc;
	bml_kbtf_type(kb, id, &v);
	bml_kbtf_type(kb, bml_kbtf_underlying(kb, v.size_type, &cyc), &t);
	struct bml_buf b = {0};
	if (cyc) bml_buf_adds(&b, "other:cycle");
	else if (t.kind == KBTF_INT) bml_buf_addf(&b, "%c%u", (bml_kbtf_u32(kb, t.aux) >> 24 & 1) ? 'i' : 'u', t.size_type * 8u);
	else if (t.kind == KBTF_PTR) {
		struct kbtf_type target;
		bml_kbtf_type(kb, bml_kbtf_underlying(kb, t.size_type, &cyc), &target);
		if (!cyc && target.kind == KBTF_STRUCT && target.name[0]) bml_buf_addf(&b, "ptr:%s", target.name);
		else { bml_buf_adds(&b, "other:pointer-to-"); if (cyc) bml_buf_adds(&b, "cycle"); else kind_name(&b, target.kind); }
	} else { bml_buf_adds(&b, "other:"); kind_name(&b, t.kind); }
	return bml_buf_take(&b);
}

int bml_kbtf_var_percpu(const struct bml_kbtf *kb, uint32_t id)
{
	for (uint32_t i = 1; i < kb->n; i++) {
		struct kbtf_type t;
		bml_kbtf_type(kb, i, &t);
		if (t.kind != KBTF_DATASEC || strcmp(t.name, ".data..percpu")) continue;
		for (uint32_t j = 0; j < t.vlen; j++)
			if (bml_kbtf_u32(kb, t.aux + j * 12u) == id) return 1;
	}
	return 0;
}
