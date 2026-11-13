#include "btf/map_values.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"

static char *fmt(const char *f, ...) __attribute__((format(printf, 1, 2)));
static char *fmt(const char *f, ...)
{
	char tmp[512];
	va_list ap;
	va_start(ap, f);
	vsnprintf(tmp, sizeof(tmp), f, ap);
	va_end(ap);
	struct bml_buf b = {0};
	bml_buf_adds(&b, tmp);
	return bml_buf_take(&b);
}
static int push(void **arr, size_t *n, size_t *cap, size_t elem, const void *v)
{
	if (*n == *cap) {
		size_t c = *cap ? *cap * 2 : 4;
		void *p = realloc(*arr, c * elem);
		if (!p)
			return -1;
		*arr = p;
		*cap = c;
	}
	memcpy((char *)*arr + *n * elem, v, elem);
	(*n)++;
	return 0;
}
static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}


struct mft {
	uint32_t kind, type_id;
	const char *name;
	struct {
		const char *name;
		uint32_t type_id;
	} *members;
	size_t n_members;
	uint32_t *secinfo;
	size_t n_secinfo;
};

struct btfr {
	struct mft *t;
	size_t n;
};

static void btfr_free(struct btfr *b)
{
	for (size_t i = 0; i < b->n; i++) {
		free(b->t[i].members);
		free(b->t[i].secinfo);
	}
	free(b->t);
}

static int btf_str(const uint8_t *strs, size_t slen, uint32_t off, const char **out, char **err)
{
	if (off >= slen)
		return (*err = fmt(".BTF name offset %u is outside the string section", off), -1);
	if (!memchr(strs + off, 0, slen - off))
		return (*err = fmt(".BTF name at offset %u has no terminating NUL", off), -1);
	*out = (const char *)strs + off;
	return 0;
}

static int btf_read(const uint8_t *raw, size_t len, struct btfr *b, char **err)
{
	if (len < 24 || (raw[0] | raw[1] << 8) != 0xeb9f)
		return (*err = fmt(".BTF has no valid header"), -1);
	uint64_t hdr = le32(raw + 4), toff = le32(raw + 8), tlen = le32(raw + 12), soff = le32(raw + 16), sl = le32(raw + 20);
	if (hdr + soff + sl > len || hdr + toff + tlen > len)
		return (*err = fmt(".BTF sections run past the data"), -1);
	const uint8_t *strs = raw + hdr + soff;
	size_t slen = (size_t)sl;
	size_t cap = 1;
	b->t = calloc(1, sizeof(*b->t));
	if (!b->t)
		return (*err = fmt("out of memory"), -1);
	b->t[0].name = "";
	b->n = 1;
	uint64_t p = hdr + toff, end = hdr + toff + tlen;
	while (p < end) {
		if (p + 12 > end)
			return (*err = fmt(".BTF type data ends with %llu stray byte(s)", (unsigned long long)(end - p)), -1);
		uint32_t info = le32(raw + p + 4);
		struct mft t = {.kind = (info >> 24) & 0x1f};
		if (btf_str(strs, slen, le32(raw + p), &t.name, err))
			return -1;
		uint64_t vlen = info & 0xffff;
		t.type_id = le32(raw + p + 8);
		p += 12;
		uint64_t extra;
		switch (t.kind) {
		case 1: case 14: case 17: extra = 4; break;
		case 3: extra = 12; break;
		case 4: case 5: case 15: case 19: extra = 12 * vlen; break;
		case 6: case 13: extra = 8 * vlen; break;
		case 2: case 7: case 8: case 9: case 10: case 11: case 12: case 16: case 18: extra = 0; break;
		default:
			return (*err = fmt(".BTF has kind %u, which this reader does not know", t.kind), -1);
		}
		if (p + extra > end)
			return (*err = fmt(".BTF type %zu (kind %u) is truncated: needs %llu byte(s), %llu left", b->n, t.kind,
					   (unsigned long long)extra, (unsigned long long)(end - p)), -1);
		if (t.kind == 4 || t.kind == 5) {
			t.members = vlen ? calloc(vlen, sizeof(*t.members)) : NULL;
			if (vlen && !t.members)
				return (*err = fmt("out of memory"), -1);
			for (uint64_t i = 0; i < vlen; i++) {
				const uint8_t *m = raw + p + 12 * i;
				if (btf_str(strs, slen, le32(m), &t.members[i].name, err)) {
					free(t.members);
					return -1;
				}
				t.members[i].type_id = le32(m + 4);
				t.n_members++;
			}
		} else if (t.kind == 15) {
			t.secinfo = vlen ? calloc(vlen, sizeof(*t.secinfo)) : NULL;
			if (vlen && !t.secinfo)
				return (*err = fmt("out of memory"), -1);
			for (uint64_t i = 0; i < vlen; i++)
				t.secinfo[i] = le32(raw + p + 12 * i);
			t.n_secinfo = vlen;
		}
		p += extra;
		if (push((void **)&b->t, &b->n, &cap, sizeof(t), &t)) {
			free(t.members);
			free(t.secinfo);
			return (*err = fmt("out of memory"), -1);
		}
	}
	return 0;
}

static int btf_get(const struct btfr *b, uint32_t id, const struct mft **out, char **err)
{
	if (id >= b->n)
		return (*err = fmt(".BTF type id %u is out of range", id), -1);
	*out = &b->t[id];
	return 0;
}

static int btf_strip(const struct btfr *b, uint32_t id, const struct mft **out, char **err)
{
	for (int n = 0; n < 32; n++) {
		const struct mft *t;
		if (btf_get(b, id, &t, err))
			return -1;
		switch (t->kind) {
		case 8: case 9: case 10: case 11: case 18:
			id = t->type_id;
			continue;
		}
		*out = t;
		return 0;
	}
	return (*err = fmt(".BTF modifier chain is too long"), -1);
}

static int cmpstr(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}


int btf_map_value_fields(const struct bml_elf *e, const char **needed, size_t n_needed, struct mapfields **out,
			    size_t *n_out, char **err)
{
	*out = NULL;
	*n_out = 0;
	const struct bml_elf_shdr *sec = bml_elf_section(e, ".BTF");
	if (!sec)
		return (*err = fmt("the object has no .BTF section, so the map values cannot be read"), -1);
	const uint8_t *raw;
	size_t len;
	if (bml_elf_section_data(e, sec, &raw, &len, err))
		return -1;
	struct btfr b = {0};
	if (btf_read(raw, len, &b, err)) {
		btfr_free(&b);
		return -1;
	}
	int rc = -1;
	struct mapfields *res = calloc(n_needed ? n_needed : 1, sizeof(*res));
	if (!res) {
		*err = fmt("out of memory");
		goto done;
	}
	for (size_t mi = 0; mi < n_needed; mi++) {
		const char *m = needed[mi];
		int done_already = 0;
		for (size_t k = 0; k < *n_out; k++)
			if (strcmp(res[k].map, m) == 0)
				done_already = 1;
		if (done_already)
			continue;

		int found = 0;
		uint32_t def_id = 0;
		for (size_t ti = 0; ti < b.n; ti++) {
			const struct mft *t = &b.t[ti];
			if (t->kind != 15 || strcmp(t->name, ".maps") != 0)
				continue;
			for (size_t k = 0; k < t->n_secinfo; k++) {
				const struct mft *v;
				if (btf_get(&b, t->secinfo[k], &v, err))
					goto done;
				if (v->kind == 14 && strcmp(v->name, m) == 0) {
					found = 1;
					def_id = v->type_id;
				}
			}
		}
		if (!found) {
			*err = fmt("map %s has no VAR in the .BTF DATASEC .maps", m);
			goto done;
		}
		const struct mft *def;
		if (btf_strip(&b, def_id, &def, err))
			goto done;
		if (def->kind != 4) {
			*err = fmt("map %s: its .BTF definition is not a struct", m);
			goto done;
		}
		struct mapfields *r = &res[(*n_out)++];
		r->map = m;
		for (size_t k = 0; k < def->n_members; k++) {
			if (strcmp(def->members[k].name, "value") != 0)
				continue;
			const struct mft *ptr, *val;
			if (btf_strip(&b, def->members[k].type_id, &ptr, err))
				goto done;
			if (ptr->kind != 2) {
				*err = fmt("map %s: the value member is not a pointer", m);
				goto done;
			}
			if (btf_strip(&b, ptr->type_id, &val, err))
				goto done;
			if (val->kind != 4)
				break;
			for (size_t j = 0; j < val->n_members; j++) {
				const struct mft *mt;
				if (btf_strip(&b, val->members[j].type_id, &mt, err))
					goto done;
				if (mt->kind == 4 && (strcmp(mt->name, "bpf_timer") == 0 || strcmp(mt->name, "bpf_spin_lock") == 0)) {
					if (r->n == sizeof(r->fields) / sizeof(r->fields[0])) {
						*err = fmt("map %s: too many timer / spin-lock members", m);
						goto done;
					}
					r->fields[r->n++] = strcmp(mt->name, "bpf_timer") == 0 ? "bpf_timer" : "bpf_spin_lock";
				}
			}
		}
		qsort(r->fields, r->n, sizeof(r->fields[0]), cmpstr);
	}
	rc = 0;
done:
	btfr_free(&b);
	if (rc) {
		free(res);
		*n_out = 0;
	} else {
		*out = res;
	}
	return rc;
}
