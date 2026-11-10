

#include "btf/kernel.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum { MAX_RESOLVE_DEPTH = 32 };

static int is_qualifier(uint32_t kind)
{
	return kind == KBTF_VOLATILE || kind == KBTF_CONST || kind == KBTF_RESTRICT || kind == KBTF_TYPE_TAG;
}

uint32_t bml_kbtf_underlying(const struct bml_kbtf *kb, uint32_t id, int *cycle)
{
	uint32_t r = id;
	*cycle = 0;
	for (int depth = 0; depth <= MAX_RESOLVE_DEPTH; depth++) {
		struct kbtf_type t;
		bml_kbtf_type(kb, r, &t);
		if (!is_qualifier(t.kind) && t.kind != KBTF_TYPEDEF)
			return r;
		r = t.size_type;
	}
	*cycle = 1;
	return id;
}

static const char *type_name(const struct bml_kbtf *kb, uint32_t id)
{
	struct kbtf_type t;
	bml_kbtf_type(kb, id, &t);
	return bml_kbtf_type_name(&t);
}


static void short_form(const struct bml_kbtf *kb, struct bml_buf *b, uint32_t id, int cycle)
{
	if (cycle) {
		bml_buf_adds(b, "cycle");
		return;
	}
	struct kbtf_type t;
	bml_kbtf_type(kb, id, &t);
	bml_buf_adds(b, bml_kbtf_goname(t.kind));
	const char *n = type_name(kb, id);
	if (n[0]) {
		bml_buf_adds(b, ":");
		bml_buf_add_goquote(b, n, strlen(n));
	}
}

static const char *linkage(uint32_t l, const char *what, char *tmp, size_t n)
{
	static const char *const names[] = {"static", "global", "extern"};
	if (l < 3)
		return names[l];
	snprintf(tmp, n, "%s(%u)", what, l);
	return tmp;
}

void bml_kbtf_format(const struct bml_kbtf *kb, struct bml_buf *b, uint32_t id, int cycle, char verb)
{
	short_form(kb, b, id, cycle);
	if (verb == 's')
		return;
	if (cycle) {
		bml_buf_adds(b, "[root=");
		short_form(kb, b, id, 0);
		bml_buf_adds(b, "]");
		return;
	}
	struct kbtf_type t;
	char tmp[48];
	bml_kbtf_type(kb, id, &t);
	switch (t.kind) {
	case KBTF_UNKN:
	case KBTF_DATASEC:
		return;
	case KBTF_INT: {
		uint32_t enc = bml_kbtf_u32(kb, t.aux) >> 24 & 0xf;
		const char *e = enc == 0 ? "unsigned" : enc == 1 ? "signed" : enc == 2 ? "char" : enc == 4 ? "bool" : NULL;
		if (!e) {
			snprintf(tmp, sizeof tmp, "IntEncoding(%u)", enc);
			e = tmp;
		}
		bml_buf_addf(b, "[%s size=%u]", e, t.size_type);
		return;
	}
	case KBTF_PTR:
		bml_buf_adds(b, "[target=");
		short_form(kb, b, t.size_type, 0);
		bml_buf_adds(b, "]");
		return;
	case KBTF_ARRAY:
		bml_buf_adds(b, "[index=");
		short_form(kb, b, bml_kbtf_u32(kb, t.aux + 4), 0);
		bml_buf_adds(b, " type=");
		short_form(kb, b, bml_kbtf_u32(kb, t.aux), 0);
		bml_buf_addf(b, " n=%u]", bml_kbtf_u32(kb, t.aux + 8));
		return;
	case KBTF_STRUCT: case KBTF_UNION: {

		bml_buf_addf(b, "[fields=%u fieldNames=[", t.vlen);
		for (uint32_t i = 0; i < t.vlen && i <= 5; i++) {
			if (i)
				bml_buf_adds(b, " ");
			if (i == 5) {
				bml_buf_adds(b, "...");
				break;
			}
			struct kbtf_member m;
			bml_kbtf_member(kb, &t, i, &m);
			if (m.name[0])
				bml_buf_adds(b, m.name);
			else
				bml_buf_addf(b, "<%u>", i);
		}
		bml_buf_adds(b, "]]");
		return;
	}
	case KBTF_ENUM: case KBTF_ENUM64:
		bml_buf_addf(b, "[size=%u values=%u]", t.size_type, t.vlen);
		return;
	case KBTF_FWD:
		bml_buf_adds(b, t.kflag ? "[union]" : "[struct]");
		return;
	case KBTF_TYPEDEF: case KBTF_VOLATILE: case KBTF_CONST: case KBTF_RESTRICT:
		bml_buf_adds(b, "[");
		short_form(kb, b, t.size_type, 0);
		bml_buf_adds(b, "]");
		return;
	case KBTF_FUNC:
		bml_buf_addf(b, "[%s proto=", linkage(t.vlen, "FuncLinkage", tmp, sizeof tmp));
		short_form(kb, b, t.size_type, 0);
		bml_buf_adds(b, "]");
		return;
	case KBTF_FUNC_PROTO:
		bml_buf_addf(b, "[args=%u return=", t.vlen);
		short_form(kb, b, t.size_type, 0);
		bml_buf_adds(b, "]");
		return;
	case KBTF_VAR:
		bml_buf_addf(b, "[%s]", linkage(bml_kbtf_u32(kb, t.aux), "VarLinkage", tmp, sizeof tmp));
		return;
	case KBTF_FLOAT:
		bml_buf_addf(b, "[size=%u]", t.size_type * 8);
		return;
	case KBTF_DECL_TAG: case KBTF_TYPE_TAG: {

		size_t vl = strlen(t.name);
		bml_buf_adds(b, "[type=");
		short_form(kb, b, t.size_type, 0);
		bml_buf_adds(b, " value=");
		bml_buf_adds(b, t.name);
		if (t.kind == KBTF_DECL_TAG) {
			if (vl > 0 && t.name[vl - 1] != '=')
				bml_buf_adds(b, " ");
			bml_buf_addf(b, "index=%d", (int32_t)bml_kbtf_u32(kb, t.aux));
		}
		bml_buf_adds(b, "]");
		return;
	}
	}
}

void bml_kbtf_gotype(const struct bml_kbtf *kb, struct bml_buf *b, uint32_t id, int cycle)
{
	struct kbtf_type t;
	bml_kbtf_type(kb, id, &t);
	bml_buf_adds(b, "*btf.");
	bml_buf_adds(b, cycle ? "cycle" : bml_kbtf_goname(t.kind));
}

static int size_err(const struct bml_kbtf *kb, uint32_t id, const char *what, char **err)
{
	struct bml_buf b = {0};
	bml_buf_adds(&b, "type ");
	short_form(kb, &b, id, 0);
	bml_buf_adds(&b, what);
	*err = bml_buf_take(&b);
	return -1;
}

int bml_kbtf_sizeof(const struct bml_kbtf *kb, uint32_t id, int64_t *size, char **err)
{
	int64_t n = 1, elem;
	*err = NULL;
	for (int i = 0; i < MAX_RESOLVE_DEPTH; i++) {
		struct kbtf_type t;
		bml_kbtf_type(kb, id, &t);
		switch (t.kind) {
		case KBTF_ARRAY: {
			uint32_t ne = bml_kbtf_u32(kb, t.aux + 8);
			if (n > 0 && (int64_t)ne > INT64_MAX / n)
				return size_err(kb, id, ": overflow", err);
			n *= ne;
			id = bml_kbtf_u32(kb, t.aux);
			continue;
		}
		case KBTF_UNKN: elem = 0; break;
		case KBTF_PTR: elem = 8; break;
		case KBTF_INT: case KBTF_STRUCT: case KBTF_UNION: case KBTF_ENUM: case KBTF_ENUM64: case KBTF_DATASEC: case KBTF_FLOAT:
			elem = t.size_type;
			break;
		case KBTF_TYPEDEF: case KBTF_VOLATILE: case KBTF_CONST: case KBTF_RESTRICT: case KBTF_TYPE_TAG:
			id = t.size_type;
			continue;
		default: {
			struct bml_buf b = {0};
			bml_buf_adds(&b, "type ");
			bml_kbtf_gotype(kb, &b, id, 0);
			bml_buf_adds(&b, ": type is unsized");
			*err = bml_buf_take(&b);
			return -1;
		}
		}
		if (n > 0 && elem > INT64_MAX / n)
			return size_err(kb, id, ": overflow", err);
		*size = n * elem;
		return 0;
	}
	return size_err(kb, id, ": exceeded type depth", err);
}
