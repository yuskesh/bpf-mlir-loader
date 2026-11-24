/* dwarf/pointer.c — the DWARF spelling of the ptr uprobe argument type of requirements format 18: a copy of
 * dwarfPointerSpelling in go/requirements/uprobe_pointer.go (from bpf-mlir's ptr parameter type). It does not use
 * Data.Type but walks the DIEs directly (members behind a pointer are not decoded). The chain of typedef / const /
 * volatile / restrict is stripped at most 64 times on the outer side and 64 on the target side, and a revisit,
 * detected with a shared set of offsets, gives Unknown. A qualifier without DW_AT_type is void; a typedef without a
 * type, a broken reference, atomic, and an unknown tag are Unknown. The width is a positive DW_AT_byte_size, or else
 * the address_size of the unit that contains the pointer's DIE. "" means Unknown (returned as a malloc'd string). */
#include "dwarf/internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/mutation.h"

struct walk {
	struct dw *d;
	uint64_t *seen;
	size_t n, cap;
	int oom;
};

/* The tag of the entry that was read, its DW_AT_type and DW_AT_byte_size, and the unit's asize (address size).
 * 1 means it was read; 0 means it could not be read, or it is a revisit. */
struct die {
	uint64_t off, tag;
	int has_type, type_ok, has_size, size_ok;
	uint64_t type;
	int64_t size;
	int asize;
};

static int read_die(struct walk *w, uint64_t off, struct die *out)
{
	for (size_t i = 0; i < w->n; i++)
		if (w->seen[i] == off)
			return 0;
	if (w->n == w->cap) {
		size_t nc = w->cap ? w->cap * 2 : 16;
		uint64_t *ns = realloc(w->seen, nc * sizeof *ns);
		if (!ns)
			return (w->oom = 1, 0);
		w->seen = ns, w->cap = nc;
	}
	w->seen[w->n++] = off;
	struct dw_reader r;
	dw_reader_init(&r, w->d);
	dw_seek(&r, off);
	struct dw_entry e;
	int k = r.err ? -1 : dw_next(&r, &e);
	int ok = k == 1 && e.off == off;
	if (ok) {
		memset(out, 0, sizeof *out);
		out->off = off, out->tag = e.tag;
		out->asize = w->d->u[r.unit].asize;
		const struct dw_val *t = dw_val(&e, 0x49), *s = dw_val(&e, 0x0b); /* DW_AT_type, DW_AT_byte_size */
		out->has_type = t != NULL, out->type_ok = t && t->kind == DV_OFF, out->type = t ? t->u : 0;
		out->has_size = s != NULL, out->size_ok = s && s->kind == DV_INT, out->size = s ? s->i : 0;
	}
	if (k == 1)
		dw_entry_free(&e);
	dw_reader_free(&r);
	return ok;
}

/* strip: the end point after the qualifiers are stripped (*out). 1 means a known tag, 0 means Unknown. */
static int strip(struct walk *w, uint64_t off, struct die *out)
{
	for (int n = 0; n < 64; n++) {
		if (!read_die(w, off, out))
			return 0;
		switch (out->tag) {
		case 0x16: case 0x26: case 0x35: case 0x37: /* typedef, const, volatile, restrict */
			if (out->tag != 0x16 && !out->has_type) { /* a qualified void (DWARF omits the type reference) */
				out->tag = 0x3b;              /* unspecified_type */
				return 1;
			}
			if (!out->type_ok)
				return 0;
			off = out->type;
			break;
		case 0x0f: case 0x24: case 0x13: case 0x02: case 0x17: case 0x01: case 0x04: case 0x15: case 0x3b: case 0x10: case 0x42:
			return 1; /* pointer, base, struct, class, union, array, enum, subroutine, unspecified, reference, rvalue_reference */
		default:          /* atomic (0x47) and unknown tags */
			return 0;
		}
	}
	return 0;
}

char *dw_pointer_spelling(struct dw *d, uint64_t off)
{
	struct walk w = {d, NULL, 0, 0, 0};
	struct die e, p;
	char buf[64] = "";
	int64_t width;
	if (!strip(&w, off, &e))
		goto out;
	if (e.tag != 0x0f) {
		snprintf(buf, sizeof buf, "non-pointer");
		goto out;
	}
	width = e.asize;
	if (e.has_size) {
		if (!e.size_ok || e.size <= 0)
			goto out;
		width = e.size; /* Go reports it as an int (64 bits) without truncating */
	}
	if (width <= 0)
		goto out;
	int deep = 0;
	if (e.has_type) {
		if (!e.type_ok || !strip(&w, e.type, &p))
			goto out;
		deep = p.tag == 0x0f && !BML_MUT("dwarf.ptr_depth_any");
	}
	if (!deep && width == 8)
		snprintf(buf, sizeof buf, "ptr");
	else
		snprintf(buf, sizeof buf, deep ? "ptr(depth>=2,width=%lld)" : "ptr(depth=1,width=%lld)", (long long)width);
out:
	free(w.seen);
	return w.oom ? NULL : strdup(buf);
}
