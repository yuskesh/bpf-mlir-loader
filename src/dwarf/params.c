






#include "dwarf/internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/mutation.h"

enum { TK_VOID, TK_BASE, TK_PTR, TK_OTHER };

struct tw {
	int kind;
	int64_t enc, bs;
	int char8;
};

static int walk(struct dw *d, const struct dw_val *ref, int depth, struct tw *out);


static int walk_off(struct dw *d, uint64_t off, int depth, struct tw *out)
{
	if (depth > 64)
		return -1;
	struct dw_reader r;
	dw_reader_init(&r, d);
	dw_seek(&r, off);
	struct dw_entry e;
	int rc = dw_next(&r, &e);
	dw_reader_free(&r);
	if (rc != 1 || e.off != off || e.tag == 0) {
		dw_entry_free(&e);
		return -1;
	}
	int res = 0;
	const struct dw_val *v;
	switch (e.tag) {
	case 0x24:
		v = dw_val(&e, 0x3e);
		if (!v || v->kind != DV_INT || v->i < 1 || v->i > 8 || (dw_val(&e, 0x0c) && dw_val(&e, 0x6b))) {
			res = -1;
			break;
		}
		out->kind = TK_BASE;
		out->enc = v->i;
		v = dw_val(&e, 0x0b);
		out->bs = v && v->kind == DV_INT ? v->i : -1;
		break;
	case 0x16: case 0x26: case 0x35: case 0x37:
		res = walk(d, dw_val(&e, 0x49), depth + 1, out);
		break;
	case 0x0f: {
		struct tw p = {TK_VOID, 0, 0, 0};
		res = walk(d, dw_val(&e, 0x49), depth + 1, &p);
		out->kind = TK_PTR;
		out->char8 = p.kind == TK_BASE && (p.enc == 6 || p.enc == 8) && p.bs == 1;
		break;
	}
	default:
		out->kind = TK_OTHER;
	}
	dw_entry_free(&e);
	return res;
}


static int walk(struct dw *d, const struct dw_val *ref, int depth, struct tw *out)
{
	if (!ref || (ref->kind != DV_OFF && ref->kind != DV_UINT)) {
		out->kind = TK_VOID;
		return 0;
	}
	if (ref->kind == DV_UINT)
		return -1;
	return walk_off(d, ref->u, depth, out);
}

static char *spelling(struct dw *d, const struct dw_val *ref)
{
	struct tw t = {TK_VOID, 0, 0, 0};
	char buf[32] = "";
	if (ref && ref->kind == DV_OFF && walk_off(d, ref->u, 0, &t) == 0) {
		if (t.kind == TK_BASE && (t.enc == 5 || t.enc == 7))
			snprintf(buf, sizeof buf, "%c%lld", t.enc == 5 ? 'i' : 'u', (long long)(t.bs * 8));
		else if (t.kind == TK_BASE && (t.enc == 6 || t.enc == 8))
			snprintf(buf, sizeof buf, "%s", t.enc == 6 ? "i8" : "u8");
		else if (t.kind == TK_PTR)
			snprintf(buf, sizeof buf, "%s", t.char8 ? "strptr" : "ptr");
	}
	return strdup(buf);
}

static int fail(char **err, const char *pre, const char *msg)
{
	size_t n = strlen(pre) + strlen(msg) + 1;
	*err = malloc(n);
	if (*err)
		snprintf(*err, n, "%s%s", pre, msg);
	return -1;
}

void bml_dwarf_sub_free(struct bml_dwarf_sub *s)
{
	for (size_t i = 0; i < s->n; i++) {
		free(s->params[i].name);
		free(s->params[i].type);
		free(s->params[i].pointer);
	}
	free(s->params);
	free(s->producer);
	memset(s, 0, sizeof *s);
}


static int push_param(struct bml_dwarf_sub *s, const char *name, char *type, char *pointer, int want_pointer)
{
	struct bml_dwarf_param *np = realloc(s->params, (s->n + 1) * sizeof *np);
	char *nm = strdup(name);
	if (!np || !nm || !type || (want_pointer && !pointer)) {
		if (np)
			s->params = np;
		free(nm);
		free(type);
		free(pointer);
		return -1;
	}
	s->params = np;
	s->params[s->n++] = (struct bml_dwarf_param){nm, type, pointer};
	return 0;
}

int bml_dwarf_open(const struct bml_elf *elf, struct bml_dwarf **out, char **err)
{
	*err = NULL;
	*out = calloc(1, sizeof **out);
	if (!*out)
		return fail(err, "", "out of memory");
	char *oerr = NULL;
	if (dw_open(elf, &(*out)->d, &oerr) != 0) {
		fail(err, "no DWARF: ", oerr ? oerr : "out of memory");
		free(oerr);
		free(*out);
		*out = NULL;
		return -1;
	}
	return 0;
}

void bml_dwarf_close(struct bml_dwarf *d)
{
	if (d)
		dw_close(&d->d);
	free(d);
}


static int read_children(struct dw *d, struct dw_reader *r, int parameters, const uint8_t *raw, size_t n_raw, struct bml_dwarf_sub *sp, char **err)
{
	for (;;) {
		struct dw_entry c;
		int k = dw_next(r, &c);
		if (k < 0)
			return fail(err, "", r->err ? r->err : "out of memory");
		if (k == 0 || c.tag == 0) {
			dw_entry_free(&c);
			return 0;
		}
		if (parameters && c.tag == 0x05) {
			const struct dw_val *vp = dw_val(&c, 0x4b);
			if (!(vp && vp->kind == DV_BOOL && vp->i) || BML_MUT("dwarf.no_varparam_skip")) {
				const struct dw_val *pn = dw_val(&c, 0x03), *ty = dw_val(&c, 0x49);

				size_t idx = sp->n + 1;
				int rp = raw && idx <= n_raw && raw[idx - 1];
				char *pt = !rp ? NULL : ty && ty->kind == DV_OFF ? dw_pointer_spelling(d, ty->u) : strdup("");
				if (push_param(sp, pn && pn->kind == DV_STR ? pn->s : "", rp ? strdup("") : spelling(d, ty), pt, rp) != 0) {
					dw_entry_free(&c);
					return fail(err, "", "out of memory");
				}
			}
		}
		int kids = c.children;
		dw_entry_free(&c);
		if (kids)
			dw_skip_children(r);
	}
}


static int matches(const struct dw_entry *e, uint64_t address, const char *name)
{
	const struct dw_val *nm = dw_val(e, 0x03), *decl = dw_val(e, 0x3c), *pc = dw_val(e, 0x11);
	int named = nm && nm->kind == DV_STR && !strcmp(nm->s, name);
	if (BML_MUT("dwarf.legacy_name_first"))
		return named && e->children;
	if (decl && decl->kind == DV_BOOL && decl->i)
		return 0;
	if (BML_MUT("dwarf.select_by_name"))
		return named;
	return pc && pc->kind == DV_UINT && pc->u == address;
}

int bml_dwarf_subprogram_at(struct bml_dwarf *dd, uint64_t address, const char *name, int parameters, struct bml_dwarf_sub *out, char **err)
{
	return bml_dwarf_subprogram_at_ptr(dd, address, name, parameters, NULL, 0, out, err);
}

int bml_dwarf_subprogram_at_ptr(struct bml_dwarf *dd, uint64_t address, const char *name, int parameters, const uint8_t *raw, size_t n_raw,
				struct bml_dwarf_sub *out, char **err)
{
	memset(out, 0, sizeof *out);
	*err = NULL;
	struct dw *d = &dd->d;
	struct dw_reader r;
	dw_reader_init(&r, d);
	int64_t lang = -1;
	char *producer = strdup("");
	struct bml_dwarf_sub sel = {0};
	size_t n = 0;
	int rc = -1;
	for (;;) {
		struct dw_entry e;
		int k = dw_next(&r, &e);
		if (k < 0) {
			fail(err, "", r.err ? r.err : "out of memory");
			goto done;
		}
		if (k == 0)
			break;
		if (e.tag == 0x11) {
			const struct dw_val *v = dw_val(&e, 0x13), *p = dw_val(&e, 0x25);
			lang = v && v->kind == DV_INT ? v->i : -1;
			free(producer);
			producer = strdup(p && p->kind == DV_STR ? p->s : "");
			dw_entry_free(&e);
			continue;
		}

		if (e.tag != 0x2e || !matches(&e, address, name)) {
			dw_entry_free(&e);
			continue;
		}
		n++;
		bml_dwarf_sub_free(&sel);
		const struct dw_val *cc = dw_val(&e, 0x36);
		sel.lang = lang;
		sel.cc = cc && cc->kind == DV_INT ? cc->i : -1;
		sel.producer = strdup(producer ? producer : "");
		int kids = e.children;
		dw_entry_free(&e);
		if (!sel.producer) {
			fail(err, "", "out of memory");
			goto done;
		}
		if (kids && read_children(d, &r, parameters, raw, n_raw, &sel, err) != 0)
			goto done;
		if (BML_MUT("dwarf.legacy_name_first"))
			break;
	}
	if (n != 1) {
		size_t l = strlen(name) + 128;
		*err = malloc(l);
		if (*err)
			snprintf(*err, l, "DWARF has %zu non-declaration DW_TAG_subprogram definitions at %s (0x%llx), want exactly one", n, name,
				 (unsigned long long)address);
		goto done;
	}
	*out = sel;
	memset(&sel, 0, sizeof sel);
	rc = 0;
done:
	bml_dwarf_sub_free(&sel);
	free(producer);
	dw_reader_free(&r);
	return rc;
}

int bml_dwarf_subprogram_names(const struct bml_elf *elf, char ***names, size_t *n, char **err)
{
	*names = NULL;
	*n = 0;
	*err = NULL;
	struct dw d;
	char *oerr = NULL;
	if (dw_open(elf, &d, &oerr) != 0) {
		fail(err, "no DWARF: ", oerr ? oerr : "out of memory");
		free(oerr);
		return -1;
	}
	struct dw_reader r;
	dw_reader_init(&r, &d);
	int rc = 0;
	for (;;) {
		struct dw_entry e;
		int k = dw_next(&r, &e);
		if (k <= 0) {
			if (k < 0)
				rc = fail(err, "", r.err ? r.err : "out of memory");
			break;
		}
		const struct dw_val *nm = dw_val(&e, 0x03);
		if (e.tag == 0x2e && e.children && nm && nm->kind == DV_STR) {
			char **nn = realloc(*names, (*n + 1) * sizeof *nn);
			char *s = strdup(nm->s);
			if (!nn || !s) {
				free(s);
				if (nn)
					*names = nn;
				dw_entry_free(&e);
				rc = fail(err, "", "out of memory");
				break;
			}
			*names = nn;
			(*names)[(*n)++] = s;
		}
		dw_entry_free(&e);
	}
	dw_reader_free(&r);
	dw_close(&d);
	return rc;
}
