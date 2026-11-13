#define _GNU_SOURCE
#include "caps/live_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util/gostr.h"
#include "util/mutation.h"

#define UNK ": cannot be determined on this target"

const char *lv_tracefs_roots[2] = {"/sys/kernel/tracing", "/sys/kernel/debug/tracing"};


static int split_event(const char *event, char **cat, char **name, char **msg)
{
	const char *sl = strchr(event, '/');
	if (!sl || sl == event || !sl[1] || strchr(sl + 1, '/') || strstr(event, "..")) {
		struct bml_buf b = {0};
		bml_buf_adds(&b, "tracepoint ");
		bml_buf_add_goquote(&b, event, strlen(event));
		bml_buf_adds(&b, " is not <category>/<event>" UNK);
		*msg = bml_buf_take(&b);
		return -1;
	}
	*cat = strndup(event, (size_t)(sl - event));
	*name = strdup(sl + 1);
	if (!*cat || !*name) {
		free(*cat);
		free(*name);
		*msg = strdup("out of memory");
		return -1;
	}
	return 0;
}


static void add_path_err(struct bml_buf *errs, const char *op, const char *path, int e)
{
	char *es = bml_go_errno_str(e);
	bml_buf_addf(errs, "%s%s %s: %s", errs->len ? "; " : "", op, path, es ? es : "");
	free(es);
}

int lv_tracefs_event_id(const char *event, int *out, char **msg)
{
	char *cat, *name;
	*out = 0;
	if (split_event(event, &cat, &name, msg))
		return BML_Q_UNKNOWN;
	struct bml_buf errs = {0};
	int found = 0;
	for (size_t i = 0; i < 2 && !found; i++) {
		char path[4096];
		snprintf(path, sizeof path, "%s/events/%s/%s/id", lv_tracefs_roots[i], cat, name);
		struct stat st;
		if (stat(path, &st) == 0)
			found = 1;
		else
			add_path_err(&errs, "stat", path, errno);
	}
	if (found) {
		bml_buf_free(&errs);
		*out = 1;
	} else {
		char *e = bml_buf_take(&errs);
		struct bml_buf b = {0};
		bml_buf_addf(&b, "tracefs event %s is not readable (%s) — a module tracepoint or no tracefs is not checked" UNK, event, e ? e : "");
		free(e);
		*msg = bml_buf_take(&b);
	}
	free(cat);
	free(name);
	return found ? BML_Q_OK : BML_Q_UNKNOWN;
}

static int is_space(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}


static void trim(const char **s, size_t *n)
{
	while (*n && is_space(**s))
		(*s)++, (*n)--;
	while (*n && is_space((*s)[*n - 1]))
		(*n)--;
}

struct tp_fmt_field {
	char *name, *decl;
	int64_t offset, size;
	int is_signed;
};


static int parse_field_line(const char *l, size_t n, struct tp_fmt_field *f, char **err)
{
	const char *decl = "";
	size_t decl_n = 0;
	int got = 0;
	memset(f, 0, sizeof *f);
	for (size_t i = 0; i <= n;) {
		size_t j = i;
		while (j < n && l[j] != ';')
			j++;
		const char *part = l + i;
		size_t pn = j - i;
		trim(&part, &pn);
		const char *colon = memchr(part, ':', pn);
		if (colon) {
			size_t kn = (size_t)(colon - part);
			const char *v = colon + 1;
			size_t vn = pn - kn - 1;
			if (kn == 5 && !memcmp(part, "field", 5)) {
				decl = v, decl_n = vn;
			} else if ((kn == 6 && !memcmp(part, "offset", 6)) || (kn == 4 && !memcmp(part, "size", 4)) ||
				   (kn == 6 && !memcmp(part, "signed", 6))) {
				int64_t x;
				if (bml_go_atoi(v, vn, &x)) {
					struct bml_buf b = {0};
					bml_buf_addf(&b, "tracepoint format: bad %.*s in ", (int)kn, part);
					bml_buf_add_goquote(&b, l, n);
					*err = bml_buf_take(&b);
					return -1;
				}
				if (part[0] == 'o')
					f->offset = x;
				else if (kn == 4)
					f->size = x;
				else
					f->is_signed = x != 0;
				got++;
			}
		}
		i = j + 1;
	}

	size_t s, e;
	if (!lv_tp_field_name(decl, decl_n, &s, &e) || got != 3) {
		struct bml_buf b = {0};
		bml_buf_adds(&b, "tracepoint format: cannot read ");
		bml_buf_add_goquote(&b, l, n);
		*err = bml_buf_take(&b);
		return -1;
	}
	const char *td = decl;
	size_t tn = decl_n;
	trim(&td, &tn);
	f->name = strndup(decl + s, e - s);
	f->decl = strndup(td, tn);
	if (!f->name || !f->decl) {
		free(f->name), free(f->decl);
		*err = strdup("out of memory");
		return -1;
	}
	return 0;
}


static int compare_str(const struct tp_fmt_field *f, const char *event, const char *field, int64_t off, int64_t bytes, const char *sign,
		       struct bml_strs *out)
{
	int depth;
	int known = lv_tp_char_depth(f->decl, strlen(f->decl), &depth);
	if (f->offset == off && f->size == bytes && bytes == 8 && known && lv_str_depth_ok(depth, sign))
		return 0;
	struct bml_buf b = {0};
	bml_buf_addf(&b, "tracepoint %s field %s declaration ", event, field);
	bml_buf_add_goquote(&b, f->decl, strlen(f->decl));
	bml_buf_addf(&b, " at offset %lld, %lld bytes does not match offset %lld, 8-byte char pointer %s", (long long)f->offset, (long long)f->size,
		     (long long)off, sign);
	return lv_push(out, &b) ? -2 : 0;
}


static int compare_array(const struct tp_fmt_field *f, const char *event, const char *field, int64_t off, int64_t bytes, const char *sign,
			 struct bml_strs *out)
{
	int64_t cnt;
	char explicit;
	int known = lv_tp_array_shape(f->decl, strlen(f->decl), &cnt, &explicit);
	size_t sl = strlen(sign);
	char want = sl >= 3 && !strcmp(sign + sl - 3, "]i8") ? 'i' : 'u', got = f->is_signed ? 'i' : 'u', spell[40];
	snprintf(spell, sizeof spell, "[%lld]%c8", (long long)cnt, want);
	int ok = known && cnt == bytes && f->size == bytes && f->offset == off && got == want && (!explicit || explicit == got) && !strcmp(sign, spell);
	if (BML_MUT("caps.tp_array_shape_any"))
		ok = f->offset == off;
	if (ok)
		return 0;
	struct bml_buf b = {0};
	bml_buf_addf(&b, "tracepoint %s field %s declaration ", event, field);
	bml_buf_add_goquote(&b, f->decl, strlen(f->decl));
	bml_buf_addf(&b, " at offset %lld, %lld bytes, signed %s does not match offset %lld, %lld bytes, %s", (long long)f->offset, (long long)f->size,
		     f->is_signed ? "true" : "false", (long long)off, (long long)bytes, sign);
	return lv_push(out, &b) ? -2 : 0;
}



static int compare_format(const char *text, size_t len, const char *event, const char *field, int64_t off, int64_t bytes, const char *sign,
			  struct bml_strs *out, char **err)
{
	int nfields = 0, matched = 0, str = lv_is_str(sign), array = sign[0] == '[';
	char *unk = NULL;
	for (size_t i = 0; i <= len;) {
		size_t j = i;
		while (j < len && text[j] != '\n')
			j++;
		const char *l = text + i;
		size_t n = j - i;
		i = j + 1;
		trim(&l, &n);
		if (n < 6 || memcmp(l, "field:", 6) != 0)
			continue;
		struct tp_fmt_field f;
		if (parse_field_line(l, n, &f, err)) {
			free(unk);
			return -1;
		}
		nfields++;
		int depth;
		int64_t cnt;
		char es;
		if ((str || array) && !unk && !strcmp(f.name, field) &&
		    !(array ? lv_tp_array_shape(f.decl, strlen(f.decl), &cnt, &es) : lv_tp_char_depth(f.decl, strlen(f.decl), &depth))) {
			struct bml_buf b = {0};
			bml_buf_addf(&b, "tracepoint %s field %s has an unknown declaration ", event, field);
			bml_buf_add_goquote(&b, f.decl, strlen(f.decl));
			bml_buf_adds(&b, UNK);
			if (!(unk = bml_buf_take(&b))) {
				free(f.name), free(f.decl);
				return -2;
			}
		}
		if (!matched && !strcmp(f.name, field) && array) {
			matched = 1;
			if (compare_array(&f, event, field, off, bytes, sign, out)) {
				free(f.name), free(f.decl), free(unk);
				return -2;
			}
		} else if (!matched && !strcmp(f.name, field) && str) {
			matched = 1;
			if (compare_str(&f, event, field, off, bytes, sign, out)) {
				free(f.name), free(f.decl), free(unk);
				return -2;
			}
		} else if (!matched && !strcmp(f.name, field)) {
			matched = 1;
			const char *got = f.is_signed ? "i" : "u";
			if (f.offset != off || f.size != bytes || strcmp(got, sign) != 0) {
				struct bml_buf b = {0};
				bml_buf_addf(&b,
					     "tracepoint %s field %s is at offset %lld, %lld bytes, %s in the target's tracefs format, but the object reads offset %lld, "
					     "%lld bytes, %s",
					     event, field, (long long)f.offset, (long long)f.size, got, (long long)off, (long long)bytes, sign);
				if (lv_push(out, &b)) {
					free(f.name), free(f.decl), free(unk);
					return -2;
				}
			}
		}
		free(f.name), free(f.decl);
	}
	if (nfields == 0) {
		*err = strdup("tracepoint format: no field lines");
		return -1;
	}
	if (unk) {
		*err = unk;
		return -3;
	}
	if (!matched) {
		struct bml_buf b = {0};
		bml_buf_addf(&b, "tracepoint %s has no field %s in the target's tracefs format", event, field);
		if (lv_push(out, &b))
			return -2;
	}
	return 0;
}

int lv_read_file(const char *path, char **data, size_t *len, int *e)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		*e = errno;
		return -1;
	}
	struct bml_buf b = {0};
	char tmp[8192];
	for (;;) {
		ssize_t r = read(fd, tmp, sizeof tmp);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0) {
			*e = errno;
			close(fd);
			bml_buf_free(&b);
			return -1;
		}
		if (r == 0)
			break;
		bml_buf_add(&b, tmp, (size_t)r);
	}
	close(fd);
	*len = b.len;
	*data = bml_buf_take(&b);
	if (!*data) {
		*e = ENOMEM;
		return -1;
	}
	return 0;
}

int lv_tp_field_text(const char *text, size_t len, const char *event, const char *field, int64_t off, int64_t bytes, const char *sign,
		     struct bml_strs *out, char **msg)
{
	char *err = NULL;
	int rc = BML_Q_UNKNOWN, c = compare_format(text, len, event, field, off, bytes, sign, out, &err);
	if (c == -2) {
		rc = lv_oom(out, msg);
	} else if (c == -3) {
		bml_strs_free(out);
		*msg = err, err = NULL;
	} else if (c == -1) {
		bml_strs_free(out);
		struct bml_buf b = {0};
		bml_buf_addf(&b, "%s: %s" UNK, event, err ? err : "");
		*msg = bml_buf_take(&b);
	} else
		rc = BML_Q_OK;
	free(err);
	return rc;
}

int bml_live_tp_field(struct bml_live *l, const char *event, const char *field, int64_t off, int64_t bytes, const char *sign, struct bml_strs *out,
		      char **msg)
{
	(void)l;
	memset(out, 0, sizeof *out);
	char *cat, *name;
	if (split_event(event, &cat, &name, msg))
		return BML_Q_UNKNOWN;
	struct bml_buf errs = {0};
	int rc = BML_Q_UNKNOWN;
	for (size_t i = 0; i < 2; i++) {
		char path[4096];
		snprintf(path, sizeof path, "%s/events/%s/%s/format", lv_tracefs_roots[i], cat, name);
		char *text;
		size_t len;
		int e;
		if (lv_read_file(path, &text, &len, &e)) {
			add_path_err(&errs, "open", path, e);
			continue;
		}
		rc = lv_tp_field_text(text, len, event, field, off, bytes, sign, out, msg);
		free(text);
		bml_buf_free(&errs);
		free(cat);
		free(name);
		return rc;
	}
	char *e = bml_buf_take(&errs);
	struct bml_buf b = {0};
	bml_buf_addf(&b,
		     "the tracefs format of %s is not readable (%s) — tracefs needs root (a non-root loader uses caps recorded as root with a live re-probe — "
		     "ebpf-precheck --caps --live), and a missing or module event is not checked" UNK,
		     event, e ? e : "");
	free(e);
	*msg = bml_buf_take(&b);
	free(cat);
	free(name);
	return rc;
}
