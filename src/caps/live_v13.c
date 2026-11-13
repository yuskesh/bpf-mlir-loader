#define _GNU_SOURCE
#include "caps/live_internal.h"
#include "btf/kernel_values.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util/gostr.h"

#define UNK ": cannot be determined on this target"


static void int_spelling(const struct bml_kbtf *kb, const struct kbtf_type *t, struct bml_buf *b)
{
	uint32_t enc = bml_kbtf_u32(kb, t->aux) >> 24 & 0xf;
	if (enc & 4)
		bml_buf_adds(b, "bool");
	else
		bml_buf_addf(b, "%c%u", (enc & 1) || (enc & 2) ? 'i' : 'u', (uint32_t)(t->size_type * 8u));
}


static void kfunc_spelling(const struct bml_kbtf *kb, uint32_t id, struct bml_buf *b)
{
	int cyc;
	uint32_t u = bml_kbtf_underlying(kb, id, &cyc);
	struct kbtf_type t;
	bml_kbtf_type(kb, u, &t);
	if (cyc) {
		bml_buf_adds(b, "?");
		bml_kbtf_gotype(kb, b, u, cyc);
		return;
	}
	switch (t.kind) {
	case KBTF_UNKN:
		bml_buf_adds(b, "void");
		return;
	case KBTF_INT:
		int_spelling(kb, &t, b);
		return;
	case KBTF_ENUM:
	case KBTF_ENUM64:
		bml_buf_addf(b, "%c%u", t.kflag ? 'i' : 'u', (uint32_t)(t.size_type * 8u));
		return;
	case KBTF_PTR: {
		uint32_t pu = bml_kbtf_underlying(kb, t.size_type, &cyc);
		struct kbtf_type p;
		bml_kbtf_type(kb, pu, &p);
		if (!cyc && p.kind == KBTF_UNKN)
			bml_buf_adds(b, "ptr:void");
		else if (!cyc && p.kind == KBTF_INT) {
			bml_buf_adds(b, "ptr:");
			int_spelling(kb, &p, b);
		} else if (!cyc && (p.kind == KBTF_STRUCT || p.kind == KBTF_UNION))
			bml_buf_addf(b, "ptr:%s", p.name);
		else {
			bml_buf_adds(b, "ptr:?");
			bml_kbtf_gotype(kb, b, pu, cyc);
		}
		return;
	}
	default:
		bml_buf_adds(b, "?");
		bml_kbtf_gotype(kb, b, u, 0);
	}
}

static char *spell(const struct bml_kbtf *kb, uint32_t id)
{
	struct bml_buf b = {0};
	kfunc_spelling(kb, id, &b);
	return bml_buf_take(&b);
}

int bml_live_kfunc(struct bml_live *l, const char *name, const char *ret, const struct bml_str *args, size_t n_args, struct bml_strs *out, char **msg)
{
	const char *verr;
	const struct bml_kbtf *kb = lv_kb(l, &verr);
	memset(out, 0, sizeof *out);
	*msg = NULL;
	if (!kb)
		return asprintf(msg, "target BTF: %s" UNK, verr ? verr : "") < 0 ? lv_oom(out, msg) : BML_Q_UNKNOWN;
	uint32_t id;
	char *err = NULL;
	int rc = lv_lookup(kb, name, KBTF_FUNC, &id, &err);
	if (rc < 0)
		return lv_oom(out, msg);
	struct bml_buf b = {0};
	if (rc == 1) {
		free(err);
		bml_buf_addf(&b, "kfunc %s is not found in the target BTF (vmlinux)", name);
		return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
	}
	if (rc) {
		size_t count = bml_kbtf_exact_kind(kb, name, KBTF_FUNC, 1, &id);
		int r2 = rc == 2 ? asprintf(msg, "kfunc %s: the target BTF has %zu FUNC named %s" UNK, name, count, name) :
			asprintf(msg, "kfunc %s: %s" UNK, name, err);
		free(err);
		return r2 < 0 ? lv_oom(out, msg) : BML_Q_UNKNOWN;
	}
	struct kbtf_type fn, fp;
	bml_kbtf_type(kb, id, &fn);
	bml_kbtf_type(kb, fn.size_type, &fp);
	if (fp.kind != KBTF_FUNC_PROTO) {
		bml_buf_addf(&b, "kfunc %s has no FUNC_PROTO in the target BTF", name);
		return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
	}

	char *got = spell(kb, fp.size_type);
	if (!got)
		return lv_oom(out, msg);
	if (strcmp(got, ret) != 0) {
		bml_buf_addf(&b, "kfunc %s returns %s in the target BTF, but the object declares %s", name, got, ret);
		if (lv_push(out, &b)) {
			free(got);
			return lv_oom(out, msg);
		}
	}
	free(got);
	if (fp.vlen != n_args) {
		bml_buf_addf(&b, "kfunc %s takes %u arguments (", name, fp.vlen);
		for (uint32_t i = 0; i < fp.vlen; i++) {
			const char *pn;
			uint32_t pt;
			bml_kbtf_param(kb, &fp, i, &pn, &pt);
			if (i)
				bml_buf_adds(&b, ", ");
			kfunc_spelling(kb, pt, &b);
		}
		bml_buf_addf(&b, ") in the target BTF, but the object passes %zu (", n_args);
		for (size_t i = 0; i < n_args; i++)
			bml_buf_addf(&b, i ? ", %s" : "%s", args[i].p);
		bml_buf_adds(&b, ")");
		return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
	}
	for (uint32_t i = 0; i < fp.vlen; i++) {
		const char *pn;
		uint32_t pt;
		bml_kbtf_param(kb, &fp, i, &pn, &pt);
		char *g = spell(kb, pt);
		if (!g)
			return lv_oom(out, msg);
		if (strcmp(g, args[i].p) != 0) {
			bml_buf_addf(&b, "argument %u (%s) of kfunc %s is %s in the target BTF, but the object passes %s", i, bml_arg_name(pn), name, g, args[i].p);
			if (lv_push(out, &b)) {
				free(g);
				return lv_oom(out, msg);
			}
		}
		free(g);
	}
	return BML_Q_OK;
}



struct sysfield {
	char *type, *name;
};

static void fields_free(struct sysfield *f, size_t n)
{
	for (size_t i = 0; i < n; i++)
		free(f[i].type), free(f[i].name);
	free(f);
}

static int is_space(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}


static void trim(const char **s, const char **e)
{
	while (*s < *e && is_space(**s))
		(*s)++;
	while (*e > *s && is_space((*e)[-1]))
		(*e)--;
}


static int parse_format(const char *text, struct sysfield **out, size_t *n, char **err)
{
	*out = NULL, *n = 0, *err = NULL;
	int seen_nr = 0;
	for (const char *l = text; l && *l;) {
		const char *nl = strchr(l, '\n');
		const char *s = l, *e = nl ? nl : l + strlen(l);
		l = nl ? nl + 1 : NULL;
		trim(&s, &e);
		if ((size_t)(e - s) < 6 || memcmp(s, "field:", 6) != 0)
			continue;
		const char *ds = s + 6, *de = memchr(ds, ';', (size_t)(e - ds));
		if (!de)
			de = e;
		trim(&ds, &de);
		const char *i = NULL;
		for (const char *p = ds; p < de; p++)
			if (*p == ' ' || *p == '*')
				i = p;
		if (!i || i == de - 1) {
			struct bml_buf b = {0};
			bml_buf_adds(&b, "syscall format: cannot read ");
			bml_buf_add_goquote(&b, s, (size_t)(e - s));
			*err = bml_buf_take(&b);
			goto fail;
		}
		const char *ts = ds, *te = i + 1;
		trim(&ts, &te);
		size_t nn = (size_t)(de - i - 1);
		if (nn == 12 && !memcmp(i + 1, "__syscall_nr", 12)) {
			seen_nr = 1;
			continue;
		}
		if (nn >= 7 && !memcmp(i + 1, "common_", 7))
			continue;
		if (!seen_nr) {
			struct bml_buf b = {0};
			bml_buf_adds(&b, "syscall format: field ");
			bml_buf_add_goquote(&b, i + 1, nn);
			bml_buf_adds(&b, " before __syscall_nr");
			*err = bml_buf_take(&b);
			goto fail;
		}
		struct sysfield *nf = realloc(*out, (*n + 1) * sizeof **out);
		if (!nf)
			goto fail;
		*out = nf;
		(*out)[*n].type = strndup(ts, (size_t)(te - ts));
		(*out)[*n].name = strndup(i + 1, nn);
		(*n)++;
		if (!(*out)[*n - 1].type || !(*out)[*n - 1].name)
			goto fail;
	}
	if (!seen_nr) {
		*err = strdup("syscall format: no __syscall_nr field");
		goto fail;
	}
	return 0;
fail:
	fields_free(*out, *n);
	*out = NULL, *n = 0;
	return -1;
}


static int type_spelling(const struct bml_kbtf *kb, const char *typ, char **s)
{
	*s = NULL;
	if (strchr(typ, '*'))
		return (*s = strdup("ptr")) != NULL;
	struct bml_buf w = {0};
	int any = 0;
	for (const char *p = typ; *p;) {
		while (*p && is_space(*p))
			p++;
		const char *st = p;
		while (*p && !is_space(*p))
			p++;
		size_t k = (size_t)(p - st);
		if (!k || (k == 5 && !memcmp(st, "const", 5)) || (k == 8 && !memcmp(st, "volatile", 8)) || (k == 6 && !memcmp(st, "__user", 6)))
			continue;
		if (any)
			bml_buf_adds(&w, " ");
		bml_buf_add(&w, st, k);
		any = 1;
	}
	char *name = bml_buf_take(&w);
	if (!name)
		name = strdup("");
	static const char *const c_int[][2] = {
		{"unsigned", "unsigned int"},	      {"signed", "int"},		 {"unsigned long", "long unsigned int"},
		{"long", "long int"},		      {"signed long", "long int"},	 {"unsigned short", "short unsigned int"},
		{"short", "short int"},		      {"long long", "long long int"}, {"unsigned long long", "long long unsigned int"},
		{"signed char", "signed char"},
	};
	const char *nm = name;
	for (size_t i = 0; nm && i < sizeof c_int / sizeof *c_int; i++)
		if (!strcmp(nm, c_int[i][0]))
			nm = c_int[i][1];
	int ok = 0;
	char *err = NULL;
	if (nm && !strncmp(nm, "enum ", 5)) {
		uint32_t id;
		if (lv_lookup(kb, nm + 5, KBTF_ENUM, &id, &err) == 0)
			ok = (*s = spell(kb, id)) != NULL;
		free(err);
		free(name);
		return ok;
	}
	uint32_t *ids = NULL;
	size_t n = 0;
	if (nm && bml_kbtf_exact_types(kb, nm, &ids, &n) == 0) {
		for (size_t i = 0; i < n && !ok; i++) {
			struct kbtf_type t;
			bml_kbtf_type(kb, ids[i], &t);
			if (t.kind != KBTF_INT && t.kind != KBTF_TYPEDEF)
				continue;
			char *sp = spell(kb, ids[i]);
			if (!sp)
				break;
			if (!strcmp(sp, "bool")) {
				free(sp);
				sp = strdup("u8");
			}
			if (sp && sp[0] != '?' && strncmp(sp, "ptr:", 4) != 0)
				*s = sp, ok = 1;
			else if (sp && !strncmp(sp, "ptr:", 4)) {
				free(sp);
				ok = (*s = strdup("ptr")) != NULL;
			} else
				free(sp);
		}
	}
	free(ids);
	free(err);
	free(name);
	return ok;
}


static int compare(const char *sc, int64_t n, const char *typ, char **args, char **names, size_t na, const char *from, struct bml_strs *out)
{
	struct bml_buf b = {0};
	if (n > (int64_t)na)
		bml_buf_addf(&b, "syscall %s takes %zu arguments in the target's %s, but the object reads argument %lld", sc, na, from, (long long)n);
	else if (strcmp(args[n - 1], typ) != 0)
		bml_buf_addf(&b, "argument %lld (%s) of syscall %s is %s in the target's %s, but the object reads it as %s", (long long)n, names[n - 1], sc,
			     args[n - 1], from, typ);
	else
		return 0;
	return lv_push(out, &b);
}

static int read_text(const char *path, char **out, int *eno)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return *eno = errno, -1;
	struct bml_buf b = {0};
	char tmp[4096];
	ssize_t k;
	while ((k = read(fd, tmp, sizeof tmp)) > 0)
		bml_buf_add(&b, tmp, (size_t)k);
	*eno = k < 0 ? errno : 0;
	close(fd);
	if (k < 0) {
		bml_buf_free(&b);
		return -1;
	}
	*out = bml_buf_take(&b);
	if (!*out)
		*out = strdup("");
	return 0;
}

int bml_live_syscall_arg(struct bml_live *l, const char *name, int64_t n, const char *typ, struct bml_strs *out, char **msg)
{
	const char *verr;
	memset(out, 0, sizeof *out);
	*msg = NULL;
	const struct bml_kbtf *kb = lv_kb(l, &verr);
	if (!kb)
		return asprintf(msg, "target BTF: %s" UNK, verr ? verr : "") < 0 ? lv_oom(out, msg) : BML_Q_UNKNOWN;
	const char **roots = lv_tracefs_roots;
	struct bml_buf errs = {0};
	for (size_t r = 0; r < 2; r++) {
		char path[512], *text = NULL;
		snprintf(path, sizeof path, "%s/events/syscalls/sys_enter_%s/format", roots[r], name);
		int eno;
		if (read_text(path, &text, &eno) != 0) {
			char *es = bml_go_errno_str(eno);
			if (eno == ENOENT) {
				bml_buf_addf(&errs, "%sopen %s: %s", errs.len ? "; " : "", path, es ? es : "");
				free(es);
				continue;
			}
			int r2 = asprintf(msg,
					  "the tracefs format of syscalls/sys_enter_%s is not readable (open %s: %s) — tracefs needs root (a non-root loader uses caps "
					  "recorded as root with a live re-probe — ebpf-precheck --caps --live)" UNK,
					  name, path, es ? es : "");
			free(es);
			bml_buf_free(&errs);
			return r2 < 0 ? lv_oom(out, msg) : BML_Q_UNKNOWN;
		}
		bml_buf_free(&errs);
		struct sysfield *f;
		size_t nf;
		char *perr;
		if (parse_format(text, &f, &nf, &perr) != 0) {
			free(text);
			int r2 = perr ? asprintf(msg, "syscalls/sys_enter_%s: %s" UNK, name, perr) : -1;
			free(perr);
			return r2 < 0 ? lv_oom(out, msg) : BML_Q_UNKNOWN;
		}
		free(text);
		char **args = calloc(nf ? nf : 1, sizeof *args), **names = calloc(nf ? nf : 1, sizeof *names);
		int rc = BML_Q_OK;
		for (size_t i = 0; args && names && i < nf; i++) {
			char *s;
			int d;
			if (lv_is_str(typ) && (int64_t)i == n - 1) {
				if (!lv_sys_char_depth(kb, f[i].type, &d)) {
					struct bml_buf b = {0};
					bml_buf_addf(&b, "argument %lld (%s) of syscall %s has unresolved string pointer type ", (long long)n, f[i].name, name);
					bml_buf_add_goquote(&b, f[i].type, strlen(f[i].type));
					bml_buf_adds(&b, UNK);
					*msg = bml_buf_take(&b);
					rc = *msg ? BML_Q_UNKNOWN : lv_oom(out, msg);
					break;
				}
				s = lv_str_arg(d, typ);
			} else if (!type_spelling(kb, f[i].type, &s)) {
				if ((int64_t)i == n - 1) {
					struct bml_buf b = {0};
					bml_buf_addf(&b, "argument %lld (%s) of syscall %s has the type ", (long long)n, f[i].name, name);
					bml_buf_add_goquote(&b, f[i].type, strlen(f[i].type));
					bml_buf_adds(&b, " in the tracefs format, which the target BTF does not resolve to an integer" UNK);
					*msg = bml_buf_take(&b);
					rc = *msg ? BML_Q_UNKNOWN : lv_oom(out, msg);
					break;
				}
				s = NULL;
				if (asprintf(&s, "?%s", f[i].type) < 0)
					s = NULL;
			}
			args[i] = s;
			names[i] = strdup(f[i].name);
		}
		if (rc == BML_Q_OK && (!args || !names || compare(name, n, typ, args, names, nf, "tracefs format", out)))
			rc = lv_oom(out, msg);
		for (size_t i = 0; args && names && i < nf; i++)
			free(args[i]), free(names[i]);
		free(args), free(names);
		fields_free(f, nf);
		return rc;
	}

	char *fname = NULL, *err = NULL;
	uint32_t id;
	if (asprintf(&fname, "__do_sys_%s", name) >= 0 && bml_kbtf_by_name(kb, fname, KBTF_FUNC, &id, &err) == 0) {
		struct kbtf_type fn, fp;
		bml_kbtf_type(kb, id, &fn);
		bml_kbtf_type(kb, fn.size_type, &fp);
		if (fp.kind == KBTF_FUNC_PROTO) {
			char **args = calloc(fp.vlen ? fp.vlen : 1, sizeof *args), **names = calloc(fp.vlen ? fp.vlen : 1, sizeof *names);
			int unres = 0;
			for (uint32_t i = 0; args && names && i < fp.vlen; i++) {
				const char *pn;
				uint32_t pt;
				bml_kbtf_param(kb, &fp, i, &pn, &pt);
				int d;
				char *s = NULL;
				if (lv_is_str(typ) && (int64_t)i == n - 1) {
					if (!lv_sys_btf_char_depth(kb, pt, &d)) {
						unres = 1;
						break;
					}
					s = lv_str_arg(d, typ);
				} else
					s = spell(kb, pt);
				if (s && !strncmp(s, "ptr:", 4)) {
					free(s);
					s = strdup("ptr");
				} else if (s && !strcmp(s, "bool")) {
					free(s);
					s = strdup("u8");
				}
				args[i] = s;
				names[i] = strdup(bml_arg_name(pn));
			}
			char *from = NULL;
			int rc = BML_Q_OK;
			if (unres)
				rc = asprintf(msg, "argument %lld of syscall %s has unresolved BTF string pointer type" UNK, (long long)n, name) < 0 ? lv_oom(out, msg)
															  : BML_Q_UNKNOWN;
			else if (!args || !names || asprintf(&from, "BTF %s", fname) < 0 || compare(name, n, typ, args, names, fp.vlen, from, out))
				rc = lv_oom(out, msg);
			for (uint32_t i = 0; args && names && i < fp.vlen; i++)
				free(args[i]), free(names[i]);
			free(args), free(names), free(from), free(fname), free(err);
			bml_buf_free(&errs);
			return rc;
		}
	}
	free(err);
	char *ej = bml_buf_take(&errs);
	int r2 = asprintf(msg, "syscall %s has neither a tracefs format syscalls/sys_enter_%s (%s) nor a BTF FUNC __do_sys_%s" UNK, name, name, ej ? ej : "",
			  name);
	free(ej);
	free(fname);
	return r2 < 0 ? lv_oom(out, msg) : BML_Q_UNKNOWN;
}
