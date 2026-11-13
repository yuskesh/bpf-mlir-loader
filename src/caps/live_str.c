#include "caps/live_internal.h"
#include "btf/kernel_values.h"

#include <stdlib.h>
#include <string.h>

#include "btf/kernel.h"
#include "util/gostr.h"
#include "util/mutation.h"


static int re_space(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r';
}


static int go_space(char c)
{
	return re_space(c) || c == '\v';
}

static int ident_start(char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

static int ident(char c)
{
	return ident_start(c) || (c >= '0' && c <= '9');
}

int lv_tp_field_name(const char *d, size_t n, size_t *s, size_t *e)
{
	for (size_t i = 0; i < n; i++) {
		if (!ident_start(d[i]))
			continue;
		size_t j = i;
		while (j < n && ident(d[j]))
			j++;
		size_t k = j;
		while (k < n && re_space(d[k]))
			k++;
		if (k < n && d[k] == ')')
			k++;
		while (k < n && re_space(d[k]))
			k++;
		while (k < n && d[k] == '[') {
			size_t m = k + 1;
			while (m < n && d[m] != ']')
				m++;
			if (m == n)
				break;
			k = m + 1;
			while (k < n && re_space(d[k]))
				k++;
		}
		if (k == n) {
			*s = i, *e = j;
			return 1;
		}
	}
	return 0;
}

static int has(const char *d, size_t n, const char *w)
{
	size_t k = strlen(w);
	for (size_t i = 0; i + k <= n; i++)
		if (!memcmp(d + i, w, k))
			return 1;
	return 0;
}

static int tok_is(const char *t, size_t k, const char *w)
{
	return strlen(w) == k && !memcmp(t, w, k);
}

int lv_tp_char_depth(const char *decl, size_t n, int *depth)
{
	*depth = 0;
	while (n && go_space(*decl))
		decl++, n--;
	while (n && go_space(decl[n - 1]))
		n--;
	if (!n)
		return 0;
	if (memchr(decl, '[', n) || memchr(decl, ']', n) || has(decl, n, "__data_loc") || has(decl, n, "__rel_loc"))
		return 1;
	size_t ns, ne;
	if (!lv_tp_field_name(decl, n, &ns, &ne))
		return 0;

	int d = 0, nbase = 0, only_char = 1, all_c = 1;
	for (size_t i = 0; i < ns;) {
		if (go_space(decl[i])) {
			i++;
			continue;
		}
		if (decl[i] == '*') {
			d++, i++;
			continue;
		}
		size_t st = i;
		while (i < ns && !go_space(decl[i]) && decl[i] != '*')
			i++;
		const char *t = decl + st;
		size_t k = i - st;
		if (tok_is(t, k, "const") || tok_is(t, k, "volatile") || tok_is(t, k, "restrict"))
			continue;
		nbase++;
		if (!tok_is(t, k, "char"))
			only_char = 0;
		static const char *const c_words[] = {"void", "int", "long", "short", "signed", "unsigned", "char", "bool"};
		int c = 0;
		for (size_t w = 0; w < sizeof c_words / sizeof *c_words; w++)
			c |= tok_is(t, k, c_words[w]);
		all_c &= c;
	}
	if (nbase == 1 && only_char) {
		*depth = d;
		return 1;
	}
	return all_c && nbase > 0;
}



int lv_tp_array_shape(const char *decl, size_t n, int64_t *count, char *sign)
{
	*count = 0, *sign = 0;
	while (n && go_space(*decl))
		decl++, n--;
	while (n && go_space(decl[n - 1]))
		n--;
	if (!n)
		return 0;
	size_t nb = 0;
	for (size_t i = 0; i < n; i++)
		nb += decl[i] == '[';
	if (memchr(decl, '*', n) || memchr(decl, '(', n) || memchr(decl, ')', n) || has(decl, n, "__data_loc") || has(decl, n, "__rel_loc") || nb > 1)
		return 1;
	size_t ns, ne;
	if (!lv_tp_field_name(decl, n, &ns, &ne))
		return 0;

	char base[64];
	size_t bl = 0;
	for (size_t i = 0; i < ns;) {
		if (go_space(decl[i])) {
			i++;
			continue;
		}
		size_t st = i;
		while (i < ns && !go_space(decl[i]))
			i++;
		size_t k = i - st;
		if (tok_is(decl + st, k, "const") || tok_is(decl + st, k, "volatile"))
			continue;
		if (bl + k + 2 > sizeof base)
			return 0;
		if (bl)
			base[bl++] = ' ';
		memcpy(base + bl, decl + st, k);
		bl += k;
	}
	base[bl] = 0;
	static const char *const u[] = {"__u8", "u8", "unsigned char"}, *const s[] = {"__s8", "s8", "signed char"};
	static const char *const ints[] = {"short", "unsigned short", "signed short", "int", "unsigned int", "signed int", "long", "unsigned long",
					   "signed long", "long long", "unsigned long long", "__u16", "u16", "__s16", "s16", "__u32", "u32", "__s32",
					   "s32", "__u64", "u64", "__s64", "s64", "bool"};
	int known = !strcmp(base, "char");
	for (size_t i = 0; i < 3; i++) {
		if (!strcmp(base, u[i]))
			*sign = 'u', known = 1;
		if (!strcmp(base, s[i]))
			*sign = 'i', known = 1;
	}
	for (size_t i = 0; i < sizeof ints / sizeof *ints; i++)
		if (!strcmp(base, ints[i])) {
			*sign = 0;
			return 1;
		}
	if (!known) {
		*sign = 0;
		return 0;
	}

	const char *t = decl + ne;
	size_t tn = n - ne;
	while (tn && go_space(*t))
		t++, tn--;
	if (!tn)
		return (*sign = 0, 1);
	if (t[0] != '[' || t[tn - 1] != ']' || tn < 2)
		return (*sign = 0, 0);
	const char *v = t + 1;
	size_t vn = tn - 2;
	while (vn && go_space(*v))
		v++, vn--;
	while (vn && go_space(v[vn - 1]))
		vn--;
	int64_t c;
	if (bml_go_atoi(v, vn, &c) || c <= 0)
		return (*sign = 0, 0);
	*count = c;
	return 1;
}

int lv_sys_btf_char_depth(const struct bml_kbtf *kb, uint32_t id, int *depth)
{
	int d = 0;
	*depth = 0;
	for (int i = 0; i < 32; i++) {
		int cyc;
		uint32_t u = bml_kbtf_underlying(kb, id, &cyc);
		if (cyc)
			return 0;
		struct kbtf_type t;
		bml_kbtf_type(kb, u, &t);
		switch (t.kind) {
		case KBTF_PTR:
			d++;
			id = t.size_type;
			continue;
		case KBTF_INT:
			*depth = !strcmp(t.name, "char") && t.size_type == 1 ? d : -1;
			return 1;
		case KBTF_UNKN:
		case KBTF_STRUCT:
		case KBTF_UNION:
		case KBTF_ENUM:
		case KBTF_ENUM64:
		case KBTF_ARRAY:
		case KBTF_FUNC_PROTO:
			*depth = -1;
			return 1;
		default:
			return 0;
		}
	}
	return 0;
}

int lv_sys_char_depth(const struct bml_kbtf *kb, const char *typ, int *depth)
{

	struct bml_buf w = {0}, base = {0};
	int stars = 0;
	for (const char *p = typ; *p;) {
		if (go_space(*p)) {
			p++;
			continue;
		}
		const char *st = p;
		if (*p == '*')
			p++;
		else
			while (*p && !go_space(*p) && *p != '*')
				p++;
		size_t k = (size_t)(p - st);
		if (tok_is(st, k, "__user"))
			continue;
		if (w.len)
			bml_buf_adds(&w, " ");
		bml_buf_add(&w, st, k);
		if (*st == '*') {
			stars++;
			continue;
		}
		if (tok_is(st, k, "const") || tok_is(st, k, "volatile") || tok_is(st, k, "restrict"))
			continue;
		if (base.len)
			bml_buf_adds(&base, " ");
		bml_buf_add(&base, st, k);
	}
	char *t = bml_buf_take(&w), *b = bml_buf_take(&base);
	struct bml_buf a = {0};
	bml_buf_addf(&a, "%s argument", t ? t : "");
	char *decl = bml_buf_take(&a);
	int known = 0;
	if (decl && lv_tp_char_depth(decl, strlen(decl), depth))
		known = 1;
	else if (kb) {
		uint32_t *ids = NULL;
		size_t n = 0;
		char *err = NULL;
		if (bml_kbtf_exact_types(kb, b ? b : "", &ids, &n) == 0)
			for (size_t i = 0; i < n && !known; i++)
				if (lv_sys_btf_char_depth(kb, ids[i], depth)) {
					known = 1;
					if (*depth >= 0)
						*depth += stars;
				}
		free(ids);
		free(err);
	}
	free(t), free(b), free(decl);
	return known;
}

int lv_str_depth_ok(int depth, const char *typ)
{
	if (BML_MUT("caps.str_depth_any"))
		return depth >= 1;
	return depth == (!strcmp(typ, "strarray") ? 2 : 1);
}

int lv_is_str(const char *typ)
{
	return !strcmp(typ, "strptr") || !strcmp(typ, "strarray");
}

char *lv_str_arg(int depth, const char *typ)
{
	struct bml_buf b = {0};
	bml_buf_addf(&b, "%s%s", lv_str_depth_ok(depth, typ) ? "" : "not-", typ);
	return bml_buf_take(&b);
}
