

#include "req/usdt.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"

#define BML_SHT_NOTE 7
#define NT_STAPSDT 3

static char *fmtd(const char *f, ...) __attribute__((format(printf, 1, 2)));
static char *fmtd(const char *f, ...)
{
	va_list ap;
	va_start(ap, f);
	int k = vsnprintf(NULL, 0, f, ap);
	va_end(ap);
	char *p = k >= 0 ? malloc((size_t)k + 1) : NULL;
	if (!p)
		return NULL;
	va_start(ap, f);
	vsnprintf(p, (size_t)k + 1, f, ap);
	va_end(ap);
	return p;
}

void bml_usdt_points_free(struct bml_usdt_points *v)
{
	for (size_t i = 0; i < v->n; i++) {
		free(v->p[i].provider);
		free(v->p[i].name);
		free(v->p[i].args);
	}
	free(v->p);
	memset(v, 0, sizeof(*v));
}


static int parse_desc(const struct bml_elf *elf, const uint8_t *d, size_t len, size_t addr, struct bml_usdt_point *pt, char **err)
{
	memset(pt, 0, sizeof(*pt));
	if (len < 3 * addr) {
		*err = strdup("a stapsdt note's description is shorter than its three addresses");
		return 1;
	}
	uint64_t w[3];
	for (int i = 0; i < 3; i++)
		w[i] = addr == 4 ? bml_elf_u32(elf, d + i * 4) : bml_elf_u64(elf, d + i * 8);
	pt->pc = w[0], pt->base = w[1], pt->semaphore = w[2];
	const uint8_t *rest = d + 3 * addr;
	size_t rl = len - 3 * addr;
	char *strs[3] = {0};
	for (int i = 0; i < 3; i++) {
		size_t j = 0;
		while (j < rl && rest[j] != 0)
			j++;
		if (j == rl) {
			for (int k = 0; k < i; k++)
				free(strs[k]);
			*err = fmtd("the stapsdt note at pc 0x%llx does not end its provider, name and arguments with NUL", (unsigned long long)pt->pc);
			return 1;
		}
		strs[i] = strndup((const char *)rest, j);
		if (!strs[i]) {
			for (int k = 0; k < i; k++)
				free(strs[k]);
			return -1;
		}
		rest += j + 1;
		rl -= j + 1;
	}
	pt->provider = strs[0], pt->name = strs[1], pt->args = strs[2];
	return 0;
}

static uint64_t align4(uint64_t n)
{
	return (n + 3) & ~(uint64_t)3;
}

int bml_usdt_read_points(const struct bml_elf *elf, struct bml_usdt_points *out, char **err)
{
	memset(out, 0, sizeof(*out));
	*err = NULL;
	size_t addr = elf->is64 ? 8 : 4;
	for (size_t si = 0; si < elf->n_sections; si++) {
		const struct bml_elf_shdr *s = &elf->sections[si];
		if (s->type != BML_SHT_NOTE)
			continue;
		const uint8_t *data;
		size_t len;
		char *derr = NULL;
		if (bml_elf_section_data(elf, s, &data, &len, &derr)) {
			*err = fmtd("section %s: %s", s->name, derr ? derr : "");
			free(derr);
			return -1;
		}
		for (uint64_t p = 0; p < len;) {
			if (len - p < 12) {
				*err = fmtd("section %s: a note header is cut at offset %llu", s->name, (unsigned long long)p);
				return -1;
			}
			uint64_t namesz = bml_elf_u32(elf, data + p), descsz = bml_elf_u32(elf, data + p + 4);
			uint32_t typ = bml_elf_u32(elf, data + p + 8);
			p += 12;
			uint64_t name_end = p + namesz, desc_off = p + align4(namesz), desc_end = desc_off + descsz;
			if (name_end > len || desc_end > len) {
				*err = fmtd("section %s: a note runs past the section at offset %llu", s->name, (unsigned long long)(p - 12));
				return -1;
			}
			size_t nl = (size_t)namesz;
			while (nl > 0 && data[p + nl - 1] == 0)
				nl--;
			int stapsdt = nl == 7 && !memcmp(data + p, "stapsdt", 7) && typ == NT_STAPSDT;
			const uint8_t *desc = data + desc_off;
			p = desc_off + align4(descsz);
			if (!stapsdt)
				continue;
			struct bml_usdt_point pt;
			char *perr = NULL;
			int rc = parse_desc(elf, desc, (size_t)descsz, addr, &pt, &perr);
			if (rc) {
				*err = rc > 0 ? fmtd("section %s: %s", s->name, perr ? perr : "") : NULL;
				free(perr);
				return -1;
			}
			if (out->n == out->cap) {
				size_t nc = out->cap ? out->cap * 2 : 8;
				struct bml_usdt_point *np = realloc(out->p, nc * sizeof(*np));
				if (!np) {
					free(pt.provider), free(pt.name), free(pt.args);
					return -1;
				}
				out->p = np;
				out->cap = nc;
			}
			out->p[out->n++] = pt;
		}
	}
	return 0;
}



static const char *const x86_regs[16][4] = {
	{"rax", "eax", "ax", "al"},     {"rbx", "ebx", "bx", "bl"},     {"rcx", "ecx", "cx", "cl"},     {"rdx", "edx", "dx", "dl"},
	{"rsi", "esi", "si", "sil"},    {"rdi", "edi", "di", "dil"},    {"rbp", "ebp", "bp", "bpl"},    {"rsp", "esp", "sp", "spl"},
	{"r8", "r8d", "r8w", "r8b"},    {"r9", "r9d", "r9w", "r9b"},    {"r10", "r10d", "r10w", "r10b"}, {"r11", "r11d", "r11w", "r11b"},
	{"r12", "r12d", "r12w", "r12b"}, {"r13", "r13d", "r13w", "r13b"}, {"r14", "r14d", "r14w", "r14b"}, {"r15", "r15d", "r15w", "r15b"},
};

int bml_usdt_reg_index(const char *r)
{
	for (int i = 0; i < 16; i++)
		for (int j = 0; j < 4; j++)
			if (!strcmp(x86_regs[i][j], r))
				return i;
	return -1;
}

static int known_reg(const char *r, size_t n)
{
	for (int i = 0; i < 16; i++)
		for (int j = 0; j < 4; j++)
			if (strlen(x86_regs[i][j]) == n && !memcmp(x86_regs[i][j], r, n))
				return 1;
	return 0;
}

static int lower(int c)
{
	return c | ('x' - 'X');
}


static int underscore_ok(const char *s, size_t n)
{
	char saw = '^';
	size_t i = 0;
	if (n >= 1 && (s[0] == '-' || s[0] == '+'))
		s++, n--;
	int hex = 0;
	if (n >= 2 && s[0] == '0' && (lower(s[1]) == 'b' || lower(s[1]) == 'o' || lower(s[1]) == 'x')) {
		i = 2;
		saw = '0';
		hex = lower(s[1]) == 'x';
	}
	for (; i < n; i++) {
		if ((s[i] >= '0' && s[i] <= '9') || (hex && lower(s[i]) >= 'a' && lower(s[i]) <= 'f')) {
			saw = '0';
			continue;
		}
		if (s[i] == '_') {
			if (saw != '0')
				return 0;
			saw = '_';
			continue;
		}
		if (saw == '_')
			return 0;
		saw = '!';
	}
	return saw != '_';
}



static int parse_int0(const char *s0, size_t n0, int64_t *out)
{
	const char *s = s0;
	size_t n = n0;
	*out = 0;
	if (n == 0)
		return -1;
	int neg = 0;
	if (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-';
		s++, n--;
	}
	if (n == 0)
		return -1;
	unsigned base = 10;
	if (s[0] == '0') {
		if (n >= 3 && lower(s[1]) == 'b')
			base = 2, s += 2, n -= 2;
		else if (n >= 3 && lower(s[1]) == 'o')
			base = 8, s += 2, n -= 2;
		else if (n >= 3 && lower(s[1]) == 'x')
			base = 16, s += 2, n -= 2;
		else
			base = 8, s++, n--;
	}
	uint64_t v = 0;
	int unders = 0;
	for (size_t i = 0; i < n; i++) {
		unsigned c = (unsigned char)s[i], d;
		if (c == '_') {
			unders = 1;
			continue;
		}
		if (c >= '0' && c <= '9')
			d = c - '0';
		else if (lower((int)c) >= 'a' && lower((int)c) <= 'z')
			d = (unsigned)lower((int)c) - 'a' + 10;
		else
			return -1;
		if (d >= base)
			return -1;
		if (v > (UINT64_MAX - d) / base) {
			*out = neg ? INT64_MIN : INT64_MAX;
			return -2;
		}
		v = v * base + d;
	}
	if (unders && !underscore_ok(s0 + (s0[0] == '+' || s0[0] == '-'), n0 - (s0[0] == '+' || s0[0] == '-')))
		return -1;
	uint64_t cutoff = (uint64_t)1 << 63;
	if ((!neg && v >= cutoff) || (neg && v > cutoff)) {
		*out = neg ? INT64_MIN : INT64_MAX;
		return -2;
	}
	*out = neg ? (int64_t)(0 - v) : (int64_t)v;
	return 0;
}


static char *arg_err(const char *s, size_t n, const char *tail)
{
	struct bml_buf b = {0};
	bml_buf_adds(&b, "argument ");
	bml_buf_add_goquote(&b, s, n);
	bml_buf_adds(&b, tail);
	return bml_buf_take(&b);
}

static int set_reg(struct bml_usdt_arg *spec, const char *s, size_t n, const char *r, size_t rn, char **err)
{
	if (!known_reg(r, rn)) {
		struct bml_buf b = {0};
		bml_buf_adds(&b, "argument ");
		bml_buf_add_goquote(&b, s, n);
		bml_buf_adds(&b, " names register %");
		bml_buf_add(&b, r, rn);
		bml_buf_adds(&b, ", which the loader does not read (x86_64 general purpose registers only)");
		*err = bml_buf_take(&b);
		return *err ? 0 : -1;
	}
	memcpy(spec->reg, r, rn);
	spec->reg[rn] = 0;
	return 0;
}

static const char *find(const char *s, size_t n, const char *pat, size_t pn)
{
	if (pn > n)
		return NULL;
	for (size_t i = 0; i + pn <= n; i++)
		if (!memcmp(s + i, pat, pn))
			return s + i;
	return NULL;
}

int bml_usdt_parse_arg(const char *s, size_t n, struct bml_usdt_arg *spec, int *size_ok, char **err)
{
	memset(spec, 0, sizeof(*spec));
	spec->kind = "";
	*size_ok = 0;
	*err = NULL;
	const char *at = memchr(s, '@', n);
	if (!at) {
		*err = arg_err(s, n, " has no <size>@ (an old note format)");
		return *err ? 0 : -1;
	}
	int64_t sz;
	if (bml_go_atoi(s, (size_t)(at - s), &sz) || sz == 0) {
		*err = arg_err(s, n, " has a size this check cannot read");
		return *err ? 0 : -1;
	}
	if (sz < 0) {
		spec->is_signed = 1;
		if (sz != INT64_MIN)
			sz = -sz;
	}
	if (sz != 1 && sz != 2 && sz != 4 && sz != 8) {
		char t[64];
		snprintf(t, sizeof t, " has size %lld (want 1, 2, 4 or 8)", (long long)sz);
		*err = arg_err(s, n, t);
		return *err ? 0 : -1;
	}
	spec->size = (int)sz;
	*size_ok = 1;
	const char *loc = at + 1;
	size_t ln = n - (size_t)(loc - s);
	if (ln > 0 && loc[0] == '%') {
		spec->kind = "reg";
		return set_reg(spec, s, n, loc + 1, ln - 1, err);
	}
	if (ln > 0 && loc[0] == '$') {
		spec->kind = "const";
		if (parse_int0(loc + 1, ln - 1, &spec->off)) {
			*err = arg_err(s, n, " has a constant this check cannot read");
			return *err ? 0 : -1;
		}
		return 0;
	}
	if (ln > 0 && loc[ln - 1] == ')' && find(loc, ln, "(%", 2)) {
		const char *p = find(loc, ln - 1, "(%", 2);
		size_t offn = p ? (size_t)(p - loc) : ln - 1;
		const char *inner = p ? p + 2 : loc + ln - 1;
		size_t inn = p ? (size_t)(loc + ln - 1 - inner) : 0;
		if (memchr(inner, ',', inn)) {
			*err = arg_err(s, n, " is a SIB memory operand (base, index, scale), which the loader does not read in v1");
			return *err ? 0 : -1;
		}
		spec->kind = "deref";
		if (offn > 0 && parse_int0(loc, offn, &spec->off)) {
			*err = arg_err(s, n, " has an offset this check cannot read");
			return *err ? 0 : -1;
		}
		return set_reg(spec, s, n, inner, inn, err);
	}
	*err = arg_err(s, n, " has a place this check cannot read");
	return *err ? 0 : -1;
}


static size_t space_at(const unsigned char *s, size_t n)
{
	unsigned c = s[0];
	if (c == ' ' || (c >= '\t' && c <= '\r'))
		return 1;
	if (n >= 2 && c == 0xc2 && (s[1] == 0x85 || s[1] == 0xa0))
		return 2;
	if (n < 3)
		return 0;
	if (c == 0xe1 && s[1] == 0x9a && s[2] == 0x80)
		return 3;
	if (c == 0xe2 && s[1] == 0x80 && ((s[2] >= 0x80 && s[2] <= 0x8a) || s[2] == 0xa8 || s[2] == 0xa9 || s[2] == 0xaf))
		return 3;
	if (c == 0xe2 && s[1] == 0x81 && s[2] == 0x9f)
		return 3;
	if (c == 0xe3 && s[1] == 0x80 && s[2] == 0x80)
		return 3;
	return 0;
}

int bml_go_fields(const char *s, size_t n, size_t **starts, size_t **lens, size_t *count)
{
	*starts = NULL, *lens = NULL, *count = 0;
	size_t cap = 0, i = 0;
	while (i < n) {
		size_t w;
		while (i < n && (w = space_at((const unsigned char *)s + i, n - i)) > 0)
			i += w;
		if (i >= n)
			break;
		size_t st = i;
		while (i < n && space_at((const unsigned char *)s + i, n - i) == 0)
			i++;
		if (*count == cap) {
			cap = cap ? cap * 2 : 8;
			size_t *ns = realloc(*starts, cap * sizeof(size_t)), *nl;
			if (!ns)
				goto oom;
			*starts = ns;
			nl = realloc(*lens, cap * sizeof(size_t));
			if (!nl)
				goto oom;
			*lens = nl;
		}
		(*starts)[*count] = st;
		(*lens)[*count] = i - st;
		(*count)++;
	}
	return 0;
oom:
	free(*starts), free(*lens);
	*starts = NULL, *lens = NULL, *count = 0;
	return -1;
}
