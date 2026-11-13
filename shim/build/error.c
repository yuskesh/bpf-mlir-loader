#include "shim/build/internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "req/uprobe.h"
#include "util/gostr.h"
#include "util/mutation.h"

void bml_build_error_free(struct bml_build_error *err)
{
	if (!err)
		return;
	free(err->text);
	free(err->detail);
	bb_init(err);
}

void bml_build_strs_free(char **names, size_t n)
{
	for (size_t i = 0; names && i < n; i++)
		free(names[i]);
	free(names);
}

void bml_build_sha256_hex(const void *data, size_t len, char out[65])
{
	bml_sha256_hex(data ? data : "", len, out);
	if (BML_MUT("build.sha_flip")) {
		unsigned v = (unsigned)(out[1] <= '9' ? out[1] - '0' : out[1] - 'a' + 10) ^ 1u;
		out[1] = "0123456789abcdef"[v];
	}
}

void bml_build_sha256(const void *data, size_t len, unsigned char out[32])
{
	char hex[65];
	bml_build_sha256_hex(data, len, hex);
	for (int i = 0; i < 32; i++) {
		unsigned hi = (unsigned)hex[2 * i], lo = (unsigned)hex[2 * i + 1];
		hi = hi <= '9' ? hi - '0' : hi - 'a' + 10;
		lo = lo <= '9' ? lo - '0' : lo - 'a' + 10;
		out[i] = (unsigned char)(hi << 4 | lo);
	}
}





static size_t utf8_seq(const unsigned char *s, size_t n)
{
	unsigned c = s[0];
	size_t k;
	uint32_t cp, min;
	if (c >= 0xc2 && c <= 0xdf)
		k = 2, cp = c & 0x1f, min = 0x80;
	else if (c >= 0xe0 && c <= 0xef)
		k = 3, cp = c & 0x0f, min = 0x800;
	else if (c >= 0xf0 && c <= 0xf4)
		k = 4, cp = c & 0x07, min = 0x10000;
	else
		return 0;
	if (n < k)
		return 0;
	for (size_t i = 1; i < k; i++) {
		if ((s[i] & 0xc0) != 0x80)
			return 0;
		cp = (cp << 6) | (s[i] & 0x3f);
	}
	return cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) ? 0 : k;
}

char *bml_build_json_string(const char *s, size_t n, int html, size_t *out_len)
{
	static const char hexd[] = "0123456789abcdef";
	const unsigned char *u = (const unsigned char *)(s ? s : "");
	struct bml_buf b = {0};
	if (BML_MUT("build.string_no_html"))
		html = 0;
	bml_buf_add(&b, "\"", 1);
	for (size_t i = 0; i < n;) {
		unsigned c = u[i];
		if (c < 0x80) {
			const char *e = NULL;
			switch (c) {
			case '"': e = "\\\""; break;
			case '\\': e = "\\\\"; break;
			case '\b': e = "\\b"; break;
			case '\f': e = "\\f"; break;
			case '\n': e = "\\n"; break;
			case '\r': e = "\\r"; break;
			case '\t': e = "\\t"; break;
			}
			if (e) {
				bml_buf_adds(&b, e);
			} else if (c < 0x20 || (html && (c == '<' || c == '>' || c == '&'))) {
				char t[6] = {'\\', 'u', '0', '0', hexd[c >> 4], hexd[c & 15]};
				bml_buf_add(&b, t, 6);
			} else {
				bml_buf_add(&b, (const char *)u + i, 1);
			}
			i++;
			continue;
		}
		size_t k = utf8_seq(u + i, n - i);
		if (!k) {
			bml_buf_add(&b, "\xef\xbf\xbd", 3);
			i++;
		} else if (k == 3 && c == 0xe2 && u[i + 1] == 0x80 && (u[i + 2] == 0xa8 || u[i + 2] == 0xa9)) {
			bml_buf_adds(&b, u[i + 2] == 0xa8 ? "\\u2028" : "\\u2029");
			i += 3;
		} else {
			bml_buf_add(&b, (const char *)u + i, k);
			i += k;
		}
	}
	bml_buf_add(&b, "\"", 1);
	size_t len = b.len;
	char *r = bml_buf_take(&b);
	if (r && out_len)
		*out_len = len;
	return r;
}
