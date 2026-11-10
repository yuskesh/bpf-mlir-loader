
#include "json/internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static void write_string(struct bml_buf *b, const char *s, size_t n, int html);

void bml_json_write_string(struct bml_buf *b, const char *s, size_t n)
{
	write_string(b, s, n, 0);
}

void bml_json_write_string_html(struct bml_buf *b, const char *s, size_t n)
{
	write_string(b, s, n, 1);
}

static void write_string(struct bml_buf *b, const char *s, size_t n, int html)
{
	static const char hexd[] = "0123456789abcdef";
	const unsigned char *u = (const unsigned char *)s;
	bml_buf_add(b, "\"", 1);
	for (size_t i = 0; i < n;) {
		unsigned c = u[i];
		if (c < 0x80) {
			if (c == '"' || c == '\\') {
				char t[2] = {'\\', (char)c};
				bml_buf_add(b, t, 2);
			} else if (c == '\n') {
				bml_buf_adds(b, "\\n");
			} else if (c == '\r') {
				bml_buf_adds(b, "\\r");
			} else if (c == '\t') {
				bml_buf_adds(b, "\\t");
			} else if (c < 0x20 || (html && (c == '<' || c == '>' || c == '&'))) {
				char t[6] = {'\\', 'u', '0', '0', hexd[c >> 4], hexd[c & 15]};
				bml_buf_add(b, t, 6);
			} else {
				bml_buf_add(b, s + i, 1);
			}
			i++;
			continue;
		}
		size_t k = json_utf8_seq(u + i, n - i);
		if (!k) {
			bml_buf_adds(b, "\\ufffd");
			i++;
			continue;
		}
		if (k == 3 && u[i] == 0xe2 && u[i + 1] == 0x80 && (u[i + 2] == 0xa8 || u[i + 2] == 0xa9)) {
			bml_buf_adds(b, u[i + 2] == 0xa8 ? "\\u2028" : "\\u2029");
		} else {
			bml_buf_add(b, s + i, k);
		}
		i += k;
	}
	bml_buf_add(b, "\"", 1);
}
