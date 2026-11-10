
#include "abi/rejected.h"

#include <string.h>

static int digit(unsigned char c) { return c >= '0' && c <= '9'; }
static int name_byte(unsigned char c)
{ return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || digit(c) || c == '_' || c == '.' || c == '/' || c == '-'; }


static int blank(const char *p, size_t n)
{
	for (size_t i = 0; i < n;) {
		unsigned char c = (unsigned char)p[i];
		if (c == ' ' || (c >= '\t' && c <= '\r')) { i++; continue; }
		if (n - i >= 2 && c == 0xc2 && ((unsigned char)p[i + 1] == 0x85 || (unsigned char)p[i + 1] == 0xa0)) { i += 2; continue; }
		if (n - i >= 3) {
			unsigned char b = (unsigned char)p[i + 1], d = (unsigned char)p[i + 2];
			if ((c == 0xe1 && b == 0x9a && d == 0x80) ||
			    (c == 0xe2 && b == 0x80 && ((d >= 0x80 && d <= 0x8a) || d == 0xa8 || d == 0xa9 || d == 0xaf)) ||
			    (c == 0xe2 && b == 0x81 && d == 0x9f) || (c == 0xe3 && b == 0x80 && d == 0x80)) { i += 3; continue; }
		}
		return 0;
	}
	return 1;
}

static int instruction(const char *p, size_t n)
{
	size_t i = 0; while (i < n && digit((unsigned char)p[i])) i++;
	return i && n - i >= 3 && !memcmp(p + i, ": (", 3);
}

static int summary(const char *p, size_t n)
{
	if (n < 17 || memcmp(p, "processed ", 10)) return 0;
	size_t i = 10; while (i < n && digit((unsigned char)p[i])) i++;
	return i > 10 && n - i >= 6 && !memcmp(p + i, " insns", 6);
}

static size_t position(const char *p, size_t n)
{
	size_t i = 0; while (i < n && name_byte((unsigned char)p[i])) i++;
	if (!i || i == n || p[i++] != ':' || i == n || p[i] < '1' || p[i] > '9') return 0;
	while (i < n && digit((unsigned char)p[i])) i++;
	return i;
}

int bml_rejected_at(const char *log, size_t n, char *out, size_t cap)
{
	if (out && cap) out[0] = 0;
	if (!log || !out || !cap) return 0;
	const char *end_line = NULL, *nearest = NULL, *chosen = NULL;
	size_t end_n = 0, nearest_n = 0, chosen_n = 0;

	for (size_t i = 0; i < n;) {
		const char *p = log + i, *nl = memchr(p, '\n', n - i);
		size_t len = nl ? (size_t)(nl - p) : n - i;
		if (!blank(p, len)) { end_line = p; end_n = len; }
		i += len + !!nl;
	}
	if (!end_line || !summary(end_line, end_n)) return 0;
	for (const char *p = log; p < end_line;) {
		const char *nl = memchr(p, '\n', (size_t)(end_line - p));
		size_t len = nl ? (size_t)(nl - p) : (size_t)(end_line - p);
		if (instruction(p, len)) { chosen = nearest; chosen_n = nearest_n; }
		if (len && p[0] == ';') { nearest = p; nearest_n = len; }
		p += len + !!nl;
	}
	if (!chosen || chosen_n < 3 || memcmp(chosen, "; ", 2)) return 0;
	const char *p = chosen + 2; size_t len = chosen_n - 2;
	size_t at = position(p, len);
	if (!at) return 0;
	if (at != len && (len - at != at + 3 || memcmp(p + at, " @ ", 3) || memcmp(p, p + at + 3, at))) return 0;
	if (at >= cap) return 0;
	memcpy(out, p, at); out[at] = 0; return 1;
}
