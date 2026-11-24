/* json/goscan.h — Go's strict JSON scan with Go's own error texts, and the float64 range of `any` numbers. It serves the
 * build-time exports; the product's checks do not use it. */
#ifndef BML_JSON_GOSCAN_H
#define BML_JSON_GOSCAN_H

#include <stddef.h>
#include <stdint.h>

#include "json/json.h"

/* CONTRACT: Go's requirements.JSONError parts — rule (a static Go rule name), offset (Go's byte position) and detail (malloc).
 * nomem is set (and detail may be NULL) when memory ran out; the scan result is then not Go's. */
struct bml_json_goerr {
	const char *rule;
	int64_t offset;
	char *detail;
	int nomem;
	int key_quote; /* the detail quotes a key that bml_json_go_key_quotable refuses: not Go's text (json-key-quote) */
};

/* 1 when Go's %q of k is bml_buf_add_goquote's: k's non-ASCII characters are only U+212A and U+017F (both printable, so Go
 * writes them raw). Any other non-ASCII character gives 0: bml has no copy of Go's printable table. */
static inline int bml_json_go_key_quotable(const char *k)
{
	for (const unsigned char *p = (const unsigned char *)k; *p;) {
		if (*p < 0x80)
			p++;
		else if (p[0] == 0xe2 && p[1] == 0x84 && p[2] == 0xaa)
			p += 3;
		else if (p[0] == 0xc5 && p[1] == 0xbf)
			p += 2;
		else
			return 0;
	}
	return 1;
}

/* scanStrictJSON(data, v) with v's type given as desc (NULL: Go's `any`). 0 when the scan passes, -1 and *e otherwise
 * (bml_json_goerr_free). */
int bml_json_go_scan(const char *data, size_t len, const struct bml_json_desc *desc, struct bml_json_goerr *e);
void bml_json_goerr_free(struct bml_json_goerr *e);

/* 1 and *spelling (the number as written, inside j) for the first number out of the float64 range, 0 for none, -1 when the C
 * locale cannot be made. */
int bml_json_float64_range(const struct bml_json *j, const char **spelling);

#endif
