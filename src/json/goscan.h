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
	int key_quote;
};



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



int bml_json_go_scan(const char *data, size_t len, const struct bml_json_desc *desc, struct bml_json_goerr *e);
void bml_json_goerr_free(struct bml_json_goerr *e);



int bml_json_float64_range(const struct bml_json *j, const char **spelling);

#endif
