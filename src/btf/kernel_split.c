#include "btf/kernel.h"

#include <stdlib.h>
#include <string.h>

static void put32(uint8_t *p, uint32_t v, int be)
{
	for (size_t i = 0; i < 4; i++) p[be ? 3 - i : i] = (uint8_t)(v >> (8 * i));
}

int bml_kbtf_from_split_raw(uint8_t *raw, size_t len, const struct bml_kbtf *base,
	struct bml_kbtf *out, char **err)
{
	*err = NULL;
	memset(out, 0, sizeof(*out));
	if (!base || !base->raw || len < 24 || raw[2] != 1 || raw[3] ||
	    raw[0] != base->raw[0] || raw[1] != base->raw[1]) goto bad_header;
	uint32_t hdr = bml_kbtf_u32(base, raw + 4);
	if (hdr < 24 || hdr > len) goto bad_header;
	for (size_t i = hdr >= 32 ? 32 : 24; i < hdr; i++)
		if (raw[i]) goto bad_header;
	uint32_t to = bml_kbtf_u32(base, raw + 8), tn = bml_kbtf_u32(base, raw + 12);
	uint32_t so = bml_kbtf_u32(base, raw + 16), sn = bml_kbtf_u32(base, raw + 20);
	if ((uint64_t)to + tn > len - hdr || (uint64_t)so + sn > len - hdr ||
	    tn > UINT32_MAX - base->types_len || sn > UINT32_MAX - base->strs_len) goto bad_bounds;
	uint32_t types = base->types_len + tn, strings = base->strs_len + sn;
	uint64_t total = UINT64_C(24) + types + strings;
	if (total > SIZE_MAX) goto bad_bounds;
	uint8_t *merged = calloc(1, (size_t)total);
	if (!merged) { *err = strdup("out of memory"); free(raw); return -1; }
	merged[0] = raw[0]; merged[1] = raw[1]; merged[2] = 1;
	put32(merged + 4, 24, base->be); put32(merged + 12, types, base->be);
	put32(merged + 16, types, base->be); put32(merged + 20, strings, base->be);
	memcpy(merged + 24, base->types, base->types_len);
	memcpy(merged + 24 + base->types_len, raw + hdr + to, tn);
	memcpy(merged + 24 + types, base->strs, base->strs_len);
	memcpy(merged + 24 + types + base->strs_len, raw + hdr + so, sn);
	free(raw);
	return bml_kbtf_from_raw(merged, (size_t)total, out, err);
bad_header:
	*err = strdup("parsing split .BTF header: invalid header or base byte order"); free(raw); return -1;
bad_bounds:
	*err = strdup("split BTF section is out of bounds"); free(raw); return -1;
}
