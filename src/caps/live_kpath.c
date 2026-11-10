

#include "caps/live_internal.h"

#include <stdlib.h>
#include <string.h>

#include "btf/kernel.h"
#include "util/gostr.h"
#include "util/mutation.h"







static int find_member(const struct bml_kbtf *kb, uint32_t struct_id, const char *name, struct kbtf_member *out, int *twice)
{
	uint32_t *q = malloc(sizeof *q * 16);
	uint8_t *seen = calloc((size_t)kb->n + 2, 1);
	size_t head = 0, tail = 0, cap = 16;
	*twice = 0;
	if (!q || !seen) {
		free(q);
		free(seen);
		return -1;
	}
	if (struct_id <= kb->n)
		seen[struct_id] = 1;
	q[tail++] = struct_id;
	int rc = 0;
	while (head < tail && !rc) {
		struct kbtf_type t;
		bml_kbtf_type(kb, q[head++], &t);
		for (uint32_t j = 0; j < t.vlen && !rc; j++) {
			struct kbtf_member m;
			bml_kbtf_member(kb, &t, j, &m);
			if (strcmp(m.name, name) == 0) {
				*out = m;
				rc = 1;
				break;
			}
			if (m.name[0] || BML_MUT("live.kfields_direct_only"))
				continue;
			int cyc;
			uint32_t u = bml_kbtf_underlying(kb, m.type, &cyc);
			struct kbtf_type ut;
			bml_kbtf_type(kb, u, &ut);
			if (cyc || (ut.kind != KBTF_STRUCT && ut.kind != KBTF_UNION))
				continue;
			if (u <= kb->n && seen[u] && !BML_MUT("live.no_member_seen")) {
				*twice = 1;
				continue;
			}
			if (u <= kb->n)
				seen[u] = 1;
			if (tail == cap) {
				uint32_t *nq = realloc(q, sizeof *q * (cap *= 2));
				if (!nq) {
					rc = -1;
					break;
				}
				q = nq;
			}
			q[tail++] = u;
		}
	}
	free(q);
	free(seen);
	return rc;
}



int lv_find_member_path(const struct bml_kbtf *kb, uint32_t struct_id, const char *path, struct kbtf_member *out, int *twice)
{
	*twice = 0;
	if (BML_MUT("caps.kpath_leaf_only") && strrchr(path, '.'))
		path = strrchr(path, '.') + 1;
	uint32_t st = struct_id;
	for (const char *p = path;;) {
		const char *dot = strchr(p, '.');
		size_t n = dot ? (size_t)(dot - p) : strlen(p);
		char *part = strndup(p, n);
		if (!part)
			return -1;
		int seen = 0, rc = find_member(kb, st, part, out, &seen);
		free(part);
		*twice |= seen;
		if (rc <= 0 || !dot)
			return rc;
		int cyc;
		uint32_t u = bml_kbtf_underlying(kb, out->type, &cyc);
		struct kbtf_type ut;
		bml_kbtf_type(kb, u, &ut);
		if (cyc || ut.kind != KBTF_STRUCT)
			return 0;
		st = u;
		p = dot + 1;
	}
}


int lv_kfield_embedded(const struct bml_kbtf *kb, const struct kbtf_member *mb, const char *name, struct bml_buf *b)
{
	int cyc;
	struct kbtf_type t;
	bml_kbtf_type(kb, bml_kbtf_underlying(kb, mb->type, &cyc), &t);
	if (!cyc && t.kind == KBTF_STRUCT && !strcmp(t.name, name) && mb->bitfield_size == 0)
		return 0;
	bml_buf_adds(b, "the target field is ");
	bml_kbtf_format(kb, b, mb->type, 0, 's');
	bml_buf_addf(b, ", not embedded struct %s", name);
	return 1;
}
