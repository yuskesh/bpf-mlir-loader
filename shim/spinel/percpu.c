#include "shim/spinel/internal.h"

#include <stdlib.h>
#include <string.h>

#include "bml/bml.h"
#include "maps/mapdecl.h"
#include "shim/spinel/spinelbpf.h"

#define S(x) (x), (int64_t)((x) ? strlen(x) : 0)
#define U26 ((int64_t)1 << 26)

int64_t spinelbpf_possible_cpus(void)
{
	return bml_possible_cpus();
}


static void sizes(int64_t obj, const char *name, int64_t *ncpu, int64_t *vlen)
{
	int64_t r = bml_possible_cpus();
	*ncpu = bml_result_kind(r) == BML_OK ? bml_result_value(r) : 0;
	bml_result_free(r);
	r = bml_map_describe(obj, S(name));
	*vlen = bml_result_kind(r) == BML_OK ? bml_result_value(r) : 0;
	bml_result_free(r);
}


static int64_t percpu_kind(const struct bml_map_decl *d)
{
	if (!strcmp(d->kind, "percpu_array") || !strcmp(d->kind, "percpu_hash"))
		return 0;
	return sh_result(BML_MAP_MISMATCH, 0, "spinelbpf: map %s is declared \"%s\" — the percpu API is for percpu_array / percpu_hash maps", d->name, d->kind);
}

int64_t spinelbpf_percpu_get(int64_t obj, char *decl, int64_t *key, int64_t klen, int64_t *out, int64_t n)
{
	struct bml_map_decl d;
	int64_t e = sh_parse_decl(decl, &d);
	if (e)
		return e;
	uint8_t *k = sh_hash_bytes(key, klen, "key", &e);
	if (!k) {
		bml_map_decl_free(&d);
		return e;
	}
	int64_t r;
	if (n <= 0 || n > U26)
		r = sh_result(BML_OTHER, 0, "spinelbpf: per-CPU value size %lld is outside 1..2^26", (long long)n);
	else if ((r = percpu_kind(&d)) == 0) {
		int64_t ncpu, vlen;
		sizes(obj, d.name, &ncpu, &vlen);
		int64_t stride = (vlen + 7) / 8 * 8;
		uint8_t *b = calloc((size_t)(ncpu > 0 && vlen > 0 ? ncpu * vlen : 1), 1);
		r = b ? bml_percpu_get(obj, S(decl), NULL, 0, NULL, 0, k, klen, vlen, b, ncpu * vlen) : sh_result(BML_OTHER, 0, "spinelbpf: out of memory");
		if (b && bml_result_kind(r) == BML_OK) {
			bml_result_free(r);
			if (n != ncpu * stride)
				r = sh_result(BML_MAP_MISMATCH, 0, "spinelbpf: the per-CPU value of %s is %lld bytes but the caller expects %lld — rebuild with spinelbpf build",
					      d.name, (long long)(ncpu * stride), (long long)n);
			else {
				for (int64_t c = 0; c < ncpu; c++)
					for (int64_t i = 0; i < stride; i++)
						out[c * stride + i] = i < vlen ? b[c * vlen + i] : 0;
				r = sh_result(BML_OK, stride, "%s", "");
			}
		}
		free(b);
	}
	bml_map_decl_free(&d);
	free(k);
	return r;
}

int64_t spinelbpf_percpu_put(int64_t obj, char *decl, int64_t *key, int64_t klen, int64_t *vals, int64_t n)
{
	struct bml_map_decl d;
	int64_t e = sh_parse_decl(decl, &d);
	if (e)
		return e;
	uint8_t *k = sh_hash_bytes(key, klen, "key", &e), *v = NULL;
	int64_t r = e;
	if (k && n > U26)
		r = sh_result(BML_OTHER, 0, "spinelbpf: per-CPU value size %lld is outside 1..2^26", (long long)n);
	else if (k && (v = sh_hash_bytes(vals, n, "value", &e)) == NULL)
		r = e;
	else if (k && (r = percpu_kind(&d)) == 0) {
		int64_t ncpu, vlen;
		sizes(obj, d.name, &ncpu, &vlen);
		r = bml_percpu_put(obj, S(decl), NULL, 0, NULL, 0, k, klen, vlen, v, n);
		if (bml_result_kind(r) == BML_OTHER) {
			struct sh_res x = sh_take(r);
			if (n != ncpu * vlen && vlen > 0)
				r = sh_result(BML_MAP_MISMATCH, 0, "spinelbpf: %s: %lld bytes of per-CPU values, want %lld CPUs × %lld bytes", d.name, (long long)n,
					      (long long)ncpu, (long long)vlen);
			else if (x.msg && strstr(x.msg, "argument list too long"))
				r = sh_result(BML_OTHER, 0, "spinelbpf: update %s: E2BIG — map is full (%llu entries): %s", d.name, (unsigned long long)d.max_entries,
					      x.msg);
			else
				r = sh_result(x.kind, x.value, "%s", x.msg ? x.msg : "");
			sh_res_free(&x);
		}
	}
	bml_map_decl_free(&d);
	free(k);
	free(v);
	return r;
}
