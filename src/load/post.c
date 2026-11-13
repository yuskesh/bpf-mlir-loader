#include "load/internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "util/mutation.h"

int lb_capture_maps(struct bpf_object *obj, struct lb_map_def **defs, size_t *n)
{
	struct bpf_map *m;
	size_t cnt = 0;
	*defs = NULL;
	*n = 0;
	bpf_object__for_each_map(m, obj)
		cnt++;
	if (!cnt)
		return 0;
	struct lb_map_def *d = calloc(cnt, sizeof *d);
	if (!d)
		return -1;
	size_t i = 0;
	bpf_object__for_each_map(m, obj) {
		d[i].name = strdup(bpf_map__name(m));
		d[i].key_id = bpf_map__btf_key_type_id(m);
		d[i].value_id = bpf_map__btf_value_type_id(m);
		d[i].flags = bpf_map__map_flags(m);
		if (!d[i].name) {
			lb_free_maps(d, i);
			return -1;
		}
		i++;
	}
	*defs = d;
	*n = cnt;
	return 0;
}

void lb_free_maps(struct lb_map_def *defs, size_t n)
{
	for (size_t i = 0; i < n; i++)
		free(defs[i].name);
	free(defs);
}


static int btf_readback(int fd, uint8_t **out, uint32_t *len, uint32_t *id)
{
	struct bpf_btf_info info;
	uint32_t l = sizeof info;
	memset(&info, 0, sizeof info);
	if (bpf_btf_get_info_by_fd(fd, &info, &l) != 0)
		return -1;
	uint32_t sz = info.btf_size;
	uint8_t *buf = malloc(sz ? sz : 1);
	if (!buf)
		return -1;
	memset(&info, 0, sizeof info);
	info.btf = (uint64_t)(uintptr_t)buf;
	info.btf_size = sz;
	l = sizeof info;
	if (bpf_btf_get_info_by_fd(fd, &info, &l) != 0 || info.btf_size != sz) {
		free(buf);
		return -1;
	}
	*out = buf;
	*len = sz;
	*id = info.id;
	return 0;
}





static int ext_info_subseq(int fd, struct bpf_program *p, const struct bpf_prog_info *pi, char *why, size_t cap)
{
	uint32_t ofi = bpf_program__func_info_cnt(p), oli = bpf_program__line_info_cnt(p);
	const struct bpf_func_info *of = bpf_program__func_info(p);
	const struct bpf_line_info *ol = bpf_program__line_info(p);
	uint32_t kfi = pi->nr_func_info, kli = pi->nr_line_info;
	if (BML_MUT("load.ext_info_exact"))
		return kfi == ofi && kli == oli ? 0 : (snprintf(why, cap, "the counts differ"), 1);
	if (BML_MUT("load.linfo_kernel_zero"))
		kli = 0;
	if (kfi > ofi || kli > oli || (ofi && !kfi) || (oli && !kli)) {
		snprintf(why, cap, "the counts are not a non-empty part of the object's");
		return 1;
	}
	struct bpf_func_info *kf = calloc(kfi ? kfi : 1, sizeof *kf);
	struct bpf_line_info *kl = calloc(kli ? kli : 1, sizeof *kl);
	struct bpf_prog_info q;
	uint32_t l = sizeof q;
	memset(&q, 0, sizeof q);
	q.nr_func_info = kfi;
	q.func_info_rec_size = sizeof *kf;
	q.func_info = (uint64_t)(uintptr_t)kf;
	q.nr_line_info = kli;
	q.line_info_rec_size = sizeof *kl;
	q.line_info = (uint64_t)(uintptr_t)kl;
	int rc = kf && kl ? bpf_prog_get_info_by_fd(fd, &q, &l) : (errno = ENOMEM, -1);
	if (rc != 0) {
		rc = -errno;
		goto out;
	}
	if (kli && BML_MUT("load.linfo_kernel_bad"))
		kl[kli - 1].line_off ^= 1;

	uint32_t j = 0;
	for (uint32_t i = 0; i < kfi; i++) {
		while (j < ofi && of[j].type_id != kf[i].type_id)
			j++;
		if (j++ >= ofi) {
			snprintf(why, cap, "the kernel's func_info %u (type %u) is not in the object's order", i, kf[i].type_id);
			rc = 1;
			goto out;
		}
	}
	j = 0;
	for (uint32_t i = 0; i < kli; i++) {
		while (j < oli && (ol[j].file_name_off != kl[i].file_name_off || ol[j].line_off != kl[i].line_off || ol[j].line_col != kl[i].line_col))
			j++;
		if (j++ >= oli) {
			snprintf(why, cap, "the kernel's line_info %u (line %u col %u) is not in the object's order", i, kl[i].line_col >> 10,
				 kl[i].line_col & 0x3ff);
			rc = 1;
			goto out;
		}
	}
	rc = 0;
out:
	free(kf);
	free(kl);
	return rc;
}

int lb_check_loaded(struct bpf_object *obj, const struct lb_map_def *defs, size_t n, struct bml_load_result *r)
{
	struct btf *btf = bpf_object__btf(obj);
	if (!btf)
		return lb_fail(r, BML_LOAD_BTF_DROPPED, "the object has no BTF");
	int fd = btf__fd(btf);
	if (fd < 0)
		return lb_fail(r, BML_LOAD_BTF_DROPPED, "libbpf did not load the BTF into the kernel (it drops the whole BTF when the kernel rejects it — B2)");
	uint32_t osz = 0, ksz = 0, kid = 0;
	const void *orig = btf__raw_data(btf, &osz);
	uint8_t *kb = NULL;
	if (!orig || btf_readback(fd, &kb, &ksz, &kid) != 0)
		return lb_fail(r, BML_LOAD_BTF_CHANGED, "the BTF in the kernel cannot be read back (%s)", lb_errno(errno));
	int same = ksz == osz && memcmp(kb, orig, osz) == 0;
	free(kb);
	if (!same)
		return lb_fail(r, BML_LOAD_BTF_CHANGED,
			       "the BTF in the kernel (%u bytes) differs from the object's BTF (%u bytes) — libbpf rewrote it (B1)", ksz, osz);
	struct bpf_program *p;
	bpf_object__for_each_program(p, obj) {
		struct bpf_prog_info pi;
		uint32_t l = sizeof pi;
		memset(&pi, 0, sizeof pi);
		if (bpf_prog_get_info_by_fd(bpf_program__fd(p), &pi, &l) != 0)
			return lb_fail(r, BML_LOAD_EXT_INFO, "program %s: the kernel's info cannot be read (%s)", bpf_program__name(p), lb_errno(errno));
		char why[160] = "";
		int sub = pi.btf_id == kid ? ext_info_subseq(bpf_program__fd(p), p, &pi, why, sizeof why) : (snprintf(why, sizeof why, "the BTF ids differ"), 1);
		if (sub < 0)
			return lb_fail(r, BML_LOAD_EXT_INFO, "program %s: the kernel's func_info / line_info cannot be read (%s)", bpf_program__name(p),
				       lb_errno(-sub));
		if (sub)
			return lb_fail(r, BML_LOAD_EXT_INFO,
				       "program %s: the kernel has BTF %u with %u func_info and %u line_info, the object BTF %u with %u and %u — %s (B4)",
				       bpf_program__name(p), pi.btf_id, pi.nr_func_info, pi.nr_line_info, kid, bpf_program__func_info_cnt(p),
				       bpf_program__line_info_cnt(p), why);
	}
	struct bpf_map *m;
	size_t i = 0;
	bpf_object__for_each_map(m, obj) {
		if (i >= n || strcmp(defs[i].name, bpf_map__name(m)) != 0)
			return lb_fail(r, BML_LOAD_MAP_BTF, "the maps changed between open and load");
		struct bpf_map_info mi;
		uint32_t l = sizeof mi;
		memset(&mi, 0, sizeof mi);
		if (bpf_map_get_info_by_fd(bpf_map__fd(m), &mi, &l) != 0)
			return lb_fail(r, BML_LOAD_MAP_BTF, "map %s: the kernel's info cannot be read (%s)", defs[i].name, lb_errno(errno));
		if (mi.btf_key_type_id != defs[i].key_id || mi.btf_value_type_id != defs[i].value_id ||
		    ((defs[i].key_id || defs[i].value_id) && mi.btf_id != kid))
			return lb_fail(r, BML_LOAD_MAP_BTF,
				       "map %s: the kernel has BTF key %u / value %u (BTF %u), the ELF %u / %u — libbpf dropped the map's BTF (M1 / M2)",
				       defs[i].name, mi.btf_key_type_id, mi.btf_value_type_id, mi.btf_id, defs[i].key_id, defs[i].value_id);
		

		if (defs[i].flags & ~mi.map_flags)
			return lb_fail(r, BML_LOAD_MAP_FLAGS, "map %s: the kernel has flags 0x%x without 0x%x of the object's 0x%x — libbpf dropped them (P3)",
				       defs[i].name, mi.map_flags, defs[i].flags & ~mi.map_flags, defs[i].flags);
		i++;
	}
	return 0;
}
