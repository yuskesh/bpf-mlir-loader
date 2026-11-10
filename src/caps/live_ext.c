


#define _GNU_SOURCE
#include "caps/live_internal.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btf/kernel.h"
#include "elf/elf.h"
#include "util/gostr.h"

#define UNK ": cannot be determined on this target"



static int prog_btf(uint32_t id, uint8_t **raw, size_t *len, char **err)
{
	union bpf_attr a;
	memset(&a, 0, sizeof a);
	a.prog_id = id;
	int pfd = lv_bpf(BPF_PROG_GET_FD_BY_ID, &a, sizeof a);
	char *es = NULL;
	if (pfd < 0) {
		es = bml_go_errno_str(-pfd);
		if (asprintf(err, "program %u: get program by id: %s", id, es ? es : "") < 0)
			*err = NULL;
		free(es);
		return -1;
	}
	struct bpf_prog_info pi;
	memset(&pi, 0, sizeof pi);
	memset(&a, 0, sizeof a);
	a.info.bpf_fd = (uint32_t)pfd;
	a.info.info_len = sizeof pi;
	a.info.info = (uint64_t)(uintptr_t)&pi;
	int rc = lv_bpf(BPF_OBJ_GET_INFO_BY_FD, &a, sizeof a);
	lv_close(pfd);
	if (rc < 0) {
		es = bml_go_errno_str(-rc);
		if (asprintf(err, "program %u info: getting object info: %s", id, es ? es : "") < 0)
			*err = NULL;
		free(es);
		return -1;
	}
	if (pi.btf_id == 0) {
		if (asprintf(err, "program %u has no BTF", id) < 0)
			*err = NULL;
		return -1;
	}
	memset(&a, 0, sizeof a);
	a.btf_id = pi.btf_id;
	int bfd = lv_bpf(BPF_BTF_GET_FD_BY_ID, &a, sizeof a);
	if (bfd < 0) {
		es = bml_go_errno_str(-bfd);
		if (asprintf(err, "program %u BTF %u: get FD for ID %u: %s", id, pi.btf_id, pi.btf_id, es ? es : "") < 0)
			*err = NULL;
		free(es);
		return -1;
	}
	struct bpf_btf_info bi;
	memset(&bi, 0, sizeof bi);
	memset(&a, 0, sizeof a);
	a.info.bpf_fd = (uint32_t)bfd;
	a.info.info_len = sizeof bi;
	a.info.info = (uint64_t)(uintptr_t)&bi;
	rc = lv_bpf(BPF_OBJ_GET_INFO_BY_FD, &a, sizeof a);
	uint32_t size = bi.btf_size;
	uint8_t *buf = rc < 0 ? NULL : malloc(size ? size : 1);
	if (buf) {
		memset(&bi, 0, sizeof bi);
		bi.btf = (uint64_t)(uintptr_t)buf;
		bi.btf_size = size;
		memset(&a, 0, sizeof a);
		a.info.bpf_fd = (uint32_t)bfd;
		a.info.info_len = sizeof bi;
		a.info.info = (uint64_t)(uintptr_t)&bi;
		rc = lv_bpf(BPF_OBJ_GET_INFO_BY_FD, &a, sizeof a);
	}
	lv_close(bfd);
	if (rc < 0 || !buf) {
		es = bml_go_errno_str(rc < 0 ? -rc : ENOMEM);
		if (asprintf(err, "program %u BTF %u: %s", id, pi.btf_id, es ? es : "") < 0)
			*err = NULL;
		free(es);
		free(buf);
		return -1;
	}
	*raw = buf;
	*len = size;
	return 0;
}

int bml_ext_target_load(const char *target, struct bml_kbtf *kb, char **err)
{
	*err = NULL;
	uint8_t *raw = NULL;
	size_t len = 0;
	if (!strncmp(target, "prog-id:", 8)) {
		uint64_t id;
		if (bml_go_parse_uint(target + 8, strlen(target + 8), 32, &id)) {
			struct bml_buf b = {0};
			bml_buf_adds(&b, "--ext-target ");
			bml_buf_add_goquote(&b, target, strlen(target));
			bml_buf_adds(&b, ": bad program id");
			*err = bml_buf_take(&b);
			return -1;
		}
		if (prog_btf((uint32_t)id, &raw, &len, err))
			return -1;
	} else {
		char *data;
		int e;
		if (lv_read_file(target, &data, &len, &e)) {
			char *es = bml_go_errno_str(e);
			if (asprintf(err, "open %s: %s", target, es ? es : "") < 0)
				*err = NULL;
			free(es);
			return -1;
		}

		struct bml_elf elf;
		char *eerr = NULL;
		if (len >= 4 && !memcmp(data, "\177ELF", 4)) {
			if (bml_elf_open(data, len, &elf, &eerr)) {
				*err = eerr;
				free(data);
				return -1;
			}
			const struct bml_elf_shdr *s = bml_elf_section(&elf, ".BTF");
			const uint8_t *p = NULL;
			size_t n = 0;
			if (!s || bml_elf_section_data(&elf, s, &p, &n, &eerr)) {
				*err = eerr ? eerr : strdup("btf: no .BTF section in the ELF");
				bml_elf_close(&elf);
				free(data);
				return -1;
			}
			raw = malloc(n ? n : 1);
			if (raw)
				memcpy(raw, p, n);
			len = n;
			bml_elf_close(&elf);
			free(data);
			if (!raw) {
				*err = strdup("out of memory");
				return -1;
			}
		} else
			raw = (uint8_t *)data;
	}
	return bml_kbtf_from_raw(raw, len, kb, err) ? -1 : 0;
}

int bml_ext_target_check(const struct bml_kbtf *kb, const char *fn, int64_t nargs, const char *ret, const struct bml_str *args, size_t n,
			 struct bml_strs *out, char **msg)
{
	memset(out, 0, sizeof *out);
	if (!kb) {
		*msg = strdup("no BTF for the replacement target" UNK);
		return BML_Q_UNKNOWN;
	}
	uint32_t id;
	char *err = NULL;
	int rc = bml_kbtf_by_name(kb, fn, KBTF_FUNC, &id, &err);
	if (rc != 0) {
		struct bml_buf b = {0};
		if (rc == 1)
			bml_buf_addf(&b, "function %s is not in the replacement target's BTF" UNK, fn);
		else
			bml_buf_addf(&b, "looking up %s in the replacement target's BTF (%s)" UNK, fn, err ? err : "");
		free(err);
		*msg = bml_buf_take(&b);
		return BML_Q_UNKNOWN;
	}
	struct kbtf_type f, fp;
	bml_kbtf_type(kb, id, &f);
	struct bml_buf b = {0};
	if (f.vlen != 1) {
		static const char *const lk[] = {"static", "global", "extern"};
		bml_buf_addf(&b, "function %s has linkage ", fn);
		if (f.vlen < 3)
			bml_buf_adds(&b, lk[f.vlen]);
		else
			bml_buf_addf(&b, "FuncLinkage(%u)", f.vlen);
		bml_buf_adds(&b, " in the replacement target, not global (ext replaces only global functions)");
		if (lv_push(out, &b))
			return lv_oom(out, msg);
	}
	bml_kbtf_type(kb, f.size_type, &fp);
	if (fp.kind != KBTF_FUNC_PROTO) {
		bml_buf_addf(&b, "function %s has no FUNC_PROTO in the replacement target", fn);
		return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
	}
	char *what = NULL;
	if (asprintf(&what, "function %s", fn) < 0)
		return lv_oom(out, msg);
	rc = lv_compare_proto(kb, &fp, what, nargs, ret, args, n, out);
	free(what);
	return rc ? lv_oom(out, msg) : BML_Q_OK;
}
