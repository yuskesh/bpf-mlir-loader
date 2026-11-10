






#define _GNU_SOURCE
#include "caps/live_internal.h"

#include <elf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>


static size_t unhex(const char *h, uint8_t *out, size_t cap)
{
	size_t n = 0;
	int hi = -1;
	for (; *h; h++) {
		int v = *h >= '0' && *h <= '9' ? *h - '0' : *h >= 'a' && *h <= 'f' ? *h - 'a' + 10 : -1;
		if (v < 0)
			continue;
		if (hi < 0)
			hi = v;
		else {
			if (n < cap)
				out[n] = (uint8_t)(hi << 4 | v);
			n++;
			hi = -1;
		}
	}
	return n;
}

static const char *const btf_blob[] = {
	[LVF_BTF] = "9feb0100180000000000000010000000100000000100000000000000000000010000000000000000 00",
	[LVF_MAP_BTF] = "9feb010018000000000000001c0000001c00000003000000010000000000000e0200000000000000000000000000000200000000006100",
	[LVF_PROG_BTF] = "9feb01001800000000000000180000001800000003000000010000000000000c02000000000000000000000d00000000006100",
	[LVF_FUNC_LINKAGE] = "9feb01001800000000000000180000001800000003000000010000000100000c02000000000000000000000d00000000006100",
	[LVF_DECL_TAGS] = "9feb010018000000000000002c0000002c0000000300000001000000000000080200000000000000000000010000000000000000010000000000001101000000ffffffff006100",
	[LVF_TYPE_TAGS] = "9feb010018000000000000001c0000001c0000000300000001000000000000120200000000000000000000010000000000000000006100",
	[LVF_ENUM64] = "9feb01001800000000000000180000001800000006000000000000000100001308000000010000000000000001000000005445535400",
};


static int probe_btf(int which)
{
	uint8_t blob[128];
	size_t n = unhex(btf_blob[which], blob, sizeof blob);
	uint8_t attr[40] = {0};
	uint64_t p = (uint64_t)(uintptr_t)blob;
	uint32_t len = (uint32_t)n;
	memcpy(attr, &p, 8);
	memcpy(attr + 16, &len, 4);
	int fd = lv_bpf(BPF_BTF_LOAD, attr, sizeof attr);
	if (fd >= 0) {
		lv_close(fd);
		return 0;
	}
	return fd;
}

static int map_create(const char *name)
{
	uint8_t attr[96] = {0};
	uint32_t v[4] = {BPF_MAP_TYPE_ARRAY, 4, 4, 1};
	memcpy(attr, v, sizeof v);
	strncpy((char *)attr + 28, name, 15);
	int fd = lv_bpf(BPF_MAP_CREATE, attr, sizeof attr);
	if (fd >= 0) {
		lv_close(fd);
		return 0;
	}
	return fd;
}


static int prog_load_raw(uint32_t type, const char *hex, const char *license, uint32_t func_info_cnt, uint32_t btf_fd)
{
	uint8_t ins[64];
	size_t n = unhex(hex, ins, sizeof ins);
	uint8_t attr[168] = {0};
	uint32_t cnt = (uint32_t)(n / 8);
	uint64_t ip = (uint64_t)(uintptr_t)ins, lp = (uint64_t)(uintptr_t)license;
	memcpy(attr, &type, 4);
	memcpy(attr + 4, &cnt, 4);
	memcpy(attr + 8, &ip, 8);
	memcpy(attr + 16, &lp, 8);
	memcpy(attr + 72, &btf_fd, 4);
	memcpy(attr + 88, &func_info_cnt, 4);
	int fd = lv_bpf(BPF_PROG_LOAD, attr, sizeof attr);
	if (fd >= 0) {
		lv_close(fd);
		return 0;
	}
	return fd;
}

static int run(struct bml_live *l, int which)
{
	int rc, pre;
	switch (which) {
	case LVF_BTF:
		rc = probe_btf(which);
		return rc == 0 ? LV_OK : rc == -EINVAL || rc == -EPERM ? LV_NOTSUP : rc;
	case LVF_MAP_BTF: case LVF_PROG_BTF:
		if ((pre = lv_feat(l, LVF_BTF)) != LV_OK)
			return pre;
		rc = probe_btf(which);
		return rc == 0 ? LV_OK : rc == -EINVAL || rc == -EPERM ? LV_NOTSUP : rc;
	case LVF_FUNC_LINKAGE: case LVF_DECL_TAGS: case LVF_TYPE_TAGS: case LVF_ENUM64:
		if ((pre = lv_feat(l, which == LVF_FUNC_LINKAGE ? LVF_PROG_BTF : LVF_BTF)) != LV_OK)
			return pre;
		rc = probe_btf(which);
		return rc == 0 ? LV_OK : rc == -EINVAL ? LV_NOTSUP : rc;
	case LVF_OBJ_NAME:
		return map_create("feature_test") == 0 ? LV_OK : LV_NOTSUP;
	case LVF_OBJ_NAME_DOT:
		if ((pre = lv_feat(l, LVF_OBJ_NAME)) != LV_OK)
			return pre;
		return map_create(".test") == 0 ? LV_OK : LV_NOTSUP;
	case LVF_EXT_INFOS:
		rc = prog_load_raw(BPF_PROG_TYPE_SOCKET_FILTER, "b7000000000000009500000000000000", "MIT", 1, 0xffffffffu);
		return rc == 0 || rc == -EBADF ? LV_OK : rc == -E2BIG ? LV_NOTSUP : rc;
	case LVF_BPF2BPF:
		rc = prog_load_raw(BPF_PROG_TYPE_SOCKET_FILTER, "85100000010000009500000000000000b7000000000000009500000000000000", "MIT",
				   0, 0);
		return rc == 0 ? LV_OK : LV_NOTSUP;
	case LVF_PROBE_READ_KERNEL:
		rc = prog_load_raw(BPF_PROG_TYPE_KPROBE,
				   "bfa1000000000000070100 00f8ffffffb702000008000000b703000000000000850000007100000095000000 00000000",
				   "GPL", 0, 0);
		return rc == 0 ? LV_OK : LV_NOTSUP;
	}
	return -1;
}

int lv_feat(struct bml_live *l, int which)
{
	if (l->feat[which] != LV_UNSET)
		return l->feat[which];
	int rc = run(l, which);
	if (rc == LV_OK || rc == LV_NOTSUP)
		l->feat[which] = rc;
	return rc;
}

void lv_kmo(struct bml_live *l, struct lv_kmo *o)
{
	o->strip_func_linkage = lv_feat(l, LVF_FUNC_LINKAGE) != LV_OK;
	o->replace_decl_tags = lv_feat(l, LVF_DECL_TAGS) != LV_OK;
	o->replace_type_tags = lv_feat(l, LVF_TYPE_TAGS) != LV_OK;
	o->replace_enum64 = lv_feat(l, LVF_ENUM64) != LV_OK;
}

uint8_t *lv_strip_func_linkage(const uint8_t *btf, size_t len)
{
	uint8_t *b = malloc(len ? len : 1);
	if (!b)
		return NULL;
	memcpy(b, btf, len);
	struct bml_kbtf kb;
	char *err = NULL;
	uint8_t *copy = malloc(len ? len : 1);
	if (!copy) {
		free(b);
		return NULL;
	}
	memcpy(copy, btf, len);
	if (bml_kbtf_from_raw(copy, len, &kb, &err) != 0) {
		free(err);
		free(b);
		return NULL;
	}
	for (uint32_t id = 1; id < kb.n; id++) {
		struct kbtf_type t;
		bml_kbtf_type(&kb, id, &t);
		if (t.kind == KBTF_FUNC) {
			size_t info = (size_t)(kb.types - kb.raw) + kb.off[id] + 4;
			b[info] = 0;
			b[info + 1] = 0;
		}
	}
	bml_kbtf_free(&kb);
	return b;
}


static int vdso_version(uint32_t *v)
{
	const uint8_t *base = (const uint8_t *)getauxval(AT_SYSINFO_EHDR);
	if (!base)
		return -1;
	const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;
	if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 || eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_shentsize != sizeof(Elf64_Shdr))
		return -1;

	size_t size = eh->e_shoff + (size_t)eh->e_shnum * sizeof(Elf64_Shdr);
	if (eh->e_shoff == 0 || size > (1u << 20))
		return -1;
	for (int i = 0; i < eh->e_shnum; i++) {
		const Elf64_Shdr *sh = (const Elf64_Shdr *)(base + eh->e_shoff + (size_t)i * sizeof(Elf64_Shdr));
		if (sh->sh_type != SHT_NOTE || sh->sh_offset + sh->sh_size > size)
			continue;
		const uint8_t *p = base + sh->sh_offset, *e = p + sh->sh_size;
		while (e - p >= 12) {
			int32_t nsz, dsz, typ;
			memcpy(&nsz, p, 4);
			memcpy(&dsz, p + 4, 4);
			memcpy(&typ, p + 8, 4);
			p += 12;
			char name[16] = {0};
			if (nsz > 0) {
				size_t a = ((size_t)nsz + 3) & ~(size_t)3;
				if ((size_t)(e - p) < a)
					return -1;
				memcpy(name, p, nsz < 15 ? (size_t)nsz : 15);
				p += a;
			}
			if (dsz > 0) {
				if (strcmp(name, "Linux") == 0 && dsz == 4 && typ == 0) {
					if (e - p < 4)
						return -1;
					memcpy(v, p, 4);
					return 0;
				}
				size_t a = ((size_t)dsz + 3) & ~(size_t)3;
				if ((size_t)(e - p) < a)
					return -1;
				p += a;
			}
		}
	}
	return -1;
}

int lv_kernel_version(struct bml_live *l, uint32_t *v)
{
	if (!l->kver_done) {
		l->kver_done = 1;
		uint32_t code;
		l->kver_ok = vdso_version(&code) == 0;

		if (l->kver_ok)
			l->kver = (code >> 16 & 0xff) << 16 | (code >> 8 & 0xff) << 8 | (code & 0xff);
	}
	*v = l->kver;
	return l->kver_ok ? 0 : -1;
}

void lv_obj_name(struct bml_live *l, const char *name, char dst[16])
{
	memset(dst, 0, 16);
	if (lv_feat(l, LVF_OBJ_NAME) == LV_NOTSUP)
		return;
	int dot = lv_feat(l, LVF_OBJ_NAME_DOT) != LV_NOTSUP;
	size_t k = 0;
	for (const char *s = name; *s && k < 15; s++) {
		char c = *s;
		int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || (c == '.' && dot);
		if (ok)
			dst[k++] = c;
	}
}
