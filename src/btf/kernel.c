

#include "btf/kernel.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

static int fail(char **err, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int fail(char **err, const char *fmt, ...)
{
	struct bml_buf b = {0};
	va_list ap;
	char tmp[512];
	va_start(ap, fmt);
	vsnprintf(tmp, sizeof tmp, fmt, ap);
	va_end(ap);
	bml_buf_adds(&b, tmp);
	*err = bml_buf_take(&b);
	return -1;
}

uint32_t bml_kbtf_u32(const struct bml_kbtf *kb, const uint8_t *p)
{
	if (kb->be)
		return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
	return (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0];
}


static const char *str_at(const struct bml_kbtf *kb, uint32_t off)
{
	if (off == 0)
		return "";
	if (off > kb->strs_len || kb->strs[off - 1] != 0)
		return NULL;
	if (!memchr(kb->strs + off, 0, kb->strs_len - off))
		return NULL;
	return (const char *)kb->strs + off;
}


static int64_t data_len(uint32_t kind, uint32_t vlen)
{
	switch (kind) {
	case KBTF_INT: return 4;
	case KBTF_ARRAY: return 12;
	case KBTF_STRUCT: case KBTF_UNION: return 12 * (int64_t)vlen;
	case KBTF_ENUM: return 8 * (int64_t)vlen;
	case KBTF_FUNC_PROTO: return 8 * (int64_t)vlen;
	case KBTF_VAR: return 4;
	case KBTF_DATASEC: return 12 * (int64_t)vlen;
	case KBTF_DECL_TAG: return 4;
	case KBTF_ENUM64: return 12 * (int64_t)vlen;
	case KBTF_PTR: case KBTF_FWD: case KBTF_TYPEDEF: case KBTF_VOLATILE: case KBTF_CONST: case KBTF_RESTRICT:
	case KBTF_FUNC: case KBTF_FLOAT: case KBTF_TYPE_TAG:
		return 0;
	}
	return -1;
}

void bml_kbtf_type(const struct bml_kbtf *kb, uint32_t id, struct kbtf_type *t)
{
	memset(t, 0, sizeof *t);
	t->name = "";
	if (id == 0 || id >= kb->n)
		return;
	const uint8_t *p = kb->types + kb->off[id];
	uint32_t info = bml_kbtf_u32(kb, p + 4);
	t->kind = info >> 24 & 0x1f;
	t->vlen = info & 0xffff;
	t->kflag = info >> 31;
	t->size_type = bml_kbtf_u32(kb, p + 8);
	t->name = str_at(kb, bml_kbtf_u32(kb, p));
	t->aux = p + 12;
}

void bml_kbtf_member(const struct bml_kbtf *kb, const struct kbtf_type *t, uint32_t i, struct kbtf_member *m)
{
	const uint8_t *p = t->aux + 12 * (size_t)i;
	m->name = str_at(kb, bml_kbtf_u32(kb, p));
	m->type = bml_kbtf_u32(kb, p + 4);
	m->offset = bml_kbtf_u32(kb, p + 8);
	m->bitfield_size = 0;
	if (t->kflag) {
		m->bitfield_size = m->offset >> 24;
		m->offset &= 0xffffff;
		return;
	}

	struct kbtf_type it;
	bml_kbtf_type(kb, m->type, &it);
	if (it.kind != KBTF_INT)
		return;
	uint32_t raw = bml_kbtf_u32(kb, it.aux);
	uint32_t ioff = raw >> 16 & 0xff, bits = raw & 0xff;
	if (ioff > 0 || bits / 8 != it.size_type) {
		m->offset += ioff;
		m->bitfield_size = bits;
	}
}

void bml_kbtf_param(const struct bml_kbtf *kb, const struct kbtf_type *t, uint32_t i, const char **name, uint32_t *type)
{
	const uint8_t *p = t->aux + 8 * (size_t)i;
	*name = str_at(kb, bml_kbtf_u32(kb, p));
	*type = bml_kbtf_u32(kb, p + 4);
}

const char *bml_kbtf_goname(uint32_t kind)
{
	static const char *const names[KBTF_NKINDS] = {
		"Void", "Int", "Pointer", "Array", "Struct", "Union", "Enum", "Fwd", "Typedef", "Volatile", "Const", "Restrict",
		"Func", "FuncProto", "Var", "Datasec", "Float", "declTag", "TypeTag", "Enum",
	};
	return kind < KBTF_NKINDS ? names[kind] : "?";
}


static int check_names(const struct bml_kbtf *kb, uint32_t id, const struct kbtf_type *t, char **err)
{
	size_t step = 0;
	switch (t->kind) {
	case KBTF_STRUCT: case KBTF_UNION: step = 12; break;
	case KBTF_ENUM: case KBTF_FUNC_PROTO: step = 8; break;
	case KBTF_ENUM64: step = 12; break;
	default: return 0;
	}
	for (uint32_t i = 0; i < t->vlen; i++)
		if (!str_at(kb, bml_kbtf_u32(kb, t->aux + step * i)))
			return fail(err, "type id %u: a member, parameter or enum value name is not in the string table", id);
	return 0;
}

static int check_ref(const struct bml_kbtf *kb, uint32_t id, uint32_t ref, char **err)
{
	if (ref >= kb->n)
		return fail(err, "type id %u refers to type id %u: not found", id, ref);
	return 0;
}

static int check_refs(const struct bml_kbtf *kb, uint32_t id, const struct kbtf_type *t, char **err)
{
	switch (t->kind) {
	case KBTF_PTR: case KBTF_TYPEDEF: case KBTF_VOLATILE: case KBTF_CONST: case KBTF_RESTRICT: case KBTF_FUNC:
	case KBTF_VAR: case KBTF_DECL_TAG: case KBTF_TYPE_TAG:
		return check_ref(kb, id, t->size_type, err);
	case KBTF_ARRAY:
		if (check_ref(kb, id, bml_kbtf_u32(kb, t->aux), err) || check_ref(kb, id, bml_kbtf_u32(kb, t->aux + 4), err))
			return -1;
		return 0;
	case KBTF_STRUCT: case KBTF_UNION:
		for (uint32_t i = 0; i < t->vlen; i++)
			if (check_ref(kb, id, bml_kbtf_u32(kb, t->aux + 12 * (size_t)i + 4), err))
				return -1;
		return 0;
	case KBTF_FUNC_PROTO:
		for (uint32_t i = 0; i < t->vlen; i++)
			if (check_ref(kb, id, bml_kbtf_u32(kb, t->aux + 8 * (size_t)i + 4), err))
				return -1;
		return check_ref(kb, id, t->size_type, err);
	case KBTF_DATASEC:
		for (uint32_t i = 0; i < t->vlen; i++)
			if (check_ref(kb, id, bml_kbtf_u32(kb, t->aux + 12 * (size_t)i), err))
				return -1;
		return 0;
	}
	return 0;
}


static int check_decl_tag(const struct bml_kbtf *kb, uint32_t id, const struct kbtf_type *t, char **err)
{
	int32_t idx = (int32_t)bml_kbtf_u32(kb, t->aux);
	struct kbtf_type to;
	bml_kbtf_type(kb, t->size_type, &to);
	switch (to.kind) {
	case KBTF_VAR: case KBTF_TYPEDEF:
		if (idx != -1)
			return fail(err, "decl tag id %u: component idx %d is not -1", id, idx);
		return 0;
	case KBTF_STRUCT: case KBTF_UNION:
		if (idx < -1 || (idx >= 0 && (uint32_t)idx >= to.vlen))
			return fail(err, "decl tag id %u: invalid component idx %d", id, idx);
		return 0;
	case KBTF_FUNC: {
		struct kbtf_type fp;
		bml_kbtf_type(kb, to.size_type, &fp);
		if (fp.kind != KBTF_FUNC_PROTO)
			return fail(err, "decl tag id %u: the tagged func is not a FuncProto", id);
		if (idx < -1 || (idx >= 0 && (uint32_t)idx >= fp.vlen))
			return fail(err, "decl tag id %u: invalid component idx %d", id, idx);
		return 0;
	}
	}
	return fail(err, "decl tag id %u: a decl tag for %s is not supported", id, bml_kbtf_goname(to.kind));
}



int bml_kbtf_from_raw(uint8_t *raw, size_t len, struct bml_kbtf *kb, char **err)
{
	memset(kb, 0, sizeof *kb);
	kb->raw = raw;
	kb->raw_len = len;
	*err = NULL;
	if (len < 24) {
		fail(err, "parsing .BTF header: read header: the data is too short");
		goto bad;
	}
	if (raw[0] == 0x9f && raw[1] == 0xeb)
		kb->be = 0;
	else if (raw[0] == 0xeb && raw[1] == 0x9f)
		kb->be = 1;
	else {
		fail(err, "parsing .BTF header: no valid BTF header");
		goto bad;
	}
	if (raw[2] != 1 || raw[3] != 0) {
		fail(err, "parsing .BTF header: unexpected version %u or flags %u", raw[2], raw[3]);
		goto bad;
	}
	uint32_t hdr_len = bml_kbtf_u32(kb, raw + 4);
	if (hdr_len < 24 || hdr_len > len) {
		fail(err, "parsing .BTF header: the header length %u is out of bounds", hdr_len);
		goto bad;
	}

	for (size_t i = hdr_len >= 32 ? 32 : 24; i < hdr_len; i++)
		if (raw[i] != 0) {
			fail(err, "parsing .BTF header: header contains non-zero trailer");
			goto bad;
		}
	const uint8_t *body = raw + hdr_len;
	uint64_t body_len = len - hdr_len;
	uint32_t type_off = bml_kbtf_u32(kb, raw + 8), type_len = bml_kbtf_u32(kb, raw + 12);
	uint32_t str_off = bml_kbtf_u32(kb, raw + 16), str_len = bml_kbtf_u32(kb, raw + 20);
	if ((uint64_t)str_off + str_len > body_len) {
		fail(err, "string table is out of bounds");
		goto bad;
	}
	kb->strs = body + str_off;
	kb->strs_len = str_len;
	if (str_len > 0 && (kb->strs[str_len - 1] != 0 || kb->strs[0] != 0)) {
		fail(err, "read string section: the string table does not start and end with NUL");
		goto bad;
	}
	if ((uint64_t)type_off + type_len > body_len) {
		fail(err, "types section is out of bounds");
		goto bad;
	}
	kb->types = body + type_off;
	kb->types_len = type_len;


	for (int pass = 0; pass < 2; pass++) {
		uint32_t id = 1;
		for (uint64_t o = 0; o < type_len; id++) {
			if (type_len - o < 12) {
				fail(err, "unmarshal type header: not enough bytes to unmarshal btfType");
				goto bad;
			}
			uint32_t info = bml_kbtf_u32(kb, kb->types + o + 4);
			int64_t dl = data_len(info >> 24 & 0x1f, info & 0xffff);
			if (dl < 0) {
				fail(err, "unknown kind: %u", info >> 24 & 0x1f);
				goto bad;
			}
			if (o + 12 + (uint64_t)dl > type_len) {
				fail(err, "auxiliary type data: unexpected EOF");
				goto bad;
			}
			if (pass == 1)
				kb->off[id] = (uint32_t)o;
			o += 12 + (uint64_t)dl;
		}
		if (pass == 0) {
			kb->n = id;
			kb->off = calloc(id, sizeof *kb->off);
			if (!kb->off) {
				fail(err, "out of memory");
				goto bad;
			}
		}
	}
	for (uint32_t id = 1; id < kb->n; id++) {
		if (!str_at(kb, bml_kbtf_u32(kb, kb->types + kb->off[id]))) {
			fail(err, "lookup type name for id %u: the offset is not a string in the table", id);
			goto bad;
		}
	}

	int rc = -3;
	for (uint32_t id = 1; id < kb->n; id++) {
		struct kbtf_type t;
		bml_kbtf_type(kb, id, &t);
		if (check_names(kb, id, &t, err) || check_refs(kb, id, &t, err))
			goto out;
	}
	for (uint32_t id = 1; id < kb->n; id++) {
		struct kbtf_type t;
		bml_kbtf_type(kb, id, &t);
		if (t.kind == KBTF_DECL_TAG && check_decl_tag(kb, id, &t, err))
			goto out;
	}
	rc = -1;
	if (bml_kbtf_build_index(kb, err))
		goto out;
	return 0;
bad:
	rc = -1;
out:
	bml_kbtf_free(kb);
	return rc;
}



static int no_sysfs(char **err)
{
	static const char *const loc[] = {
		"/boot/vmlinux-%s", "/lib/modules/%s/vmlinux-%s", "/lib/modules/%s/build/vmlinux", "/usr/lib/modules/%s/kernel/vmlinux",
		"/usr/lib/debug/boot/vmlinux-%s", "/usr/lib/debug/boot/vmlinux-%s.debug", "/usr/lib/debug/lib/modules/%s/vmlinux",
	};
	struct utsname u;
	if (uname(&u) != 0)
		return fail(err, "uname: %s", strerror(errno));
	for (size_t i = 0; i < sizeof loc / sizeof *loc; i++) {
		char p[1024];
		snprintf(p, sizeof p, loc[i], u.release, u.release);
		int fd = open(p, O_RDONLY | O_CLOEXEC);
		if (fd < 0 && errno == ENOENT)
			continue;
		if (fd >= 0)
			close(fd);
		return fail(err, "/sys/kernel/btf/vmlinux is not readable and %s exists — reading a vmlinux ELF (cilium/ebpf's fallback) is not implemented", p);
	}
	fail(err, "no BTF found for kernel version %s: not supported", u.release);
	return -2;
}

int bml_kbtf_load_kernel(struct bml_kbtf *kb, char **err)
{
	const char *path = "/sys/kernel/btf/vmlinux";
	memset(kb, 0, sizeof *kb);
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return no_sysfs(err);
	struct stat st;
	if (fstat(fd, &st) != 0 || st.st_size <= 0) {
		close(fd);
		return fail(err, "stat %s: no size", path);
	}
	size_t len = (size_t)st.st_size, got = 0;
	uint8_t *raw = malloc(len);
	if (!raw) {
		close(fd);
		return fail(err, "out of memory");
	}
	while (got < len) {
		ssize_t r = read(fd, raw + got, len - got);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0) {
			int e = r < 0 ? errno : 0;
			close(fd);
			free(raw);
			return fail(err, "read %s: %s", path, e ? strerror(e) : "short read");
		}
		got += (size_t)r;
	}
	close(fd);
	int rc = bml_kbtf_from_raw(raw, len, kb, err);
	if (rc != 0) {
		char *inner = *err;
		fail(err, "load vmlinux: %s", inner ? inner : "?");
		free(inner);
		return rc;
	}
	return 0;
}

void bml_kbtf_free(struct bml_kbtf *kb)
{
	free(kb->raw);
	free(kb->off);
	free(kb->idx);
	memset(kb, 0, sizeof *kb);
}

