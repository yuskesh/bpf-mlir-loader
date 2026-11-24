/* abi/testonly.c — entries that exist only in the test build: global_set_raw, ringbuf_fault and
 * freeze_map. (They are the landing of the "test entries" section of the downstream C ABI document.
 * The load that skips the check is in object.c, and the uprobe mutations are in uprobe.c.) All of
 * them exist only in a build with -DBML_TEST_CAPS; the gate checks with nm that the product's
 * libbml.a has no bml_testonly_ symbol. */
#ifdef BML_TEST_CAPS
#define _GNU_SOURCE
#include "abi/internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bml/bml_testonly.h"
#include "btf/globals.h"
#include "util/mutation.h"

static char *name_of(const char *s, int64_t n)
{
	return n < 0 || (!s && n) ? NULL : strndup(s ? s : "", (size_t)n);
}

static struct bpf_map *map_named(struct abi_object *o, const char *name)
{
	return bpf_object__find_map_by_name(bml_obj_bpf(o->lo), name);
}

/* A direct write to a global after load (the downstream testonly_global_set_raw, the negative control
 * that shows a frozen .rodata really rejects the write): libbpf's bpf_map__set_initial_value, and a
 * BPF_MAP_UPDATE_ELEM on the section's map. The result is OK with the message
 * "libbpf=<error|nil> kernel=<error|nil>"; a name that is not in the declaration is STATE. */
static int64_t set_raw_body(struct abi_object *o, const char *name, uint64_t bits)
{
	const struct bml_global_decl *g = NULL;
	for (size_t i = 0; i < o->n_globals; i++)
		if (!strcmp(o->globals[i].name, name))
			g = &o->globals[i];
	if (!g)
		return abi_fail(BML_STATE, "bml: the object declares no global %s (maps.json globals)", name);
	struct bpf_map *m, *sm = NULL;
	char suffix[16];
	snprintf(suffix, sizeof suffix, ".%s", g->section);
	bpf_object__for_each_map(m, bml_obj_bpf(o->lo))
	{
		const char *nm = bpf_map__name(m);
		size_t l = strlen(nm), sl = strlen(suffix);
		if (bpf_map__is_internal(m) && l >= sl && !strcmp(nm + l - sl, suffix))
			sm = m;
	}
	uint64_t off, size;
	uint32_t vs = sm ? bpf_map__value_size(sm) : 0, key = 0;
	uint8_t *buf = vs ? calloc(1, vs) : NULL;
	if (!sm || !buf || btf_global_offset(o->elf, o->elf_len, name, &off, &size) != 0 || size > 8 || off > vs || vs - off < size) {
		free(buf);
		return abi_fail(BML_OTHER, "bml: global %s: the %s map or the symbol cannot be read", name, suffix);
	}
	/* libbpf: the initial value cannot be changed after load (EBUSY is expected); pass the whole of the same value. */
	size_t isz = 0;
	const void *init = bpf_map__initial_value(sm, &isz);
	int le = 0;
	if (init && isz == vs) {
		memcpy(buf, init, vs);
		for (uint64_t b = 0; b < size; b++)
			buf[off + b] = (uint8_t)(bits >> (8 * b));
		le = bpf_map__set_initial_value(sm, buf, vs) != 0 ? errno : 0;
	} else
		le = EINVAL;
	/* kernel: read the current value, overwrite the width in question and update (.rodata is frozen; EPERM is expected). */
	int ke = 0;
	if (bpf_map_lookup_elem(bpf_map__fd(sm), &key, buf) != 0)
		ke = errno;
	else {
		for (uint64_t b = 0; b < size; b++)
			buf[off + b] = (uint8_t)(bits >> (8 * b));
		ke = bpf_map_update_elem(bpf_map__fd(sm), &key, buf, BPF_ANY) != 0 ? errno : 0;
	}
	free(buf);
	char *msg = NULL;
	char lb[128], kb[128];
	snprintf(lb, sizeof lb, "%s", le ? abi_errno(le) : "nil");
	snprintf(kb, sizeof kb, "%s", ke ? abi_errno(ke) : "nil");
	if (asprintf(&msg, "libbpf=%s kernel=%s", lb, kb) < 0)
		return abi_fail(BML_OTHER, "bml: out of memory");
	struct abi_result r = {.kind = BML_OK, .msg = msg, .msg_len = strlen(msg)};
	return abi_put(&r);
}

int64_t bml_testonly_global_set_raw(int64_t obj, const char *name, int64_t len, int64_t bits)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	char *nm = name_of(name, len);
	e = nm ? set_raw_body(o, nm, (uint64_t)bits) : abi_fail(BML_OTHER, "bml: a negative length or a NULL string with a length");
	free(nm);
	abi_object_release(o);
	return e;
}

/* Freezes a map (BPF_MAP_FREEZE: writes and deletes from user space then fail with EPERM). A map that does not exist is STATE. */
int64_t bml_testonly_freeze_map(int64_t obj, const char *name, int64_t len)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	char *nm = name_of(name, len);
	struct bpf_map *m = nm ? map_named(o, nm) : NULL;
	if (!nm)
		e = abi_fail(BML_OTHER, "bml: a negative length or a NULL string with a length");
	else if (!m)
		e = abi_fail(BML_STATE, "bml: the embedded object has no map %s", nm);
	else if (BML_MUT("testonly.freeze_noop")) /* mutation control: do not freeze (only the test that expects the write after the freeze to fail with EPERM then fails) */
		e = abi_ok(0);
	else if (bpf_map_freeze(bpf_map__fd(m)) != 0)
		e = abi_fail(BML_OTHER, "bml: freeze %s: %s", nm, abi_errno(errno));
	else
		e = abi_ok(0);
	free(nm);
	abi_object_release(o);
	return e;
}

/* Maps the consumer page of a ring buffer, unmaps it and then reads it. It does not return: the
 * process dies with SIGSEGV. bml installs no signal handler, so the downstream runtime's handler or
 * the default action takes over; this fixes the fail-loud behaviour. If the mapping cannot be made,
 * the result is OTHER. */
int64_t bml_testonly_ringbuf_fault(int64_t obj, const char *name, int64_t len)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	char *nm = name_of(name, len);
	struct bpf_map *m = nm ? map_named(o, nm) : NULL;
	if (!m || bpf_map__type(m) != BPF_MAP_TYPE_RINGBUF) {
		e = abi_fail(BML_STATE, "bml: the embedded object has no ring buffer %s", nm ? nm : "");
		free(nm);
		abi_object_release(o);
		return e;
	}
	free(nm);
	long pg = sysconf(_SC_PAGESIZE);
	volatile uint8_t *p = mmap(NULL, (size_t)pg, PROT_READ | PROT_WRITE, MAP_SHARED, bpf_map__fd(m), 0);
	if (p == MAP_FAILED) {
		e = abi_fail(BML_OTHER, "bml: ringbuf_fault: mmap: %s", abi_errno(errno));
		abi_object_release(o);
		return e;
	}
	munmap((void *)p, (size_t)pg);
	uint8_t x = p[0]; /* a deliberate fault */
	abi_object_release(o);
	return abi_ok(x); /* not reached */
}
#endif
