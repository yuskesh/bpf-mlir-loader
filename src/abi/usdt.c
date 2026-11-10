






#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "abi/internal.h"
#include "load/load.h"
#include "req/usdt.h"
#include "util/mutation.h"

#ifdef BML_TEST_CAPS
#include <pthread.h>

#include "bml/bml_testonly.h"

static pthread_mutex_t usdt_mu = PTHREAD_MUTEX_INITIALIZER;
static int usdt_force_perf;

int64_t bml_testonly_usdt_mode(const char *mode, int64_t len)
{
	int m = len == 0 ? 0 : len == 5 && !memcmp(mode, "multi", 5) ? 1 : len == 10 && !memcmp(mode, "multi_perf", 10) ? 2 : -1;
	if (m < 0)
		return abi_fail(BML_OTHER, "bml: testonly_usdt_mode: the modes are \"\", \"multi\" and \"multi_perf\"");
	bml_load_testonly_usdt_multi(m != 0);
	pthread_mutex_lock(&usdt_mu);
	usdt_force_perf = m == 2;
	pthread_mutex_unlock(&usdt_mu);
	return abi_ok(0);
}

static int force_perf(void)
{
	pthread_mutex_lock(&usdt_mu);
	int f = usdt_force_perf;
	pthread_mutex_unlock(&usdt_mu);
	return f;
}
#else
static int force_perf(void)
{
	return 0;
}
#endif

static int str_is(const struct bml_str *s, const char *z)
{
	return s->len == strlen(z) && !memcmp(s->p, z, s->len);
}

const struct bml_attach *abi_usdt_row(const struct abi_object *o, const char *name)
{
	for (size_t i = 0; i < o->req->n_attaches; i++) {
		const struct bml_attach *a = &o->req->attaches[i];
		if (str_is(&a->program, name) && str_is(&a->attach_type, "usdt"))
			return a;
	}
	return NULL;
}


static int64_t attach_points(struct bpf_program *p, const char *name, int pid, const char *fdpath, const struct bml_usdt_attach_point *pts, size_t n,
			     struct bpf_link **ls)
{
	for (size_t i = 0; i < n; i++) {
		uint64_t cookie = BML_MUT("usdt.cookie_zero") ? 0 : pts[i].index;
		LIBBPF_OPTS(bpf_uprobe_opts, uo, .bpf_cookie = cookie, .ref_ctr_offset = BML_MUT("usdt.no_ref_ctr") ? 0 : (size_t)pts[i].sem_off);
		ls[i] = bpf_program__attach_uprobe_opts(p, pid, fdpath, (size_t)pts[i].off, &uo);
		if (!ls[i])
			return abi_fail(BML_OTHER, "bml: attach usdt %s point %zu (pc 0x%llx): %s", name, i, (unsigned long long)pts[i].pc, abi_errno(errno));
		uint32_t got = 0;
		uint64_t got_cookie = 0;
		char file[4096];
		int rc = abi_uprobe_info(bpf_link__fd(ls[i]), BPF_PERF_EVENT_UPROBE, &got, &got_cookie, file, sizeof file);
		if (rc != 0 || got != pts[i].off || got_cookie != cookie)
			return abi_fail(BML_OTHER, "bml: attach usdt %s point %zu: the perf link info (%s) does not show offset 0x%llx and cookie %llu", name, i,
					rc < 0 ? abi_errno(-rc) : rc > 0 ? "not a uprobe" : "differs", (unsigned long long)pts[i].off,
					(unsigned long long)cookie);
	}
	return 0;
}


static int64_t attach_multi(struct bpf_program *p, const char *name, int pid, const char *fdpath, const struct bml_usdt_attach_point *pts, size_t n,
			    struct bpf_link **l)
{
	unsigned long *offs = calloc(n, sizeof *offs), *refs = calloc(n, sizeof *refs);
	__u64 *cks = calloc(n, sizeof *cks), *g_offs = calloc(n, sizeof *g_offs), *g_refs = calloc(n, sizeof *g_refs), *g_cks = calloc(n, sizeof *g_cks);
	int64_t e = 0;
	if (!offs || !refs || !cks || !g_offs || !g_refs || !g_cks) {
		e = abi_fail(BML_OTHER, "bml: out of memory");
		goto out;
	}
	for (size_t i = 0; i < n; i++) {
		offs[i] = pts[i].off;
		refs[i] = BML_MUT("usdt.no_ref_ctr") ? 0 : pts[i].sem_off;
		cks[i] = BML_MUT("usdt.cookie_zero") ? 0 : pts[i].index;
	}
	LIBBPF_OPTS(bpf_uprobe_multi_opts, mo, .offsets = offs, .ref_ctr_offsets = refs, .cookies = cks, .cnt = n);
	*l = bpf_program__attach_uprobe_multi(p, pid, fdpath, NULL, &mo);
	if (!*l) {
		e = abi_fail(BML_OTHER, "bml: attach usdt %s (uprobe_multi, %zu points): %s", name, n, abi_errno(errno));
		goto out;
	}
	struct bpf_link_info info;
	uint32_t len = sizeof info;
	memset(&info, 0, sizeof info);
	info.uprobe_multi.offsets = (uintptr_t)g_offs;
	info.uprobe_multi.ref_ctr_offsets = (uintptr_t)g_refs;
	info.uprobe_multi.cookies = (uintptr_t)g_cks;
	info.uprobe_multi.count = (uint32_t)n;
	if (bpf_link_get_info_by_fd(bpf_link__fd(*l), &info, &len) != 0 || info.type != BPF_LINK_TYPE_UPROBE_MULTI || info.uprobe_multi.count != n) {
		e = abi_fail(BML_OTHER, "bml: attach usdt %s: the uprobe_multi link info does not show %zu points", name, n);
		goto out;
	}
	for (size_t i = 0; i < n && !e; i++)
		if (g_offs[i] != offs[i] || g_cks[i] != cks[i] || g_refs[i] != refs[i])
			e = abi_fail(BML_OTHER, "bml: attach usdt %s: the uprobe_multi link info point %zu differs (offset 0x%llx cookie %llu ref_ctr 0x%llx)", name,
				     i, (unsigned long long)g_offs[i], (unsigned long long)g_cks[i], (unsigned long long)g_refs[i]);
out:
	free(offs);
	free(refs);
	free(cks);
	free(g_offs);
	free(g_refs);
	free(g_cks);
	return e;
}

static int64_t attach_usdt_body(int64_t obj, const char *prog, int64_t plen, int64_t pid)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, plen, &p)))
		return e;
	const char *name = bpf_program__name(p);
	const struct bml_attach *a = abi_usdt_row(o, name);
	if (bpf_program__type(p) != BPF_PROG_TYPE_KPROBE || !a)
		return abi_fail(BML_STATE, "bml: %s is a %s program, not usdt — attach it with its own kind", name, abi_kind_name(o, p));
	int fd = abi_uprobe_target_fd(o, name);
	if (fd < 0)
		return abi_fail(BML_STATE, "bml: usdt %s has no target (it was not given to load — a checked load would have stopped)", name);
	if (pid < 0 || pid > INT32_MAX)
		return abi_fail(BML_OTHER, "bml: attach usdt %s: pid %lld is out of range (0 is every process)", name, (long long)pid);

	char pn[256];
	snprintf(pn, sizeof pn, "%.*s", (int)a->target.len, a->target.p);
	char *colon = strchr(pn, ':');
	if (!colon)
		return abi_fail(BML_OTHER, "bml: attach usdt %s: the attach target %s is not <provider>:<name>", name, pn);
	*colon = 0;
	size_t len = 0;
	uint8_t *data = abi_read_fd(fd, &len);
	if (!data)
		return abi_fail(BML_OTHER, "bml: attach usdt %s: reading the target: %s", name, abi_errno(errno));
	struct bml_usdt_attach_point *pts = NULL;
	size_t n = 0;
	char *why = NULL;
	int prc = bml_usdt_attach_points(data, len, pn, colon + 1, &pts, &n, &why);
	free(data);
	if (prc != 0) {
		e = abi_fail(BML_OTHER, "bml: attach usdt %s: %s", name, why ? why : "out of memory");
		free(why);
		return e;
	}

	char mname[BPF_OBJ_NAME_LEN + 64];
	snprintf(mname, sizeof mname, "%s%s", BML_USDT_SPEC_MAP_PREFIX, name);
	struct bpf_map *m = bpf_object__find_map_by_name(bml_obj_bpf(o->lo), mname);
	if (m && (bpf_map__key_size(m) != 4 || bpf_map__value_size(m) != BML_USDT_SPEC_SIZE)) {
		e = abi_fail(BML_OTHER, "bml: attach usdt %s: the spec map has key %u / value %u bytes, want 4 / %d (requirements_format.md §8)", name,
			     bpf_map__key_size(m), bpf_map__value_size(m), BML_USDT_SPEC_SIZE);
		goto out;
	}
	if (m && n > bpf_map__max_entries(m)) {
		e = abi_fail(BML_OTHER, "bml: attach usdt %s: %s:%s has %zu points, but the spec map holds %u (max_points)", name, pn, colon + 1, n,
			     bpf_map__max_entries(m));
		goto out;
	}
	for (size_t i = 0; m && i < n && !BML_MUT("usdt.spec_skip"); i++) {
		uint32_t k = (uint32_t)pts[i].index;
		if (bpf_map__update_elem(m, &k, sizeof k, pts[i].spec, BML_USDT_SPEC_SIZE, 0) != 0) {
			e = abi_fail(BML_OTHER, "bml: attach usdt %s: spec of point %zu: %s", name, i, abi_errno(errno));
			goto out;
		}
	}
	char fdpath[32];
	snprintf(fdpath, sizeof fdpath, "/proc/self/fd/%d", fd);
	int kpid = pid == 0 ? -1 : (int)pid;
	if (bpf_program__expected_attach_type(p) == BPF_TRACE_UPROBE_MULTI && !force_perf()) {
		struct bpf_link *l = NULL;
		if ((e = attach_multi(p, name, kpid, fdpath, pts, n, &l))) {
			bpf_link__destroy(l);
			goto out;
		}
		e = abi_link_put(l);
		goto out;
	}
	struct bpf_link **ls = calloc(n, sizeof *ls);
	if (!ls) {
		e = abi_fail(BML_OTHER, "bml: out of memory");
		goto out;
	}
	if ((e = attach_points(p, name, kpid, fdpath, pts, n, ls))) {
		for (size_t i = 0; i < n; i++)
			bpf_link__destroy(ls[i]);
		free(ls);
		goto out;
	}
	e = abi_link_put_more(ls[0], ls + 1, n - 1);
	free(ls);
out:
	free(pts);
	return e;
}

int64_t bml_attach_usdt(int64_t obj, const char *prog, int64_t prog_len, int64_t pid)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_usdt_body(obj, prog, prog_len, pid);
	abi_object_release(o);
	return e;
}
