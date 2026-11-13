#define _GNU_SOURCE
#include "abi/internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "elf/elf.h"
#include "req/uprobe.h"
#include "json/json.h"
#include "util/mutation.h"

static int str_is(const struct bml_str *s, const char *lit)
{
	return s->len == strlen(lit) && memcmp(s->p, lit, s->len) == 0;
}


static const struct bml_attach *uprobe_row(const struct abi_object *o, const char *name, int *ret)
{
	for (size_t i = 0; i < o->req->n_attaches; i++) {
		const struct bml_attach *a = &o->req->attaches[i];
		if (str_is(&a->program, name) && (str_is(&a->attach_type, "uprobe") || str_is(&a->attach_type, "uretprobe"))) {
			if (ret)
				*ret = str_is(&a->attach_type, "uretprobe");
			return a;
		}
	}
	return NULL;
}

static int64_t unreadable(const char *why)
{
	return abi_fail(BML_PRECHECK_FAILED, "bml: the uprobe targets are unreadable: %s", why);
}

int64_t abi_uprobe_targets(struct abi_object *o, const char *doc, int64_t len)
{
	if (len <= 0)
		return 0;
	struct bml_json *j = NULL;
	char *err = NULL;
	if (bml_json_parse(doc, (size_t)len, &j, &err) != 0) {
		int64_t e = unreadable(err ? err : "");
		free(err);
		return e;
	}
	int64_t e = 0;
	const struct bml_json *ts = j->type == BML_JSON_OBJECT ? bml_json_get(j, "uprobe_targets") : NULL;
	const struct bml_json *dr = j->type == BML_JSON_OBJECT ? bml_json_get(j, "debug_root") : NULL;
	if (j->type != BML_JSON_OBJECT || (j->n && !ts) || j->n > 1 + (dr != NULL)) {
		e = unreadable("want an object {\"uprobe_targets\": [{\"program\": …, \"path\": …, \"debug\": …}], \"debug_root\": …} (no other keys)");
		goto out;
	}
	if (!ts || ts->type != BML_JSON_ARRAY) {
		e = unreadable("no \"uprobe_targets\" array");
		goto out;
	}
	if (dr) {
		if (dr->type != BML_JSON_STRING || strlen(dr->str) != dr->len) {
			e = unreadable("debug_root is a string");
			goto out;
		}
		free(o->caps.debug_root);
		if (!(o->caps.debug_root = strdup(dr->str))) {
			e = abi_fail(BML_OTHER, "bml: out of memory");
			goto out;
		}
	}
	for (size_t i = 0; i < ts->n && !e; i++) {
		const struct bml_json *t = ts->items[i];
		const struct bml_json *p = t->type == BML_JSON_OBJECT ? bml_json_get(t, "program") : NULL,
				      *f = t->type == BML_JSON_OBJECT ? bml_json_get(t, "path") : NULL,
				      *dg = t->type == BML_JSON_OBJECT ? bml_json_get(t, "debug") : NULL;
		int keys_ok = t->type == BML_JSON_OBJECT;
		for (size_t k = 0; keys_ok && k < t->n; k++)
			keys_ok = !strcmp(t->members[k].key, "program") || !strcmp(t->members[k].key, "path") || !strcmp(t->members[k].key, "debug");
		if (!keys_ok || (p && p->type != BML_JSON_STRING) || (f && f->type != BML_JSON_STRING) ||
		    (dg && (dg->type != BML_JSON_STRING || !dg->len || strlen(dg->str) != dg->len))) {
			e = unreadable("a uprobe target is an object with the strings program and path (and a non-empty debug)");
			break;
		}
		if (!p || !f || !p->len || !f->len || strlen(p->str) != p->len || strlen(f->str) != f->len) {
			e = unreadable("a uprobe target needs a program and a path");
			break;
		}
		for (size_t k = 0; k < o->caps.n_bins; k++)
			if (!strcmp(o->caps.bins[k].program, p->str))
				e = abi_fail(BML_PRECHECK_FAILED, "bml: the uprobe targets are unreadable: program %s is given two uprobe targets", p->str);
		if (e)
			break;
		if (!uprobe_row(o, p->str, NULL) && !abi_usdt_row(o, p->str)) {
			e = abi_fail(BML_OTHER, "bml: uprobe target for %s: the embedded object has no uprobe, uretprobe or usdt program %s", p->str, p->str);
			break;
		}
		struct bml_live_bin *nb = realloc(o->caps.bins, (o->caps.n_bins + 1) * sizeof *nb);
		if (!nb) {
			e = abi_fail(BML_OTHER, "bml: out of memory");
			break;
		}
		o->caps.bins = nb;
		int fd = open(f->str, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			e = abi_fail(BML_OTHER, "bml: uprobe target for %s: open %s: %s", p->str, f->str, abi_errno(errno));
			break;
		}
		nb[o->caps.n_bins] = (struct bml_live_bin){strdup(p->str), strdup(f->str), fd};
		o->caps.n_bins++;
		if (dg) {
			struct bml_live_debug *nd = realloc(o->caps.debugs, (o->caps.n_debugs + 1) * sizeof *nd);
			if (!nd) {
				e = abi_fail(BML_OTHER, "bml: out of memory");
				break;
			}
			o->caps.debugs = nd;
			nd[o->caps.n_debugs++] = (struct bml_live_debug){strdup(p->str), strdup(dg->str)};
		}
	}
out:
	bml_json_free(j);
	return e;
}


int abi_uprobe_target_fd(const struct abi_object *o, const char *prog)
{
	for (size_t i = o->caps.n_bins; i-- > 0;)
		if (!strcmp(o->caps.bins[i].program, prog))
			return o->caps.bins[i].fd;
	return -1;
}


uint8_t *abi_read_fd(int fd, size_t *len)
{
	size_t cap = 1 << 16, n = 0;
	uint8_t *b = malloc(cap);
	while (b) {
		if (n == cap) {
			uint8_t *nb = realloc(b, cap *= 2);
			if (!nb)
				break;
			b = nb;
		}
		ssize_t r = pread(fd, b + n, cap - n, (off_t)n);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0)
			break;
		if (r == 0) {
			*len = n;
			return b;
		}
		n += (size_t)r;
	}
	int e = errno ? errno : ENOMEM;
	free(b);
	errno = e;
	return NULL;
}

#ifdef BML_TEST_CAPS

#include <pthread.h>

#include "bml/bml_testonly.h"

static pthread_mutex_t test_mu = PTHREAD_MUTEX_INITIALIZER;
static char test_prog[256], test_sym[256];
static int test_mode;

int64_t bml_testonly_uprobe_symbol(const char *prog, int64_t pl, const char *sym, int64_t sl)
{
	if (pl < 0 || sl < 0 || (!prog && pl) || (!sym && sl) || pl >= (int64_t)sizeof test_prog || sl >= (int64_t)sizeof test_sym)
		return abi_fail(BML_OTHER, "bml: testonly_uprobe_symbol: a bad length");
	pthread_mutex_lock(&test_mu);
	snprintf(test_prog, sizeof test_prog, "%.*s", (int)pl, prog ? prog : "");
	snprintf(test_sym, sizeof test_sym, "%.*s", (int)sl, sym ? sym : "");
	pthread_mutex_unlock(&test_mu);
	return abi_ok(0);
}

int64_t bml_testonly_uprobe_offset_mode(const char *mode, int64_t ml)
{
	int m = ml == 0 ? 0 : ml == 11 && !memcmp(mode, "no_p_offset", 11) ? 1 : ml == 5 && !memcmp(mode, "vaddr", 5) ? 2 : -1;
	if (m < 0)
		return abi_fail(BML_OTHER, "bml: testonly_uprobe_offset_mode: the modes are \"\", \"no_p_offset\" and \"vaddr\"");
	pthread_mutex_lock(&test_mu);
	test_mode = m;
	pthread_mutex_unlock(&test_mu);
	return abi_ok(0);
}


static const char *test_symbol_for(const char *prog, const char *sym, char *buf, size_t cap)
{
	pthread_mutex_lock(&test_mu);
	int hit = test_sym[0] && !strcmp(test_prog, prog);
	if (hit)
		snprintf(buf, cap, "%s", test_sym);
	pthread_mutex_unlock(&test_mu);
	return hit ? buf : sym;
}

static int test_offset_mode(void)
{
	pthread_mutex_lock(&test_mu);
	int m = test_mode;
	pthread_mutex_unlock(&test_mu);
	return m;
}
#endif


static int file_offset(int fd, const char *sym, uint64_t *off, char **why)
{
	size_t len = 0;
	uint8_t *data = abi_read_fd(fd, &len);
	if (!data)
		return asprintf(why, "reading the target: %s", abi_errno(errno)) < 0 ? (*why = NULL, -1) : -1;
	struct bml_elf elf;
	char *err = NULL;
	int rc = -1;
	if (bml_elf_open(data, len, &elf, &err) != 0) {
		*why = err;
		free(data);
		return -1;
	}

	uint64_t val = 0, vaddr = 0;
	if (bml_uprobe_file_offset(&elf, sym, off, &val, &vaddr, why) == 0) {
		if (BML_MUT("uprobe.offset_no_p_offset"))
			*off = val - vaddr;
#ifdef BML_TEST_CAPS
		if (test_offset_mode() == 1)
			*off = val - vaddr;
		else if (test_offset_mode() == 2)
			*off = val;
#endif
		rc = 0;
	}
	bml_elf_close(&elf);
	free(data);
	return rc;
}


int abi_uprobe_info(int fd, uint32_t want, uint32_t *off, uint64_t *cookie, char *file, uint32_t cap)
{
	struct bpf_link_info info;
	uint32_t len = sizeof info;
	memset(&info, 0, sizeof info);
	file[0] = 0;
	info.perf_event.uprobe.file_name = (uint64_t)(uintptr_t)file;
	info.perf_event.uprobe.name_len = cap;
	if (bpf_link_get_info_by_fd(fd, &info, &len) != 0)
		return -errno;
	file[cap - 1] = 0;
	if (info.type != BPF_LINK_TYPE_PERF_EVENT || info.perf_event.type != want)
		return 1;
	*off = info.perf_event.uprobe.offset;
	if (cookie)
		*cookie = info.perf_event.uprobe.cookie;
	return 0;
}


static int64_t attach_uprobe_body(int64_t obj, const char *prog, int64_t plen, int64_t pid, int ret)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, plen, &p)))
		return e;
	const char *name = bpf_program__name(p), *kind = ret ? "uretprobe" : "uprobe";
	int row_ret = 0;
	const struct bml_attach *a = uprobe_row(o, name, &row_ret);
	if (bpf_program__type(p) != BPF_PROG_TYPE_KPROBE || !a || row_ret != ret)
		return abi_fail(BML_STATE,
				"bml: %s is a %s program, not %s — attach it with its own kind (attach_xdp / attach_fentry / attach_fexit / attach_tcx / attach_kprobe / "
				"attach_kretprobe / attach_uprobe / attach_uretprobe)",
				name, abi_kind_name(o, p), kind);
	int fd = abi_uprobe_target_fd(o, name);
	if (fd < 0)
		return abi_fail(BML_STATE, "bml: %s %s has no target (it was not given to load — a checked load would have stopped)", kind, name);
	if (pid < 0 || pid > INT32_MAX)
		return abi_fail(BML_OTHER, "bml: attach %s %s: pid %lld is out of range (0 is every process)", kind, name, (long long)pid);
	const char *sym = a->target.p;
	uint64_t off = 0;
	char *why = NULL;
	const char *at = BML_MUT("uprobe.symbol_other") ? "main" : sym;
#ifdef BML_TEST_CAPS
	char tbuf[256];
	at = test_symbol_for(name, at, tbuf, sizeof tbuf);
#endif
	if (file_offset(fd, at, &off, &why) != 0) {
		e = abi_fail(BML_OTHER, "bml: attach %s %s: %s", kind, name, why ? why : "out of memory");
		free(why);
		return e;
	}
	char fdpath[32];
	snprintf(fdpath, sizeof fdpath, "/proc/self/fd/%d", fd);
	LIBBPF_OPTS(bpf_uprobe_opts, uo, .retprobe = ret != 0);

	struct bpf_link *l = bpf_program__attach_uprobe_opts(p, pid == 0 ? -1 : (pid_t)pid, fdpath, (size_t)off, &uo);
	if (!l) {
		int err = errno;
		return abi_fail(BML_OTHER, "bml: attach %s %s to %s: %s%s", kind, name, sym, abi_errno(err),
				err == EPERM || err == EACCES
					? " (hint: attaching a uprobe needs CAP_SYS_ADMIN in addition to CAP_BPF + CAP_PERFMON — bpf-mlir nonroot.md)"
					: "");
	}

	uint32_t got = 0;
	char file[4096];
	int rc = abi_uprobe_info(bpf_link__fd(l), ret ? BPF_PERF_EVENT_URETPROBE : BPF_PERF_EVENT_UPROBE, &got, NULL, file, sizeof file);
	if (rc == 0 && ret && BML_MUT("attach.uretprobe_offset_other"))
		got += 16;
	if (rc < 0) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: attach %s %s: reading the perf link info: %s (detached)", kind, name, abi_errno(-rc));
	}
	if (rc > 0) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: attach %s %s: the perf link info has no %s (cannot confirm the attach offset 0x%llx — detached)", kind, name, kind,
				(unsigned long long)off);
	}
	if (got != off) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: attach %s %s: the kernel attached it at offset 0x%x, but the checked target's %s is at 0x%llx (detached)", kind,
				name, got, sym, (unsigned long long)off);
	}
	char *f = strdup(file);
	if (!f) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: out of memory");
	}
	return abi_link_put_uprobe(l, obj, f);
}

int64_t bml_attach_uprobe(int64_t obj, const char *prog, int64_t prog_len, int64_t pid)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_uprobe_body(obj, prog, prog_len, pid, 0);
	abi_object_release(o);
	return e;
}

int64_t bml_attach_uretprobe(int64_t obj, const char *prog, int64_t prog_len, int64_t pid)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_uprobe_body(obj, prog, prog_len, pid, 1);
	abi_object_release(o);
	return e;
}

int64_t bml_uprobe_link_file(int64_t obj, int64_t link)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	abi_lock();
	struct abi_link *al = abi_handle_get(link, H_LINK);
	char *f = al && al->uprobe_owner == obj && al->uprobe_file ? strdup(al->uprobe_file) : NULL;
	int mine = al && al->uprobe_owner == obj && al->uprobe_file;
	abi_unlock();
	abi_object_release(o);
	if (!mine)
		return abi_fail(BML_STATE, "bml: link %lld is not a uprobe link of this object", (long long)link);
	if (!f)
		return abi_fail(BML_OTHER, "bml: out of memory");
	struct abi_result r = {.kind = BML_OK, .msg = f, .msg_len = strlen(f)};
	return abi_put(&r);
}
