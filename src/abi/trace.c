/* CONTRACT: fentry / fexit / kprobe attach
 * and the tracing test run.
 * - The kind comes from libbpf's program type and expected attach type. The kprobe / uprobe distinction and the kprobe function come from the requirements attach row (the declaration
 *   checked before load)
 * - kprobe: after attaching, the function name in the perf link info is compared with the declaration; different or unreadable: detach and BML_OTHER (libbpf v1.7 does not
 *   re-target to an alias, but what the kernel actually attached to is not accepted silently)
 * - test_run_tracing: runs a repeat-1 test run n times on a short-lived thread different from the caller and joins before returning. value is that thread's tid (tid != tgid, so
 *   a pid / tgid mix-up shows in the value). **This is the only place the library creates a thread**: the new thread
 *   starts with all signals blocked (pthread_attr_setsigmask_np; the caller's mask is not touched, so a downstream runtime's handler does not run on a thread with no
 *   runtime context), and is joined before returning (no thread is left behind) */
#define _GNU_SOURCE
#include "abi/internal.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "util/mutation.h"

static int str_is(const struct bml_str *s, const char *lit)
{
	return s->len == strlen(lit) && memcmp(s->p, lit, s->len) == 0;
}


static const struct bml_attach *attach_row(const struct abi_object *o, const char *name)
{
	for (size_t i = 0; i < o->req->n_attaches; i++)
		if (str_is(&o->req->attaches[i].program, name))
			return &o->req->attaches[i];
	return NULL;
}


const char *abi_kind_name(const struct abi_object *o, struct bpf_program *p)
{
	const struct bml_attach *a = attach_row(o, bpf_program__name(p));
	enum bpf_attach_type at = bpf_program__expected_attach_type(p);
	switch (bpf_program__type(p)) {
	case BPF_PROG_TYPE_XDP:
		return "xdp";
	case BPF_PROG_TYPE_TRACING:
		if (at == BPF_TRACE_FENTRY)
			return "fentry";
		if (at == BPF_TRACE_FEXIT)
			return "fexit";
		if (at == BPF_TRACE_RAW_TP)
			return "tp_btf";
		if (at == BPF_MODIFY_RETURN)
			return "fmod_ret";
		if (at == BPF_TRACE_ITER)
			return "iter";
		break;
	case BPF_PROG_TYPE_RAW_TRACEPOINT:
		return "raw_tp";
	case BPF_PROG_TYPE_CGROUP_SKB:
		return at == BPF_CGROUP_INET_EGRESS ? "cgroup_skb egress" : "cgroup_skb ingress";
	case BPF_PROG_TYPE_SK_LOOKUP:
		return "sk_lookup";
	case BPF_PROG_TYPE_FLOW_DISSECTOR:
		return "flow_dissector";
	case BPF_PROG_TYPE_SOCKET_FILTER:
		return "socket_filter";
	case BPF_PROG_TYPE_KPROBE:
		if (a && str_is(&a->attach_type, "uprobe"))
			return "uprobe";
		if (a && str_is(&a->attach_type, "uretprobe"))
			return "uretprobe";
		if (a && str_is(&a->attach_type, "kretprobe"))
			return "kretprobe";
		if (a && str_is(&a->attach_type, "ksyscall"))
			return "ksyscall";
		return "kprobe";
	case BPF_PROG_TYPE_SCHED_CLS:
		if (at == BPF_TCX_INGRESS)
			return "tc ingress";
		if (at == BPF_TCX_EGRESS)
			return "tc egress";
		if (at == BPF_NETKIT_PRIMARY)
			return "netkit primary";
		if (at == BPF_NETKIT_PEER)
			return "netkit peer";
		break;
	default:
		break;
	}
	const char *s = libbpf_bpf_prog_type_str(bpf_program__type(p));
	return s ? s : "?";
}

static int64_t attach_trace_body(int64_t obj, const char *prog, int64_t len, enum bpf_attach_type want, const char *wname, const char *others)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, len, &p)))
		return e;
	if (bpf_program__type(p) != BPF_PROG_TYPE_TRACING || bpf_program__expected_attach_type(p) != want)
		return abi_fail(BML_STATE, "bml: %s is a %s program, not %s — attach it with its own kind (%s)", bpf_program__name(p), abi_kind_name(o, p),
				wname, others);
	struct bpf_link *l = bpf_program__attach_trace(p);
	if (!l)
		return abi_fail(BML_OTHER, "bml: attach %s %s: %s", wname, bpf_program__name(p), abi_errno(errno));
	return abi_link_put(l);
}


int abi_kprobe_link_name(int fd, uint32_t want, char *buf, uint32_t cap)
{
	struct bpf_link_info info;
	uint32_t len = sizeof info;
	memset(&info, 0, sizeof info);
	buf[0] = 0;
	info.perf_event.kprobe.func_name = (uint64_t)(uintptr_t)buf;
	info.perf_event.kprobe.name_len = cap;
	if (bpf_link_get_info_by_fd(fd, &info, &len) != 0)
		return -errno;
	if (info.type != BPF_LINK_TYPE_PERF_EVENT || info.perf_event.type != want)
		buf[0] = 0;
	buf[cap - 1] = 0;
	return 0;
}


static int64_t attach_kprobe_body(int64_t obj, const char *prog, int64_t len, int ret)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, len, &p)))
		return e;
	const char *name = bpf_program__name(p), *kind = ret ? "kretprobe" : "kprobe";
	const struct bml_attach *a = attach_row(o, name);
	const char *got_kind = abi_kind_name(o, p);
	if (bpf_program__type(p) != BPF_PROG_TYPE_KPROBE || strcmp(got_kind, kind) != 0 || (!a && ret))
		return abi_fail(BML_STATE,
				"bml: %s is a %s program, not %s — attach it with its own kind (attach_xdp / attach_fentry / attach_fexit / attach_tcx / attach_kprobe / "
				"attach_kretprobe / attach_uprobe / attach_uretprobe)",
				name, got_kind, kind);
	if (!a || !str_is(&a->attach_type, kind) || a->target.len == 0 || strlen(a->target.p) != a->target.len)
		return abi_fail(BML_OTHER, "bml: %s %s: the ELF declares no kernel function (an attach row %s <fn>)", kind, name, kind);
	const char *fn = a->target.p;
	LIBBPF_OPTS(bpf_kprobe_opts, ko, .retprobe = ret != 0);
	struct bpf_link *l = bpf_program__attach_kprobe_opts(p, fn, &ko);
	if (!l) {
		int err = errno;
		return abi_fail(BML_OTHER, "bml: attach %s %s to %s: %s%s", kind, name, fn, abi_errno(err),
				err == EPERM ? " (hint: attaching a kprobe needs CAP_PERFMON; perf_event_paranoid may also restrict it)" : "");
	}

	char got[512];
	int rc = abi_kprobe_link_name(bpf_link__fd(l), ret ? BPF_PERF_EVENT_KRETPROBE : BPF_PERF_EVENT_KPROBE, got, sizeof got);
	if (rc == 0 && BML_MUT(ret ? "attach.kretprobe_info_other" : "trace.kprobe_info_other"))
		snprintf(got, sizeof got, "__x64_%s", fn);
	if (rc != 0) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: attach %s %s: reading the perf link info: %s (detached)", kind, name, abi_errno(-rc));
	}
	if (strcmp(got, fn) != 0) {
		bpf_link__destroy(l);
		if (!got[0])
			return abi_fail(BML_OTHER, "bml: attach %s %s: the perf link info has no %s function name (cannot confirm the attach target %s — detached)",
					kind, name, kind, fn);
		return abi_fail(BML_OTHER, "bml: attach %s %s: the kernel attached it to %s, but the ELF declares %s (detached)", kind, name, got, fn);
	}
	return abi_link_put(l);
}


#ifdef BML_TEST_CAPS

static pthread_mutex_t tp_mu = PTHREAD_MUTEX_INITIALIZER;
static char tp_declared[128];
int64_t bml_testonly_tpbtf_declared(const char *tp, int64_t len)
{
	if (len < 0 || (size_t)len >= sizeof tp_declared || (len > 0 && !tp))
		return abi_fail(BML_VALUE_RANGE, "bml: testonly tpbtf_declared: the name length %lld is out of range", (long long)len);
	pthread_mutex_lock(&tp_mu);
	if (len > 0)
		memcpy(tp_declared, tp, (size_t)len);
	tp_declared[len] = 0;
	pthread_mutex_unlock(&tp_mu);
	return abi_ok(0);
}
#endif


static int tp_link_name(int fd, char *buf, uint32_t cap)
{
	struct bpf_link_info info;
	uint32_t len = sizeof info;
	memset(&info, 0, sizeof info);
	buf[0] = 0;
	info.raw_tracepoint.tp_name = (uint64_t)(uintptr_t)buf;
	info.raw_tracepoint.tp_name_len = cap;
	if (bpf_link_get_info_by_fd(fd, &info, &len) != 0)
		return -errno;
	if (info.type != BPF_LINK_TYPE_RAW_TRACEPOINT)
		buf[0] = 0;
	buf[cap - 1] = 0;
	return 0;
}

static int64_t attach_tp_btf_body(int64_t obj, const char *prog, int64_t len)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, len, &p)))
		return e;
	const char *name = bpf_program__name(p);
	if (bpf_program__type(p) != BPF_PROG_TYPE_TRACING ||
	    (bpf_program__expected_attach_type(p) != BPF_TRACE_RAW_TP && !BML_MUT("trace.tpbtf_kind_fentry")))
		return abi_fail(BML_STATE, "bml: %s is a %s program, not tp_btf — attach it with its own kind (attach_xdp / attach_fentry / attach_fexit / "
				"attach_kprobe / attach_tcx)", name, abi_kind_name(o, p));
	const struct bml_attach *a = attach_row(o, name);
	if (!a || !str_is(&a->attach_type, "trace_raw_tp") || a->target.len == 0 || strlen(a->target.p) != a->target.len)
		return abi_fail(BML_OTHER, "bml: tp_btf %s: the ELF declares no tracepoint (an attach row trace_raw_tp <tracepoint>)", name);
	char want[128];
	snprintf(want, sizeof want, "%s", a->target.p);
#ifdef BML_TEST_CAPS
	pthread_mutex_lock(&tp_mu);
	if (tp_declared[0])
		snprintf(want, sizeof want, "%s", tp_declared);
	pthread_mutex_unlock(&tp_mu);
#endif
	struct bpf_link *l = bpf_program__attach_trace(p);
	if (!l)
		return abi_fail(BML_OTHER, "bml: attach tp_btf %s: %s", name, abi_errno(errno));

	char got[256];
	int rc = tp_link_name(bpf_link__fd(l), got, sizeof got);
	if (rc != 0) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: attach tp_btf %s: reading the raw tracepoint link info: %s (detached)", name, abi_errno(-rc));
	}
	if (strcmp(got, want) != 0 && !BML_MUT("trace.tpbtf_no_name_check")) {
		bpf_link__destroy(l);
		if (!got[0])
			return abi_fail(BML_OTHER, "bml: attach tp_btf %s: the link info has no tracepoint name (cannot confirm the attach target %s — detached)",
					name, want);
		return abi_fail(BML_OTHER, "bml: attach tp_btf %s: the kernel attached it to %s, but the ELF declares %s (detached)", name, got, want);
	}
	return abi_link_put(l);
}


struct trun {
	int fd;
	int64_t n, done;
	int err;
	pid_t tid;
	sigset_t mask;
};

static void *trun_main(void *arg)
{
	struct trun *x = arg;
	x->tid = (pid_t)syscall(SYS_gettid);
#ifdef BML_TEST_CAPS
	pthread_sigmask(SIG_BLOCK, NULL, &x->mask);
#endif
	for (int64_t i = 0; i < x->n; i++) {
		LIBBPF_OPTS(bpf_test_run_opts, t, .repeat = 1);
		if (bpf_prog_test_run_opts(x->fd, &t) != 0) {
			x->err = errno;
			break;
		}
		x->done++;
	}
	return NULL;
}

#ifdef BML_TEST_CAPS
static pthread_mutex_t test_mu = PTHREAD_MUTEX_INITIALIZER;
static sigset_t test_mask;
static int test_have;

int bml_testonly_tracing_sigmask(sigset_t *out)
{
	pthread_mutex_lock(&test_mu);
	int r = test_have ? 0 : -1;
	if (test_have)
		*out = test_mask;
	pthread_mutex_unlock(&test_mu);
	return r;
}
#endif

static int64_t test_run_tracing_body(int64_t obj, const char *prog, int64_t len, int64_t n)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, len, &p)))
		return e;
	const char *name = bpf_program__name(p);
	if (bpf_program__type(p) != BPF_PROG_TYPE_TRACING)
		return abi_fail(BML_STATE, "bml: %s is a %s program, not fentry or fexit — test_run_tracing runs tracing programs", name, abi_kind_name(o, p));

	if (n < 1)
		return abi_fail(BML_VALUE_RANGE, "bml: tracing test run %s: the run count %lld is below 1", name, (long long)n);
	struct trun x = {.fd = bpf_program__fd(p), .n = n};
	if (BML_MUT("trace.run_on_caller")) {
		trun_main(&x);
	} else {
		pthread_attr_t at;
		sigset_t all;
		sigfillset(&all);
		int rc = pthread_attr_init(&at);
		if (rc == 0 && !BML_MUT("trace.no_sigmask"))
			rc = pthread_attr_setsigmask_np(&at, &all);
		pthread_t th;
		if (rc == 0)
			rc = pthread_create(&th, &at, trun_main, &x);
		pthread_attr_destroy(&at);
		if (rc != 0)
			return abi_fail(BML_OTHER, "bml: tracing test run %s: creating the run thread: %s", name, abi_errno(rc));
		pthread_join(th, NULL);
	}
#ifdef BML_TEST_CAPS
	pthread_mutex_lock(&test_mu);
	test_mask = x.mask;
	test_have = 1;
	pthread_mutex_unlock(&test_mu);
#endif

	int tp_hint = x.err == EFAULT && bpf_program__expected_attach_type(p) == BPF_TRACE_RAW_TP && !BML_MUT("trace.tpbtf_no_run_hint");
	if (x.err)
		return abi_fail(BML_OTHER, "bml: tracing test run %s (run %lld of %lld): %s%s", name, (long long)(x.done + 1), (long long)n, abi_errno(x.err),
				tp_hint ? " (hint: this kernel does not test-run tp_btf programs — trigger the tracepoint instead (bpf_prog_test_run_tracing))" : "");
	return abi_ok((int64_t)x.tid);
}


int64_t bml_attach_fentry(int64_t obj, const char *prog, int64_t prog_len)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_trace_body(obj, prog, prog_len, BPF_TRACE_FENTRY, "fentry", "attach_xdp / attach_fexit / attach_tcx / attach_kprobe");
	abi_object_release(o);
	return e;
}

int64_t bml_attach_fexit(int64_t obj, const char *prog, int64_t prog_len)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_trace_body(obj, prog, prog_len, BPF_TRACE_FEXIT, "fexit", "attach_xdp / attach_fentry / attach_tcx / attach_kprobe");
	abi_object_release(o);
	return e;
}

int64_t bml_attach_kprobe(int64_t obj, const char *prog, int64_t prog_len)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_kprobe_body(obj, prog, prog_len, 0);
	abi_object_release(o);
	return e;
}

int64_t bml_attach_kretprobe(int64_t obj, const char *prog, int64_t prog_len)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_kprobe_body(obj, prog, prog_len, 1);
	abi_object_release(o);
	return e;
}

int64_t bml_attach_tp_btf(int64_t obj, const char *prog, int64_t prog_len)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_tp_btf_body(obj, prog, prog_len);
	abi_object_release(o);
	return e;
}

int64_t bml_test_run_tracing(int64_t obj, const char *prog, int64_t prog_len, int64_t n)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = test_run_tracing_body(obj, prog, prog_len, n);
	abi_object_release(o);
	return e;
}
