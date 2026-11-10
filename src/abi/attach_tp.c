/* CONTRACT: attaching a tracepoint on every CPU
 * (the library opens the perf events itself instead of libbpf's attach on CPU 0).
 *
 * On 7.1.8, perf_syscall_enter does not call BPF when the hlist of the perf event on the CPU where the syscall happened is empty, for syscall events that read user
 * memory (for example syscalls/sys_enter_write). libbpf's bpf_program__attach_tracepoint and cilium's link.Tracepoint open the perf event on CPU 0 only,
 * so events on other CPUs are silently dropped. Here a perf event is opened on every online CPU and the program is attached only to the first CPU's event with
 * BPF_LINK_CREATE (perf_event) (attaching the same program to a second event makes the kernel's prog_array return EEXIST); the other CPUs' events are
 * held without a program, with the same lifetime as the link. If possible and online CPUs differ, the default is a named error (an offline CPU has no event even if it comes online later;
 * BML_TRACEPOINT_ONLINE_ONLY explicitly selects the currently online CPUs). After attaching, the tracepoint name in the perf link info is compared with the declaration.
 * The library does not touch thread affinity or signals. */
#define _GNU_SOURCE
#include "abi/internal.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "abi/tp_cpus.h"
#include "bml/bml.h"
#include "util/mutation.h"

static int str_is(const struct bml_str *s, const char *lit)
{
	return s->len == strlen(lit) && memcmp(s->p, lit, s->len) == 0;
}

/* CONTRACT: tracefs group / event names go into a path, so only [A-Za-z0-9_]+ is accepted */
static int valid_name(const char *s, size_t n)
{
	if (n == 0)
		return 0;
	for (size_t i = 0; i < n; i++) {
		char c = s[i];
		if (!(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))
			return 0;
	}
	return 1;
}


static int declared(const struct abi_object *o, const char *name, char cat[256], char ev[256])
{
	for (size_t i = 0; i < o->req->n_attaches; i++) {
		const struct bml_attach *a = &o->req->attaches[i];
		if (!str_is(&a->program, name))
			continue;
		const struct bml_str *t = NULL;
		if (str_is(&a->attach_type, "trace_tp"))
			t = &a->target;
		else if (str_is(&a->attach_type, "tracepoint") && str_is(&a->tkind, "tp"))
			t = &a->tval;
		if (!t)
			return 0;
		const char *sl = memchr(t->p, '/', t->len);
		if (!sl)
			return 0;
		size_t cn = (size_t)(sl - t->p), en = t->len - cn - 1;
		if (!valid_name(t->p, cn) || !valid_name(sl + 1, en) || cn >= 256 || en >= 256)
			return 0;
		memcpy(cat, t->p, cn);
		cat[cn] = 0;
		memcpy(ev, sl + 1, en);
		ev[en] = 0;
		return 1;
	}
	return 0;
}


static int read_small(const char *path, char *buf, size_t cap)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	size_t n = 0;
	for (;;) {
		ssize_t k = read(fd, buf + n, cap - 1 - n);
		if (k < 0 && errno == EINTR)
			continue;
		if (k < 0) {
			int e = errno;
			close(fd);
			return -e;
		}
		if (k == 0 || n + (size_t)k >= cap - 1) {
			n += (size_t)(k > 0 ? k : 0);
			break;
		}
		n += (size_t)k;
	}
	close(fd);
	buf[n] = 0;
	return 0;
}


static int event_id(const char *cat, const char *ev, uint64_t *id)
{
	static const char *const roots[] = {"/sys/kernel/tracing", "/sys/kernel/debug/tracing"};
	int rc = -ENOENT;
	for (size_t i = 0; i < 2; i++) {
		char path[640], buf[64];
		snprintf(path, sizeof path, "%s/events/%s/%s/id", roots[i], cat, ev);
		if ((rc = read_small(path, buf, sizeof buf)) != 0)
			continue;
		char *end;
		errno = 0;
		unsigned long long v = strtoull(buf, &end, 10);
		while (*end == '\n' || *end == ' ')
			end++;
		if (errno || end == buf || *end || buf[0] < '0' || buf[0] > '9')
			return -EINVAL;
		*id = v;
		return 0;
	}
	return rc;
}

static int perf_open(uint64_t id, int cpu)
{
	struct perf_event_attr attr;
	memset(&attr, 0, sizeof attr);
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.size = sizeof attr;
	attr.config = id;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	return (int)syscall(SYS_perf_event_open, &attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
}

static int64_t attach_tp_body(int64_t obj, const char *prog, int64_t len, int64_t flags)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, len, &p)))
		return e;
	const char *name = bpf_program__name(p);
	if (bpf_program__type(p) != BPF_PROG_TYPE_TRACEPOINT)
		return abi_fail(BML_STATE, "bml: %s is a %s program, not tracepoint — attach it with its own kind", name, abi_kind_name(o, p));
	if (flags & ~(int64_t)BML_TRACEPOINT_ONLINE_ONLY)
		return abi_fail(BML_VALUE_RANGE, "bml: attach tracepoint %s: unknown flags 0x%llx (known: BML_TRACEPOINT_ONLINE_ONLY 0x1)", name,
				(unsigned long long)flags);
	char cat[256], ev[256];
	if (!declared(o, name, cat, ev))
		return abi_fail(BML_OTHER,
				"bml: tracepoint %s: the ELF declares no tracepoint (an attach row trace_tp <category>/<event> or tracepoint tp:<category>/<event> "
				"with names [A-Za-z0-9_]+)",
				name);
	uint64_t id = 0;
	int rc = event_id(cat, ev, &id);
	if (rc != 0)
		return abi_fail(BML_OTHER, "bml: attach tracepoint %s: tracepoint %s/%s: reading its tracefs id: %s", name, cat, ev, abi_errno(-rc));
	int *cpus = NULL;
	size_t ncpu = 0;
	char *cerr = NULL;
	if (bml_tp_cpus(flags & BML_TRACEPOINT_ONLINE_ONLY, &cpus, &ncpu, &cerr) != 0) {
		e = abi_fail(BML_OTHER, "bml: attach tracepoint %s: tracepoint %s/%s: %s", name, cat, ev, cerr ? cerr : "out of memory");
		free(cerr);
		return e;
	}
	if (BML_MUT("attach.tp_cpu0_only"))
		ncpu = 1;
	int *fds = calloc(ncpu, sizeof *fds);
	if (!fds) {
		free(cpus);
		return abi_fail(BML_OTHER, "bml: out of memory");
	}
	size_t nfd = 0;
	for (; nfd < ncpu; nfd++) {
		fds[nfd] = perf_open(id, cpus[nfd]);
		if (fds[nfd] < 0) {
			int en = errno;
			e = abi_fail(BML_OTHER, "bml: attach tracepoint %s: tracepoint %s/%s: perf_event_open on CPU %d: %s", name, cat, ev, cpus[nfd],
				     abi_errno(en));
			goto fail;
		}
	}
	struct bpf_link *l = bpf_program__attach_perf_event(p, fds[0]);
	if (!l) {
		e = abi_fail(BML_OTHER, "bml: attach tracepoint %s to %s/%s: link on CPU %d: %s", name, cat, ev, cpus[0], abi_errno(errno));
		goto fail;
	}
	fds[0] = -1;
	char got[256] = {0};
	struct bpf_link_info info;
	memset(&info, 0, sizeof info);
	info.perf_event.tracepoint.tp_name = (uint64_t)(uintptr_t)got;
	info.perf_event.tracepoint.name_len = sizeof got;
	uint32_t ilen = sizeof info;
	int irc = bpf_link_get_info_by_fd(bpf_link__fd(l), &info, &ilen) != 0 ? -errno : 0;
	got[sizeof got - 1] = 0;
	if (irc == 0 && BML_MUT("attach.tp_name_other"))
		strcat(got, "_x");
	if (irc != 0 || info.type != BPF_LINK_TYPE_PERF_EVENT || info.perf_event.type != BPF_PERF_EVENT_TRACEPOINT || strcmp(got, ev) != 0) {
		bpf_link__destroy(l);
		if (irc != 0)
			e = abi_fail(BML_OTHER, "bml: attach tracepoint %s: reading the perf event link info: %s (detached)", name, abi_errno(-irc));
		else if (info.type != BPF_LINK_TYPE_PERF_EVENT || info.perf_event.type != BPF_PERF_EVENT_TRACEPOINT || !got[0])
			e = abi_fail(BML_OTHER, "bml: attach tracepoint %s: the link info is not a tracepoint perf event (cannot confirm the attach target %s/%s — detached)",
				     name, cat, ev);
		else
			e = abi_fail(BML_OTHER, "bml: attach tracepoint %s: the kernel attached it to %s, but the ELF declares %s/%s (detached)", name, got, cat, ev);
		goto fail;
	}
	free(cpus);

	int *extra = NULL;
	size_t nx = nfd - 1;
	if (nx) {
		extra = malloc(nx * sizeof *extra);
		if (!extra) {
			bpf_link__destroy(l);
			for (size_t i = 1; i < nfd; i++)
				close(fds[i]);
			free(fds);
			return abi_fail(BML_OTHER, "bml: out of memory");
		}
		memcpy(extra, fds + 1, nx * sizeof *extra);
	}
	free(fds);
	return abi_link_put_extra(l, extra, nx);
fail:
	for (size_t i = 0; i < nfd; i++)
		if (fds[i] >= 0)
			close(fds[i]);
	free(fds);
	free(cpus);
	return e;
}

int64_t bml_attach_tracepoint(int64_t obj, const char *prog, int64_t prog_len, int64_t flags)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_tp_body(obj, prog, prog_len, flags);
	abi_object_release(o);
	return e;
}
