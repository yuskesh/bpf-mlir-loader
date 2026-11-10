




#define _GNU_SOURCE
#include "abi/internal.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/nsfs.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "util/mutation.h"

#define OTHERS "attach_cgroup / attach_netns / attach_socket / attach_xdp / attach_tcx / attach_kprobe / attach_fentry / …"

static int64_t wrong_kind(struct abi_object *o, struct bpf_program *p, const char *kind)
{
	return abi_fail(BML_STATE, "bml: %s is a %s program, not %s — attach it with its own kind (" OTHERS ")", bpf_program__name(p), abi_kind_name(o, p),
			kind);
}


static int64_t check_fd(int64_t fd, char want, const char *what, uint64_t *ino)
{
	if (fd < 0 || fd > INT32_MAX)
		return abi_fail(BML_VALUE_RANGE, "bml: the %s fd %lld is out of range", what, (long long)fd);
	struct stat st;
	if (fstat((int)fd, &st) != 0)
		return abi_fail(BML_OTHER, "bml: the %s fd %lld: %s", what, (long long)fd, abi_errno(errno));
	*ino = (uint64_t)st.st_ino;
	if (BML_MUT("attach.fd_kind_skip"))
		return 0;
	struct statfs sf;
	const char *bad = NULL;
	if (want == 's') {
		if (!S_ISSOCK(st.st_mode))
			bad = "not a socket";
	} else if (fstatfs((int)fd, &sf) != 0) {
		return abi_fail(BML_OTHER, "bml: the %s fd %lld: %s", what, (long long)fd, abi_errno(errno));
	} else if (want == 'c') {
		if ((unsigned long)sf.f_type != CGROUP2_SUPER_MAGIC || !S_ISDIR(st.st_mode))
			bad = "not a cgroup v2 directory";
	} else if ((unsigned long)sf.f_type != NSFS_MAGIC || ioctl((int)fd, NS_GET_NSTYPE) != CLONE_NEWNET) {
		bad = "not a network namespace (nsfs)";
	}
	if (bad)
		return abi_fail(BML_OTHER, "bml: the %s fd %lld is %s", what, (long long)fd, bad);
	return 0;
}


static int64_t confirm(struct bpf_link *l, const char *name, const char *kind, uint32_t want_type, uint32_t want_at, uint64_t want_ino)
{
	struct bpf_link_info info;
	uint32_t len = sizeof info;
	memset(&info, 0, sizeof info);
	if (bpf_link_get_info_by_fd(bpf_link__fd(l), &info, &len) != 0) {
		int en = errno;
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: attach %s %s: reading the link info: %s (detached)", kind, name, abi_errno(en));
	}
	uint64_t got;
	uint32_t at;
	if (want_type == BPF_LINK_TYPE_CGROUP) {
		got = info.cgroup.cgroup_id, at = info.cgroup.attach_type;
		if (BML_MUT("attach.cgroup_id_other"))
			got++;
	} else {
		got = info.netns.netns_ino, at = info.netns.attach_type;
		if (BML_MUT("attach.netns_ino_other"))
			got++;
	}
	if (info.type != want_type || at != want_at || got != want_ino) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER,
				"bml: attach %s %s: the kernel attached it to %s %llu with attach type %u, but the given fd is %llu with attach type %u (detached)", kind,
				name, want_type == BPF_LINK_TYPE_CGROUP ? "cgroup" : "netns", (unsigned long long)got, at, (unsigned long long)want_ino, want_at);
	}
	return 0;
}

static int64_t attach_cgroup_body(int64_t obj, const char *prog, int64_t len, int64_t cg)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, len, &p)))
		return e;
	const char *name = bpf_program__name(p);
	enum bpf_attach_type at = bpf_program__expected_attach_type(p);
	if (bpf_program__type(p) != BPF_PROG_TYPE_CGROUP_SKB || (at != BPF_CGROUP_INET_INGRESS && at != BPF_CGROUP_INET_EGRESS))
		return wrong_kind(o, p, "cgroup_skb");
	uint64_t ino;
	if ((e = check_fd(cg, 'c', "cgroup", &ino)))
		return e;
	struct bpf_link *l = bpf_program__attach_cgroup(p, (int)cg);
	if (!l)
		return abi_fail(BML_OTHER, "bml: attach cgroup_skb %s to cgroup fd %lld: %s", name, (long long)cg, abi_errno(errno));
	if ((e = confirm(l, name, "cgroup_skb", BPF_LINK_TYPE_CGROUP, at, ino)))
		return e;
	return abi_link_put(l);
}

static int64_t attach_netns_body(int64_t obj, const char *prog, int64_t len, int64_t ns)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, len, &p)))
		return e;
	const char *name = bpf_program__name(p);
	enum bpf_prog_type t = bpf_program__type(p);
	if (t != BPF_PROG_TYPE_SK_LOOKUP && t != BPF_PROG_TYPE_FLOW_DISSECTOR)
		return wrong_kind(o, p, "sk_lookup or flow_dissector");
	const char *kind = t == BPF_PROG_TYPE_SK_LOOKUP ? "sk_lookup" : "flow_dissector";
	uint64_t ino;
	if ((e = check_fd(ns, 'n', "netns", &ino)))
		return e;
	struct bpf_link *l = bpf_program__attach_netns(p, (int)ns);
	if (!l)
		return abi_fail(BML_OTHER, "bml: attach %s %s to netns fd %lld: %s", kind, name, (long long)ns, abi_errno(errno));
	if ((e = confirm(l, name, kind, BPF_LINK_TYPE_NETNS, t == BPF_PROG_TYPE_SK_LOOKUP ? BPF_SK_LOOKUP : BPF_FLOW_DISSECTOR, ino)))
		return e;
	return abi_link_put(l);
}

static int64_t attach_socket_body(int64_t obj, const char *prog, int64_t len, int64_t sock)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, len, &p)))
		return e;
	if (bpf_program__type(p) != BPF_PROG_TYPE_SOCKET_FILTER)
		return wrong_kind(o, p, "socket_filter");
	uint64_t ino;
	if ((e = check_fd(sock, 's', "socket", &ino)))
		return e;
	int pfd = bpf_program__fd(p);
	if (setsockopt((int)sock, SOL_SOCKET, SO_ATTACH_BPF, &pfd, sizeof pfd) != 0)
		return abi_fail(BML_OTHER, "bml: attach socket_filter %s to socket fd %lld: %s", bpf_program__name(p), (long long)sock, abi_errno(errno));
	return abi_ok(0);
}

static int64_t program_fd_body(int64_t obj, const char *prog, int64_t len)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, len, &p)))
		return e;
	if (bpf_program__type(p) != BPF_PROG_TYPE_SOCKET_FILTER)
		return abi_fail(BML_STATE, "bml: %s is a %s program — program_fd is only for socket_filter (attach the others with their own kind)",
				bpf_program__name(p), abi_kind_name(o, p));
	int fd = fcntl(bpf_program__fd(p), F_DUPFD_CLOEXEC, 3);
	if (fd < 0)
		return abi_fail(BML_OTHER, "bml: program_fd %s: %s", bpf_program__name(p), abi_errno(errno));
	return abi_ok(fd);
}

int64_t bml_attach_cgroup(int64_t obj, const char *prog, int64_t prog_len, int64_t cgroup_fd)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_cgroup_body(obj, prog, prog_len, cgroup_fd);
	abi_object_release(o);
	return e;
}

int64_t bml_attach_netns(int64_t obj, const char *prog, int64_t prog_len, int64_t netns_fd)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_netns_body(obj, prog, prog_len, netns_fd);
	abi_object_release(o);
	return e;
}

int64_t bml_attach_socket(int64_t obj, const char *prog, int64_t prog_len, int64_t sock_fd)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_socket_body(obj, prog, prog_len, sock_fd);
	abi_object_release(o);
	return e;
}

int64_t bml_program_fd(int64_t obj, const char *prog, int64_t prog_len)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = program_fd_body(obj, prog, prog_len);
	abi_object_release(o);
	return e;
}





static int64_t attach_netfilter_body(int64_t obj, const char *prog, int64_t len, int64_t pf, int64_t hooknum, int64_t priority, int64_t flags)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, len, &p)))
		return e;
	const char *name = bpf_program__name(p);
	if (bpf_program__type(p) != BPF_PROG_TYPE_NETFILTER)
		return wrong_kind(o, p, "netfilter");
	if (pf < 0 || pf > UINT32_MAX || hooknum < 0 || hooknum > UINT32_MAX || flags < 0 || flags > UINT32_MAX)
		return abi_fail(BML_VALUE_RANGE, "bml: attach netfilter %s: pf %lld / hooknum %lld / flags %lld is out of the u32 range", name, (long long)pf,
				(long long)hooknum, (long long)flags);
	if (priority < INT32_MIN || priority > INT32_MAX)
		return abi_fail(BML_VALUE_RANGE, "bml: attach netfilter %s: priority %lld is out of the int32 range", name, (long long)priority);

	int unconfirmed = BML_MUT("nf.priority_other_unconfirmed");
	int32_t at_prio = BML_MUT("nf.priority_other") || unconfirmed ? (int32_t)priority + 1 : (int32_t)priority;
	LIBBPF_OPTS(bpf_netfilter_opts, no, .pf = (uint32_t)pf, .hooknum = (uint32_t)hooknum, .priority = at_prio, .flags = (uint32_t)flags);
	struct bpf_link *l = bpf_program__attach_netfilter(p, &no);
	if (!l)
		return abi_fail(BML_OTHER, "bml: attach netfilter %s (pf %lld hooknum %lld priority %lld flags %lld): %s", name, (long long)pf, (long long)hooknum,
				(long long)priority, (long long)flags, abi_errno(errno));
	struct bpf_link_info info;
	uint32_t il = sizeof info;
	memset(&info, 0, sizeof info);
	if (bpf_link_get_info_by_fd(bpf_link__fd(l), &info, &il) != 0) {
		int err = errno;
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: attach netfilter %s: reading the link info: %s (detached)", name, abi_errno(err));
	}
	if (!unconfirmed && (info.type != BPF_LINK_TYPE_NETFILTER || info.netfilter.pf != (uint32_t)pf || info.netfilter.hooknum != (uint32_t)hooknum ||
			     info.netfilter.priority != (int32_t)priority || info.netfilter.flags != (uint32_t)flags)) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER,
				"bml: attach netfilter %s: the link info (type %u pf %u hooknum %u priority %d flags %u) is not the requested pf %lld hooknum %lld "
				"priority %lld flags %lld (detached)",
				name, info.type, info.netfilter.pf, info.netfilter.hooknum, info.netfilter.priority, info.netfilter.flags, (long long)pf,
				(long long)hooknum, (long long)priority, (long long)flags);
	}
	return abi_link_put(l);
}

int64_t bml_attach_netfilter(int64_t obj, const char *prog, int64_t prog_len, int64_t pf, int64_t hooknum, int64_t priority, int64_t flags)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_netfilter_body(obj, prog, prog_len, pf, hooknum, priority, flags);
	abi_object_release(o);
	return e;
}
