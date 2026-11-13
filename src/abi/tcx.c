#define _GNU_SOURCE
#include "abi/internal.h"

#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "util/mutation.h"

#define TC_RUN_HINT                                                                                                                         \
	" (hint: the kernel refused the tc (skb) test run's data — measured: at least 14 bytes; an IPv4 frame (EtherType " \
	"0x0800) at least 34 bytes; an IPv6 frame (0x86DD) at least 54 bytes on a kernel with CONFIG_IPV6; at most 3712 bytes on 6.12 / 6.6 "      \
	"(non-linear data), larger on 7.1.8. bml passes the data as is and does not check its length)"

static const char *direction(uint32_t at)
{
	return at == BPF_TCX_INGRESS ? "ingress" : at == BPF_TCX_EGRESS ? "egress" : "";
}


static int tcx_info(int fd, uint32_t *at, uint32_t *ifindex)
{
	struct bpf_link_info info;
	uint32_t len = sizeof info;
	memset(&info, 0, sizeof info);
	if (bpf_link_get_info_by_fd(fd, &info, &len) != 0)
		return -errno;
	if (info.type != BPF_LINK_TYPE_TCX)
		return 1;
	*at = info.tcx.attach_type;
	*ifindex = info.tcx.ifindex;
	return 0;
}

static int64_t attach_tcx_body(int64_t obj, const char *prog, int64_t len, const char *ifname, int64_t if_len)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, len, &p)))
		return e;
	const char *name = bpf_program__name(p);
	uint32_t want = bpf_program__expected_attach_type(p);
	if (bpf_program__type(p) != BPF_PROG_TYPE_SCHED_CLS || !direction(want)[0])
		return abi_fail(BML_STATE, "bml: %s is a %s program, not tc — attach it with its own kind (attach_xdp / attach_fentry / attach_fexit / attach_kprobe)",
				name, abi_kind_name(o, p));
	if (if_len < 0 || (!ifname && if_len))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL string with a length");
	char *ifn = strndup(ifname ? ifname : "", (size_t)if_len);
	if (!ifn)
		return abi_fail(BML_OTHER, "bml: out of memory");
	unsigned idx = strlen(ifn) == (size_t)if_len ? if_nametoindex(ifn) : 0;
	if (!idx) {
		e = abi_fail(BML_OTHER, "bml: interface %s: %s", ifn, abi_errno(errno ? errno : ENODEV));
		free(ifn);
		return e;
	}
	struct bpf_link *l = bpf_program__attach_tcx(p, (int)idx, NULL);
	if (!l) {
		int err = errno;
		e = abi_fail(BML_OTHER, "bml: attach tcx %s %s to %s: %s%s", direction(want), name, ifn, abi_errno(err),
			     err == EPERM ? " (hint: attaching a tcx link needs CAP_NET_ADMIN)" : "");
		free(ifn);
		return e;
	}
	free(ifn);

	uint32_t at = 0, got_if = 0;
	int rc = tcx_info(bpf_link__fd(l), &at, &got_if);
	if (rc == 0 && BML_MUT("tcx.info_other_direction"))
		at = at == BPF_TCX_INGRESS ? BPF_TCX_EGRESS : BPF_TCX_INGRESS;
	if (rc < 0) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: attach tcx %s: reading the link info: %s (detached)", name, abi_errno(-rc));
	}
	if (rc > 0 || at != want || got_if != idx) {
		bpf_link__destroy(l);
		char got[64];
		if (rc > 0)
			snprintf(got, sizeof got, "no tcx info");
		else
			snprintf(got, sizeof got, "%s on ifindex %u", direction(at)[0] ? direction(at) : "?", got_if);
		return abi_fail(BML_OTHER, "bml: attach tcx %s: the kernel attached it as %s, but the ELF declares %s on ifindex %u (detached)", name, got,
				direction(want), idx);
	}
	return abi_link_put(l);
}

int64_t bml_link_tcx_direction(int64_t link)
{
	int64_t e = 0;
	int fd = abi_link_dup_fd(link, &e);
	if (fd < 0)
		return e;
	uint32_t at = 0, ifindex = 0;
	int rc = tcx_info(fd, &at, &ifindex);
	close(fd);
	if (rc < 0)
		return abi_fail(BML_OTHER, "bml: link %lld info: %s", (long long)link, abi_errno(-rc));
	if (rc > 0)
		return abi_fail(BML_STATE, "bml: link %lld is not a tcx link", (long long)link);
	const char *d = direction(at);
	if (!d[0])
		return abi_fail(BML_OTHER, "bml: link %lld: unknown tcx attach type %u", (long long)link, at);
	struct abi_result r = {.kind = BML_OK, .value = ifindex, .msg = strdup(d), .msg_len = strlen(d)};
	if (!r.msg)
		return abi_fail(BML_OTHER, "bml: out of memory");
	return abi_put(&r);
}

static int64_t test_run_tc_data_body(int64_t obj, const char *prog, int64_t len, const uint8_t *data, int64_t n)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, len, &p)))
		return e;
	const char *name = bpf_program__name(p);
	if (bpf_program__type(p) != BPF_PROG_TYPE_SCHED_CLS)
		return abi_fail(BML_STATE, "bml: %s is a %s program, not tc — test-run it with its own kind (test_run_xdp_data / test_run_tracing)", name,
				abi_kind_name(o, p));
	if (n < 0 || n > UINT32_MAX || (!data && n))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL buffer with a length");
	LIBBPF_OPTS(bpf_test_run_opts, t, .data_in = data, .data_size_in = (uint32_t)n, .repeat = 1);
	if (bpf_prog_test_run_opts(bpf_program__fd(p), &t) != 0) {
		int err = errno;
		return abi_fail(BML_OTHER, "bml: tc test run %s with %lld bytes: %s%s", name, (long long)n, abi_errno(err), err == EINVAL ? TC_RUN_HINT : "");
	}
	return abi_ok((int64_t)(int32_t)t.retval);
}


int64_t bml_attach_tcx(int64_t obj, const char *prog, int64_t prog_len, const char *ifname, int64_t if_len)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_tcx_body(obj, prog, prog_len, ifname, if_len);
	abi_object_release(o);
	return e;
}

int64_t bml_test_run_tc_data(int64_t obj, const char *prog, int64_t prog_len, const uint8_t *data, int64_t n)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = test_run_tc_data_body(obj, prog, prog_len, data, n);
	abi_object_release(o);
	return e;
}
