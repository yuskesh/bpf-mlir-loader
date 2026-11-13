#define _GNU_SOURCE
#include "abi/netkit.h"

#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "abi/internal.h"

static int real_peer(void *ctx, uint32_t primary, struct abi_nk_peer *out)
{
	(void)ctx;
	return abi_netkit_query_peer(primary, out);
}

static int real_info(void *ctx, struct bpf_link_info *out)
{
	uint32_t len = sizeof *out;
	return bpf_link_get_info_by_fd(bpf_link__fd(ctx), out, &len) != 0 ? -errno : 0;
}

static int real_close(void *ctx)
{
	return bpf_link__destroy(ctx);
}

static const char *direction(uint32_t at)
{
	return at == BPF_NETKIT_PRIMARY ? "primary" : at == BPF_NETKIT_PEER ? "peer" : "";
}

static const char *attach_hint(int err)
{
	switch (err) {
	case ENXIO: return " (hint: the device is not a netkit device)";
	case EACCES: return " (hint: pass the primary device of the netkit pair, for peer programs too)";
	case EPERM: return " (hint: attaching a netkit link needs CAP_NET_ADMIN)";
	default: return "";
	}
}

static int64_t attach_netkit_body(int64_t obj, const char *prog, int64_t len, const char *ifname, int64_t if_len)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, len, &p)))
		return e;
	const char *name = bpf_program__name(p);
	uint32_t want = bpf_program__expected_attach_type(p);
	if (bpf_program__type(p) != BPF_PROG_TYPE_SCHED_CLS || !direction(want)[0])
		return abi_fail(BML_STATE, "bml: %s is a %s program, not netkit — attach it with its own kind (attach_tcx / attach_xdp / attach_fentry)", name,
				abi_kind_name(o, p));
	if (if_len < 0 || (!ifname && if_len))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL string with a length");
	char *ifn = strndup(ifname ? ifname : "", (size_t)if_len);
	if (!ifn)
		return abi_fail(BML_OTHER, "bml: out of memory");
	errno = 0;
	unsigned idx = strlen(ifn) == (size_t)if_len ? if_nametoindex(ifn) : 0;
	if (!idx) {
		e = abi_fail(BML_OTHER, "bml: interface %s: %s", ifn, abi_errno(errno ? errno : ENODEV));
		free(ifn);
		return e;
	}
	struct bpf_prog_info pi;
	uint32_t pl = sizeof pi;
	memset(&pi, 0, sizeof pi);
	if (bpf_prog_get_info_by_fd(bpf_program__fd(p), &pi, &pl) != 0) {
		e = abi_fail(BML_OTHER, "bml: attach netkit %s: reading the program info: %s", name, abi_errno(errno));
		free(ifn);
		return e;
	}
	struct bpf_link *l = bpf_program__attach_netkit(p, (int)idx, NULL);
	if (!l) {
		int err = errno;
		e = abi_fail(BML_OTHER, "bml: attach netkit %s %s to %s: %s%s", direction(want), name, ifn, abi_errno(err), attach_hint(err));
		free(ifn);
		return e;
	}
	free(ifn);
	const struct abi_nk_ops ops = {.ctx = l, .peer = real_peer, .info = real_info, .close_link = real_close};
	char *msg = NULL;
	if (abi_netkit_finish(name, want, idx, pi.id, &ops, &msg) != 0) {
		e = abi_fail(BML_OTHER, "%s", msg ? msg : "bml: attach netkit: out of memory");
		free(msg);
		return e;
	}
	return abi_link_put(l);
}

int64_t bml_attach_netkit(int64_t obj, const char *prog, int64_t prog_len, const char *ifname, int64_t if_len)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_netkit_body(obj, prog, prog_len, ifname, if_len);
	abi_object_release(o);
	return e;
}
