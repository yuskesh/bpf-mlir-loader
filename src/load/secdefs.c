#include "load/internal.h"

#include <stdio.h>
#include <string.h>

#include "util/mutation.h"

static const struct {
	const char *sec;
	int exp_opt;
} defs[] = {
	{"socket", 0},
	{"sk_reuseport/migrate", 0},
	{"sk_reuseport", 0},
	{"kprobe+", 0},
	{"uprobe+", 0},
	{"uprobe.s+", 0},
	{"kretprobe+", 0},
	{"uretprobe+", 0},
	{"uretprobe.s+", 0},
	{"kprobe.multi+", 0},
	{"kretprobe.multi+", 0},
	{"kprobe.session+", 0},
	{"uprobe.multi+", 0},
	{"uretprobe.multi+", 0},
	{"uprobe.session+", 0},
	{"uprobe.multi.s+", 0},
	{"uretprobe.multi.s+", 0},
	{"uprobe.session.s+", 0},
	{"ksyscall+", 0},
	{"kretsyscall+", 0},
	{"usdt+", 0},
	{"usdt.s+", 0},
	{"tc/ingress", 0},
	{"tc/egress", 0},
	{"tcx/ingress", 0},
	{"tcx/egress", 0},
	{"tc", 0},
	{"classifier", 0},
	{"action", 0},
	{"netkit/primary", 0},
	{"netkit/peer", 0},
	{"tracepoint+", 0},
	{"tp+", 0},
	{"raw_tracepoint+", 0},
	{"raw_tp+", 0},
	{"raw_tracepoint.w+", 0},
	{"raw_tp.w+", 0},
	{"tp_btf+", 0},
	{"fentry+", 0},
	{"fmod_ret+", 0},
	{"fexit+", 0},
	{"fentry.s+", 0},
	{"fmod_ret.s+", 0},
	{"fexit.s+", 0},
	{"fsession+", 0},
	{"fsession.s+", 0},
	{"freplace+", 0},
	{"lsm+", 0},
	{"lsm.s+", 0},
	{"lsm_cgroup+", 0},
	{"iter+", 0},
	{"iter.s+", 0},
	{"syscall", 0},
	{"xdp.frags/devmap", 0},
	{"xdp/devmap", 0},
	{"xdp.frags/cpumap", 0},
	{"xdp/cpumap", 0},
	{"xdp.frags", 0},
	{"xdp", 1},
	{"perf_event", 0},
	{"lwt_in", 0},
	{"lwt_out", 0},
	{"lwt_xmit", 0},
	{"lwt_seg6local", 0},
	{"sockops", 1},
	{"sk_skb/stream_parser", 1},
	{"sk_skb/stream_verdict", 1},
	{"sk_skb/verdict", 1},
	{"sk_skb", 0},
	{"sk_msg", 1},
	{"lirc_mode2", 1},
	{"flow_dissector", 1},
	{"cgroup_skb/ingress", 1},
	{"cgroup_skb/egress", 1},
	{"cgroup/skb", 0},
	{"cgroup/sock_create", 0},
	{"cgroup/sock_release", 0},
	{"cgroup/sock", 1},
	{"cgroup/post_bind4", 0},
	{"cgroup/post_bind6", 0},
	{"cgroup/bind4", 0},
	{"cgroup/bind6", 0},
	{"cgroup/connect4", 0},
	{"cgroup/connect6", 0},
	{"cgroup/connect_unix", 0},
	{"cgroup/sendmsg4", 0},
	{"cgroup/sendmsg6", 0},
	{"cgroup/sendmsg_unix", 0},
	{"cgroup/recvmsg4", 0},
	{"cgroup/recvmsg6", 0},
	{"cgroup/recvmsg_unix", 0},
	{"cgroup/getpeername4", 0},
	{"cgroup/getpeername6", 0},
	{"cgroup/getpeername_unix", 0},
	{"cgroup/getsockname4", 0},
	{"cgroup/getsockname6", 0},
	{"cgroup/getsockname_unix", 0},
	{"cgroup/sysctl", 0},
	{"cgroup/getsockopt", 0},
	{"cgroup/setsockopt", 0},
	{"cgroup/dev", 1},
	{"struct_ops+", 0},
	{"struct_ops.s+", 0},
	{"sk_lookup", 0},
	{"netfilter", 0},
};


static int matches(const char *def, const char *sec)
{
	size_t len = strlen(def);
	if (len && def[len - 1] == '/')
		return strncmp(sec, def, len) == 0;
	if (len && def[len - 1] == '+') {
		len--;
		return strncmp(sec, def, len) == 0 && (sec[len] == 0 || sec[len] == '/');
	}
	return strcmp(sec, def) == 0;
}

int lb_sec_exp_attach_opt(const char *sec)
{
	for (size_t i = 0; i < sizeof defs / sizeof defs[0]; i++)
		if (matches(defs[i].sec, sec))
			return defs[i].exp_opt || (BML_MUT("load.fentry_exp_opt") && !strcmp(defs[i].sec, "fentry+"));
	return 0;
}

void lb_secdefs_print(void)
{
	for (size_t i = 0; i < sizeof defs / sizeof defs[0]; i++)
		printf("%s\t%d\n", defs[i].sec, defs[i].exp_opt);
}
