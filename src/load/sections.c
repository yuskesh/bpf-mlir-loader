/* load/sections.c — the section-form table of the guard (moved unchanged from load/pre.c when pre.c reached the
 * 500-line limit): the program sections bpf-mlir's emitter writes, read by the ELF shape check (lb_prog_section) and by
 * the C ABI's test-run kind decision (bml_load_section_kind). */
#include "load/internal.h"

#include <string.h>

#include "util/mutation.h"

/* The section forms of the programs that bpf-mlir's emitter writes (ProgramKinds.def), with their kind and test-run
 * family. The guard's ELF shape check and the C ABI's test-run kind decision both look here, so when a kind is added
 * only this table needs to change. prefix means the form is "<form>/<target>" (the target is not empty). */
static const struct sec_def {
	const char *name;
	int prefix, wave1; /* wave1: 1 is the first wave of sections (the mutant load.wave1_sections_reject removes it); 2 is the second to fourth waves (the mutant load.wave24_sections_reject removes it) */
	const char *kind;
	int family;
} sec_defs[] = {
	{".text", 0, 0, "", BML_RUN_NONE},
	{"xdp", 0, 0, "xdp", BML_RUN_XDP},
	{"tcx/ingress", 0, 0, "sched_cls", BML_RUN_SKB},
	{"tcx/egress", 0, 0, "sched_cls", BML_RUN_SKB},
	{"uprobe", 0, 0, "uprobe", BML_RUN_NONE},
	{"kprobe/", 1, 0, "kprobe", BML_RUN_NONE},
	{"uprobe/", 1, 0, "uprobe", BML_RUN_NONE},
	{"fentry/", 1, 0, "fentry", BML_RUN_TRACING},
	{"fexit/", 1, 0, "fexit", BML_RUN_TRACING},
	{"tp_btf/", 1, 0, "tp_btf", BML_RUN_TRACING},
	/* The first wave of bpf-mlir's program-type coverage (libbpf's behavior for these sections was examined when they were added) */
	{"socket", 0, 1, "socket_filter", BML_RUN_SKB},
	{"action", 0, 1, "sched_act", BML_RUN_SKB},
	{"cgroup_skb/ingress", 0, 1, "cgroup_skb", BML_RUN_SKB},
	{"cgroup_skb/egress", 0, 1, "cgroup_skb", BML_RUN_SKB},
	{"lwt_in", 0, 1, "lwt_in", BML_RUN_SKB},
	{"lwt_out", 0, 1, "lwt_out", BML_RUN_SKB},
	{"lwt_xmit", 0, 1, "lwt_xmit", BML_RUN_SKB},
	{"flow_dissector", 0, 1, "flow_dissector", BML_RUN_FLOW},
	{"sk_lookup", 0, 1, "sk_lookup", BML_RUN_CTX},
	{"netfilter", 0, 1, "netfilter", BML_RUN_NF},
	{"uretprobe", 0, 1, "uretprobe", BML_RUN_NONE},
	{"uretprobe/", 1, 1, "uretprobe", BML_RUN_NONE}, /* the repository's uretprobe sections are uretprobe/<symbol> (the first survey looked only at ELFs that the check already stops, and missed this one) */
	{"syscall", 0, 1, "syscall", BML_RUN_CTX},
	{"raw_tp/", 1, 1, "raw_tp", BML_RUN_CTX},
	{"kretprobe/", 1, 1, "kretprobe", BML_RUN_NONE},
	{"iter/", 1, 1, "iter", BML_RUN_NONE},
	{"fmod_ret/", 1, 1, "fmod_ret", BML_RUN_TRACING},
	/* Fourth-wave tracepoint (libbpf's tracepoint+ is SEC_NONE with expected attach type 0, and is not rewritten at load time). Attach is done by bml_attach_tracepoint. */
	{"tracepoint/", 1, 0, "tracepoint", BML_RUN_NONE},
	/* Second to fourth waves (sections from bpf-mlir's ProgramAttaches.def; libbpf's behavior for them was examined when they were added). No test-run hook is opened (family NONE).
	 * freplace (load needs the target program's fd) is not in the table. struct_ops is in it (below), behind G1 to G3. */
	{"lsm/", 1, 2, "lsm", BML_RUN_NONE},
	{"lsm.s/", 1, 2, "lsm_s", BML_RUN_NONE},
	{"cgroup/sock_create", 0, 2, "cgroup_sock", BML_RUN_NONE},
	{"cgroup/sock_release", 0, 2, "cgroup_sock", BML_RUN_NONE},
	{"cgroup/post_bind4", 0, 2, "cgroup_sock", BML_RUN_NONE},
	{"cgroup/post_bind6", 0, 2, "cgroup_sock", BML_RUN_NONE},
	{"cgroup/bind4", 0, 2, "cgroup_sock_addr", BML_RUN_NONE},
	{"cgroup/bind6", 0, 2, "cgroup_sock_addr", BML_RUN_NONE},
	{"cgroup/connect4", 0, 2, "cgroup_sock_addr", BML_RUN_NONE},
	{"cgroup/connect6", 0, 2, "cgroup_sock_addr", BML_RUN_NONE},
	{"cgroup/sendmsg4", 0, 2, "cgroup_sock_addr", BML_RUN_NONE},
	{"cgroup/sendmsg6", 0, 2, "cgroup_sock_addr", BML_RUN_NONE},
	{"cgroup/recvmsg4", 0, 2, "cgroup_sock_addr", BML_RUN_NONE},
	{"cgroup/recvmsg6", 0, 2, "cgroup_sock_addr", BML_RUN_NONE},
	{"cgroup/getpeername4", 0, 2, "cgroup_sock_addr", BML_RUN_NONE},
	{"cgroup/getpeername6", 0, 2, "cgroup_sock_addr", BML_RUN_NONE},
	{"cgroup/getsockname4", 0, 2, "cgroup_sock_addr", BML_RUN_NONE},
	{"cgroup/getsockname6", 0, 2, "cgroup_sock_addr", BML_RUN_NONE},
	/* the unix sock_addr hooks (Linux 6.7; libbpf's SEC_ATTACHABLE, no SEC_EXP_ATTACH_OPT). Load only: bml has no
	 * cgroup_sock_addr attach path. The rows are exact names, so a near name is still stopped. */
	{"cgroup/connect_unix", 0, 2, "cgroup_sock_addr", BML_RUN_NONE},
	{"cgroup/sendmsg_unix", 0, 2, "cgroup_sock_addr", BML_RUN_NONE},
	{"cgroup/recvmsg_unix", 0, 2, "cgroup_sock_addr", BML_RUN_NONE},
	{"cgroup/getpeername_unix", 0, 2, "cgroup_sock_addr", BML_RUN_NONE},
	{"cgroup/getsockname_unix", 0, 2, "cgroup_sock_addr", BML_RUN_NONE},
	{"sockops", 0, 2, "sock_ops", BML_RUN_NONE},
	{"cgroup/dev", 0, 2, "cgroup_device", BML_RUN_NONE},
	{"cgroup/sysctl", 0, 2, "cgroup_sysctl", BML_RUN_NONE},
	{"cgroup/getsockopt", 0, 2, "cgroup_sockopt", BML_RUN_NONE},
	{"cgroup/setsockopt", 0, 2, "cgroup_sockopt", BML_RUN_NONE},
	{"lwt_seg6local", 0, 2, "lwt_seg6local", BML_RUN_NONE},
	{"sk_skb/stream_verdict", 0, 2, "sk_skb", BML_RUN_NONE},
	{"sk_skb/stream_parser", 0, 2, "sk_skb", BML_RUN_NONE},
	{"sk_msg", 0, 2, "sk_msg", BML_RUN_NONE},
	{"sk_reuseport", 0, 2, "sk_reuseport", BML_RUN_NONE},
	{"sk_reuseport/migrate", 0, 2, "sk_reuseport", BML_RUN_NONE},
	{"perf_event", 0, 2, "perf_event", BML_RUN_NONE},
	{"raw_tp.w/", 1, 2, "raw_tp_writable", BML_RUN_NONE},
	{"lirc_mode2", 0, 2, "lirc_mode2", BML_RUN_NONE},
	/* USDT (libbpf's usdt+; the UPROBE_MULTI rewrite at load time is removed by usdt_point_form in load.c). Attach is done by bml_attach_usdt. */
	{"usdt", 0, 0, "usdt", BML_RUN_NONE},
	/* ksyscall (libbpf's ksyscall+ is KPROBE and SEC_NONE, and loads like a kprobe; bpf-mlir does not emit kretsyscall). Attach is done by bml_attach_ksyscall. */
	{"ksyscall/", 1, 0, "ksyscall", BML_RUN_NONE},
	/* Sections introduced with requirements formats 30 to 32 (the BPF_F_SLEEPABLE check is in load.c). No test-run hook is opened. The mutant load.target_sections_reject restores the stop at stage A. */
	{"fentry.s/", 1, 3, "fentry", BML_RUN_NONE},
	{"netkit/primary", 0, 3, "netkit", BML_RUN_NONE},
	{"netkit/peer", 0, 3, "netkit", BML_RUN_NONE},
	/* struct_ops programs. The table must be in .struct_ops.link (G1, in pre.c); slots, programs and members are G2
	 * and G3 (struct_ops.c). The table is registered only by bml_attach_struct_ops. No test-run hook is opened. */
	{"struct_ops", 0, 0, "struct_ops", BML_RUN_NONE},
	{"struct_ops.s", 0, 0, "struct_ops_s", BML_RUN_NONE},
};

static const struct sec_def *sec_def_of(const char *n)
{
	int skip_w1 = BML_MUT("load.wave1_sections_reject"), skip_w24 = BML_MUT("load.wave24_sections_reject");
	for (size_t i = 0; n && i < sizeof sec_defs / sizeof *sec_defs; i++) {
		const struct sec_def *d = &sec_defs[i];
		if ((d->wave1 == 1 && skip_w1) || (d->wave1 == 2 && skip_w24) || (d->wave1 == 3 && BML_MUT("load.target_sections_reject")))
			continue;
		size_t l = strlen(d->name);
		if (d->prefix ? (strncmp(n, d->name, l) == 0 && n[l]) : strcmp(n, d->name) == 0)
			return d;
	}
	return NULL;
}

const char *bml_load_section_kind(const char *section, int *family)
{
	const struct sec_def *d = sec_def_of(section);
	if (family)
		*family = d ? d->family : BML_RUN_NONE;
	return d ? d->kind : NULL;
}

int lb_prog_section(const char *n)
{
	return sec_def_of(n) != NULL;
}
