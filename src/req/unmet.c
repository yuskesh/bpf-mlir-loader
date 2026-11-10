
#include "req/check_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "req/uprobe.h"
#include "util/gostr.h"
#include "util/mutation.h"



int bml_unmet_unknown(const struct bml_unmet *u)
{
	size_t n = strlen(u->kind);
	return n >= 8 && strcmp(u->kind + n - 8, "_unknown") == 0;
}

int bml_unmet_blocks_load(const struct bml_unmet *u)
{
	static const char *const blocking_unknown[] = {
		"btf_feature_unknown", "kfield_unknown",        "attach_unknown",       "arg_nullable_mark_unknown",
		"arg_tag_unknown",     "retsig_unknown",        "arch_unknown",         "ctxfield_unknown",
		"kprobearg_unknown",   "attach_symbol_unknown", "attach_alias_unknown", "binary_unknown",
		"uprobearg_unknown",   "farg_unknown",          "uprobearg_abi_unknown",
		"uretprobe_abi_unknown",
		"tpfield_unknown",       "ext_target_unknown", "structop_unknown",
		"usdtarg_unknown",       "usdt_loader_unknown",
		"kfunc_sig_unknown",     "sysarg_unknown",     "lsm_cgroup_loader_unknown", "fsession_loader_unknown",
		"ksyscall_loader_unknown",
		"enumval_unknown", "coreenum_unknown", "funcret_unknown", "kstructsize_unknown", "fibflags_unknown",
		"datakptr_loader_unknown", "arena_loader_unknown", "typed_ksym_loader_unknown", "ksymvar_unknown",
		"kconfig_loader_unknown", "kconfig_unknown",
		"helper_target_unknown",
	};
	if (!bml_unmet_unknown(u))
		return 1;
	if (!strcmp(u->kind, "arena_loader_unknown") && BML_MUT("check.arena_unknown_nonblocking")) return 0;
	if (!strcmp(u->kind, "helper_target_unknown") && BML_MUT("check.helper_target_unknown_nonblocking")) return 0;
	if ((!strcmp(u->kind, "attach_netkit_unknown") && BML_MUT("check.netkit_unknown_blocks")) ||
	    (!strcmp(u->kind, "sleepable_type_unknown") && BML_MUT("check.sleepable_unknown_blocks")))
		return 1;
	if (BML_MUT("check.unknown_not_blocking"))
		return 0;

	if (BML_MUT("check.v9_unknown_blocks") &&
	    (!strcmp(u->kind, "attach_type_unknown") || !strcmp(u->kind, "attach_target_unknown") || !strcmp(u->kind, "ctx_access_unknown")))
		return 1;
	for (size_t i = 0; i < sizeof(blocking_unknown) / sizeof(blocking_unknown[0]); i++)
		if (strcmp(u->kind, blocking_unknown[i]) == 0)
			return 1;
	return 0;
}

void bml_unmets_free(struct bml_unmets *v)
{
	for (size_t i = 0; i < v->n; i++) {
		free(v->u[i].program);
		free(v->u[i].name);
		free(v->u[i].detail);
	}
	free(v->u);
	memset(v, 0, sizeof(*v));
}

char *bml_unmet_string(const struct bml_unmet *u)
{
	char *added = NULL;
	if (bml_unmet_kernel_string(u, &added)) return added;
	struct bml_buf b = {0};
	const char *k = u->kind, *P = u->program, *N = u->name, *D = u->detail;
	long long I = (long long)u->id;
#define IS(x) (strcmp(k, x) == 0)
	if (IS("map_field"))
		bml_buf_addf(&b, "program %s uses map %s whose value holds %s; the target's verifier rejects this map in this program type ( probe)", P, N, D);
	else if (IS("map_field_unknown")) {
		if (P[0] == 0)
			bml_buf_addf(&b, "map %s has a record value; whether a program uses it with bpf_timer / bpf_spin_lock cannot be determined (Unknown — %s). Loading anyway: the verifier rejects a disallowed use loudly", N, D);
		else
			bml_buf_addf(&b, "program %s uses map %s (%s); whether the target allows this cannot be determined (Unknown). Loading anyway: the verifier rejects a disallowed use loudly", P, N, D);
	} else if (IS("helper"))
		bml_buf_addf(&b, "program %s needs helper %s (%lld), which the target does not offer to this program type", P, N, I);
	else if (IS("program_type"))
		bml_buf_addf(&b, "program %s needs program type %s (%lld), which the target does not have", P, N, I);
	else if (IS("attach") || IS("arch") || IS("ctxfield") || IS("attach_alias") || IS("kprobearg") || IS("binary") ||
		 IS("uprobe_symbol") || IS("uprobearg") || IS("uprobe_debug_build_id") || IS("uprobe_debug_crc"))
		bml_buf_addf(&b, "program %s: %s", P, D);
	else if (IS("kfield"))
		bml_buf_adds(&b, D);
	else if (IS("arg_nullable_unknown"))
		bml_buf_addf(&b, "program %s: whether %s argument %lld may be NULL is not in the target BTF (Unknown — the kernel keeps it in an internal table; the verifier decides at load)", P, N, I);
	else if (IS("arg_nullable"))
		bml_buf_addf(&b, "program %s reads pointer argument %lld of tracepoint %s; the target's verifier does not mark NULL-able tracepoint arguments (%s), so it does not enforce a NULL check before a read — not loading", P, I, N, D);
	else if (IS("arg_nullable_mark_unknown"))
		bml_buf_addf(&b, "program %s reads pointer argument %lld of tracepoint %s; whether the target's verifier marks NULL-able tracepoint arguments cannot be determined (Unknown — %s). Not loading: the verifier might not enforce a NULL check before a read", P, I, N, D);
	else if (IS("farg"))
		bml_buf_adds(&b, D);
	else if (IS("farg_unknown"))
		bml_buf_addf(&b, "program %s reads the pointer arguments of kernel function %s through fentry; this check cannot judge their types (Unknown — it needs the target BTF). Not loading: an argument of another type is read as the declared struct silently", P, N);
	else if (IS("kfield_unknown"))
		bml_buf_addf(&b, "program %s reads kernel field %s through CO-RE; this check cannot judge it (Unknown — it needs the target BTF). Not loading: the loader turns a missing field into a poisoned instruction and does not check the width or sign", P, N);
	else if (IS("retsig_unknown"))
		bml_buf_addf(&b, "program %s reads the return value of kernel function %s through fexit; this check cannot judge its signature (Unknown — it needs the target BTF). Not loading: a wrong signature passes the verifier and reads another argument as the return value", P, N);
	else if (IS("attach_tcx_unknown"))
		bml_buf_addf(&b, "program %s attaches with tcx (%s); whether the target has tcx cannot be determined (Unknown — %s; the loader decides at attach)", P, N, D);
	else if (IS("attach_func_unknown"))
		bml_buf_addf(&b, "program %s attaches (fentry) to kernel function %s; this check cannot judge whether it exists (Unknown — it needs the target BTF; the loader and the kernel decide at attach)", P, N);
	else if (IS("attach_unknown") && D[0])
		bml_buf_addf(&b, "program %s: %s (Unknown — Not loading: the tracepoint signature cannot be judged)", P, D);
	else if (IS("attach_unknown"))
		bml_buf_addf(&b, "program %s attaches to %s; this check cannot judge the tracepoint signature (Unknown — it needs the target BTF). Not loading: an argument of another type may pass the verifier", P, N);
	else if (IS("btf_feature"))
		bml_buf_addf(&b, "the object's BTF uses %s, which the target kernel does not accept (load would fail or need the loader to rewrite the BTF)", N);
	else if (IS("btf_feature_unknown"))
		bml_buf_addf(&b, "the object's BTF uses %s; whether the target accepts it cannot be determined (Unknown — %s). Not loading: a loader could silently rewrite the BTF", N, D);
	else if (IS("btf_rewrite"))
		bml_buf_addf(&b, "the loader would rewrite the object's BTF on this target (%s) — not loading (no silent fallback)", D);
	else if (IS("arg_tag"))
		bml_buf_addf(&b, "program %s relies on the verifier reading argument tag %s, which the target's verifier does not (the same object means something else there — not loading)", P, N);
	else if (IS("arg_tag_unknown"))
		bml_buf_addf(&b, "program %s relies on the verifier reading argument tag %s; this cannot be determined (Unknown — %s). Not loading", P, N, D);
	else if (IS("arch_unknown"))
		bml_buf_addf(&b, "program %s reads pt_regs with the calling convention of %s; the target arch cannot be determined (Unknown — %s). Not loading: another arch reads other registers", P, N, D);
	else if (IS("ctxfield_unknown"))
		bml_buf_addf(&b, "program %s reads %s at a fixed offset; the target BTF cannot confirm it (Unknown — %s). Not loading: a moved field is read silently", P, N, D);
	else if (IS("attach_symbol_unknown"))
		bml_buf_addf(&b, "program %s attaches (kprobe) to %s; whether the kernel symbol exists cannot be determined (Unknown — %s). Not loading: the loader may silently attach to another symbol", P, N, D);
	else if (IS("attach_alias_unknown"))
		bml_buf_addf(&b, "program %s attaches (kprobe) to %s; whether the loader's fallback alias exists cannot be determined (Unknown — %s). Not loading", P, N, D);
	else if (IS("kprobearg_unknown"))
		bml_buf_addf(&b, "program %s reads argument %s as a typed value; the target BTF cannot confirm the function signature (Unknown — %s). Not loading: a changed signature passes load and attach and is read silently", P, N, D);
	else if (IS("binary_unknown"))
		bml_buf_addf(&b, "program %s attaches (uprobe) to %s in a user binary; the binary was not given to this check (Unknown — %s). Not loading: its identity cannot be confirmed", P, N, D);
	else if (IS("uprobearg_unknown"))
		bml_buf_addf(&b, "program %s reads argument %s as a typed value; the binary's DWARF cannot confirm it (Unknown — %s). Not loading", P, N, D);
	else if (IS("uprobearg_abi"))
		bml_buf_addf(&b, "program %s reads the arguments of %s with the SysV registers, which that function does not use: %s", P, N, D);
	else if (IS("uprobearg_abi_unknown"))
		bml_buf_addf(&b, "program %s reads the arguments of %s with the SysV registers; the binary's DWARF cannot confirm the calling convention (Unknown — %s). Not loading", P, N, D);
	else if (IS("uretprobe_abi"))
		bml_buf_addf(&b, "program %s reads the return value of %s from the SysV return value register, which that function does not use alone: %s", P, N, D);
	else if (IS("uretprobe_abi_unknown"))
		bml_buf_addf(&b, "program %s reads the return value of %s from the SysV return value register; the binary's DWARF cannot confirm the calling convention (Unknown — %s). Not loading", P, N, D);
	else if (IS("helper_unknown"))
		bml_buf_addf(&b, "program %s needs helper %s (%lld); the target cannot be probed for it (Unknown — %s)", P, N, I, D);
	else if (IS("attach_type") && (!strcmp(D, "sk_skb") || !strcmp(D, "sk_msg")))
		bml_buf_addf(&b,
			     "program %s (program type %s) loads with expected attach type %s, but the target kernel cannot create a BPF link of that attach type on a "
			     "sockmap (the attach this object needs)",
			     P, D, N);
	else if (IS("attach_type") && (!strcmp(N, "trace_kprobe_multi") || !strcmp(N, "trace_uprobe_multi")))
		bml_buf_addf(&b,
			     "program %s (program type %s) loads with expected attach type %s, but the target kernel cannot create a BPF link of that attach type "
			     "(the attach this object needs)",
			     P, D, N);
	else if (IS("attach_type"))
		bml_buf_addf(&b, "program %s is loaded with expected attach type %s, which the target kernel does not accept for program type %s", P, N, D);
	else if (IS("attach_type_unknown"))
		bml_buf_addf(&b, "program %s is loaded with expected attach type %s; whether the target accepts it cannot be determined (Unknown — %s). Loading anyway: the kernel rejects an unknown attach type loudly at load", P, N, D);
	else if (IS("attach_target") && !strncmp(N, "map:", 4))
		bml_buf_addf(&b, "program %s: %s", P, D);
	else if (IS("attach_target"))
		bml_buf_addf(&b, "program %s attaches (%s) to %s, which the target kernel does not have", P, D, N);
	else if (IS("attach_target_unknown"))
		bml_buf_addf(&b, "program %s attaches to %s; whether the target has it cannot be determined (Unknown — %s). Loading anyway: the attach fails loudly if it is missing", P, N, D);
	else if (IS("ctx_access"))
		bml_buf_addf(&b, "program %s accesses ctx field %s, which the target's verifier does not allow for %s", P, N, D);
	else if (IS("ctx_access_unknown"))
		bml_buf_addf(&b, "program %s accesses ctx field %s; whether the target's verifier allows it cannot be determined (Unknown — %s). Loading anyway: the verifier rejects a disallowed access loudly", P, N, D);
	else if (IS("tpfield"))
		bml_buf_addf(&b, "program %s reads tracepoint field %s: %s", P, N, D);
	else if (IS("tpfield_unknown"))
		bml_buf_addf(&b, "program %s reads tracepoint field %s at a fixed offset; the target's tracepoint format cannot confirm it (Unknown — %s). Not loading: a moved or resized field is read silently", P, N, D);
	else if (IS("ext_target"))
		bml_buf_addf(&b, "program %s replaces function %s: %s", P, N, D);
	else if (IS("ext_target_unknown"))
		bml_buf_addf(&b, "program %s replaces function %s; its signature cannot be confirmed (Unknown — %s). Not loading: the kernel compares neither the sign of the arguments nor the return value's width, and a mismatch is read silently", P, N, D);
	else if (IS("structop"))
		bml_buf_addf(&b, "program %s implements struct_ops member %s: %s", P, N, D);
	else if (IS("structop_unknown"))
		bml_buf_addf(&b, "program %s implements struct_ops member %s; the target BTF cannot confirm the member and its signature (Unknown — %s). Not loading: an argument of another type is read silently", P, N, D);
	else if (IS("map_type") && !strcmp(D, "inner"))
		bml_buf_addf(&b, "map %s holds inner maps of map type %s (%lld), which the target does not have", P, N, I);
	else if (IS("map_type"))
		bml_buf_addf(&b, "map %s needs map type %s (%lld), which the target does not have", P, N, I);
	else if (IS("usdt_probe"))
		bml_buf_addf(&b, "program %s attaches (usdt) to %s: %s", P, N, D);
	else if (IS("usdtarg"))
		bml_buf_addf(&b, "program %s reads USDT argument %s: %s", P, N, D);
	else if (IS("usdtarg_unknown"))
		bml_buf_addf(&b, "program %s reads USDT argument %s; the point's argument cannot be read by this check (Unknown — %s). Not loading: an argument of another size or place is read silently", P, N, D);
	else if (IS("usdt_loader"))
		bml_buf_addf(&b, "program %s attaches (usdt) to %s: %s — not loading", P, N, D);
	else if (IS("kfunc_sig"))
		bml_buf_addf(&b, "program %s calls kfunc %s: %s", P, N, D);
	else if (IS("kfunc_sig_unknown"))
		bml_buf_addf(&b, "program %s calls kfunc %s; its prototype cannot be confirmed (Unknown — %s). Not loading: an argument of another integer width or sign passes the verifier and is read silently", P, N, D);
	else if (IS("kfunc_allowed"))
		bml_buf_addf(&b, "program %s calls kfunc %s, which the kernel rejects in its exact initial profile (%s). Not loading", P, N, D);
	else if (IS("kfunc_allowed_unknown"))
		bml_buf_addf(&b, "program %s calls kfunc %s; its use in the exact initial profile cannot be confirmed (Unknown — %s). Loading anyway: the kernel rejects a disallowed kfunc loudly at load", P, N, D);
	else if (IS("sysarg"))
		bml_buf_addf(&b, "program %s reads syscall argument %s: %s", P, N, D);
	else if (IS("sysarg_unknown"))
		bml_buf_addf(&b, "program %s reads syscall argument %s; the target cannot confirm its type (Unknown — %s). Not loading: a wrong width, sign or pointer is read silently", P, N, D);
	else if (IS("lsm_cgroup_loader"))
		bml_buf_addf(&b, "program %s attaches (lsm_cgroup) to %s: %s — not loading", P, N, D);
	else if (IS("lsm_cgroup_loader_unknown"))
		bml_buf_addf(&b, "program %s attaches (lsm_cgroup) to %s; whether the loader can load an lsm_cgroup program cannot be determined (Unknown — %s). Not loading", P, N, D);
	else if (IS("fsession_loader"))
		bml_buf_addf(&b, "program %s attaches (fsession) to %s: %s — not loading", P, N, D);
	else if (IS("fsession_loader_unknown"))
		bml_buf_addf(&b, "program %s attaches (fsession) to %s; whether the loader can load an fsession program cannot be determined (Unknown — %s). Not loading", P, N, D);
	else if (IS("ksyscall_loader"))
		bml_buf_addf(&b, "program %s attaches (ksyscall) to syscall %s: %s — not loading", P, N, D);
	else if (IS("ksyscall_loader_unknown"))
		bml_buf_addf(&b, "program %s attaches (ksyscall) to syscall %s; where the loader attaches a ksyscall program cannot be determined (Unknown — %s). Not loading", P, N, D);
	else if (IS("usdt_loader_unknown"))
		bml_buf_addf(&b, "program %s attaches (usdt) to %s; how the loader attaches USDT points cannot be determined (Unknown — %s). Not loading: a loader that does not pass the semaphore's ref_ctr_offset leaves a guarded point silent", P, N, D);
	else
		bml_buf_addf(&b, "unmet requirement %s: program %s, %s (%s)", k, P, N, D);
#undef IS
	return bml_buf_take(&b);
}
