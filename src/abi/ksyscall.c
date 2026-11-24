/* abi/ksyscall.c — the ksyscall attach (a port of the Go reference livecaps.AttachKsyscall). A program
 * with the attach row `ksyscall <syscall>` is attached with a kprobe at the entry of the syscall
 * wrapper `<prefix>sys_<syscall>`. The prefix is looked up by the kernel's machine (from uname, not the
 * process's architecture) in the same table as the Go requirements.SyscallPrefixes; a machine that is not
 * in the table is an error before anything is attached (the program is never attached to the bare
 * name). After attaching, the name of the kprobe function in the perf link's info is compared with
 * the wrapper; if it differs or cannot be read, the link is detached and an error is returned, so a
 * re-attachment to an alias by libbpf or cilium is not accepted.
 * The loader declaration used by the C ABI check is cilium-v0.22-usdt-ksyscall (ksyscall_attach
 * prefix). A ksyscall ELF in the product's checked load reaches this code too. (The earlier declaration,
 * cilium-v0.22-usdt, has ksyscall_attach none; such an ELF reached here only through the test entry
 * that loads without the check.) */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

#include <bpf/libbpf.h>

#include "abi/internal.h"
#include "util/mutation.h"

static int str_is(const struct bml_str *s, const char *lit)
{
	return s->len == strlen(lit) && memcmp(s->p, lit, s->len) == 0;
}

/* The Go requirements.SyscallPrefixes (a subset of libbpf's arch_specific_syscall_pfx; only x86_64 for now). */
static const char *syscall_prefix(const char *machine)
{
	return !strcmp(machine, "x86_64") ? "__x64_" : NULL;
}

static int64_t attach_ksyscall_body(int64_t obj, const char *prog, int64_t len)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, len, &p)))
		return e;
	const char *name = bpf_program__name(p);
	const struct bml_attach *a = NULL;
	for (size_t i = 0; i < o->req->n_attaches; i++)
		if (str_is(&o->req->attaches[i].program, name) && str_is(&o->req->attaches[i].attach_type, "ksyscall"))
			a = &o->req->attaches[i];
	if (bpf_program__type(p) != BPF_PROG_TYPE_KPROBE || !a)
		return abi_fail(BML_STATE, "bml: %s is a %s program, not ksyscall — attach it with its own kind", name, abi_kind_name(o, p));
	if (a->target.len == 0 || strlen(a->target.p) != a->target.len)
		return abi_fail(BML_OTHER, "bml: ksyscall %s: the attach row names no syscall", name);
	struct utsname u;
	if (uname(&u) != 0)
		return abi_fail(BML_OTHER, "bml: attach ksyscall %s: uname: %s", name, abi_errno(errno));
	const char *machine = BML_MUT("ksys.machine_other") ? "riscv64" : u.machine;
	const char *pfx = syscall_prefix(machine);
	if (!pfx)
		return abi_fail(BML_OTHER,
				"bml: attach ksyscall %s: no syscall wrapper prefix is known for the kernel machine \"%s\" — refusing to attach %s to the bare name", name,
				machine, a->target.p);
	char want[256];
	snprintf(want, sizeof want, "%ssys_%s", pfx, a->target.p);
	/* Mutation: the form that attached to another function (the comparison sees it).
 * ksys.target_other_unconfirmed also removes the comparison (a hook carries only one name). */
	int unconfirmed = BML_MUT("ksys.target_other_unconfirmed");
	const char *at = BML_MUT("ksys.target_other") || unconfirmed ? "__x64_sys_getpid" : want;
	LIBBPF_OPTS(bpf_kprobe_opts, ko, .retprobe = false);
	struct bpf_link *l = bpf_program__attach_kprobe_opts(p, at, &ko);
	if (!l) {
		int err = errno;
		return abi_fail(BML_OTHER, "bml: attach ksyscall %s: kprobe %s: %s%s", name, want, abi_errno(err),
				err == EPERM ? " (hint: attaching a kprobe needs CAP_PERFMON; perf_event_paranoid may also restrict it)" : "");
	}
	char got[512];
	int rc = abi_kprobe_link_name(bpf_link__fd(l), BPF_PERF_EVENT_KPROBE, got, sizeof got);
	if (rc != 0) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: attach ksyscall %s: cannot confirm the attach target %s: %s (detached)", name, want, abi_errno(-rc));
	}
	if (strcmp(got, want) != 0 && !BML_MUT("ksys.no_confirm") && !unconfirmed) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: attach ksyscall %s: attached to %s, not the syscall wrapper %s (the loader substituted another symbol — detached)",
				name, got[0] ? got : "(no kprobe function name)", want);
	}
	return abi_link_put(l);
}

int64_t bml_attach_ksyscall(int64_t obj, const char *prog, int64_t prog_len)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_ksyscall_body(obj, prog, prog_len);
	abi_object_release(o);
	return e;
}
