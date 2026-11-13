#include "req/check_internal.h"

#include <string.h>

#include "util/gostr.h"

int bml_unmet_kernel_string(const struct bml_unmet *u, char **out)
{
	struct bml_buf b = {0};
	const char *P = u->program, *N = u->name, *D = u->detail;
#define IS(s) (!strcmp(u->kind, s))
	if (IS("enumval")) bml_buf_addf(&b, "program %s uses the enum constant %s: %s — not loading", P, N, D);
	else if (IS("enumval_unknown")) bml_buf_addf(&b, "program %s uses the enum constant %s; its value on the target cannot be confirmed (Unknown — %s). Not loading: a different value silently changes what the program does", P, N, D);
	else if (IS("coreenum")) bml_buf_addf(&b, "program %s reads the enum constant %s through a CO-RE relocation: %s — not loading (the loader would poison the instruction)", P, N, D);
	else if (IS("coreenum_unknown")) bml_buf_addf(&b, "program %s reads the enum constant %s through a CO-RE relocation; whether the target has it cannot be determined (Unknown — %s). Not loading: an absent constant is a poisoned instruction", P, N, D);
	else if (IS("funcret")) bml_buf_addf(&b, "program %s reads the return value of kernel function %s through fexit (bpf_get_func_ret): %s — not loading (a wrong width or sign passes the verifier and reads the value wrong)", P, N, D);
	else if (IS("funcret_unknown")) bml_buf_addf(&b, "program %s reads the return value of kernel function %s through fexit (bpf_get_func_ret); this check cannot judge its return type (Unknown — %s). Not loading: a wrong width or sign passes the verifier and reads the value wrong", P, N, D);
	else if (IS("helper_target")) bml_buf_addf(&b, "program %s calls helper %s at a typed target: %s — not loading", P, N, D);
	else if (IS("helper_target_unknown")) bml_buf_addf(&b, "program %s calls helper %s at a typed target; acceptance cannot be determined (Unknown — %s). Not loading", P, N, D);
	else if (IS("attach_netkit_unknown")) bml_buf_addf(&b, "program %s attaches with netkit (%s); whether the target has netkit cannot be determined (Unknown — %s; the loader decides at attach)", P, N, D);
	else if (IS("sleepable_type")) bml_buf_addf(&b, "program %s is loaded sleepable (fentry.s/%s) but the target kernel cannot load this program type / attach type pair sleepable (%s)", P, N, D);
	else if (IS("sleepable_type_unknown")) bml_buf_addf(&b, "program %s is loaded sleepable (fentry.s/%s); whether the target kernel accepts a sleepable program of this type cannot be determined (Unknown — %s; the kernel refuses a bad load loudly)", P, N, D);
	else if (IS("fibflags")) bml_buf_addf(&b, "program %s calls bpf_fib_lookup with flags %s, which the target's helper rejects for %s. Not loading: the helper returns -EINVAL at run time and the verifier does not see it", P, N, D);
	else if (IS("fibflags_unknown")) bml_buf_addf(&b, "program %s calls bpf_fib_lookup with flags %s; whether the target's helper accepts them cannot be determined (Unknown — %s). Not loading: a rejected mask is only seen at run time", P, N, D);
	else if (IS("datakptr_loader")) bml_buf_addf(&b, "section %s holds hidden kptr globals; %s. Not loading: the kernel refuses mmap of a map with a kptr (-ENOTSUPP), failing the load", N, D);
	else if (IS("datakptr_loader_unknown")) bml_buf_addf(&b, "section %s holds hidden kptr globals; whether the loader mmaps them cannot be determined (Unknown — %s). Not loading: the kernel refuses mmap of a map with a kptr (-ENOTSUPP), failing the load", N, D);
	else if (IS("arena_loader")) bml_buf_addf(&b, "map %s is a BPF arena; %s. Not loading: the program's addr_space_cast must reach the kernel byte for byte, and the arena must be mmapped at its map_extra address to share it with userspace", N, D);
	else if (IS("arena_loader_unknown")) bml_buf_addf(&b, "map %s is a BPF arena; whether the loader keeps addr_space_cast intact and mmaps the arena at map_extra cannot be determined (Unknown — %s). Not loading", N, D);
	else if (IS("typed_ksym_loader")) bml_buf_addf(&b, "the object reads the per-CPU kernel variable %s through bpf_per_cpu_ptr; %s. Not loading: a kallsyms address is a scalar to the verifier, and bpf_per_cpu_ptr needs a BTF-typed pointer (ARG_PTR_TO_PERCPU_BTF_ID)", N, D);
	else if (IS("typed_ksym_loader_unknown")) bml_buf_addf(&b, "the object reads the per-CPU kernel variable %s; how the loader resolves a typed ksym cannot be determined (Unknown — %s). Not loading: without BPF_PSEUDO_BTF_ID the verifier rejects bpf_per_cpu_ptr", N, D);
	else if (IS("ksymvar")) bml_buf_addf(&b, "the object reads the per-CPU kernel variable %s; %s. Not loading: an unresolved strong extern fails the load, and a variable of another type is read as the declared slot", N, D);
	else if (IS("ksymvar_unknown")) bml_buf_addf(&b, "the object reads the per-CPU kernel variable %s; whether the target has it with the declared slot type cannot be determined (Unknown — %s). Not loading", N, D);
	else if (IS("kconfig_loader")) bml_buf_addf(&b, "the object reads %s; %s. Not loading: the loader refuses a weak .kconfig extern", N, D);
	else if (IS("kconfig_loader_unknown")) bml_buf_addf(&b, "the object reads %s; how the loader resolves CONFIG_* externs cannot be determined (Unknown — %s). Not loading", N, D);
	else if (IS("kconfig")) bml_buf_addf(&b, "the object reads %s, which the target's kconfig does not set (%s). Not loading: an unset strong extern fails the load", N, D);
	else if (IS("kconfig_type")) bml_buf_addf(&b, "the object reads %s, whose kconfig value does not fit the extern (%s). Not loading: the loader rejects the value", N, D);
	else if (IS("kconfig_unknown")) bml_buf_addf(&b, "the object reads %s; its kconfig value cannot be determined (Unknown — %s). Not loading: a loader that cannot read the kconfig file fails the load, and the value is never guessed", N, D);
	else if (IS("kstructsize") || IS("kstructsize_unknown")) {
		const char *slash = strchr(N, '/');
		if (!slash) slash = N + strlen(N);
		bml_buf_adds(&b, "the object embeds struct "); bml_buf_add(&b, N, (size_t)(slash - N));
		bml_buf_addf(&b, IS("kstructsize") ? " (%s bytes): %s — not loading (a kfunc writes the target's struct size and would overwrite the bytes after the field)" :
			" (%s bytes); the target's struct size cannot be confirmed (Unknown — %s). Not loading: a larger struct would let a kfunc overwrite the bytes after the field", *slash ? slash + 1 : "", D);
	} else return 0;
	*out = bml_buf_take(&b);
	return 1;
#undef IS
}
