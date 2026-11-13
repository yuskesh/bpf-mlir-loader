/* bml.h — C ABI of bpf-mlir-loader (a single interface that replaces the Go c-archive used by the downstream language bindings).
 *
 * Rules:
 * - Every operation returns a **result handle** (int64, 1 or greater). Read kind, value, message and Unmet through the accessors and release it with bml_result_free.
 *   The kind of an unknown or released result is BML_STATE
 * - All integers are int64 (range checks are inside the library; out of range is BML_OTHER, or BML_VALUE_RANGE at the Spinel binding's Integer entry points)
 * - Input strings and bytes are (pointer, length); NUL is not relied on. They are read only during the call (the library does not take ownership)
 * - Message and Unmet fields are NUL-terminated strings owned by the result (with a length, so embedded NULs can be read through it). Valid until bml_result_free
 * - Objects, links, readers and iterators are integer handles (no pointers are passed; an operation after close is BML_STATE, not a use-after-free)
 * - The checked load is the only entry point (there is no entry point that skips the checks). One process has at most one loaded object
 * - No signal handler is installed and no thread is left behind (only bml_test_run_tracing creates one thread, which is joined and starts with all signals blocked);
 *   RLIMIT_MEMLOCK is not changed and no BPF token is created (process state is not changed)
 * - **libbpf print**: while an object is loaded (from a successful load until bml_close), bml borrows libbpf's print callback and
 *   discards the output (libbpf warnings from attach etc. do not reach the caller's stderr; errors are named by the result message with errno and a hint). bml_close restores the
 *   callback in place before the load (libbpf's default or the caller's libbpf_set_print). During the load, bml reads libbpf's text (the verifier's rejection text).
 *   The borrow is counted by the number of internal libbpf objects and restored at the last close (nothing leaks when loads or a close and a load overlap).
 *   If the caller calls libbpf_set_print while a bml object exists, it overwrites bml's borrow (the caller's responsibility)
 * - Callable from any thread (the registry is protected by a mutex)
 * - **close and calls on other threads**: a call that looks up an object raises the object's count while it runs. bml_close returns BML_STATE without closing if the count is
 *   not 0 (it does not wait; the caller retries later); at 0 it closes, and every later call is BML_STATE. Ring buffer read and
 *   iterator next are also calls that look up the object (bml_close during a blocked read is STATE). **close does not wait**:
 *   bml_ringbuf_close / bml_hash_iter_close are also BML_STATE during a read / next on another thread. Closing an object closes its readers and iterators first
 *
 * The kind numbers are defined by bml/kind.h (authoritative). */
#ifndef BML_BML_H
#define BML_BML_H

#include <stdint.h>

#include "bml/kind.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Version string of the library (static storage; do not free) */
const char *bml_version(void);
/* Policy version (the same as requirements.PolicyVersion in bpf-mlir) */
int64_t bml_policy_version(void);
/* Largest requirements format version this library reads (the same as requirements.MaxFormatVersion in bpf-mlir) */
int64_t bml_max_format_version(void);

/* Version facts stamped by scripts/build-libs.sh. They are build provenance, not proof of what the code does.
 * bml_source_form: "dev" (built from a git checkout of bml), "public" (from a tree with SOURCE_VERSION and PINS) or "none"
 * (neither; the commits are then "unknown" and dirty is -1). Strings are static storage; do not free. */
const char *bml_source_form(void);
/* The bml source commit: 40 lowercase hex digits (dev: git HEAD; public: SOURCE_VERSION's source_commit), or "unknown" */
const char *bml_source_commit(void);
/* 1 if the bml tree had changes (tracked, untracked or submodule) when built, 0 if clean, -1 if unknown (no git) */
int bml_source_dirty(void);
/* The bpf-mlir commit this bml pins (dev: the third_party/bpf-mlir gitlink in HEAD; public: PINS), or "unknown".
 * It names the contract bml copies; bml compiles no bpf-mlir source. */
const char *bml_bpf_mlir_commit(void);

/* ---- Results ---- */
int64_t bml_result_kind(int64_t r);
int64_t bml_result_value(int64_t r);
/* Message (owned by the result, NUL-terminated). *len receives the length (may be NULL) */
const char *bml_result_message(int64_t r, int64_t *len);
/* Copies min(length, cap) bytes of the message into buf (no NUL is added) and returns the full length */
int64_t bml_result_message_copy(int64_t r, char *buf, int64_t cap);
int64_t bml_result_unmet_count(int64_t r);
/* Field of the i-th Unmet (0 kind, 1 program, 2 name, 3 detail). Out of range gives "" */
const char *bml_result_unmet_field(int64_t r, int64_t i, int64_t field, int64_t *len);
int64_t bml_result_unmet_field_copy(int64_t r, int64_t i, int64_t field, char *buf, int64_t cap);
void bml_result_free(int64_t r);

/* ---- Load ---- */
/* Checked load. elf (n bytes), the hex SHA-256 of the schema (sha), and maps.json (bpf-mlir's map declaration document, section 12 of requirements_format.md). caps_kind 0 queries the target
 * kernel (live). The value on OK is the object handle; Unmet holds the Unmet entries that did not stop the load (Unknown) */
int64_t bml_load_checked(const uint8_t *elf, int64_t n, const char *sha, int64_t sha_len, const char *maps, int64_t maps_len,
			 int64_t caps_kind);
/* The same, with .rodata configuration values as load arguments (the process holds no state). config is JSON
 * {"set": {"<name>": <bits>}, "optional": ["<name>"]} (empty means neither set nor optional, the same as bml_load_checked). Checked against the globals in maps.json:
 * an unreadable document, or values given with a maps.json that has no globals -> BML_PRECHECK_FAILED; a name that is not a declared .rodata global ->
 * BML_MAP_MISMATCH; a value that does not fit the width -> BML_VALUE_RANGE; a declared .rodata global that is neither set nor optional -> BML_CONFIG_NOT_SET
 * (all such names, before any kernel object is created). An optional global that is not set keeps the ELF's initial value */
int64_t bml_load_checked_config(const uint8_t *elf, int64_t n, const char *sha, int64_t sha_len, const char *maps, int64_t maps_len,
				const char *config, int64_t config_len, int64_t caps_kind);
/* The same, with uprobe targets as load arguments too. targets is JSON {"uprobe_targets": [{"program": "<name>", "path": "<binary>"}]} (empty means no
 * targets; the check stops a uprobe program with binary_unknown). The load opens path exactly once and shares that fd between the check (the binary's SHA-256, symbol, DWARF) and
 * bml_attach_uprobe (the fd is closed when the object is closed). An unreadable document or two targets for one program is BML_PRECHECK_FAILED; a name that is not a
 * uprobe program in the ELF, or a path that cannot be opened, is BML_OTHER. Split DWARF (policy version 16): the target's "debug" (a per-program
 * file; takes priority and does not fall back to the root even if unreadable) and the document's "debug_root" (root of the build ID search; omitted means /usr/lib/debug, "" means no search). Only when the main file has no
 * DWARF, it is opened once during the check, read in full, and closed (attach does not use it). If the build ID or debuglink CRC differs from the main file: TARGET_REJECTED
 * (uprobe_debug_build_id / uprobe_debug_crc) */
int64_t bml_load_checked_targets(const uint8_t *elf, int64_t n, const char *sha, int64_t sha_len, const char *maps, int64_t maps_len,
				 const char *config, int64_t config_len, const char *targets, int64_t targets_len, int64_t caps_kind);
/* Value of a global (bits zero-extended; .rodata is the value at load, .bss is the current value). decl is one element of the globals in maps.json, {name, section, type}:
 * if it differs from the declaration at load, BML_MAP_MISMATCH; a name not declared is BML_STATE. There is no entry point for rewriting .rodata after load (the kernel freezes it) */
int64_t bml_global_get(int64_t obj, const char *decl, int64_t decl_len);
/* The Unmet entries that did not stop the load (read through the Unmet accessors) */
int64_t bml_object_unmet(int64_t obj);
/* Closes the object (readers and iterators first; links are not closed). Idempotent (a second call also returns OK); operations on a closed object are BML_STATE */
int64_t bml_close(int64_t obj);

/* ---- Attach ---- */
int64_t bml_attach_xdp(int64_t obj, const char *prog, int64_t prog_len, const char *ifname, int64_t if_len);
/* Idempotent (a second call also returns OK) */
int64_t bml_detach(int64_t link);
/* fentry / fexit: attaches to the kernel function in the ELF section. A program of another kind is BML_STATE (mix-up); an attach error is BML_OTHER */
int64_t bml_attach_fentry(int64_t obj, const char *prog, int64_t prog_len);
int64_t bml_attach_fexit(int64_t obj, const char *prog, int64_t prog_len);
/* kprobe: attaches to the entry of the function in the requirements attach row (kprobe <fn>), and after attaching compares the function name in the perf link info
 * with <fn> (different or unreadable: detach and BML_OTHER; a silent re-target to an alias is not accepted). uprobe and other kinds are BML_STATE */
int64_t bml_attach_kprobe(int64_t obj, const char *prog, int64_t prog_len);
/* tp_btf: attaches to the tracepoint in the ELF section, and after attaching compares the tracepoint name in the raw tracepoint link info with the requirements
 * attach row (trace_raw_tp <tracepoint>) (different, unreadable or no row: detach and BML_OTHER). A program of another kind is BML_STATE.
 * On all 3 kernels (7.1.8, 6.12.111, 6.6.157) the kernel refuses to run a tp_btf test run with EFAULT; bml_test_run_tracing passes it to the kernel and
 * adds a hint to the BML_OTHER text. Tests must actually fire the tracepoint */
int64_t bml_attach_tp_btf(int64_t obj, const char *prog, int64_t prog_len);
/* uprobe: attaches to the entry of the function (requirements attach row uprobe <symbol>) in the target fd checked at load. pid 0 means every process.
 * The file offset comes from the ELF of that same fd (exactly one FUNC in symtab, an executable PT_LOAD); attaches through `/proc/self/fd/N` (the path is not reopened); after
 * attaching, compares the offset in the perf link info (different: detach and BML_OTHER). A program with no target, or of another kind, is BML_STATE; a negative pid is BML_OTHER */
int64_t bml_attach_uprobe(int64_t obj, const char *prog, int64_t prog_len, int64_t pid);
/* The file in the perf link info at attach time of a uprobe link (message). BML_STATE if it is not a uprobe link of this object */
int64_t bml_uprobe_link_file(int64_t obj, int64_t link);
/* ---- Attach to kernel objects: all compare the kernel link info with the declaration after attaching; different or unreadable: detach and
 * BML_OTHER. A program of another kind is BML_STATE (mix-up) ---- */
/* kretprobe: to the return of the function in attach row kretprobe <fn>. Checks the perf link info is KRETPROBE and the function name is <fn> */
int64_t bml_attach_kretprobe(int64_t obj, const char *prog, int64_t prog_len);
/* uretprobe: attach row uretprobe <symbol>; the same as bml_attach_uprobe (the target fd from load, pid 0 means every process) at the return.
 * uprobe_targets in bml_load_checked_targets may also name uretprobe programs. Checks the link info is URETPROBE and the offset is the computed value.
 * bml_uprobe_link_file also works */
int64_t bml_attach_uretprobe(int64_t obj, const char *prog, int64_t prog_len, int64_t pid);
/* usdt (the ref_ctr contract in section 8 of requirements_format.md): to every point of the binary in attach row usdt <provider>:<name>. The binary is the target fd from
 * load (name the usdt program in uprobe_targets). Writes the argument spec of point i (note order) to key i of the spec map __ebpf_usdt_spec_<program>,
 * and attaches with cookie i and, for semaphore points, ref_ctr_offset (one uprobe per point; usdt programs are loaded with expected_attach_type 0).
 * Compares the offset and cookie in the perf link info of every point. The link is one handle (bml_detach closes every point). pid 0 means every process */
int64_t bml_attach_usdt(int64_t obj, const char *prog, int64_t prog_len, int64_t pid);
/* ksyscall: attaches the program in attach row ksyscall <syscall> by kprobe to the entry of the syscall wrapper `<prefix>sys_<syscall>`
 * (the prefix depends on the kernel's machine, __x64_ on x86_64; not in the table means BML_OTHER before attaching). After attaching, compares the function
 * name in the perf link info with the wrapper; different: detach and BML_OTHER. The loader declaration of the product's checked load, cilium-v0.22-usdt-ksyscall, has ksyscall_attach
 * prefix; this function carries that obligation (attaching to the wrapper and comparing afterwards) */
int64_t bml_attach_ksyscall(int64_t obj, const char *prog, int64_t prog_len);
/* netfilter (the same as cilium's link.AttachNetfilter): links a netfilter program to the netfilter hook in the **netns of the calling thread**
 * (bml does not change the netns; the caller's responsibility). pf (NFPROTO_IPV4 2 / IPV6 10), hooknum (NF_INET_PRE_ROUTING 0 ... POST_ROUTING 4), priority and flags
 * (BPF_F_NETFILTER_IP_DEFRAG) are caller arguments. Outside the u32 / int32 range is BML_VALUE_RANGE; a kernel rejection is BML_OTHER. After attaching, compares the 4 values in the link info
 * with the arguments; different: detach and BML_OTHER */
int64_t bml_attach_netfilter(int64_t obj, const char *prog, int64_t prog_len, int64_t pf, int64_t hooknum, int64_t priority, int64_t flags);
/* fmod_ret: attach row trace_fmod_ret <fn> (format 10) or modify_return func:<fn> (format 9). Checks the attach type in the tracing link info is MODIFY_RETURN and
 * the target BTF id is the id of FUNC <fn> in the vmlinux BTF (as read by bml itself) */
int64_t bml_attach_fmod_ret(int64_t obj, const char *prog, int64_t prog_len);
/* raw_tp: to the tracepoint in attach row raw_tp rawtp:<tracepoint> (attaches with an explicit declaration). Compares the name in the raw tracepoint link info.
 * The raw_tp test run is bml_test_run_ctx_inout */
int64_t bml_attach_raw_tp(int64_t obj, const char *prog, int64_t prog_len);
/* tracepoint: opens a perf event **on every online CPU** for the tracefs event in attach row trace_tp <category>/<event> (format 11) or tracepoint tp:<category>/<event> (format 9) and attaches
 * (the libbpf / cilium default is CPU 0 only, which silently drops events on other CPUs for syscall events that read user memory).
 * The program is linked only to the first CPU's event; the other CPUs' events have the same lifetime
 * as the link (bml_detach closes them all). Compares the tracepoint name in the perf link info. If possible and online CPUs differ, the default is BML_OTHER
 * (naming the offline CPUs; a CPU that comes online later has no event); BML_TRACEPOINT_ONLINE_ONLY in flags uses only the currently online CPUs. Any other flags
 * bit is BML_VALUE_RANGE */
#define BML_TRACEPOINT_ONLINE_ONLY 1
int64_t bml_attach_tracepoint(int64_t obj, const char *prog, int64_t prog_len, int64_t flags);
/* iter: creates the iterator link for attach row trace_iter iter:<target>. map_fd is the caller's map fd for targets that need a map (bpf_map_elem etc.)
 * (negative means none; bml neither closes nor remembers the fd). Compares the target name in the link info (and the map id if a map was passed) */
int64_t bml_attach_iter(int64_t obj, const char *prog, int64_t prog_len, int64_t map_fd);
/* Creates a new iterator fd from an iter link and returns it in value; **the caller read(2)s and closes it** (bml does not remember it). The kernel runs the
 * program on each read. A link that is not iter is BML_STATE */
int64_t bml_iter_open(int64_t link);
/* Reads the same iterator to EOF into buf (cap bytes); value is the byte count. Output larger than cap is BML_VALUE_RANGE (not truncated; the contents of buf are undefined).
 * Read long output through bml_iter_open */
int64_t bml_iter_read(int64_t link, uint8_t *buf, int64_t cap);

/* ---- Attach to a caller-supplied target: the target is the caller's fd (bml does not open a path). If the fd is not the right thing (cgroup v2 directory, net namespace, socket):
 * BML_OTHER; a negative fd is BML_VALUE_RANGE; a program of another kind is BML_STATE ---- */
/* BPF_LINK_CREATE of cgroup_skb (the direction is the ELF section, ingress / egress) on a cgroup. Compares the cgroup id and attach type in the link info with the fd
 * (different: detach and BML_OTHER). bml neither closes nor remembers the fd */
int64_t bml_attach_cgroup(int64_t obj, const char *prog, int64_t prog_len, int64_t cgroup_fd);
/* Links sk_lookup or flow_dissector to a network namespace (the caller's nsfs fd, /proc/<pid>/ns/net etc.). Compares the netns inode in the link info */
int64_t bml_attach_netns(int64_t obj, const char *prog, int64_t prog_len, int64_t netns_fd);
/* SO_ATTACH_BPF of socket_filter on the caller's socket (**an explicit request that changes the caller's process state**; the caller removes it with SO_DETACH_BPF or close).
 * Creates no link (value 0). The kernel cannot read back an eBPF socket filter, so the attached program is not compared */
int64_t bml_attach_socket(int64_t obj, const char *prog, int64_t prog_len, int64_t sock_fd);
/* Dups the fd of a socket_filter program and returns it in value (**the caller owns and closes it**; for callers doing SO_ATTACH_BPF etc. themselves). Other kinds are BML_STATE */
int64_t bml_program_fd(int64_t obj, const char *prog, int64_t prog_len);

/* tcx: attaches a sched_cls program to the interface's tcx; the direction is the ELF section (tcx/ingress, tcx/egress). After attaching, compares the
 * direction and ifindex in the link info (different: detach and BML_OTHER). A program of another kind is BML_STATE; an interface error is BML_OTHER */
int64_t bml_attach_tcx(int64_t obj, const char *prog, int64_t prog_len, const char *ifname, int64_t if_len);
/* netkit: attaches a sched_cls program to a netkit device; the direction is the ELF section (netkit/primary, netkit/peer). For either direction, ifname is the name of the
 * **primary device** in the caller's netns. After attaching, compares the link info (type, ID, program, direction, device; a PEER link is the peer of the same pair);
 * different: detach and BML_OTHER. A program of another kind is BML_STATE; a device error is BML_OTHER (text for ENXIO on a non-netkit device, EACCES on the peer device) */
int64_t bml_attach_netkit(int64_t obj, const char *prog, int64_t prog_len, const char *ifname, int64_t if_len);
/* Actual direction of a tcx link (link info): message is "ingress" / "egress", value is ifindex. A link that is not tcx, absent or already detached is BML_STATE */
int64_t bml_link_tcx_direction(int64_t link);

/* ---- array maps (key is u32; out of range is BML_OTHER). decl is the JSON declaration of one map ({name,kind,key,value,max_entries,flags?}) ---- */
/* bits: a 4-byte value is zero-extended, 8 bytes are as is */
int64_t bml_map_get_bits(int64_t obj, const char *decl, int64_t decl_len, int64_t key);
int64_t bml_map_put_bits(int64_t obj, const char *decl, int64_t decl_len, int64_t key, int64_t bits);
/* Integer: reads with the sign of the declared value spelling (i32, u32, i64, u64); not representable in int64 is BML_VALUE_RANGE. INT64_MIN is always VALUE_RANGE */
int64_t bml_map_get_int(int64_t obj, const char *decl, int64_t decl_len, int64_t key);
int64_t bml_map_put_int(int64_t obj, const char *decl, int64_t decl_len, int64_t key, int64_t value);
/* record: members is the records JSON ({"<S>":{size,members[...]}}; empty means none). n is the record size */
int64_t bml_map_get_bytes(int64_t obj, const char *decl, int64_t decl_len, const char *members, int64_t members_len, int64_t key,
			  uint8_t *dst, int64_t n);
int64_t bml_map_put_bytes(int64_t obj, const char *decl, int64_t decl_len, const char *members, int64_t members_len, int64_t key,
			  const uint8_t *src, int64_t n);

/* ---- hash / lru_hash (key and value are bytes; km / vm are the records JSON for the key / value, empty means integer) ---- */
/* OK if present (value 1, written to dst); a missing key is BML_NOT_FOUND */
int64_t bml_hash_get(int64_t obj, const char *decl, int64_t decl_len, const char *km, int64_t km_len, const char *vm, int64_t vm_len,
		     const uint8_t *key, int64_t klen, uint8_t *dst, int64_t dlen);
int64_t bml_hash_put(int64_t obj, const char *decl, int64_t decl_len, const char *km, int64_t km_len, const char *vm, int64_t vm_len,
		     const uint8_t *key, int64_t klen, const uint8_t *val, int64_t vlen);
/* OK if deleted (value 1); a missing key is BML_NOT_FOUND */
int64_t bml_hash_delete(int64_t obj, const char *decl, int64_t decl_len, const char *km, int64_t km_len, const uint8_t *key, int64_t klen);
/* Iterator (the semantics of cilium's MapIterator: concurrent deletions are skipped; more than max_entries steps is BML_OTHER) */
int64_t bml_hash_iter_open(int64_t obj, const char *decl, int64_t decl_len, const char *km, int64_t km_len, const char *vm, int64_t vm_len,
			   int64_t klen, int64_t vlen);
/* value 1 means present (written to kdst, vdst), 0 means the end. A closed iterator is BML_STATE */
int64_t bml_hash_iter_next(int64_t iter, uint8_t *kdst, int64_t klen, uint8_t *vdst, int64_t vlen);
/* A second call also returns OK. During a next on another thread: BML_STATE (does not wait) */
int64_t bml_hash_iter_close(int64_t iter);

/* ---- per-CPU (percpu_array, percpu_hash, lru_percpu_hash): the value is packed as possible CPUs x vlen ---- */
int64_t bml_possible_cpus(void);
int64_t bml_percpu_get(int64_t obj, const char *decl, int64_t decl_len, const char *km, int64_t km_len, const char *vm, int64_t vm_len,
		       const uint8_t *key, int64_t klen, int64_t vlen, uint8_t *dst, int64_t dlen);
/* Replaces the slot of every CPU */
int64_t bml_percpu_put(int64_t obj, const char *decl, int64_t decl_len, const char *km, int64_t km_len, const char *vm, int64_t vm_len,
		       const uint8_t *key, int64_t klen, int64_t vlen, const uint8_t *src, int64_t slen);
int64_t bml_percpu_delete(int64_t obj, const char *decl, int64_t decl_len, const char *km, int64_t km_len, const uint8_t *key, int64_t klen);
/* next is bml_hash_iter_next (the value is possible x vlen) */
int64_t bml_percpu_iter_open(int64_t obj, const char *decl, int64_t decl_len, const char *km, int64_t km_len, const char *vm, int64_t vm_len,
			     int64_t klen, int64_t vlen);

/* ---- lpm_trie (IPv4). prefix / address are strings ("a.b.c.d/n" / "a.b.c.d", read by the same rules as Go's net/netip). IPv6, malformed input and prefixes with host
 * bits set are BML_OTHER without touching the kernel (naming the fix). The declaration has kind lpm_trie and an 8-byte key record (prefixlen u32, addr [4]u8) ---- */
/* Checks a prefix without an object; value is the prefix length */
int64_t bml_lpm_check_prefix(const char *prefix, int64_t len);
/* status in value: 0 or -28 (ENOSPC, full for a new prefix). bits is the value (truncated to the value width) */
int64_t bml_lpm_put(int64_t obj, const char *decl, int64_t decl_len, const char *prefix, int64_t prefix_len, int64_t bits);
/* status in value: 0 or -2 (ENOENT, no such prefix) */
int64_t bml_lpm_remove(int64_t obj, const char *decl, int64_t decl_len, const char *prefix, int64_t prefix_len);
/* Longest match: message "found" with the value bits, or "absent" */
int64_t bml_lpm_match(int64_t obj, const char *decl, int64_t decl_len, const char *addr, int64_t addr_len);
/* Every prefix: lines of "a.b.c.d/n <bits>" in message (byte order); value is the line count */
int64_t bml_lpm_list(int64_t obj, const char *decl, int64_t decl_len);

/* ---- Map declarations ---- */
/* The declaration of a map row in the ELF requirements (message: one map declaration JSON {name,kind,key,value,max_entries,flags}) and the value size
 * (value: the size of the STRUCT in the ELF BTF for record:<S>, otherwise the map's value size). An unknown name is BML_STATE. The declaration is the ELF's own row;
 * this is for callers that hold no declaration (the form that opens a ring buffer by name only) */
int64_t bml_map_describe(int64_t obj, const char *name, int64_t name_len);

/* ---- Ring buffer reader (pull style: the mapping is not handed to the caller, events are returned as copies. A read on a closed reader is BML_STATE) ---- */
int64_t bml_ringbuf_open(int64_t obj, const char *decl, int64_t decl_len, const char *members, int64_t members_len, int64_t rec_size);
/* Waits up to timeout_ms and copies one event into dst (rec_size bytes). value 1 means read, 0 means none during the timeout */
int64_t bml_ringbuf_read(int64_t reader, int64_t timeout_ms, uint8_t *dst, int64_t n);
/* A second call also returns OK. During a read on another thread: BML_STATE (does not wait, not even for the read's timeout) */
int64_t bml_ringbuf_close(int64_t reader);

/* ---- Test run ---- */
/* Runs a 64-byte zero frame repeat times (repeat runs of repeat 1, so the kernel's repeat and EINTR restarts from signals do not inflate the count). repeat is 1 or greater
 * (0 and negative are BML_VALUE_RANGE),
 * value is the last return value. EINTR is not retried: BML_OTHER (value is the number of completed runs, the text says at which run) */
int64_t bml_test_run_xdp(int64_t obj, const char *prog, int64_t prog_len, int64_t repeat);
/* Runs once with data as the packet */
int64_t bml_test_run_xdp_data(int64_t obj, const char *prog, int64_t prog_len, const uint8_t *data, int64_t n);
/* Pins the calling thread to cpu and runs once (checks getcpu before and after and restores the affinity; failing to restore is BML_OTHER) */
int64_t bml_test_run_xdp_data_on_cpu(int64_t obj, const char *prog, int64_t prog_len, const uint8_t *data, int64_t n, int64_t cpu);
/* Test run with no data of tracing (fentry / fexit), n times (n runs of repeat 1; n is 1 or greater, 0 and negative are BML_VALUE_RANGE). The kernel
 * calls bpf_fentry_test1 and friends; an attached program runs there. Runs on **a short-lived thread different from the caller** (all signals blocked, joined before returning), and
 * value is that thread's tid (tid != tgid, so a pid / tgid mix-up shows in the value). Failure to create the thread is BML_OTHER */
int64_t bml_test_run_tracing(int64_t obj, const char *prog, int64_t prog_len, int64_t n);
/* tc (skb) test run with data, once. value is the return value (int32: TC_ACT 0 / 2 / 7 etc.). The data length is not judged; a kernel EINVAL is
 * BML_OTHER with a hint giving the measured condition. A program that is not sched_cls is BML_STATE */
int64_t bml_test_run_tc_data(int64_t obj, const char *prog, int64_t prog_len, const uint8_t *data, int64_t n);
/* Test runs by program family. The kind comes from the ELF section (bml's section table; a mix-up is BML_STATE), each runs once, value is the return value (int32),
 * a kernel error is BML_OTHER with the errno text */
/* skb family (socket_filter, sched_cls, sched_act, cgroup_skb, lwt_in / out / xmit): data as the packet */
int64_t bml_test_run_skb_data(int64_t obj, const char *prog, int64_t prog_len, const uint8_t *data, int64_t n);
/* flow_dissector: data as the packet, struct bpf_flow_keys in keys_out. keys_cap too small, or a kernel-written length different from keys_cap, is BML_VALUE_RANGE
 * (not truncated) */
int64_t bml_test_run_flow_dissector(int64_t obj, const char *prog, int64_t prog_len, const uint8_t *data, int64_t n, uint8_t *keys_out,
				    int64_t keys_cap);
/* ctx-only programs (syscall, raw_tp, sk_lookup). **The kernel rewrites ctx_inout** (syscall writes ctx, sk_lookup writes ctx_out to the same buffer;
 * a kernel-written length different from ctx_len is BML_VALUE_RANGE). raw_tp takes an array of u64 arguments (a multiple of 8, up to 12 = 96 bytes), syscall takes up to 65535 bytes;
 * outside these is BML_VALUE_RANGE */
int64_t bml_test_run_ctx_inout(int64_t obj, const char *prog, int64_t prog_len, uint8_t *ctx_inout, int64_t ctx_len);
/* netfilter: data as the packet, pf is NFPROTO_IPV4 (2) or NFPROTO_IPV6 (10), hook is NF_INET_PRE_ROUTING (0) to NF_INET_POST_ROUTING (4); outside these is
 * BML_VALUE_RANGE */
int64_t bml_test_run_netfilter(int64_t obj, const char *prog, int64_t prog_len, const uint8_t *data, int64_t n, int64_t pf, int64_t hook);

/* Bounded arena copies, OK.value=0. No pointer escapes the acquired object.
 * All checked loads require a declaration and map_extra for every arena map,
 * including old requirements formats. This is an extra load guard beyond Go's
 * generic CheckMapDecls. ASan shadow mappings can collide with low fixed addresses.
 * Flags are exactly 1024 or 132096 (MMAPABLE|SEGV_ON_FAULT).
 * With SEGV_ON_FAULT, the caller must confirm allocation success for the copied
 * pages before access, and stop accessing before free. Bounds do not establish
 * allocation or residency. No signal handler converts an unallocated/freed page
 * access to an error. Concurrent external free is outside this contract.
 * len=0 still validates object, declaration and bounds; NULL is then allowed.
 * Overlap uses memmove. No atomicity or ordering guarantee is provided. */
int64_t bml_arena_read(int64_t obj, const char *decl, int64_t decl_len, uint64_t off, uint64_t len,
	uint8_t *dst, int64_t capacity);
int64_t bml_arena_write(int64_t obj, const char *decl, int64_t decl_len, uint64_t off, uint64_t len,
	const uint8_t *src, int64_t capacity);

#ifdef __cplusplus
}
#endif

#endif /* BML_BML_H */
