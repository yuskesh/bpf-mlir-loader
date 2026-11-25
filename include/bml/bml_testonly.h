/* bml_testonly.h — the test-only interface, which exists only in a library built with -DBML_TEST_CAPS. The gate checks
 * with nm that the product libbml.a contains no bml_testonly_ symbol. This is the "test hooks" part of the C ABI that the
 * downstream Mojo frontend specified; its tests use it (a load that skips the requirements check as a negative control,
 * freezing, deliberate faults, and mutations of a uprobe attach). Product code must never call it. */
#ifndef BML_BML_TESTONLY_H
#define BML_BML_TESTONLY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A load that does not check: it skips stage 3, the check of the target's requirements against the kernel. The schema
 * check, the map declarations, the configuration values, the reading of the targets and the guarded load are still done,
 * and the caps are live. targets has the same form as in bml_load_checked_targets (empty means none). */
int64_t bml_testonly_load_unchecked_targets(const uint8_t *elf, int64_t n, const char *sha, int64_t sha_len, const char *maps, int64_t maps_len,
					    const char *config, int64_t config_len, const char *targets, int64_t targets_len);
/* A direct write to a global after the load. On BML_OK the message is "libbpf=<error|nil> kernel=<error|nil>". A write
 * to .rodata is expected to be refused by the kernel, because the map is frozen. */
int64_t bml_testonly_global_set_raw(int64_t obj, const char *name, int64_t len, int64_t bits);
/* Freezes a map (BPF_MAP_FREEZE) */
int64_t bml_testonly_freeze_map(int64_t obj, const char *name, int64_t len);
/* A deliberate fault: reads the ring buffer mapping after it was unmapped. It does not return (SIGSEGV kills the process). */
int64_t bml_testonly_ringbuf_fault(int64_t obj, const char *name, int64_t len);
/* A mutation of the uprobe attach: compute the program's attach file offset from a different symbol (an empty sym undoes it). */
int64_t bml_testonly_uprobe_symbol(const char *prog, int64_t prog_len, const char *sym, int64_t sym_len);
/* A mutation of the uprobe file offset computation. "" is the correct one (st_value - p_vaddr + p_offset); "no_p_offset"
 * leaves out p_offset (st_value - p_vaddr); "vaddr" uses st_value alone. Any other mode returns BML_OTHER. */
int64_t bml_testonly_uprobe_offset_mode(const char *mode, int64_t mode_len);
/* A negative control for the tp_btf attach check: replaces the declared tracepoint name with this name (len 0 undoes it).
 * A name longer than 127 bytes returns BML_VALUE_RANGE. */
int64_t bml_testonly_tpbtf_declared(const char *tp, int64_t len);
/* The shape of the USDT load and attach. "" is the product: load with expected_attach_type 0 and attach one uprobe per
 * probe point. "multi" keeps libbpf's rewrite of a SEC_USDT program to BPF_TRACE_UPROBE_MULTI and attaches one
 * uprobe_multi link. "multi_perf" keeps the rewrite but attaches one uprobe per point (used to observe the kernel's
 * refusal). The mode takes effect from the next load. Any other mode returns BML_OTHER. */
int64_t bml_testonly_usdt_mode(const char *mode, int64_t len);
/* struct_ops: an object record with fake maps and no libbpf or kernel object, for the static controls of bml_attach_struct_ops
 * and the close rule. spec is "name:kind,…" with kind link (a .struct_ops.link table), plain (a .struct_ops table) or map
 * (another map). Its attach makes a fake live link (no kernel call) that bml_detach clears. It is not the process's loaded
 * object (bml_load_checked is not blocked by it). The result's value is the object handle. */
int64_t bml_testonly_struct_ops_object(const char *spec, int64_t len);
/* struct_ops (destroy before release): the synchronization seam of the struct_ops controls. "pause:detach-destroy" or
 * "pause:attach-cleanup" arms one pause (the next thread that reaches the point waits there); "wait" blocks until a thread
 * is paused; "resume" lets it go on. "destroy-fail" makes the next fake link's destroy fail with EIO; "handle-fail" makes
 * the next struct_ops attach fail to store its link handle (the cleanup path). Any other seam returns BML_OTHER. */
int64_t bml_testonly_struct_ops_seam(const char *what, int64_t len);
/* struct_ops: a fake live link of another kind (not struct_ops) for the close rule's control. The value is the link handle. */
int64_t bml_testonly_fake_link(void);
/* record globals: a fake object (no ELF, no kernel) that holds the globals of the maps.json maps, as a load keeps
 * them, for bml_global_get's declaration-form controls. The value is the object handle. Only the paths that stop before
 * the map read may be used on it (a .data record global, a mismatch, an undeclared name). */
int64_t bml_testonly_globals_object(const char *maps, int64_t len);
/* record globals: the load's configuration check (set / optional against the maps.json globals) without an ELF. It
 * must stop before the symbol offsets; the value is the number of set values when it passes. */
int64_t bml_testonly_config_check(const char *maps, int64_t maps_len, const char *config, int64_t config_len);

#ifdef __cplusplus
}
#endif

#endif /* BML_BML_TESTONLY_H */
