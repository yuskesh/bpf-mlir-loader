/* load/load.h — load an ELF with libbpf v1.7.0 and stop libbpf's silent behaviors with guards before and after the load.
 *
 * Fixed options: libbpf may not touch RLIMIT_MEMLOCK (libbpf_set_memlock_rlim(0), once per process); it may not create
 * a BPF token (bpf_token_path = ""); libbpf's print output is collected into the library's log only during the load
 * (the previous callback is restored, so no process state is left behind); the kernel log goes into the library's own
 * buffer; the CO-RE target is /sys/kernel/btf/vmlinux (the same vmlinux the check uses); and automatic attach,
 * skeletons and pinning are not used.
 *
 * Call this after the check (bml_check); it does not check anything itself. Guards before the load: the shape of the
 * ELF; a comparison of libbpf's feat_supported with the answers of the check's btf_feature; and missing features that
 * would make libbpf sanitize the BTF or rewrite program and map attributes. Guards after the load: the BTF was loaded
 * into the kernel; the kernel's BTF and the object's BTF are byte-identical; the number of func_info / line_info
 * records; and the BTF ids and flags of the maps. */
#ifndef BML_LOAD_H
#define BML_LOAD_H

#include <stddef.h>
#include <stdint.h>

#include "caps/caps.h"
#include "req/req.h"

struct bpf_object;

enum bml_load_stage {
	BML_LOAD_OK = 0,
	BML_LOAD_ENV,         /* a precondition of the process (for example libbpf has already raised memlock) */
	BML_LOAD_SHAPE,       /* the shape of the ELF (sections, relocations, symbols, .maps definitions) */
	BML_LOAD_PREDICT,     /* libbpf's feat_supported disagrees with the check's btf_feature answers (Unknown: the prediction cannot be trusted) */
	BML_LOAD_SANITIZE,    /* a missing feature that makes libbpf sanitize the BTF (including features outside the four BTF features) */
	BML_LOAD_REWRITE,     /* a missing feature that makes libbpf rewrite a program or map (replacing a helper, and other program / map attribute rewrites) */
	BML_LOAD_OPEN,        /* libbpf's open failed */
	BML_LOAD_LIBBPF,      /* libbpf's load failed (including a verifier rejection, which carries a log) */
	BML_LOAD_BTF_DROPPED, /* the BTF was not loaded into the kernel */
	BML_LOAD_BTF_CHANGED, /* the kernel's BTF and the object's BTF differ */
	BML_LOAD_EXT_INFO,    /* the number of func_info / line_info records, or the program's BTF id, is wrong */
	BML_LOAD_MAP_BTF,     /* the BTF key / value ids of a map differ from the ELF's */
	BML_LOAD_MAP_FLAGS,   /* a map's flags differ from the ELF's (libbpf's definition at open time) */
	BML_LOAD_ARENA,
	BML_LOAD_STRUCT_OPS_TARGET, /* struct_ops guard G3: a member the ELF's struct_ops table sets is missing (or of another size) in the target's struct */
};

const char *bml_load_stage_name(int stage);

/* The kind of a program section and its test-run family (from one place, the sec_defs table of the guard's ELF shape check in pre.c). An unknown section gives NULL and BML_RUN_NONE. */
enum { BML_RUN_NONE = 0, BML_RUN_XDP, BML_RUN_TRACING, BML_RUN_SKB, BML_RUN_FLOW, BML_RUN_CTX, BML_RUN_NF };
const char *bml_load_section_kind(const char *section, int *family);

struct bml_load_result {
	int stage;
	char *msg; /* a message that names the problem (malloc'd) */
	char *log;    /* libbpf's print output, including the verifier log (malloc'd; NULL if there is none) */
	int verifier; /* BML_LOAD_LIBBPF: the kernel (verifier) rejected the program load */
};
void bml_load_result_free(struct bml_load_result *r);

struct bml_obj; /* the loaded object (libbpf's bpf_object, before attach) */

/* Load elf (len bytes). req is the checked requirements, and caps is the caps used for the check (its btf_feature
 * answers are compared with libbpf's). Success is 0 with *out set; failure is -1 with r set (everything that was loaded has been closed). */
int bml_load_guarded(const uint8_t *elf, size_t len, const struct bml_requirements *req, const struct bml_caps *caps,
		     struct bml_obj **out, struct bml_load_result *r);

/* One value to set in .rodata: the offset and size of a global symbol whose declaration has been checked, and the bits to write (little endian) */
struct bml_rodata_value {
	uint64_t off;
	uint32_t size;
	uint64_t bits;
};
/* The same, but between open and load it writes values into the initial contents of the .rodata map (a value out of range is a BML_LOAD_ENV error; it should not happen because the check has run) */
int bml_load_guarded_values(const uint8_t *elf, size_t len, const struct bml_requirements *req, const struct bml_caps *caps,
			    const struct bml_rodata_value *values, size_t n_values, struct bml_obj **out, struct bml_load_result *r);
void bml_obj_close(struct bml_obj *o);
/* CONTRACT: libbpf object (map and program access and attach, used by the ABI). Only bml_obj_close closes it */
struct bpf_object *bml_obj_bpf(const struct bml_obj *o);
#ifdef BML_TEST_CAPS
/* Test hook: keep (1) or remove (0, the product behavior) libbpf's rewrite of a usdt program to UPROBE_MULTI */
void bml_load_testonly_usdt_multi(int keep);
#endif

#endif
