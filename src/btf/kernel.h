/* btf/kernel.h — reading the target kernel's BTF (vmlinux) and looking up names in it. It is a copy of cilium/ebpf
 * v0.22's btf.LoadKernelSpec, Spec.TypeByName, UnderlyingType, Sizeof and the type formatting (%s / %v / %T).
 *
 * For mismatches in live-caps queries (func, func_sig, tracepoint, kfields, struct_field, func_param), the messages
 * copy Go's formatting byte for byte (the recorded diffs become the Unmet messages of the verdict). cilium inflates a
 * type lazily when it is looked up by name, so a broken type is an error only when it is looked up; the C code checks
 * every type at load time. With a broken vmlinux BTF the C code therefore fails every query, which is stricter than
 * Go. This is a stated boundary of the live-caps differential check. */
#ifndef BML_BTF_KERNEL_H
#define BML_BTF_KERNEL_H

#include <stddef.h>
#include <stdint.h>

#include "util/gostr.h"

enum {
	KBTF_UNKN = 0, KBTF_INT, KBTF_PTR, KBTF_ARRAY, KBTF_STRUCT, KBTF_UNION, KBTF_ENUM, KBTF_FWD, KBTF_TYPEDEF, KBTF_VOLATILE,
	KBTF_CONST, KBTF_RESTRICT, KBTF_FUNC, KBTF_FUNC_PROTO, KBTF_VAR, KBTF_DATASEC, KBTF_FLOAT, KBTF_DECL_TAG, KBTF_TYPE_TAG,
	KBTF_ENUM64, KBTF_NKINDS
};

struct bml_kbtf {
	uint8_t *raw; /* the whole BTF that was read (malloc'd) */
	size_t raw_len;
	int be;
	const uint8_t *types; /* the type section */
	uint32_t types_len;
	const uint8_t *strs; /* the string section */
	uint32_t strs_len;
	uint32_t n;    /* number of types + 1 (id 0 is Void) */
	uint32_t *off; /* id -> offset inside types (off[0] is not used) */
	uint32_t *idx; /* name index: the ids that have a name, ordered by (key, id), where the key is the name before the last "___" (the same key as cilium's namedTypes) */
	uint32_t nidx;
};

/* the header of one type (id 0 is Void, kind 0) */
struct kbtf_type {
	uint32_t kind, vlen, kflag, size_type;
	const char *name; /* NUL-terminated (inside strs) */
	const uint8_t *aux;
};

/* CONTRACT: reads raw (a malloc'd buffer; ownership moves). Failure is *err (malloc) with -1 (errors cilium's loadRawSpec also stops on) or -3 (checked by cilium only
 * when a type is looked up: referenced ids, member names, decl tags). raw is released even on failure */
int bml_kbtf_from_raw(uint8_t *raw, size_t len, struct bml_kbtf *kb, char **err);
int bml_kbtf_from_split_raw(uint8_t *raw, size_t len, const struct bml_kbtf *base, struct bml_kbtf *out, char **err);
/* Read /sys/kernel/btf/vmlinux (the first location in cilium's LoadKernelSpec). When it cannot be opened, cilium
 * searches seven locations for a vmlinux ELF; the C code does not copy that and fails closed (all three kernels that
 * were tested have /sys/kernel/btf/vmlinux). -2 means none of the seven locations exists either (cilium's "no BTF
 * found"; the prog_type probes for Tracing and LSM then read it as false), and -1 means any other error. */
int bml_kbtf_load_kernel(struct bml_kbtf *kb, char **err);
void bml_kbtf_free(struct bml_kbtf *kb);

uint32_t bml_kbtf_u32(const struct bml_kbtf *kb, const uint8_t *p);
void bml_kbtf_type(const struct bml_kbtf *kb, uint32_t id, struct kbtf_type *t);

/* A Struct / Union member (cilium's convertMembers, which also converts kind_flag bitfields and legacy bitfields) */
struct kbtf_member {
	const char *name;
	uint32_t type, offset, bitfield_size; /* offset and size are in bits */
};
void bml_kbtf_member(const struct bml_kbtf *kb, const struct kbtf_type *t, uint32_t i, struct kbtf_member *m);
/* an argument of a FuncProto */
void bml_kbtf_param(const struct bml_kbtf *kb, const struct kbtf_type *t, uint32_t i, const char **name, uint32_t *type);

/* Type.TypeName: only for Go types that have a name (Pointer, Array, qualifiers, FuncProto, declTag and TypeTag give "") */
const char *bml_kbtf_type_name(const struct kbtf_type *t);
/* Build the name index (called inside from_raw; in kernel_name.c) */
int bml_kbtf_build_index(struct bml_kbtf *kb, char **err);
#ifdef BML_TEST_CAPS
/* Test builds only: the earlier index (which decodes on every comparison); tests compare it byte for byte with the new index */
int bml_kbtf_build_index_reference(struct bml_kbtf *kb, char **err);
#endif

/* the name of cilium's Go type (Enum and Enum64 are both "Enum") */
const char *bml_kbtf_goname(uint32_t kind);

/* Spec.TypeByName(name, &<Go type of the kind>): 0 means found (*id), 1 means not found, 2 means several; 1 and 2 set *err to Go's error message (malloc'd) */
int bml_kbtf_by_name(const struct bml_kbtf *kb, const char *name, uint32_t kind, uint32_t *id, char **err);
/* Spec.AnyTypesByName(name): the ids of types whose whole name is name, in cilium's order and with its skipping quirk (*ids is malloc'd). 0, 1 (not found) and 2 (memory) are as in by_name. */
int bml_kbtf_any_by_name(const struct bml_kbtf *kb, const char *name, uint32_t **ids, size_t *n, char **err);

/* UnderlyingType (strips qualifiers and Typedefs; beyond depth 32 it is cycle{root}). If *cycle is set, root is the original id. */
uint32_t bml_kbtf_underlying(const struct bml_kbtf *kb, uint32_t id, int *cycle);
/* Sizeof: 0 with *size; an error is -1 with *err set to Go's message (malloc'd) */
int bml_kbtf_sizeof(const struct bml_kbtf *kb, uint32_t id, int64_t *size, char **err);

/* Type formatting: verb 's' (down to the name) or 'v' (detailed; nested types are shown only down to the name). cycle is UnderlyingType's cycle{root=id}. */
void bml_kbtf_format(const struct bml_kbtf *kb, struct bml_buf *b, uint32_t id, int cycle, char verb);
/* %T (*btf.Int ...; a cycle is *btf.cycle) */
void bml_kbtf_gotype(const struct bml_kbtf *kb, struct bml_buf *b, uint32_t id, int cycle);

#endif
