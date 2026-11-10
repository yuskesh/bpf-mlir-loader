/* bml/kind.h — authoritative numbering of result kinds (C ABI of bpf-mlir-loader).
 *
 * Downstream bindings follow this table. Numbers are never changed and never
 * reused. Classify by kind; do not decide the kind by matching message text. */
#ifndef BML_KIND_H
#define BML_KIND_H

enum bml_kind {
	BML_OK = 0,
	BML_SCHEMA_MISMATCH = 1,   /* the schema hash in the ELF differs from the hash in the bindings */
	BML_PRECHECK_FAILED = 2,   /* the check itself failed (probe error, unreadable requirements or maps.json, guard stop) */
	BML_TARGET_REJECTED = 3,   /* a BlocksLoad Unmet from the check (no kernel object was created; has Unmet entries) */
	BML_VERIFIER_REJECTED = 4, /* rejected by the kernel verifier */
	BML_OTHER = 5,             /* none of the above (attach or map errno, malformed input, etc.) */
	BML_STATE = 6,             /* handle state error (second load, absent or closed handle, absent program or map name) */
	BML_RUNTIME_CONFLICT = 7,  /* reserved: a kind for the Go c-archive's signal check only. The C library never returns it */
	BML_MAP_MISMATCH = 8,      /* the map declaration (load document, operation declaration, record, event size) disagrees with the ELF */
	BML_VALUE_RANGE = 9,       /* an integer cannot be represented in the value type (the Spinel binding's Integer entry points) */
	BML_CONFIG_NOT_SET = 10,   /* a non-optional .rodata configuration value (global) is missing from the load arguments (before any kernel object is created; names every unset global) */
	BML_NOT_FOUND = 11,        /* get / delete of a missing key (OK + value 0 could not be told apart from an entry whose value is 0) */
};

#endif
