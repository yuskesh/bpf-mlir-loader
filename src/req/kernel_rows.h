/* CONTRACT: data owned by the rows that require kernel values and loader declarations.
 * Included by req.h after bml_str is defined. All strings are owned by the requirements. */
#ifndef BML_REQ_KERNEL_ROWS_H
#define BML_REQ_KERNEL_ROWS_H

struct bml_enum_value {
	struct bml_str program, enumeration, name;
	uint64_t value;
};
struct bml_fib_flag {
	struct bml_str program, name;
	uint32_t mask;
};
struct bml_struct_size {
	struct bml_str strct;
	uint32_t size;
};
struct bml_guard_list {
	int64_t *numbers;
	size_t count;
};
struct bml_ksym_var {
	struct bml_str name, cls, slot, bind;
	struct bml_guard_list guards;
};
struct bml_kconfig {
	struct bml_str name, type, bind;
};
struct bml_guard {
	struct bml_str kind, target;
};
struct bml_guarded_row {
	int line;
	long ksym, kfield;
};

#endif
