#ifndef BML_BTF_KERNEL_VALUES_H
#define BML_BTF_KERNEL_VALUES_H

#include "btf/kernel.h"

size_t bml_kbtf_exact_kind(const struct bml_kbtf *kb, const char *name, uint32_t kind, uint32_t first, uint32_t *id);
int bml_kbtf_exact_types(const struct bml_kbtf *kb, const char *name, uint32_t **ids, size_t *count);
int bml_kbtf_enum_constant(const struct bml_kbtf *kb, uint32_t id, const char *name, uint64_t *value);
char *bml_kbtf_var_slot(const struct bml_kbtf *kb, uint32_t id);
int bml_kbtf_var_percpu(const struct bml_kbtf *kb, uint32_t id);

#endif
