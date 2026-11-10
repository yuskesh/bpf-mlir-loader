
#ifndef BML_BTF_STRUCTOPS_H
#define BML_BTF_STRUCTOPS_H

#include <stddef.h>


struct bml_struct_ops_table {
	char *var, *spelling;
};


int bml_struct_ops_tables(const void *elf, size_t len, struct bml_struct_ops_table **out, size_t *n, char **err);
void bml_struct_ops_tables_free(struct bml_struct_ops_table *t, size_t n);

#endif
