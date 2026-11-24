/* btf/structops.h — the struct_ops tables of an ELF (StructOpsTables in go/layout, from bpf-mlir's struct_ops declaration support) */
#ifndef BML_BTF_STRUCTOPS_H
#define BML_BTF_STRUCTOPS_H

#include <stddef.h>

/* The table of one global variable (spelling is Go's StructOpsTable.Spelling) */
struct bml_struct_ops_table {
	char *var, *spelling;
};

/* Read the tables. If there is no struct_ops section the result is zero tables. Failure is -1 with *err set to Go's message (malloc'd). */
int bml_struct_ops_tables(const void *elf, size_t len, struct bml_struct_ops_table **out, size_t *n, char **err);
void bml_struct_ops_tables_free(struct bml_struct_ops_table *t, size_t n);

#endif
