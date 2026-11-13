#ifndef BML_ABI_TP_CPUS_H
#define BML_ABI_TP_CPUS_H

#include <stddef.h>

/* CONTRACT: turns "0-3,5,7-8" (surrounding blanks removed) into an ascending CPU list. Success is 0 with *out (malloc); error is -1 with *err (malloc; NULL means out of memory).
 * CPU numbers go up to 65535 (a fail-closed difference from Go, which has no limit: a huge range does not build a huge list) */
int bml_tp_parse_cpus(const char *s, int **out, size_t *n, char **err);

int bml_tp_select_cpus(const int *possible, size_t np, const int *online, size_t no, int online_only, int **out, size_t *n, char **err);

int bml_tp_cpus(int online_only, int **out, size_t *n, char **err);

#endif
