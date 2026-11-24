/* A pure C port of the Go reference function bindrt.RejectedAt. cap counts the terminating NUL;
 * if it is too small, no position is reported. */
#ifndef BML_ABI_REJECTED_H
#define BML_ABI_REJECTED_H
#include <stddef.h>
int bml_rejected_at(const char *log, size_t n, char *out, size_t cap);
#endif
