#ifndef BML_GOPATH_H
#define BML_GOPATH_H

#include <stddef.h>


char *bml_go_path_clean(const char *path);

char *bml_go_path_join(const char *const *elem, size_t n);

char *bml_go_path_abs(const char *path);

#endif
