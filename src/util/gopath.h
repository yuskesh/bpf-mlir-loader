/* util/gopath.h — copies of Go's path/filepath (Unix) Clean, Join and Abs. Results are malloc'd (NULL on failure). */
#ifndef BML_GOPATH_H
#define BML_GOPATH_H

#include <stddef.h>

/* filepath.Clean */
char *bml_go_path_clean(const char *path);
/* filepath.Join (empty elements are skipped; if all are empty the result is "") */
char *bml_go_path_join(const char *const *elem, size_t n);
/* filepath.Abs (a relative path is joined with the working directory, an absolute one is cleaned);
 * NULL if getcwd fails */
char *bml_go_path_abs(const char *path);

#endif
