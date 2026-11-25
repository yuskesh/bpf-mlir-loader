/* errtext.h — errno spellings (the errno tables). Two classes:
 *   class G, compared with Go: bml_go_errno_str (declared in util/gostr.h), exactly Go's syscall.Errno text;
 *   class B, bml's own messages: bml_errno_text and bml_errno_named, which also name the kernel-internal errnos.
 * Both tables are generated (util/errno_tables.h, from src/util/kernel_errno.tsv and go_errno.tsv). */
#ifndef BML_UTIL_ERRTEXT_H
#define BML_UTIL_ERRTEXT_H

/* The name of a kernel-internal errno (include/linux/errno.h, 512-531 without 520), e.g. "ENOTSUPP"; NULL otherwise. */
const char *bml_kernel_errno_name(int err);
/* Class B text: "ENOTSUPP (kernel-internal errno 524)" for a kernel-internal errno, else Go's text. malloc'd. */
char *bml_errno_text(int err);
/* Class B text with the name: "EBUSY (device or resource busy)" for an errno glibc names, the bml_errno_text of a
 * kernel-internal errno, else Go's text ("errno 520"). malloc'd. */
char *bml_errno_named(int err);

#endif
