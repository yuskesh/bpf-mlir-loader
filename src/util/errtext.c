/* errtext.c — errno spellings from the generated tables (the errno tables; see util/errtext.h). */
#define _GNU_SOURCE
#include "util/errtext.h"
#include "util/errno_tables.h"
#include "util/gostr.h"
#include "util/mutation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *bml_go_errno_str(int err)
{
	if (BML_MUT("util.go_errno_glibc")) { /* mutant "glibc speller": the speller before the errno tables (glibc strerror, first letter lower-cased) */
		char *s = strdup(strerror(err));
		if (s && s[0] >= 'A' && s[0] <= 'Z')
			s[0] = (char)(s[0] - 'A' + 'a');
		return s;
	}
	size_t n = sizeof bml_go_errnos / sizeof bml_go_errnos[0];
	if (err >= 0 && (size_t)err < n && bml_go_errnos[err])
		return strdup(bml_go_errnos[err]);
	char *s = NULL;
	return asprintf(&s, "errno %d", err) < 0 ? NULL : s;
}

const char *bml_kernel_errno_name(int err)
{
	if (BML_MUT("util.errno_no_kernel_names")) /* mutant M2: no kernel table */
		return NULL;
	for (size_t i = 0; i < sizeof bml_kernel_errnos / sizeof bml_kernel_errnos[0]; i++)
		if (bml_kernel_errnos[i].n == err)
			return bml_kernel_errnos[i].name;
	return NULL;
}

char *bml_errno_text(int err)
{
	const char *k = bml_kernel_errno_name(err);
	if (!k)
		return bml_go_errno_str(err);
	char *s = NULL;
	return asprintf(&s, "%s (kernel-internal errno %d)", k, err) < 0 ? NULL : s;
}

char *bml_errno_named(int err)
{
	const char *g = err > 0 ? strerrorname_np(err) : NULL;
	if (!g || bml_kernel_errno_name(err))
		return bml_errno_text(err);
	char *t = bml_go_errno_str(err), *s = NULL;
	if (!t || asprintf(&s, "%s (%s)", g, t) < 0)
		s = NULL;
	free(t);
	return s;
}
