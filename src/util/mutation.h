/* mutation.h — hooks for mutation controls (a test-only build feature).
 *
 * In a build with -DBML_MUTATION, BML_MUT("name") is true when the environment variable BML_MUTANT equals the name.
 * In the product build (build-libs.sh) it is the constant 0, and neither the hook code nor any symbol of it remains
 * (the gate checks this with nm). Each mutant name is paired with the test case that is expected to fail when the
 * mutant is active; that table is kept with the offline-corpus experiment's record. */
#ifndef BML_MUTATION_H
#define BML_MUTATION_H

#ifdef BML_MUTATION
#include <stdlib.h>
#include <string.h>
static inline int bml_mutant_active(const char *name)
{
	const char *m = getenv("BML_MUTANT");
	return m && strcmp(m, name) == 0;
}
#define BML_MUT(name) bml_mutant_active(name)
#else
#define BML_MUT(name) 0
#endif

#endif
