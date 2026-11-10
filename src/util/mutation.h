



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
