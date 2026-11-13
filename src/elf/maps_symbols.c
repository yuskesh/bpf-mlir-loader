#include "elf/maps_symbols.h"

#include <stdlib.h>
#include <string.h>

#include "util/mutation.h"

#define STT_SECTION_ 3

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

void bml_elf_names_free(char **v, size_t n)
{
	for (size_t i = 0; i < n; i++)
		free(v[i]);
	free(v);
}

int bml_elf_maps_symbols(const struct bml_elf *elf, char ***out, size_t *n, char **err)
{
	*out = NULL;
	*n = 0;
	*err = NULL;
	size_t idx = 0;
	int found = 0;
	for (size_t i = 0; i < elf->n_sections && !found; i++)
		if (!strcmp(elf->sections[i].name, ".maps"))
			idx = i, found = 1;
	if (!found)
		return 0;
	struct bml_elf_sym *syms = NULL;
	size_t ns = 0;
	if (bml_elf_symbols(elf, 2                 , &syms, &ns, err))
		return -1;
	char **names = ns ? calloc(ns, sizeof *names) : NULL;
	size_t k = 0;
	if (ns && !names) {
		free(syms);
		*err = strdup("out of memory");
		return -1;
	}
	for (size_t i = 0; i < ns; i++) {
		const struct bml_elf_sym *s = &syms[i];
		if (s->shndx != idx || !s->name[0] || BML_ST_TYPE(s->info) == STT_SECTION_)
			continue;
		int seen = 0;
		for (size_t j = 0; j < k && !seen && !BML_MUT("build.symbols_no_dedup"); j++)
			seen = !strcmp(names[j], s->name);
		if (seen)
			continue;
		if (!(names[k] = strdup(s->name))) {
			bml_elf_names_free(names, k);
			free(syms);
			*err = strdup("out of memory");
			return -1;
		}
		k++;
	}
	free(syms);
	if (k > 1 && !BML_MUT("build.symbols_unsorted"))
		qsort(names, k, sizeof *names, cmp_str);
	*out = names;
	*n = k;
	return 0;
}
