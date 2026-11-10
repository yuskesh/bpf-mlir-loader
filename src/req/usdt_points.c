

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "req/usdt.h"
#include "util/mutation.h"


int bml_usdt_encode_spec(const char *args, uint8_t spec[BML_USDT_SPEC_SIZE])
{
	memset(spec, 0, BML_USDT_SPEC_SIZE);
	size_t *st = NULL, *ln = NULL, n = 0;
	if (bml_go_fields(args, strlen(args), &st, &ln, &n) != 0)
		return -1;
	int rc = 0;
	for (size_t i = 0; i < n && i < BML_USDT_SPEC_SIZE / BML_USDT_ARG_SPEC_SIZE; i++) {
		struct bml_usdt_arg a;
		int size_ok = 0;
		char *err = NULL;
		if (bml_usdt_parse_arg(args + st[i], ln[i], &a, &size_ok, &err) != 0) {
			rc = -1;
			break;
		}
		if (err) {
			free(err);
			continue;
		}
		uint8_t *b = spec + i * BML_USDT_ARG_SPEC_SIZE;
		b[0] = !strcmp(a.kind, "const") ? BML_USDT_KIND_CONST : !strcmp(a.kind, "reg") ? BML_USDT_KIND_REG : BML_USDT_KIND_DEREF;
		if (strcmp(a.kind, "const") != 0)
			b[1] = (uint8_t)bml_usdt_reg_index(a.reg);
		uint64_t off = (uint64_t)a.off;
		for (int k = 0; k < 8; k++)
			b[8 + k] = (uint8_t)(off >> (8 * k));
	}
	free(st);
	free(ln);
	return rc;
}


static int file_offset(const struct bml_elf *e, uint64_t addr, int exec, uint64_t *off)
{
	for (size_t i = 0; i < e->n_progs; i++) {
		const struct bml_elf_phdr *p = &e->progs[i];
		if (p->type != 1               || (exec && !(p->flags & 1           )))
			continue;
		if (p->vaddr <= addr && addr < p->vaddr + p->filesz) {
			*off = addr - p->vaddr + p->offset;
			return 0;
		}
	}
	return -1;
}

static int fail(char **err, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int fail(char **err, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (vasprintf(err, fmt, ap) < 0)
		*err = NULL;
	va_end(ap);
	return -1;
}

int bml_usdt_attach_points(const uint8_t *data, size_t len, const char *provider, const char *name, struct bml_usdt_attach_point **out, size_t *n,
			   char **err)
{
	*out = NULL;
	*n = 0;
	*err = NULL;
	struct bml_elf e;
	if (bml_elf_open(data, len, &e, err) != 0)
		return -1;
	struct bml_usdt_points all = {0};
	int rc = -1;
	if (bml_usdt_read_points(&e, &all, err) != 0)
		goto out;
	const struct bml_elf_shdr *bs = bml_elf_section(&e, ".stapsdt.base");
	struct bml_usdt_attach_point *v = calloc(all.n ? all.n : 1, sizeof *v);
	if (!v) {
		fail(err, "out of memory");
		goto out;
	}
	size_t k = 0;
	for (size_t i = 0; i < all.n; i++) {
		const struct bml_usdt_point *p = &all.p[i];
		if (strcmp(p->provider, provider) != 0 || strcmp(p->name, name) != 0)
			continue;
		uint64_t pc = p->pc;
		if (bs && p->base != 0 && !BML_MUT("usdt.no_prelink"))
			pc = pc + bs->addr - p->base;
		struct bml_usdt_attach_point *q = &v[k];
		q->index = k;
		q->pc = p->pc;
		q->semaphore = p->semaphore;
		if (file_offset(&e, pc, 1, &q->off) != 0) {
			fail(err, "%s:%s at pc 0x%llx: address 0x%llx is in no loadable segment with file bytes", provider, name, (unsigned long long)p->pc,
			     (unsigned long long)pc);
			free(v);
			goto out;
		}
		if (p->semaphore && file_offset(&e, p->semaphore, 0, &q->sem_off) != 0) {
			fail(err, "%s:%s at pc 0x%llx: semaphore: address 0x%llx is in no loadable segment with file bytes", provider, name,
			     (unsigned long long)p->pc, (unsigned long long)p->semaphore);
			free(v);
			goto out;
		}
		if (bml_usdt_encode_spec(p->args, q->spec) != 0) {
			fail(err, "out of memory");
			free(v);
			goto out;
		}
		k++;
	}
	if (k == 0) {
		fail(err, "the target has no USDT point %s:%s", provider, name);
		free(v);
		goto out;
	}
	*out = v;
	*n = k;
	rc = 0;
out:
	bml_usdt_points_free(&all);
	bml_elf_close(&e);
	return rc;
}
