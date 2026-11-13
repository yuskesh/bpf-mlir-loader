#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btf/kernel_values.h"
#include "caps/live.h"
#include "caps/value_sources.h"

static struct bml_buf types, strings;
static uint32_t string_base;
static unsigned failures;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); failures++; } } while (0)
static void u32(struct bml_buf *b, uint32_t v) { uint8_t p[4]; for (size_t i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); bml_buf_add(b, (const char *)p, 4); }
static uint32_t str(const char *s) { uint32_t at = string_base + (uint32_t)strings.len; bml_buf_add(&strings, s, strlen(s) + 1); return at; }
static void type(const char *name, uint32_t info, uint32_t value) { u32(&types, name[0] ? str(name) : 0); u32(&types, info); u32(&types, value); }
static uint8_t *raw(size_t *len)
{
	struct bml_buf b = {0};
	u32(&b, 0x0001eb9f); u32(&b, 24); u32(&b, 0); u32(&b, (uint32_t)types.len); u32(&b, (uint32_t)types.len); u32(&b, (uint32_t)strings.len);
	bml_buf_add(&b, types.p, types.len); bml_buf_add(&b, strings.p, strings.len);
	*len = b.len; return (uint8_t *)bml_buf_take(&b);
}

int main(void)
{
	bml_buf_add(&strings, "", 1);
	type("i32", 1u << 24, 4); u32(&types, 1u << 24 | 32);
	type("", 2u << 24, 0);
	type("E", 0x86000001, 4); u32(&types, str("NEG")); u32(&types, UINT32_MAX);
	type("W", 19u << 24 | 1, 8); u32(&types, str("HIGH")); u32(&types, 2); u32(&types, 0x80000000);
	type("S", 4u << 24 | 2, 16); u32(&types, str("p")); u32(&types, 2); u32(&types, 0); u32(&types, str("e")); u32(&types, 3); u32(&types, 64);
	type("v", 14u << 24, 1); u32(&types, 1);
	type(".data..percpu", 15u << 24 | 1, 4); u32(&types, 6); u32(&types, 0); u32(&types, 4);
	type("", 13u << 24, 1); type("f", 12u << 24 | 1, 8);
	type("S___noise", 4u << 24, 32); type("S___other", 4u << 24, 64);
	type("dup", 4u << 24, 8); type("dup", 4u << 24, 16);
	type("___f", 12u << 24 | 1, 8); type("____f", 12u << 24 | 1, 8);
	size_t len; uint8_t *bytes = raw(&len);
	struct bml_live l = {.kb_done = 1}; char *msg = NULL;
	int rc = bml_kbtf_from_raw(bytes, len, &l.kb, &msg);
	CHECK(rc == 0); free(msg); msg = NULL;
	if (rc) return 1;
	l.kernel_sources = calloc(1, sizeof(*l.kernel_sources));
	if (!l.kernel_sources) return 1;
	l.kernel_sources->modules_done = 1;
	uint64_t value = 0;
	CHECK(bml_live_enum_value(&l, "E", "NEG", &value, &msg) == BML_Q_OK && value == UINT64_MAX);
	CHECK(bml_live_enum_value(&l, "W", "HIGH", &value, &msg) == BML_Q_OK && value == UINT64_C(0x8000000000000002));
	CHECK(bml_live_enum_value(&l, "E", "missing", &value, &msg) == BML_Q_ABSENT); free(msg); msg = NULL;
	uint32_t id, size;
	CHECK(bml_kbtf_exact_kind(&l.kb, "S", KBTF_STRUCT, 1, &id) == 1 && id == 5);
	CHECK(bml_kbtf_exact_kind(&l.kb, "S___noise", KBTF_STRUCT, 1, &id) == 1 && id == 10);
	CHECK(bml_kbtf_exact_kind(&l.kb, "dup", KBTF_STRUCT, 1, &id) == 2);
	CHECK(bml_kbtf_exact_kind(&l.kb, "___f", KBTF_FUNC, 1, &id) == 1);
	CHECK(bml_kbtf_exact_kind(&l.kb, "____f", KBTF_FUNC, 1, &id) == 1);
	CHECK(bml_live_struct_size(&l, "S", &size, &msg) == BML_Q_OK && size == 16);
	CHECK(bml_live_struct_size(&l, "absent", &size, &msg) == BML_Q_ABSENT); free(msg); msg = NULL;
	int present;
	CHECK(bml_live_btf_presence(&l, "field", "S.p", &present, &msg) == BML_Q_OK && present);
	CHECK(bml_live_btf_presence(&l, "field", "S.missing", &present, &msg) == BML_Q_OK && !present);
	CHECK(bml_live_btf_presence(&l, "type", "absent", &present, &msg) == BML_Q_OK && !present);
	char *slot = NULL;
	CHECK(bml_live_ksym_var(&l, "v", &slot, &msg) == BML_Q_OK && slot && !strcmp(slot, "percpu i32")); free(slot);
	struct bml_strs diffs = {0};
	CHECK(bml_live_func_ret(&l, "f", "i32", &diffs, &msg) == BML_Q_OK && !diffs.n); bml_strs_free(&diffs);
	CHECK(bml_live_func_ret(&l, "f", "u32", &diffs, &msg) == BML_Q_OK && diffs.n == 1); bml_strs_free(&diffs);
	struct bml_kfield fields[] = {{.program = {"p",1}, .strct = {"S",1}, .field = {"p",1}, .type = {"ptr:void",8}},
		{.program = {"p",1}, .strct = {"S",1}, .field = {"e",1}, .type = {"enum:32",7}}};
	CHECK(bml_live_kfields(&l, fields, 2, &diffs, &msg) == BML_Q_OK && !diffs.n); bml_strs_free(&diffs);
	l.kernel_sources->modules_failed = 1; l.kernel_sources->module_error = strdup("module set unreadable");
	CHECK(bml_live_struct_size(&l, "absent", &size, &msg) == BML_Q_UNKNOWN); free(msg); msg = NULL;
	CHECK(bml_live_struct_size(&l, "S", &size, &msg) == BML_Q_OK && size == 16);
	CHECK(bml_live_fib_flags(&l, "sched_cls", 3, 0, &present, &msg) == BML_Q_UNKNOWN); free(msg); msg = NULL;
	CHECK(bml_live_fib_flags(&l, "xdp", 6, 2, &present, &msg) == BML_Q_UNKNOWN); free(msg); msg = NULL;

	bml_buf_free(&types); bml_buf_free(&strings); string_base = l.kb.strs_len;
	type("module_var", 14u << 24, 1); u32(&types, 1);
	bytes = raw(&len);
	struct bml_kbtf split;
	rc = bml_kbtf_from_split_raw(bytes, len, &l.kb, &split, &msg);
	CHECK(rc == 0);
	if (!rc) {
		CHECK(bml_kbtf_exact_kind(&split, "module_var", KBTF_VAR, l.kb.n, &id) == 1);
		slot = bml_kbtf_var_slot(&split, id); CHECK(slot && !strcmp(slot, "i32")); free(slot);
		CHECK(bml_kbtf_exact_kind(&split, "v", KBTF_VAR, l.kb.n, &id) == 0);
		bml_kbtf_free(&split);
	}
	free(msg); msg = NULL;
	bytes = calloc(1, 1);
	CHECK(bml_kbtf_from_split_raw(bytes, 1, &l.kb, &split, &msg) != 0); free(msg); msg = NULL;
	bml_live_free(&l); bml_buf_free(&types); bml_buf_free(&strings);
	printf("kernel-values-unit: %s (%u failures; no kernel access)\n", failures ? "FAIL" : "GREEN", failures);
	return failures ? 1 : 0;
}
