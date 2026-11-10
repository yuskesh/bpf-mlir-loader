

#define _GNU_SOURCE
#include "load/internal.h"
#include "load/arena.h"

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "util/mutation.h"

const char *bml_load_stage_name(int s)
{
	static const char *const n[] = {"ok", "env", "shape", "predict", "sanitize", "rewrite", "open", "libbpf",
					"btf_dropped", "btf_changed", "ext_info", "map_btf", "map_flags", "arena"};
	return s >= 0 && (size_t)s < sizeof n / sizeof *n ? n[s] : "?";
}

void bml_load_result_free(struct bml_load_result *r)
{
	free(r->msg);
	free(r->log);
	memset(r, 0, sizeof *r);
}

/* CONTRACT: libbpf print: collected during load (read by the guard and the verifier log) and discarded from a successful load until the object closes (libbpf warnings from attach etc. do not
 * reach the caller's stderr; bml's result text names errno and a hint).
 * The borrow is counted per bml_obj (the unit of a guarded load): incremented when a load starts (0 -> 1 saves the caller's callback in lb_prev and replaces it) and
 * decremented by bml_obj_close (1 -> 0 restores it). The C ABI's "one object at a time" holds only for registered objects; guarded loads can overlap in the window between load entry and
 * close. The collection buffer is per thread (libbpf calls print on the calling thread, so logs of concurrent loads do not mix) */
static __thread struct bml_buf *lb_log;
static struct bml_buf *lb_log_shared;
static pthread_mutex_t lb_mu = PTHREAD_MUTEX_INITIALIZER;
static int lb_holders;
static libbpf_print_fn_t lb_prev;

static int print_fn(enum libbpf_print_level level, const char *fmt, va_list ap);

static void print_hold(struct bml_obj *o)
{
	pthread_mutex_lock(&lb_mu);
	if (lb_holders++ == 0)
		lb_prev = libbpf_set_print(print_fn);
	o->print_held = 1;
	pthread_mutex_unlock(&lb_mu);
}

static void print_release(struct bml_obj *o)
{
	if (!o->print_held)
		return;
	o->print_held = 0;
	pthread_mutex_lock(&lb_mu);
	int last = --lb_holders == 0;
	if ((last || BML_MUT("load.print_restore_each_close")) && !BML_MUT("load.print_no_restore"))
		libbpf_set_print(lb_prev);
	pthread_mutex_unlock(&lb_mu);
}

static int print_fn(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	struct bml_buf *b = BML_MUT("load.print_shared_log") ? lb_log_shared : lb_log;
	if (!b || level == LIBBPF_DEBUG)
		return 0;
	char *tmp = NULL;
	if (vasprintf(&tmp, fmt, ap) < 0)
		return 0;
	bml_buf_adds(b, level == LIBBPF_WARN ? "warn: " : "info: ");
	bml_buf_adds(b, tmp);
	free(tmp);
	return 0;
}



static int memlock_fixed;

static int fix_memlock(struct bml_load_result *r)
{
	if (memlock_fixed || BML_MUT("load.no_memlock_fix"))
		return 0;
	int rc = libbpf_set_memlock_rlim(0);
	if (rc != 0)
		return lb_fail(r, BML_LOAD_ENV, "libbpf was used in this process before bpf-mlir-loader (RLIMIT_MEMLOCK may have been raised): %s",
			       lb_errno(-rc));
	memlock_fixed = 1;
	return 0;
}


static int write_rodata(struct bpf_object *obj, const struct bml_rodata_value *v, size_t n, struct bml_load_result *r)
{
	if (!n)
		return 0;
	struct bpf_map *m, *ro = NULL;
	bpf_object__for_each_map(m, obj)
	{
		const char *nm = bpf_map__name(m);
		size_t l = strlen(nm);
		if (bpf_map__is_internal(m) && l >= 7 && !strcmp(nm + l - 7, ".rodata"))
			ro = m;
	}
	size_t sz = 0;
	uint8_t *p = ro ? bpf_map__initial_value(ro, &sz) : NULL;
	if (!p)
		return lb_fail(r, BML_LOAD_ENV, "the ELF has no .rodata map to set the configuration values in");
	for (size_t i = 0; i < n; i++) {
		if (v[i].size > 8 || v[i].off > sz || sz - v[i].off < v[i].size)
			return lb_fail(r, BML_LOAD_ENV, "a configuration value at offset %llu (%u bytes) is outside the %zu-byte .rodata",
				       (unsigned long long)v[i].off, v[i].size, sz);
		for (uint32_t b = 0; b < v[i].size; b++)
			p[v[i].off + b] = (uint8_t)(v[i].bits >> (8 * b));
	}
	return 0;
}

#ifdef BML_TEST_CAPS
static int usdt_keep_multi;
void bml_load_testonly_usdt_multi(int keep)
{
	__atomic_store_n(&usdt_keep_multi, keep, __ATOMIC_SEQ_CST);
}
#endif





static void usdt_point_form(struct bpf_object *obj)
{
#ifdef BML_TEST_CAPS
	if (__atomic_load_n(&usdt_keep_multi, __ATOMIC_SEQ_CST))
		return;
#endif
	if (BML_MUT("usdt.keep_libbpf_multi"))
		return;
	struct bpf_program *p;
	bpf_object__for_each_program(p, obj) {
		const char *s = bpf_program__section_name(p);
		if (bpf_program__type(p) == BPF_PROG_TYPE_KPROBE && (!strcmp(s, "usdt") || !strncmp(s, "usdt/", 5))) {
			bpf_program__set_type(p, BPF_PROG_TYPE_SOCKET_FILTER);
			bpf_program__set_type(p, BPF_PROG_TYPE_KPROBE);
		}
	}
}



int lb_mark_sleepable(struct bpf_object *obj, struct bml_load_result *r)
{
	struct bpf_program *p;
	bpf_object__for_each_program(p, obj) {
		const char *sec = bpf_program__section_name(p);
		if (strncmp(sec, "fentry.s/", 9) != 0 || BML_MUT("load.sleepable_not_marked"))
			continue;
		int rc = bpf_program__set_flags(p, bpf_program__flags(p) | BPF_F_SLEEPABLE);
		if (rc != 0)
			return lb_fail(r, BML_LOAD_ENV, "program %s in section %s: cannot set BPF_F_SLEEPABLE: %s", bpf_program__name(p), sec, lb_errno(-rc));
	}
	return 0;
}

int bml_load_guarded_values(const uint8_t *elf, size_t len, const struct bml_requirements *req, const struct bml_caps *caps,
			    const struct bml_rodata_value *values, size_t n_values,
		     struct bml_obj **out, struct bml_load_result *r)
{
	memset(r, 0, sizeof *r);
	*out = NULL;
	if (lb_check_shape(elf, len, r) || fix_memlock(r) || lb_check_features(elf, len, req, caps, r))
		return -1;
	struct bml_buf log = {0};
	struct bml_obj *o = calloc(1, sizeof *o);
	if (!o) {
		return lb_fail(r, BML_LOAD_ENV, "out of memory");
	}
	lb_log = &log;
	lb_log_shared = &log;
	print_hold(o);
	LIBBPF_OPTS(bpf_object_open_opts, oo, .object_name = "bml", .relaxed_maps = false, .btf_custom_path = "/sys/kernel/btf/vmlinux",
		    

		    .bpf_token_path = BML_MUT("load.token_default") ? NULL : "");
	struct lb_map_def *defs = NULL;
	size_t ndefs = 0;
	int rc = -1;
	o->obj = bpf_object__open_mem(elf, len, &oo);
	if (!o->obj) {
		lb_fail(r, BML_LOAD_OPEN, "libbpf cannot open the ELF: %s", lb_errno(errno));
		goto done;
	}
	if (lb_mark_sleepable(o->obj, r) != 0)
		goto done;
	if (write_rodata(o->obj, values, n_values, r) != 0)
		goto done;
	if (lb_capture_maps(o->obj, &defs, &ndefs) != 0) {
		lb_fail(r, BML_LOAD_ENV, "out of memory");
		goto done;
	}
	usdt_point_form(o->obj);
	if (lb_arena_prepare(o, elf, len, r))
		goto done;
	int err = bpf_object__load(o->obj);
	lb_arena_observe(o);
	if (err) {
		const char *lg = log.p ? log.p : "";
		r->verifier = strstr(lg, "BPF program load failed") != NULL;

		lb_fail(r, BML_LOAD_LIBBPF, "libbpf could not load the object: %s%s", lb_errno(-err),
			strstr(lg, "BTF is optional, ignoring") ? " (after the kernel rejected the BTF and libbpf dropped it — B2)" : "");
		goto done;
	}
	if (lb_check_loaded(o->obj, defs, ndefs, r) != 0)
		goto done;
	if (lb_arena_check(o, r))
		goto done;
	rc = 0;
done:
	lb_log = NULL;
	lb_log_shared = NULL;
	if (rc == 0 && BML_MUT("load.print_passthrough")) {
		pthread_mutex_lock(&lb_mu);
		libbpf_set_print(lb_prev);
		pthread_mutex_unlock(&lb_mu);
	}

	lb_free_maps(defs, ndefs);

	r->log = log.len ? bml_buf_take(&log) : NULL;
	bml_buf_free(&log);
	if (rc != 0) {
		bml_obj_close(o);
		return -1;
	}
	*out = o;
	return 0;
}

void bml_obj_close(struct bml_obj *o)
{
	if (!o)
		return;
	if (o->obj)
		bpf_object__close(o->obj);
	lb_arena_cleanup(o);

	print_release(o);
	free(o);
}

struct bpf_object *bml_obj_bpf(const struct bml_obj *o)
{
	return o ? o->obj : NULL;
}

int bml_load_guarded(const uint8_t *elf, size_t len, const struct bml_requirements *req, const struct bml_caps *caps,
		     struct bml_obj **out, struct bml_load_result *r)
{
	return bml_load_guarded_values(elf, len, req, caps, NULL, 0, out, r);
}
