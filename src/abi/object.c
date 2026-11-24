/* abi/object.c — the checked load, the Unmet entries that did not stop it, close, and the version of the
 * verdict rules. The order of the stages and the kinds follow the downstream Go loader (the mojo
 * loader's internal/loader). The Go runtime stage (a check for a signal of -1) does not exist here.
 * The messages are the bindrt type messages, byte for byte. */
#define _GNU_SOURCE
#include "abi/internal.h"
#include "abi/rejected.h"
#include "maps/arena.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "req/from_elf.h"
#include "util/gostr.h"
#include "util/mutation.h"

int64_t bml_policy_version(void)
{
	return BML_POLICY_VERSION;
}

/* The format limit is a constant, not stamped; it is kept here so that it does not pull in util/stamp.o. */
int64_t bml_max_format_version(void)
{
	return BML_MAX_FORMAT_VERSION;
}

/* How to fix a schema mismatch (the hint of bindrt.CheckSchema, which names no tool). */
static const char schema_hint[] = "rebuild both ELF and bindings from the same schema";

/* The verifier log inside libbpf's print output (from the last "-- BEGIN PROG LOAD LOG --" to "-- END PROG LOAD LOG --"). */
static void verifier_log(const char *log, const char **s, size_t *n)
{
	*s = "";
	*n = 0;
	const char *b = NULL;
	for (const char *p = strstr(log, "-- BEGIN PROG LOAD LOG --\n"); p; p = strstr(p + 1, "-- BEGIN PROG LOAD LOG --\n"))
		b = p;
	if (!b)
		return;
	b += strlen("-- BEGIN PROG LOAD LOG --\n");
	const char *e = strstr(b, "-- END PROG LOAD LOG --");
	*s = b;
	*n = e ? (size_t)(e - b) : strlen(b);
}

/* The message for a verifier rejection: "rejected at <f>:<l> — <error>\n<last 20 lines of the log>". The downstream tests check this form (the mojo VERIFIER_REJECTED). */
static int64_t verifier_fail(const struct bml_load_result *lr)
{
	const char *vl;
	size_t vn;
	verifier_log(lr->log ? lr->log : "", &vl, &vn);
	while (vn && (vl[vn - 1] == '\n' || vl[vn - 1] == ' '))
		vn--;
	size_t start = vn, lines = 0;
	while (start > 0 && lines < 20) {
		start--;
		if (vl[start] == '\n' && ++lines == 20) {
			start++;
			break;
		}
	}
	char at[512];
	struct bml_buf b = {0};
	if (bml_rejected_at(vl, vn, at, sizeof at))
		bml_buf_addf(&b, "rejected at %s — ", at);
	bml_buf_adds(&b, lr->msg ? lr->msg : "");
	bml_buf_adds(&b, "\n");
	bml_buf_add(&b, vl + start, vn - start);
	struct abi_result r = {.kind = BML_VERIFIER_REJECTED, .msg_len = b.len};
	r.msg = bml_buf_take(&b);
	return abi_put(&r);
}

#ifdef BML_TEST_CAPS
#define BML_TEST_CAPS_KIND(k) ((k) == 1 || (k) == 2)
#else
#define BML_TEST_CAPS_KIND(k) 0
#endif

#ifdef BML_TEST_CAPS
/* Caps that exist only in the test build (-DBML_TEST_CAPS; they are not in the product libbml.a, which
 * the gate checks with nm). They are the same as denyCaps and unknownHelperCaps in the downstream test
 * archive: kind 1 answers that no program type, helper or map type exists (it has no other queries,
 * so those are Unknown); kind 2 is the live caps except that the helper probe alone is Unknown. */
static int deny_type(void *ctx, const char *name, int64_t id, int *out, char **msg)
{
	(void)ctx, (void)name, (void)id, (void)msg;
	*out = 0;
	return BML_Q_OK;
}
static int deny_helper(void *ctx, const char *pt, int64_t pid, const char *h, int64_t hid, int *out, char **msg)
{
	(void)ctx, (void)pt, (void)pid, (void)h, (void)hid, (void)msg;
	*out = 0;
	return BML_Q_OK;
}
static int unknown_helper(void *ctx, const char *pt, int64_t pid, const char *h, int64_t hid, int *out, char **msg)
{
	(void)ctx, (void)pt, (void)pid, (void)h, (void)hid, (void)out;
	*msg = strdup("bml_test: helper probe unavailable: unknown");
	return BML_Q_UNKNOWN;
}
#endif

/* The kind of caps (0 is live). An unknown kind gives -1. */
static int caps_of(int64_t kind, struct bml_live_caps *lc, struct bml_caps *out)
{
	memset(out, 0, sizeof *out);
	/* The loader declaration used by the C ABI check is cilium-v0.22-usdt-ksyscall. It differs from
	 * cilium-v0.22 in the name, in usdt_attach ref_ctr and in ksyscall_attach prefix: bml_attach_usdt
	 * takes on the loader's ref_ctr obligation, and bml_attach_ksyscall takes on its prefix obligation.
	 * Earlier there was no declaration (the default cilium-v0.22 stopped a USDT ELF with usdt_loader;
	 * mutation abi.decl_cilium022), and before ksyscall the declaration was cilium-v0.22-usdt. Two
	 * mutations drop one half of the declaration: abi.decl_no_ksyscall (the earlier cilium-v0.22-usdt)
	 * and abi.decl_no_usdt (cilium-v0.22-ksyscall). */
	lc->decl = &bml_loader_cilium022usdtksyscall;
	if (BML_MUT("abi.decl_cilium022"))
		lc->decl = NULL;
	else if (BML_MUT("abi.decl_no_ksyscall"))
		lc->decl = &bml_loader_cilium022usdt;
	else if (BML_MUT("abi.decl_no_usdt"))
		lc->decl = &bml_loader_cilium022ksyscall;
	if (kind == 0) {
		bml_live_caps(lc, out);
		return 0;
	}
#ifdef BML_TEST_CAPS
	if (kind == 1) {
		out->prog_type = deny_type;
		out->map_type = deny_type;
		out->helper = deny_helper;
		return 0;
	}
	if (kind == 2) {
		bml_live_caps(lc, out);
		out->helper = unknown_helper;
		return 0;
	}
#endif
	return -1;
}

/* Whether the maps of the map-declaration document exist in the loaded object (stage 5 downstream). */
static const char *missing_map(struct bpf_object *obj, const struct bml_map_decls *d)
{
	for (size_t i = 0; i < d->n_maps; i++)
		if (!bpf_object__find_map_by_name(obj, d->maps[i].name))
			return d->maps[i].name;
	return NULL;
}

/* A privilege hint for an EPERM from the check or the load (a byte-for-byte copy of permHint in the
 * downstream mojo loader's tracing.go): tracing and kprobe programs need CAP_PERFMON, xdp and
 * sched_cls need CAP_NET_ADMIN, and CAP_BPF is always needed; the names are joined by " + " in this
 * order. For anything other than EPERM the hint is "". */
static const char *perm_hint(const struct bml_requirements *req, const char *text, char *buf, size_t cap)
{
	buf[0] = 0;
	if (!req || !text || !strstr(text, "operation not permitted"))
		return buf;
	int net = 0, perf = 0;
	for (size_t i = 0; i < req->n_programs; i++) {
		const char *t = req->programs[i].prog_type.p ? req->programs[i].prog_type.p : "";
		perf |= !strcmp(t, "tracing") || !strcmp(t, "kprobe");
		net |= !strcmp(t, "xdp") || !strcmp(t, "sched_cls");
	}
	snprintf(buf, cap, " (hint: loading this object needs CAP_BPF%s%s — fentry and kprobe need CAP_PERFMON, xdp and tc need CAP_NET_ADMIN)",
		 net ? " + CAP_NET_ADMIN" : "", perf ? " + CAP_PERFMON" : "");
	return buf;
}

static void object_free(struct abi_object *o)
{
	if (!o)
		return;
	bml_obj_close(o->lo);
	bml_requirements_free(o->req);
	free(o->elf);
	bml_unmets_free(&o->rest);
	bml_live_caps_free(&o->caps);
	abi_globals_free(o);
	free(o);
}

/* The body of load. check 0 skips stage 3 (the check of the target requirements); only bml_testonly_load_unchecked_targets of the test build does that. */
static int64_t load_impl(const uint8_t *elf, int64_t n, const char *sha, int64_t sha_len, const char *maps, int64_t maps_len, const char *config,
			 int64_t config_len, const char *targets, int64_t targets_len, int64_t caps_kind, int check)
{
	if (targets_len < 0 || (!targets && targets_len))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL string with a length");
	abi_lock();
	int already = abi_loaded != 0;
	abi_unlock();
	if (already)
		return abi_fail(BML_STATE, "bml: the embedded object is already loaded (close it before loading again)");
	if (!elf || n <= 0)
		return abi_fail(BML_PRECHECK_FAILED, "bml: no embedded ELF");
	if (sha_len < 0 || maps_len < 0 || config_len < 0 || (!sha && sha_len) || (!maps && maps_len) || (!config && config_len))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL string with a length");
	if (caps_kind != 0 && !BML_TEST_CAPS_KIND(caps_kind))
		return abi_fail(BML_PRECHECK_FAILED, "bml: no capabilities given (the check is not skipped)");
	struct abi_object *o = calloc(1, sizeof *o);
	if (!o)
		return abi_fail(BML_OTHER, "bml: out of memory");
	int64_t res = -1;
	struct bml_map_decls d = {0};
	char *err = NULL;
	struct bml_rodata_value *vals = NULL; /* the configured values of .rodata (load arguments) */
	size_t n_vals = 0;
	/* stage 0': the map-declaration document */
	if (bml_arena_map_decls_parse(maps ? maps : "", (size_t)maps_len, &d, &err) != 0 || !d.has_maps) {
		res = abi_fail(BML_PRECHECK_FAILED, "bml: the map declarations are unreadable: %s", err ? err : "no \"maps\" array");
		goto out;
	}
	/* stage 1: requirements (bindrt.Parse; *RequirementsError) */
	struct bml_req_elf_error ee;
	if (bml_req_from_elf(elf, (size_t)n, &o->req, &ee) != 0) {
		const char *m = ee.stage == BML_REQ_ELF_PARSE ? ee.parse.msg : ee.msg;
		res = abi_fail(BML_PRECHECK_FAILED, "bml: cannot read requirements from the embedded ELF: %s", m ? m : "");
		bml_req_elf_error_free(&ee);
		goto out;
	}
	/* stage 2: schema (SchemaMismatchError; %q is Go's strconv.Quote) */
	const char *es = o->req->schema_sha256.p ? o->req->schema_sha256.p : "";
	if (strlen(es) != (size_t)sha_len || memcmp(es, sha ? sha : "", (size_t)sha_len) != 0) {
		struct bml_buf b = {0};
		bml_buf_adds(&b, "ELF was built from schema ");
		bml_buf_add_goquote(&b, es, strlen(es));
		bml_buf_adds(&b, ", bindings from schema ");
		bml_buf_add_goquote(&b, sha ? sha : "", (size_t)sha_len);
		bml_buf_addf(&b, " — %s", schema_hint);
		struct abi_result r = {.kind = BML_SCHEMA_MISMATCH, .msg_len = b.len};
		r.msg = bml_buf_take(&b);
		res = abi_put(&r);
		goto out;
	}
	o->elf = malloc((size_t)n);
	if (!o->elf) {
		res = abi_fail(BML_OTHER, "bml: out of memory");
		goto out;
	}
	memcpy(o->elf, elf, (size_t)n);
	o->elf_len = (size_t)n;
	/* stage 2': the map declaration (MapDeclError) */
	struct bml_map_problems mp = {0};
	int mrc = bml_check_map_decls(o->req, o->elf, o->elf_len, &d, &mp);
	if (!mrc)
		mrc = bml_check_arena_decls(o->req, o->elf, o->elf_len, &d, 1, &mp);
	if (mrc != 0) {
		struct bml_buf b = {0};
		bml_buf_adds(&b, "bml: the map declarations differ from the ELF (regenerate the bindings from the same schema):");
		for (size_t i = 0; i < mp.n; i++) {
			char *s = bml_map_problem_string(&mp.p[i]);
			bml_buf_adds(&b, "\n  ");
			bml_buf_adds(&b, s ? s : "");
			free(s);
		}
		bml_map_problems_free(&mp);
		struct abi_result r = {.kind = mrc < 0 ? BML_OTHER : BML_MAP_MISMATCH, .msg_len = b.len};
		r.msg = bml_buf_take(&b);
		res = abi_put(&r);
		goto out;
	}
	/* stage 2''': the configured values (the config document is checked against the declared globals; a missing one is CONFIG_NOT_SET, before any kernel object exists) */
	if ((res = abi_config(config, config_len, &d, o->elf, o->elf_len, &vals, &n_vals)) != 0)
		goto out;
	/* stage 2'''': the uprobe targets (a load argument; each path is opened once and shared by the caps used for the check and by the attach) */
	if ((res = abi_uprobe_targets(o, targets, targets_len)) != 0)
		goto out;
	res = -1;
	/* stage 3: the check (Precheck; PrecheckError / TargetError) */
	struct bml_caps caps;
	caps_of(caps_kind, &o->caps, &caps);
	/* Only objects with an arena use our checked pre-mmap contract.
	 * Preserve every other declaration and the lifetime of its borrowed strings. */
	for (size_t i = 0; i < o->req->n_maps; i++) {
		if (strcmp(o->req->maps[i].map_type.p, "arena") || !o->caps.decl)
			continue;
		o->arena_decl = *o->caps.decl;
		o->arena_decl.arena_cast = "preserve";
		o->arena_decl.arena_premmap = "create_then_mmap";
		o->caps.decl = &o->arena_decl;
		break;
	}
	struct bml_unmets all = {0};
	if (check && bml_check(o->req, &caps, &all, &err) != 0) {
		char hint[256];
		res = abi_fail(BML_PRECHECK_FAILED, "target precheck failed before loading the embedded program: %s%s", err ? err : "",
			       perm_hint(o->req, err, hint, sizeof hint));
		goto out;
	}
	size_t nb = 0;
	for (size_t i = 0; i < all.n; i++)
		nb += bml_unmet_blocks_load(&all.u[i]) != 0;
	if (nb) {
		struct bml_buf b = {0};
		struct bml_unmet *blk = calloc(nb, sizeof *blk);
		bml_buf_adds(&b, "the target does not satisfy this object's requirements (not loaded):");
		size_t k = 0;
		for (size_t i = 0; i < all.n; i++)
			if (bml_unmet_blocks_load(&all.u[i])) {
				char *s = bml_unmet_string(&all.u[i]);
				bml_buf_adds(&b, "\n  ");
				bml_buf_adds(&b, s ? s : "");
				free(s);
				if (blk)
					blk[k++] = all.u[i];
			}
		struct abi_result r = {.kind = BML_TARGET_REJECTED, .msg_len = b.len};
		r.msg = bml_buf_take(&b);
		if (!blk || abi_set_unmets(&r, blk, k) != 0)
			r.kind = BML_OTHER;
		free(blk);
		bml_unmets_free(&all);
		res = abi_put(&r);
		goto out;
	}
	o->rest = all; /* the Unmet entries that did not stop the load */
	/* stage 4: the load behind the guard */
	struct bml_load_result lr;
	if (bml_load_guarded_values(o->elf, o->elf_len, o->req, &caps, vals, n_vals, &o->lo, &lr) != 0) {
		if (lr.stage == BML_LOAD_LIBBPF && lr.verifier)
			res = verifier_fail(&lr);
		else if (lr.stage == BML_LOAD_LIBBPF || lr.stage == BML_LOAD_OPEN || lr.stage == BML_LOAD_ENV)
		{
			char hint[256];
			res = abi_fail(BML_OTHER, "bml: load: %s%s", lr.msg ? lr.msg : "", perm_hint(o->req, lr.msg, hint, sizeof hint));
		}
		else
			res = abi_fail(BML_PRECHECK_FAILED, "bml: the loader refused to load (%s): %s", bml_load_stage_name(lr.stage),
				       lr.msg ? lr.msg : "");
		bml_load_result_free(&lr);
		goto out;
	}
	bml_load_result_free(&lr);
	/* stage 5: whether the declared maps exist in the object */
	const char *mm = missing_map(bml_obj_bpf(o->lo), &d);
	if (mm) {
		res = abi_fail(BML_PRECHECK_FAILED, "bml: the embedded ELF has no map %s", mm);
		goto out;
	}
	if (abi_globals_keep(o, &d) != 0) {
		res = abi_fail(BML_OTHER, "bml: out of memory");
		goto out;
	}
	abi_lock();
	int64_t id = abi_loaded ? -2 : abi_handle_new(H_OBJECT, o, 0);
	if (id > 0)
		abi_loaded = id;
	abi_unlock();
	if (id == -2) {
		res = abi_fail(BML_STATE, "bml: the embedded object is already loaded (close it before loading again)");
		goto out;
	}
	if (id < 0) {
		res = abi_fail(BML_OTHER, "bml: out of memory");
		goto out;
	}
	struct abi_result r = {.kind = BML_OK, .value = id};
	if (abi_set_unmets(&r, o->rest.u, o->rest.n) != 0)
		r.kind = BML_OTHER;
	o = NULL;
	res = abi_put(&r);
out:
	free(err);
	free(vals);
	bml_map_decls_free(&d);
	object_free(o);
	return res;
}

int64_t bml_object_unmet(int64_t obj)
{
	int64_t err;
	struct abi_object *o = abi_object_acquire(obj, &err); /* counted as a running call of the object */
	if (!o)
		return err;
	struct abi_result r = {.kind = BML_OK};
	int bad = abi_set_unmets(&r, o->rest.u, o->rest.n) != 0;
	abi_object_release(o);
	if (bad)
		return abi_fail(BML_OTHER, "bml: out of memory");
	return abi_put(&r);
}


int64_t bml_close(int64_t obj)
{
	/* Idempotent by design, so that a second close on a cleanup path is not an error. A closed object stays in the table, and every other operation on it is STATE. */
	/* CONTRACT: if calls are running (the abi_object_acquire count), returns STATE without closing (does not wait;
 * the caller retries). Reading the count and setting the closed mark happen under one lock: calls after the mark get STATE from acquire, and calls counted before the mark are
 * seen by close through the count (there is no check-then-close window) */
	abi_lock();
	struct abi_object *o = abi_handle_get(obj, H_OBJECT);
	int closed = o && o->closed, busy = o && !closed ? o->inflight : 0;
	int first = o && !closed && (busy == 0 || BML_MUT("abi.close_ignores_inflight"));
	if (first) {
		o->closed = 1;
		if (abi_loaded == obj)
			abi_loaded = 0;
	}
	abi_unlock();
	if (!o)
		return abi_fail(BML_STATE, "bml: no loaded object %lld (load it first)", (long long)obj);
	if (closed)
		return abi_ok(0);
	if (!first)
		return abi_fail(BML_STATE, "bml: the object %lld has %d calls in flight on other threads — close it again after they return", (long long)obj,
				busy);
	abi_close_owned(obj);
	if (first) { /* release the resources (the struct stays in the table) */
		bml_obj_close(o->lo);
		o->lo = NULL;
		bml_requirements_free(o->req);
		o->req = NULL;
		free(o->elf);
		o->elf = NULL;
		bml_unmets_free(&o->rest);
		bml_live_caps_free(&o->caps);
		abi_globals_free(o);
	}
	return abi_ok(0);
}

int64_t bml_load_checked(const uint8_t *elf, int64_t n, const char *sha, int64_t sha_len, const char *maps, int64_t maps_len,
			 int64_t caps_kind)
{
	return bml_load_checked_targets(elf, n, sha, sha_len, maps, maps_len, NULL, 0, NULL, 0, caps_kind);
}

int64_t bml_load_checked_config(const uint8_t *elf, int64_t n, const char *sha, int64_t sha_len, const char *maps, int64_t maps_len,
				const char *config, int64_t config_len, int64_t caps_kind)
{
	return bml_load_checked_targets(elf, n, sha, sha_len, maps, maps_len, config, config_len, NULL, 0, caps_kind);
}

int64_t bml_load_checked_targets(const uint8_t *elf, int64_t n, const char *sha, int64_t sha_len, const char *maps, int64_t maps_len,
				 const char *config, int64_t config_len, const char *targets, int64_t targets_len, int64_t caps_kind)
{
	return load_impl(elf, n, sha, sha_len, maps, maps_len, config, config_len, targets, targets_len, caps_kind, 1);
}

#ifdef BML_TEST_CAPS
/* Test build only (the counterpart of the downstream testonly_load_unchecked and its _targets variant):
 * a load that skips the stage-3 check. It still does the schema, the map declaration, the configured
 * values, the reading of the targets and the load behind the guard; the caps are live. The name starts
 * with bml_testonly_ (the gate checks with nm that the product has no such symbol). */
int64_t bml_testonly_load_unchecked_targets(const uint8_t *elf, int64_t n, const char *sha, int64_t sha_len, const char *maps, int64_t maps_len,
					    const char *config, int64_t config_len, const char *targets, int64_t targets_len)
{
	return load_impl(elf, n, sha, sha_len, maps, maps_len, config, config_len, targets, targets_len, 0, 0);
}
#endif
