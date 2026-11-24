/* req/parse_v9.c — reading the attach rows and the ctxaccess rows of requirements (format version 9). A port of the attach and ctxaccess
 * branches of Parse in bpf-mlir's go/requirements/requirements.go and of parseAttachTarget, validAttachTypeName and validCName in spec.go;
 * split out of parse.c.
 *
 * A type that is not one of those with companion rows (the 6 types of that time, plus kretprobe / uretprobe from version 9) is a generic
 * attach row: its type is a UAPI bpf_attach_type name or a mechanism name. Only the spelling is checked here; whether the type exists is
 * left to the attach_type check. The target is `<kind>` or `<kind>:<value>`. */
#include "req/parse_internal.h"

#include <string.h>

#include "util/mutation.h"

/* the attach types of versions 4 to 8 (before generic attach rows existed) */
static const char *const legacy_types[] = {"trace_raw_tp", "trace_fentry", "trace_fexit", "kprobe", "uprobe", "tcx"};

/* mechanism names that have no expected_attach_type (fixed in version 9); the check does not ask about attach_type for them */
static const char *const mechanisms[] = {"raw_tp",   "raw_tp_writable", "tracepoint", "socket_filter", "sched_act",
					 "lwt_in",   "lwt_out",         "lwt_xmit",   "lwt_seg6local", "syscall"};

/* the kinds of target (fixed in version 9); value says whether the kind carries a value */
static const struct {
	const char *name;
	int value;
} target_kinds[] = {
	{"func", 1},   {"tp", 1},    {"rawtp", 1},  {"iter", 1},    {"lsm", 1},  {"sym", 1},    {"map", 1},  {"prog", 1},
	{"cgroup", 0}, {"netns", 0}, {"socket", 0}, {"netlink", 0}, {"perf", 0}, {"device", 0}, {"none", 0},
};

static int in_list(struct field f, const char *const *list, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (req_eq(f, list[i]))
			return 1;
	return 0;
}

int req_attach_mechanism(const char *s, size_t n)
{
	return in_list((struct field){s, n}, mechanisms, sizeof mechanisms / sizeof *mechanisms);
}

/* validAttachTypeName: [a-z0-9_]+ starting with a lowercase letter */
int req_valid_attach_type_name(struct field f)
{
	if (f.n == 0 || f.p[0] < 'a' || f.p[0] > 'z')
		return 0;
	for (size_t i = 0; i < f.n; i++) {
		char c = f.p[i];
		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
			return 0;
	}
	return 1;
}

/* validCName: a C identifier (it does not start with a digit) */
static int valid_cname(struct field f)
{
	if (f.n == 0 || (f.p[0] >= '0' && f.p[0] <= '9'))
		return 0;
	for (size_t i = 0; i < f.n; i++) {
		char c = f.p[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
			return 0;
	}
	return 1;
}

int req_valid_cname(struct field f)
{
	return valid_cname(f);
}

static int has_map(const struct bml_requirements *r, struct field sym)
{
	for (size_t i = 0; i < r->n_maps; i++)
		if (req_str_eq(&r->maps[i].symbol, sym))
			return 1;
	return 0;
}

static int second_attach(const struct bml_requirements *r, struct field program)
{
	for (size_t i = 0; i < r->n_attaches; i++)
		if (req_str_eq(&r->attaches[i].program, program))
			return 1;
	return 0;
}

/* attachTypeMinVersion: the types of versions 4 to 8 need 4, trace_fmod_ret needs 10, and kretprobe / uretprobe and the generic types need 9 */
static int64_t attach_type_min_version(struct field t)
{
	if (in_list(t, legacy_types, sizeof legacy_types / sizeof *legacy_types))
		return 4;
	if (req_eq(t, "trace_fmod_ret"))
		return 10;
	if (req_v11_attach_type(t))
		return 11;
	if (req_v12_attach_type(t)) /* format 12 types */
		return 12;
	if (req_v13_attach_type(t)) /* format 13 types */
		return 13;
	if (req_eq(t, "netkit")) /* netkit */
		return 30;
	return 9;
}

/* isV13AttachType (format 13) */
int req_v13_attach_type(struct field t)
{
	return req_eq(t, "trace_lsm_cgroup") || req_eq(t, "ksyscall");
}

/* Format 12: the multi family and usdt */
int req_multi_attach_type(struct field t)
{
	return req_eq(t, "kprobe_multi") || req_eq(t, "kretprobe_multi") || req_eq(t, "uprobe_multi") || req_eq(t, "uretprobe_multi");
}

int req_v12_attach_type(struct field t)
{
	return req_multi_attach_type(t) || req_eq(t, "usdt");
}

/* multiCount: strconv.Atoi can read it and it is at least 1 */
static int multi_count(struct field s, int64_t *n)
{
	return !bml_go_atoi(s.p, s.n, n) && *n >= 1;
}

/* validUSDTTarget: split at the first colon; both sides must be C identifiers */
static int valid_usdt_target(struct field tg)
{
	const char *c = memchr(tg.p, ':', tg.n);
	if (!c)
		return 0;
	struct field a = {tg.p, (size_t)(c - tg.p)}, b = {c + 1, tg.n - a.n - 1};
	return valid_cname(a) && valid_cname(b);
}

/* Format 11: the types of the companion-row families */
int req_v11_attach_type(struct field t)
{
	return req_eq(t, "trace_lsm") || req_eq(t, "trace_tp") || req_eq(t, "trace_perf") || req_eq(t, "freplace") || req_eq(t, "trace_struct_ops");
}

/* validV11Target: lsm, freplace and struct_ops take a C identifier; tp takes `<cat>/<event>` (both C identifiers); perf takes `perf`. */
static int valid_v11_target(struct field t, struct field tg)
{
	if (req_eq(t, "trace_lsm") || req_eq(t, "freplace") || req_eq(t, "trace_struct_ops"))
		return valid_cname(tg);
	if (req_eq(t, "trace_tp")) {
		const char *sl = memchr(tg.p, '/', tg.n);
		if (!sl)
			return 0;
		struct field cat = {tg.p, (size_t)(sl - tg.p)}, ev = {sl + 1, tg.n - cat.n - 1};
		return valid_cname(cat) && valid_cname(ev);
	}
	if (req_eq(t, "trace_perf"))
		return req_eq(tg, "perf");
	return 0;
}

/* An attach row. Returns 0 when it was read, -1 for an error (stored in e) and -2 when memory runs out. */
int req_v9_attach(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e)
{
	int generic = !req_known_attach_type(f[2]);
	if (r->version < 9 && !BML_MUT("parse.v9_rows_any_version")) {
		if (generic) /* before version 9 an unknown type is a value error (as before generic attach rows existed) */
			return req_perr(e, n, "attach", "value", "%s line %d: bad attach row %q", SEC, (int64_t)n, Q(line));
		if (!in_list(f[2], legacy_types, sizeof legacy_types / sizeof *legacy_types))
			return req_perr(e, n, "attach", "min_version", "%s line %d: attach type %q needs version %d", SEC, (int64_t)n, Q(f[2]),
					attach_type_min_version(f[2]));
	}
	/* The minimum version of each companion-row family type (trace_fmod_ret needs version 10). The mutation parse.v12_rows_any_version ignores the
	 * minimum version of the version-12 types. */
	if (!generic && r->version < attach_type_min_version(f[2]) && !BML_MUT("parse.v9_rows_any_version") &&
	    !(req_v12_attach_type(f[2]) && BML_MUT("parse.v12_rows_any_version")) && !(req_v13_attach_type(f[2]) && BML_MUT("parse.v13_rows_any_version")) &&
	    !(req_eq(f[2], "netkit") && BML_MUT("parse.netkit_any_version")))
		return req_perr(e, n, "attach", "min_version", "%s line %d: attach type %q needs version %d", SEC, (int64_t)n, Q(f[2]),
				attach_type_min_version(f[2]));
	struct field kind = {0}, value = {0};
	int64_t multi_n = 0;
	if (generic) {
		if (!req_valid_attach_type_name(f[2]))
			return req_perr(e, n, "attach", "value", "%s line %d: bad attach row %q", SEC, (int64_t)n, Q(line));
		/* parseAttachTarget: strings.Cut(s, ":") */
		const char *colon = memchr(f[3].p, ':', f[3].n);
		kind = (struct field){f[3].p, colon ? (size_t)(colon - f[3].p) : f[3].n};
		if (colon)
			value = (struct field){colon + 1, f[3].n - kind.n - 1};
		size_t k = 0;
		while (k < sizeof target_kinds / sizeof *target_kinds && !req_eq(kind, target_kinds[k].name))
			k++;
		if (k == sizeof target_kinds / sizeof *target_kinds)
			return req_perr(e, n, "attach", "value", "%s line %d: bad attach target %q: unknown target kind %q", SEC, (int64_t)n,
					Q(f[3]), Q(kind));
		const char *kn = target_kinds[k].name;
		if (target_kinds[k].value && (!colon || value.n == 0 || memchr(value.p, ' ', value.n) || memchr(value.p, '\t', value.n)))
			return req_perr(e, n, "attach", "value", "%s line %d: bad attach target %q: target kind %q needs a value (%s:<value>)", SEC,
					(int64_t)n, Q(f[3]), Q(kind), kn);
		if (!target_kinds[k].value && colon)
			return req_perr(e, n, "attach", "value",
					"%s line %d: bad attach target %q: target kind %q takes no value (the loader supplies it)", SEC, (int64_t)n,
					Q(f[3]), Q(kind));
		if (req_eq(kind, "map") && !has_map(r, value))
			return req_perr(e, n, "attach", "order", "%s line %d: attach target map %q is not a map row", SEC, (int64_t)n, Q(value));
	} else if (f[3].n == 0 || (req_eq(f[2], "tcx") && !req_eq(f[3], "ingress") && !req_eq(f[3], "egress")) ||
		   (req_eq(f[2], "netkit") && !req_eq(f[3], "primary") && !req_eq(f[3], "peer") && !BML_MUT("parse.netkit_any_direction")) ||
		   (req_v11_attach_type(f[2]) && !valid_v11_target(f[2], f[3])) ||
		   (req_multi_attach_type(f[2]) && !multi_count(f[3], &multi_n)) || (req_eq(f[2], "usdt") && !valid_usdt_target(f[3])) ||
		   (req_v13_attach_type(f[2]) && !valid_cname(f[3]))) {
		return req_perr(e, n, "attach", "value", "%s line %d: bad attach row %q", SEC, (int64_t)n, Q(line));
	} else if (req_eq(f[2], "trace_struct_ops") && !has_map(r, f[3])) { /* the target is a map row of the same ELF (the map row comes first) */
		return req_perr(e, n, "attach", "order", "%s line %d: attach target map %q is not a map row", SEC, (int64_t)n, Q(f[3]));
	}
	/* one attach per program */
	if (second_attach(r, f[1]))
		return req_perr(e, n, "attach", "order", "%s line %d: program %q has a second attach row", SEC, (int64_t)n, Q(f[1]));
	if (GROW(r->attaches, r->n_attaches, r->cap_attaches))
		return -2;
	struct bml_attach *a = &r->attaches[r->n_attaches];
	memset(a, 0, sizeof(*a));
	a->ret_nargs = -1;
	a->ext_nargs = -1;
	a->generic = generic;
	a->multi_n = multi_n;
	r->n_attaches++; /* count first, so that free also sees the contents when mkstr fails */
	if (req_mkstr(&a->program, f[1]) || req_mkstr(&a->attach_type, f[2]) || req_mkstr(&a->target, f[3]))
		return -2;
	if (generic && (req_mkstr(&a->tkind, kind) || req_mkstr(&a->tval, value)))
		return -2;
	return 0;
}

/* A ctxaccess row. It is tied to its program by name: the program row comes first, and a program has one row per field and mode. The return
 * values 0 / -1 / -2 are as for req_v9_attach. */
int req_v9_ctxaccess(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e)
{
	if (req_find_program(r, f[1]) < 0)
		return req_perr(e, n, "ctxaccess", "order", "%s line %d: ctxaccess for unknown program %q", SEC, (int64_t)n, Q(f[1]));
	int64_t bytes;
	int berr = bml_go_atoi(f[6].p, f[6].n, &bytes);
	if ((!req_eq(f[2], "-") && !req_valid_attach_type_name(f[2])) || !valid_cname(f[3]) || !valid_cname(f[4]) ||
	    (!req_eq(f[5], "r") && !req_eq(f[5], "w")) || berr || (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8))
		return req_perr(e, n, "ctxaccess", "value", "%s line %d: bad ctxaccess row %q", SEC, (int64_t)n, Q(line));
	for (size_t i = 0; i < r->n_ctxaccesses; i++) {
		const struct bml_ctxaccess *p = &r->ctxaccesses[i];
		if (req_str_eq(&p->program, f[1]) && req_str_eq(&p->strct, f[3]) && req_str_eq(&p->field, f[4]) && req_str_eq(&p->mode, f[5]))
			return req_perr(e, n, "ctxaccess", "order", "%s line %d: ctxaccess row repeated %q", SEC, (int64_t)n, Q(line));
	}
	if (GROW(r->ctxaccesses, r->n_ctxaccesses, r->cap_ctxaccesses))
		return -2;
	struct bml_ctxaccess *c = &r->ctxaccesses[r->n_ctxaccesses];
	memset(c, 0, sizeof(*c));
	r->n_ctxaccesses++;
	c->bytes = bytes;
	if (req_mkstr(&c->program, f[1]) || req_mkstr(&c->attach_type, f[2]) || req_mkstr(&c->strct, f[3]) || req_mkstr(&c->field, f[4]) ||
	    req_mkstr(&c->mode, f[5]))
		return -2;
	return 0;
}
