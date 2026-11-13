#include "req/kfunc_profile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json/json.h"
#include "util/gostr.h"

static const struct prow {
	const char *kind, *section, *typ, *attach, *req_attach, *target_kind;
	int64_t id;
	uint32_t flags;
	int prefix;
} rows[] = {
	{"syscall", "syscall", "syscall", "-", "syscall", "none", 31, 16, 0},
	{"xdp", "xdp", "xdp", "xdp", "", "none", 6, 0, 0},
	{"sched_cls", "tcx/ingress", "sched_cls", "tcx_ingress", "tcx", "ingress", 3, 0, 0},
	{"sched_cls", "tcx/egress", "sched_cls", "tcx_egress", "tcx", "egress", 3, 0, 0},
	{"sched_cls", "netkit/primary", "sched_cls", "netkit_primary", "netkit", "primary", 3, 0, 0},
	{"sched_cls", "netkit/peer", "sched_cls", "netkit_peer", "netkit", "peer", 3, 0, 0},
	{"cgroup_skb", "cgroup_skb/ingress", "cgroup_skb", "cgroup_inet_ingress", "cgroup_inet_ingress", "cgroup", 8, 0, 0},
	{"cgroup_skb", "cgroup_skb/egress", "cgroup_skb", "cgroup_inet_egress", "cgroup_inet_egress", "cgroup", 8, 0, 0},
	{"tp_btf", "tp_btf/", "tracing", "trace_raw_tp", "trace_raw_tp", "tp_btf", 26, 0, 1},
	{"fentry", "fentry/", "tracing", "trace_fentry", "trace_fentry", "func", 26, 0, 1},
	{"fexit", "fexit/", "tracing", "trace_fexit", "trace_fexit", "func", 26, 0, 1},
	{"fmod_ret", "fmod_ret/", "tracing", "modify_return", "trace_fmod_ret", "func", 26, 0, 1},
	{"iter", "iter/", "tracing", "trace_iter", "trace_iter", "iter", 26, 0, 1},
	{"kprobe_session", "kprobe.session/", "kprobe", "trace_kprobe_session", "trace_kprobe_session", "func", 2, 0, 1},
	{"fsession", "fsession/", "tracing", "trace_fsession", "trace_fsession", "func", 26, 0, 1},
	{"tracepoint", "tracepoint/", "tracepoint", "-", "trace_tp", "tp", 5, 0, 1},
	{"raw_tp", "raw_tp/", "raw_tracepoint", "-", "raw_tp", "rawtp", 17, 0, 1},
	{"perf_event", "perf_event", "perf_event", "-", "trace_perf", "perf", 7, 0, 0},
	{"lsm", "lsm/", "lsm", "lsm_mac", "lsm_mac", "lsm", 29, 0, 1},
	{"cgroup_sock", "cgroup/sock_create", "cgroup_sock", "cgroup_inet_sock_create", "cgroup_inet_sock_create", "cgroup", 9, 0, 0},
	{"cgroup_device", "cgroup/dev", "cgroup_device", "cgroup_device", "cgroup_device", "cgroup", 15, 0, 0},
	{"cgroup_sock_addr", "cgroup/connect4", "cgroup_sock_addr", "cgroup_inet4_connect", "cgroup_inet4_connect", "cgroup", 18, 0, 0},
	{"cgroup_sockopt", "cgroup/getsockopt", "cgroup_sockopt", "cgroup_getsockopt", "cgroup_getsockopt", "cgroup", 25, 0, 0},
	{"cgroup_sysctl", "cgroup/sysctl", "cgroup_sysctl", "cgroup_sysctl", "cgroup_sysctl", "cgroup", 23, 0, 0},
	{"sock_ops", "sockops", "sock_ops", "cgroup_sock_ops", "cgroup_sock_ops", "cgroup", 13, 0, 0},
};

static int str_is(const struct bml_str *s, const char *lit)
{
	return s->len == strlen(lit) && !memcmp(s->p, lit, s->len);
}

static void jstr(struct bml_buf *b, const struct bml_str *s)
{
	bml_json_write_string_html(b, s->p ? s->p : "", s->len);
}

static void jstrs(struct bml_buf *b, const struct bml_str *v, size_t n)
{
	if (!n) {
		bml_buf_adds(b, "null");
		return;
	}
	bml_buf_adds(b, "[");
	for (size_t i = 0; i < n; i++) {
		if (i)
			bml_buf_adds(b, ",");
		jstr(b, &v[i]);
	}
	bml_buf_adds(b, "]");
}

static void jargs(struct bml_buf *b, const struct bml_intarg *v, size_t n)
{
	if (!n) {
		bml_buf_adds(b, "null");
		return;
	}
	bml_buf_adds(b, "[");
	for (size_t i = 0; i < n; i++) {
		bml_buf_addf(b, "%s{\"N\":%lld,\"Type\":", i ? "," : "", (long long)v[i].n);
		jstr(b, &v[i].type);
		bml_buf_adds(b, "}");
	}
	bml_buf_adds(b, "]");
}

#define F(name) bml_buf_adds(b, "," "\"" name "\":")

void bml_req_attach_json(struct bml_buf *b, const struct bml_attach *a, int blank_program)
{
	static const struct bml_str empty = {"", 0};
	bml_buf_adds(b, "{\"Program\":");
	jstr(b, blank_program ? &empty : &a->program);
	F("AttachType"), jstr(b, &a->attach_type);
	F("Target"), jstr(b, &a->target);
	F("Args"), jstrs(b, a->args, a->n_args);
	bml_buf_addf(b, ",\"RetNargs\":%lld", (long long)a->ret_nargs);
	F("RetType"), jstr(b, &a->ret_type);
	F("Arch"), jstr(b, &a->arch);
	F("CtxFields");
	if (!a->n_ctxfields)
		bml_buf_adds(b, "null");
	for (size_t i = 0; i < a->n_ctxfields; i++) {
		bml_buf_adds(b, i ? ",{\"Struct\":" : "[{\"Struct\":");
		jstr(b, &a->ctxfields[i].strct);
		F("Field"), jstr(b, &a->ctxfields[i].field);
		bml_buf_addf(b, ",\"Offset\":%lld,\"Size\":%lld}%s", (long long)a->ctxfields[i].offset, (long long)a->ctxfields[i].size,
			     i + 1 == a->n_ctxfields ? "]" : "");
	}
	F("KprobeArgs"), jargs(b, a->kprobe_args, a->n_kprobe_args);
	F("BinarySHA256"), jstr(b, &a->binary_sha256);
	F("UprobeArgs"), jargs(b, a->uprobe_args, a->n_uprobe_args);
	F("FArgs"), jstrs(b, a->fargs, a->n_fargs);
	bml_buf_addf(b, ",\"Generic\":%s", a->generic ? "true" : "false");
	F("TargetKind"), jstr(b, &a->tkind);
	F("TargetValue"), jstr(b, &a->tval);
	F("TPBufferType"), jstr(b, &a->tpbuf_type);
	F("TPFields");
	if (!a->n_tpfields)
		bml_buf_adds(b, "null");
	for (size_t i = 0; i < a->n_tpfields; i++) {
		bml_buf_adds(b, i ? ",{\"Field\":" : "[{\"Field\":");
		jstr(b, &a->tpfields[i].field);
		bml_buf_addf(b, ",\"Offset\":%lld,\"Bytes\":%lld,\"Sign\":", (long long)a->tpfields[i].offset, (long long)a->tpfields[i].bytes);
		jstr(b, &a->tpfields[i].sign);
		bml_buf_adds(b, i + 1 == a->n_tpfields ? "}]" : "}");
	}
	bml_buf_addf(b, ",\"ExtNargs\":%lld", (long long)a->ext_nargs);
	F("ExtRet"), jstr(b, &a->ext_ret);
	F("ExtArgs"), jstrs(b, a->ext_args, a->n_ext_args);
	F("StructOpStruct"), jstr(b, &a->sop_struct);
	F("StructOpMember"), jstr(b, &a->sop_member);
	bml_buf_addf(b, ",\"MultiN\":%lld", (long long)a->multi_n);
	F("MTargets"), jstrs(b, a->mtargets, a->n_mtargets);
	F("USDTSem"), jstr(b, &a->usdt_sem);
	F("USDTArgs"), jargs(b, a->usdt_args, a->n_usdt_args);
	F("SysArgs"), jargs(b, a->sys_args, a->n_sys_args);
	F("MTargetArgs");
	if (!a->n_mtarget_args)
		bml_buf_adds(b, "null");
	for (size_t i = 0; i < a->n_mtarget_args; i++) {
		bml_buf_addf(b, "%s{\"I\":%lld,\"N\":%lld,\"Type\":", i ? "," : "[", (long long)a->mtarget_args[i].i, (long long)a->mtarget_args[i].n);
		jstr(b, &a->mtarget_args[i].type);
		bml_buf_adds(b, i + 1 == a->n_mtarget_args ? "}]" : "}");
	}
	bml_buf_adds(b, "}");
}


static int canonical(const char *section, const struct bml_program *p, const struct bml_attach **as, size_t nas, struct bml_kfunc_profile_entry *e)
{
	for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
		const struct prow *r = &rows[i];
		const char *target = "";
		if (r->prefix) {
			size_t pl = strlen(r->section);
			if (strncmp(section, r->section, pl) != 0)
				continue;
			target = section + pl;
			int bad = !target[0] || strpbrk(target, " \t\n:") != NULL;
			const char *slash = strchr(target, '/');
			if (!strcmp(r->kind, "tracepoint"))
				bad |= !slash || slash == target || !slash[1] || strchr(slash + 1, '/') != NULL;
			else
				bad |= slash != NULL;
			if (bad)
				continue;
		} else if (strcmp(section, r->section) != 0) {
			continue;
		}
		if (!str_is(&p->prog_type, r->typ) || p->prog_type_id != r->id)
			return -1;
		if (!r->req_attach[0]) {
			if (nas != 0)
				return -1;
		} else {
			if (nas != 1)
				return -1;
			const struct bml_attach *a = as[0];
			char *ft = NULL;
			int gfr = 0;
			if (!strcmp(r->kind, "fmod_ret") && a->generic && str_is(&a->attach_type, "modify_return") && str_is(&a->tkind, "func") &&
			    str_is(&a->tval, target)) {
				ft = malloc(strlen(target) + 6);
				if (!ft)
					return -1;
				strcpy(ft, "func:");
				strcat(ft, target);
				gfr = str_is(&a->target, ft);
				free(ft);
			}
			if (!str_is(&a->attach_type, r->req_attach) && !gfr)
				return -1;
			char want[512];
			if (!strcmp(r->kind, "iter") || !strcmp(r->kind, "kprobe_session") || !strcmp(r->kind, "fsession") ||
			    !strcmp(r->kind, "raw_tp") || !strcmp(r->kind, "lsm"))
				snprintf(want, sizeof want, "%s:%s", r->target_kind, target);
			else
				snprintf(want, sizeof want, "%s", r->prefix ? target : r->target_kind);
			if (!str_is(&a->target, want) && !gfr)
				return -1;
		}
		e->kind = r->kind;
		e->prog_type = r->typ;
		e->prog_type_id = r->id;
		e->prog_flags = r->flags;
		e->attach_type = r->attach;
		e->target_kind = !strcmp(r->kind, "sched_cls") ? "none" : !strcmp(r->kind, "tp_btf") ? "tp" : r->target_kind;
		e->target = strdup(target);
		if (nas == 1) {
			struct bml_buf b = {0};
			bml_req_attach_json(&b, as[0], 1);
			e->context_identity = bml_buf_take(&b);
		} else {
			e->context_identity = strdup(r->kind);
		}
		return e->target && e->context_identity ? 0 : -2;
	}
	return -1;
}

#define UNK "cannot be determined on this target"

static int derive_one(const struct bml_elf *elf, const struct bml_elf_sym *syms, size_t nsyms, int sym_ok, struct bml_requirements *r, const char *prog,
		      struct bml_kfunc_profile_entry *e)
{
	const struct bml_program *p = NULL;
	size_t np = 0;
	for (size_t i = 0; i < r->n_programs; i++)
		if (!strcmp(r->programs[i].symbol.p, prog))
			p = &r->programs[i], np++;
	const struct bml_elf_sym *found = NULL;
	size_t nf = 0;
	for (size_t i = 0; sym_ok && i < nsyms; i++)
		if (!strcmp(syms[i].name, prog) && BML_ST_TYPE(syms[i].info) == BML_STT_FUNC && syms[i].shndx != BML_SHN_UNDEF)
			found = &syms[i], nf++;
	if (np != 1 || !sym_ok || nf != 1)
		return (e->reason = strdup("actual ELF entry FUNC is unavailable or not unique")) ? 0 : -2;
	if (found->shndx >= elf->n_sections || found->shndx >= 0xff00)
		return (e->reason = strdup("actual ELF entry section is unavailable")) ? 0 : -2;
	const struct bml_elf_shdr *sec = &elf->sections[found->shndx];
	size_t named = 0, entries = 0;
	for (size_t i = 0; i < elf->n_sections; i++)
		named += !strcmp(elf->sections[i].name, sec->name);
	for (size_t i = 0; i < nsyms; i++)
		entries += syms[i].shndx == found->shndx && BML_ST_TYPE(syms[i].info) == BML_STT_FUNC && syms[i].value == 0;
	if (named != 1 || entries != 1 || sec->type != 1                    || !(sec->flags & BML_SHF_EXECINSTR) || found->size == 0 || found->value != 0 ||
	    found->size % 8 != 0 || found->size > sec->size)
		return (e->reason = strdup("actual ELF entry bounds are invalid")) ? 0 : -2;
	const struct bml_attach **as = calloc(r->n_attaches ? r->n_attaches : 1, sizeof *as);
	if (!as)
		return -2;
	size_t nas = 0;
	for (size_t i = 0; i < r->n_attaches; i++)
		if (!strcmp(r->attaches[i].program.p, prog))
			as[nas++] = &r->attaches[i];
	int rc = canonical(sec->name, p, as, nas, e);
	free(as);
	if (rc == -2)
		return -2;
	if (rc)
		return (e->reason = strdup(UNK ": section/program/attach has no canonical initial profile")) ? 0 : -2;
	return (e->section = strdup(sec->name)) ? 0 : -2;
}

int bml_req_kfunc_profiles_derive(const struct bml_elf *elf, struct bml_requirements *r)
{
	if (!r->n_kfuncs)
		return 0;
	struct bml_elf_sym *syms = NULL;
	size_t nsyms = 0;
	char *err = NULL;
	int sym_ok = bml_elf_symbols(elf, BML_SHT_SYMTAB, &syms, &nsyms, &err) == 0;
	free(err);
	r->kfunc_profiles = calloc(r->n_kfuncs, sizeof *r->kfunc_profiles);
	if (!r->kfunc_profiles) {
		free(syms);
		return -1;
	}
	int rc = 0;
	for (size_t k = 0; k < r->n_kfuncs && !rc; k++) {
		const char *prog = r->kfuncs[k].program.p;
		int seen = 0;
		for (size_t j = 0; j < r->n_kfunc_profiles; j++)
			seen |= !strcmp(r->kfunc_profiles[j].program, prog);
		if (seen)
			continue;
		struct bml_kfunc_profile_entry *e = &r->kfunc_profiles[r->n_kfunc_profiles++];
		memset(e, 0, sizeof *e);
		e->program = strdup(prog);
		rc = e->program ? derive_one(elf, syms, nsyms, sym_ok, r, prog, e) : -2;
	}
	free(syms);
	return rc ? -1 : 0;
}

void bml_req_kfunc_profiles_free(struct bml_requirements *r)
{
	for (size_t i = 0; i < r->n_kfunc_profiles; i++) {
		struct bml_kfunc_profile_entry *e = &r->kfunc_profiles[i];
		free(e->program), free(e->reason), free(e->section), free(e->target), free(e->context_identity);
	}
	free(r->kfunc_profiles);
	r->kfunc_profiles = NULL;
	r->n_kfunc_profiles = 0;
}

const struct bml_kfunc_profile_entry *bml_req_kfunc_profile_for(const struct bml_requirements *r, const char *program, char **why)
{
	*why = NULL;
	for (size_t i = 0; i < r->n_kfunc_profiles; i++) {
		const struct bml_kfunc_profile_entry *e = &r->kfunc_profiles[i];
		if (strcmp(e->program, program) != 0)
			continue;
		if (e->reason) {
			struct bml_buf b = {0};
			bml_buf_addf(&b, UNK ": %s", e->reason);
			*why = bml_buf_take(&b);
			return NULL;
		}
		return e;
	}
	*why = strdup(UNK ": kfunc profile is not actual-ELF-derived");
	return NULL;
}
