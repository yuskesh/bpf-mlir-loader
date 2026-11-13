#define _GNU_SOURCE
#include "abi/internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "util/mutation.h"

static int str_is(const struct bml_str *s, const char *lit)
{
	return s->len == strlen(lit) && memcmp(s->p, lit, s->len) == 0;
}


static int clean(const struct bml_str *s)
{
	return s->len > 0 && strlen(s->p) == s->len;
}

static const struct bml_attach *attach_row(const struct abi_object *o, const char *name)
{
	for (size_t i = 0; i < o->req->n_attaches; i++)
		if (str_is(&o->req->attaches[i].program, name))
			return &o->req->attaches[i];
	return NULL;
}

#define OTHERS "attach_xdp / attach_fentry / attach_fexit / attach_fmod_ret / attach_kprobe / attach_kretprobe / attach_uprobe / attach_uretprobe / " \
	       "attach_tp_btf / attach_raw_tp / attach_iter / attach_tcx"

static int64_t wrong_kind(struct abi_object *o, struct bpf_program *p, const char *kind)
{
	return abi_fail(BML_STATE, "bml: %s is a %s program, not %s — attach it with its own kind (" OTHERS ")", bpf_program__name(p), abi_kind_name(o, p),
			kind);
}

static int link_info(int fd, struct bpf_link_info *info)
{
	uint32_t len = sizeof *info;
	return bpf_link_get_info_by_fd(fd, info, &len) != 0 ? -errno : 0;
}


static int64_t attach_fmod_ret_body(int64_t obj, const char *prog, int64_t len)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, len, &p)))
		return e;
	const char *name = bpf_program__name(p);
	if (bpf_program__type(p) != BPF_PROG_TYPE_TRACING || bpf_program__expected_attach_type(p) != BPF_MODIFY_RETURN)
		return wrong_kind(o, p, "fmod_ret");

	const struct bml_attach *a = attach_row(o, name);
	const struct bml_str *fn = NULL;
	if (a && str_is(&a->attach_type, "trace_fmod_ret"))
		fn = &a->target;
	else if (a && str_is(&a->attach_type, "modify_return") && str_is(&a->tkind, "func"))
		fn = &a->tval;
	if (!fn || !clean(fn))
		return abi_fail(BML_OTHER, "bml: fmod_ret %s: the ELF declares no kernel function (an attach row trace_fmod_ret <fn> or modify_return func:<fn>)",
				name);
	uint32_t want = 0;
	char *err = NULL;
	if (bml_live_func_btf_id(&o->caps.live, fn->p, &want, &err) != 0) {
		e = abi_fail(BML_OTHER, "bml: attach fmod_ret %s: looking up FUNC %s in the target BTF: %s", name, fn->p, err ? err : "");
		free(err);
		return e;
	}
	struct bpf_link *l = bpf_program__attach_trace(p);
	if (!l)
		return abi_fail(BML_OTHER, "bml: attach fmod_ret %s to %s: %s", name, fn->p, abi_errno(errno));
	struct bpf_link_info info;
	memset(&info, 0, sizeof info);
	int rc = link_info(bpf_link__fd(l), &info);
	if (rc == 0 && BML_MUT("attach.fmodret_btf_other"))
		info.tracing.target_btf_id = want + 1;
	if (rc != 0) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: attach fmod_ret %s: reading the tracing link info: %s (detached)", name, abi_errno(-rc));
	}
	if (info.type != BPF_LINK_TYPE_TRACING || info.tracing.attach_type != BPF_MODIFY_RETURN) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: attach fmod_ret %s: the link is not a modify_return tracing link (type %u, attach type %u — detached)", name,
				info.type, info.tracing.attach_type);
	}
	if (info.tracing.target_btf_id != want) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: attach fmod_ret %s: the kernel attached it to BTF id %u, but the ELF declares %s (BTF id %u — detached)", name,
				info.tracing.target_btf_id, fn->p, want);
	}
	return abi_link_put(l);
}


static int64_t attach_raw_tp_body(int64_t obj, const char *prog, int64_t len)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, len, &p)))
		return e;
	const char *name = bpf_program__name(p);
	if (bpf_program__type(p) != BPF_PROG_TYPE_RAW_TRACEPOINT)
		return wrong_kind(o, p, "raw_tp");
	const struct bml_attach *a = attach_row(o, name);
	if (!a || !str_is(&a->attach_type, "raw_tp") || !str_is(&a->tkind, "rawtp") || !clean(&a->tval))
		return abi_fail(BML_OTHER, "bml: raw_tp %s: the ELF declares no tracepoint (an attach row raw_tp rawtp:<tracepoint>)", name);
	const char *tp = a->tval.p;
	struct bpf_link *l = bpf_program__attach_raw_tracepoint(p, tp);
	if (!l)
		return abi_fail(BML_OTHER, "bml: attach raw_tp %s to %s: %s", name, tp, abi_errno(errno));
	char got[256] = {0};
	struct bpf_link_info info;
	memset(&info, 0, sizeof info);
	info.raw_tracepoint.tp_name = (uint64_t)(uintptr_t)got;
	info.raw_tracepoint.tp_name_len = sizeof got;
	int rc = link_info(bpf_link__fd(l), &info);
	got[sizeof got - 1] = 0;
	if (rc == 0 && BML_MUT("attach.rawtp_name_other"))
		snprintf(got, sizeof got, "%s_other", tp);
	if (rc != 0) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: attach raw_tp %s: reading the raw tracepoint link info: %s (detached)", name, abi_errno(-rc));
	}
	if (info.type != BPF_LINK_TYPE_RAW_TRACEPOINT || strcmp(got, tp) != 0) {
		bpf_link__destroy(l);
		if (info.type != BPF_LINK_TYPE_RAW_TRACEPOINT || !got[0])
			return abi_fail(BML_OTHER, "bml: attach raw_tp %s: the link info has no tracepoint name (cannot confirm the attach target %s — detached)", name,
					tp);
		return abi_fail(BML_OTHER, "bml: attach raw_tp %s: the kernel attached it to %s, but the ELF declares %s (detached)", name, got, tp);
	}
	return abi_link_put(l);
}


static int64_t attach_iter_body(int64_t obj, const char *prog, int64_t len, int64_t map_fd)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, len, &p)))
		return e;
	const char *name = bpf_program__name(p);
	if (bpf_program__type(p) != BPF_PROG_TYPE_TRACING || bpf_program__expected_attach_type(p) != BPF_TRACE_ITER)
		return wrong_kind(o, p, "iter");
	const struct bml_attach *a = attach_row(o, name);
	if (!a || !str_is(&a->attach_type, "trace_iter") || !str_is(&a->tkind, "iter") || !clean(&a->tval))
		return abi_fail(BML_OTHER, "bml: iter %s: the ELF declares no iterator target (an attach row trace_iter iter:<target>)", name);
	if (map_fd > INT32_MAX)
		return abi_fail(BML_VALUE_RANGE, "bml: attach iter %s: map fd %lld is out of range (negative is no map)", name, (long long)map_fd);
	const char *target = a->tval.p;
	uint32_t map_id = 0;
	union bpf_iter_link_info li;
	memset(&li, 0, sizeof li);
	LIBBPF_OPTS(bpf_iter_attach_opts, io);
	if (map_fd >= 0) {
		struct bpf_map_info mi;
		uint32_t ml = sizeof mi;
		memset(&mi, 0, sizeof mi);
		if (bpf_map_get_info_by_fd((int)map_fd, &mi, &ml) != 0)
			return abi_fail(BML_OTHER, "bml: attach iter %s: map fd %lld: %s", name, (long long)map_fd, abi_errno(errno));
		map_id = mi.id;
		li.map.map_fd = (uint32_t)map_fd;
		io.link_info = &li;
		io.link_info_len = sizeof li;
	}
	struct bpf_link *l = bpf_program__attach_iter(p, &io);
	if (!l) {
		int en = errno;
		return abi_fail(BML_OTHER, "bml: attach iter %s to %s: %s%s", name, target, abi_errno(en),
				map_fd < 0 && en == EBADF ? " (hint: this iterator target needs a map — pass its fd)" : "");
	}
	char got[128] = {0};
	struct bpf_link_info info;
	memset(&info, 0, sizeof info);
	info.iter.target_name = (uint64_t)(uintptr_t)got;
	info.iter.target_name_len = sizeof got;
	int rc = link_info(bpf_link__fd(l), &info);
	got[sizeof got - 1] = 0;
	if (rc == 0 && BML_MUT("attach.iter_target_other"))
		snprintf(got, sizeof got, "%s_other", target);
	if (rc != 0) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: attach iter %s: reading the iter link info: %s (detached)", name, abi_errno(-rc));
	}
	if (info.type != BPF_LINK_TYPE_ITER || strcmp(got, target) != 0) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: attach iter %s: the kernel made an iterator for %s, but the ELF declares %s (detached)", name,
				info.type == BPF_LINK_TYPE_ITER ? got : "(not an iter link)", target);
	}
	if (map_fd >= 0 && info.iter.map.map_id != map_id) {
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: attach iter %s: the iterator walks map id %u, but the given fd is map id %u (detached)", name,
				info.iter.map.map_id, map_id);
	}
	return abi_link_put(l);
}


static int iter_create(int64_t link, int64_t *err)
{
	int lfd = abi_link_dup_fd(link, err);
	if (lfd < 0)
		return -1;
	struct bpf_link_info info;
	memset(&info, 0, sizeof info);
	int rc = link_info(lfd, &info);
	if (rc != 0 || info.type != BPF_LINK_TYPE_ITER) {
		close(lfd);
		*err = rc != 0 ? abi_fail(BML_OTHER, "bml: link %lld info: %s", (long long)link, abi_errno(-rc))
			       : abi_fail(BML_STATE, "bml: link %lld is not an iter link", (long long)link);
		return -1;
	}
	int fd = bpf_iter_create(lfd);
	int en = errno;
	close(lfd);
	if (fd < 0) {
		*err = abi_fail(BML_OTHER, "bml: link %lld: creating the iterator: %s", (long long)link, abi_errno(en));
		return -1;
	}
	return fd;
}

int64_t bml_iter_open(int64_t link)
{
	int64_t e;
	int fd = iter_create(link, &e);
	return fd < 0 ? e : abi_ok(fd);
}

int64_t bml_iter_read(int64_t link, uint8_t *buf, int64_t cap)
{
	if (cap < 0 || (cap > 0 && !buf))
		return abi_fail(BML_VALUE_RANGE, "bml: iter_read: the buffer capacity %lld is out of range", (long long)cap);
	int64_t e;
	int fd = iter_create(link, &e);
	if (fd < 0)
		return e;
	int64_t n = 0;
	for (;;) {
		uint8_t extra;
		uint8_t *dst = n < cap ? buf + n : &extra;
		size_t want = n < cap ? (size_t)(cap - n) : 1;
		ssize_t r = read(fd, dst, want);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0) {
			int en = errno;
			close(fd);
			return abi_fail(BML_OTHER, "bml: link %lld: reading the iterator: %s", (long long)link, abi_errno(en));
		}
		if (r == 0)
			break;
		if (n >= cap) {
			close(fd);
			if (BML_MUT("attach.iter_read_truncate"))
				return abi_ok(n);
			return abi_fail(BML_VALUE_RANGE, "bml: link %lld: the iterator output does not fit in %lld bytes (nothing is truncated — read it with "
							 "iter_open or give a larger buffer)",
					(long long)link, (long long)cap);
		}
		n += r;
	}
	close(fd);
	return abi_ok(n);
}

int64_t bml_attach_fmod_ret(int64_t obj, const char *prog, int64_t prog_len)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_fmod_ret_body(obj, prog, prog_len);
	abi_object_release(o);
	return e;
}

int64_t bml_attach_raw_tp(int64_t obj, const char *prog, int64_t prog_len)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_raw_tp_body(obj, prog, prog_len);
	abi_object_release(o);
	return e;
}

int64_t bml_attach_iter(int64_t obj, const char *prog, int64_t prog_len, int64_t map_fd)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_iter_body(obj, prog, prog_len, map_fd);
	abi_object_release(o);
	return e;
}
