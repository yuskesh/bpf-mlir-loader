




#define _GNU_SOURCE
#include "abi/internal.h"

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "util/gostr.h"
#include "util/mutation.h"


static char *name_of(const char *s, int64_t n)
{
	if (n < 0 || (!s && n))
		return NULL;
	return strndup(s ? s : "", (size_t)n);
}

int64_t abi_program(struct abi_object *o, const char *prog, int64_t len, struct bpf_program **p)
{
	char *nm = name_of(prog, len);
	if (!nm)
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL string with a length");
	*p = strlen(nm) == (size_t)len ? bpf_object__find_program_by_name(bml_obj_bpf(o->lo), nm) : NULL;
	int64_t e = 0;
	if (!*p) {
		struct bml_buf b = {0};
		bml_buf_adds(&b, "bml: the embedded ELF has no program ");
		bml_buf_add_goquote(&b, prog ? prog : "", (size_t)len);
		struct abi_result r = {.kind = BML_STATE, .msg_len = b.len};
		r.msg = bml_buf_take(&b);
		e = abi_put(&r);
	}
	free(nm);
	return e;
}

static int64_t want_xdp(struct bpf_program *p, const char *what)
{
	if (bpf_program__type(p) == BPF_PROG_TYPE_XDP)
		return 0;
	return abi_fail(BML_STATE, "bml: %s is a %s program, not xdp — %s it with its own kind", bpf_program__name(p),
			libbpf_bpf_prog_type_str(bpf_program__type(p)) ? libbpf_bpf_prog_type_str(bpf_program__type(p)) : "?", what);
}

static int64_t attach_xdp_body(int64_t obj, const char *prog, int64_t prog_len, const char *ifname, int64_t if_len)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, prog_len, &p)) || (e = want_xdp(p, "attach")))
		return e;
	char *ifn = name_of(ifname, if_len);
	if (!ifn)
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL string with a length");
	unsigned idx = strlen(ifn) == (size_t)if_len ? if_nametoindex(ifn) : 0;
	if (!idx) {
		e = abi_fail(BML_OTHER, "bml: interface %s: %s", ifn, abi_errno(errno ? errno : ENODEV));
		free(ifn);
		return e;
	}
	struct bpf_link *l = bpf_program__attach_xdp(p, (int)idx);
	if (!l) {
		e = abi_fail(BML_OTHER, "bml: attach %s to %s: %s", bpf_program__name(p), ifn, abi_errno(errno));
		free(ifn);
		return e;
	}
	free(ifn);
	return abi_link_put(l);
}

int64_t abi_link_put(struct bpf_link *l)
{
	return abi_link_put_uprobe(l, 0, NULL);
}

static void close_fds(int *fds, size_t n)
{
	for (size_t i = 0; i < n; i++)
		close(fds[i]);
	free(fds);
}

static int64_t link_put(struct bpf_link *l, int64_t owner, char *file, int *fds, size_t n)
{
	struct abi_link *al = calloc(1, sizeof *al);
	int64_t id = -1;
	if (al) {
		al->l = l;
		al->uprobe_owner = owner;
		al->uprobe_file = file;
		al->extra_fds = fds;
		al->n_extra = n;
		abi_lock();
		id = abi_handle_new(H_LINK, al, 0);
		abi_unlock();
	}
	if (id < 0) {
		free(al);
		free(file);
		close_fds(fds, n);
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: out of memory");
	}
	return abi_ok(id);
}

int64_t abi_link_put_uprobe(struct bpf_link *l, int64_t owner, char *file)
{
	return link_put(l, owner, file, NULL, 0);
}

int64_t abi_link_put_extra(struct bpf_link *l, int *fds, size_t n)
{
	return link_put(l, 0, NULL, fds, n);
}

int64_t abi_link_put_more(struct bpf_link *l, struct bpf_link **more, size_t n)
{
	struct bpf_link **m = n ? malloc(n * sizeof *m) : NULL;
	if (n && !m) {
		for (size_t i = 0; i < n; i++)
			bpf_link__destroy(more[i]);
		bpf_link__destroy(l);
		return abi_fail(BML_OTHER, "bml: out of memory");
	}
	if (n)
		memcpy(m, more, n * sizeof *m);
	int64_t r = link_put(l, 0, NULL, NULL, 0);
	if (bml_result_kind(r) != BML_OK) {
		for (size_t i = 0; i < n; i++)
			bpf_link__destroy(m[i]);
		free(m);
		return r;
	}
	int64_t id = bml_result_value(r);
	abi_lock();
	struct abi_link *al = abi_handle_get(id, H_LINK);
	al->more = m;
	al->n_more = n;
	abi_unlock();
	return r;
}

int abi_link_dup_fd(int64_t link, int64_t *err)
{
	abi_lock();
	struct abi_link *al = abi_handle_get(link, H_LINK);
	/* CONTRACT: dup under the lock (detach removes l under the lock before destroying it, so the dup'd fd can safely read info after a detach) */
	int live = al && al->l;
	int fd = live ? fcntl(bpf_link__fd(al->l), F_DUPFD_CLOEXEC, 3) : -1;
	int e = errno;
	abi_unlock();
	if (!al)
		*err = abi_fail(BML_STATE, "bml: no link %lld", (long long)link);
	else if (!live)
		*err = abi_fail(BML_STATE, "bml: the link %lld is detached", (long long)link);
	else if (fd < 0)
		*err = abi_fail(BML_OTHER, "bml: link %lld: %s", (long long)link, abi_errno(e));
	return fd;
}

int64_t bml_detach(int64_t link)
{

	abi_lock();
	struct abi_link *al = abi_handle_get(link, H_LINK);
	struct bpf_link *l = al ? al->l : NULL;
	int *fds = al ? al->extra_fds : NULL;
	size_t n = al ? al->n_extra : 0;
	struct bpf_link **more = al ? al->more : NULL;
	size_t n_more = al ? al->n_more : 0;
	if (al) {
		al->l = NULL;
		al->extra_fds = NULL;
		al->n_extra = 0;
		al->more = NULL;
		al->n_more = 0;
	}
	abi_unlock();
	if (!al)
		return abi_fail(BML_STATE, "bml: no link %lld", (long long)link);
	if (!l)
		return abi_ok(0);

	for (size_t i = 0; i < n_more && !BML_MUT("usdt.keep_more"); i++)
		bpf_link__destroy(more[i]);
	free(more);

	if (BML_MUT("attach.tp_keep_extra"))
		free(fds);
	else
		close_fds(fds, n);
	if (bpf_link__destroy(l) != 0)
		return abi_fail(BML_OTHER, "bml: detach: %s", abi_errno(errno));
	return abi_ok(0);
}


static int run_once(int fd, const uint8_t *data, size_t n, uint32_t *ret)
{
	LIBBPF_OPTS(bpf_test_run_opts, t, .data_in = data, .data_size_in = (uint32_t)n, .repeat = 1);
	if (bpf_prog_test_run_opts(fd, &t) != 0)
		return -errno;
	*ret = t.retval;
	return 0;
}

static int64_t test_run_xdp_body(int64_t obj, const char *prog, int64_t prog_len, int64_t repeat)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, prog_len, &p)) || (e = want_xdp(p, "test-run")))
		return e;

	if (repeat < 1)
		return abi_fail(BML_VALUE_RANGE, "bml: test run %s: the run count %lld is below 1", bpf_program__name(p), (long long)repeat);
	static const uint8_t frame[64];
	uint32_t ret = 0;
	for (int64_t i = 0; i < repeat; i++) {
		int rc = run_once(bpf_program__fd(p), frame, sizeof frame, &ret);
		if (i == 2 && BML_MUT("run.fake_eintr_at_3"))
			rc = -EINTR;
		if (rc == -EINTR) {
			struct abi_result r = {.kind = BML_OTHER, .value = i};
			if (asprintf(&r.msg, "bml: test run %s was interrupted by a signal at run %lld of %lld — %lld runs completed (not retried)",
				     bpf_program__name(p), (long long)(i + 1), (long long)repeat, (long long)i) >= 0)
				r.msg_len = strlen(r.msg);
			else
				r.msg = NULL;
			return abi_put(&r);
		}
		if (rc)
			return abi_fail(BML_OTHER, "bml: test run %s (run %lld of %lld): %s", bpf_program__name(p), (long long)(i + 1),
					(long long)repeat, abi_errno(-rc));
	}
	return abi_ok((int64_t)ret);
}

static int64_t test_run_xdp_data_body(int64_t obj, const char *prog, int64_t prog_len, const uint8_t *data, int64_t n)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	struct bpf_program *p;
	if (!o || (e = abi_program(o, prog, prog_len, &p)) || (e = want_xdp(p, "test-run")))
		return e;
	if (n < 0 || n > UINT32_MAX || (!data && n))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL buffer with a length");
	uint32_t ret = 0;
	int rc = run_once(bpf_program__fd(p), data, (size_t)n, &ret);
	if (rc)
		return abi_fail(BML_OTHER, "bml: test run %s with %lld bytes: %s", bpf_program__name(p), (long long)n, abi_errno(-rc));
	return abi_ok((int64_t)ret);
}

/* CONTRACT: public entry points count as running calls
 * (abi_object_acquire; close is STATE unless the count is 0). The body looks up the object with the uncounted abi_object_get */
int64_t bml_attach_xdp(int64_t obj, const char *prog, int64_t prog_len, const char *ifname, int64_t if_len)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = attach_xdp_body(obj, prog, prog_len, ifname, if_len);
	abi_object_release(o);
	return e;
}

int64_t bml_test_run_xdp(int64_t obj, const char *prog, int64_t prog_len, int64_t repeat)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = test_run_xdp_body(obj, prog, prog_len, repeat);
	abi_object_release(o);
	return e;
}

int64_t bml_test_run_xdp_data(int64_t obj, const char *prog, int64_t prog_len, const uint8_t *data, int64_t n)
{
	int64_t e;
	struct abi_object *o = abi_object_acquire(obj, &e);
	if (!o)
		return e;
	e = test_run_xdp_data_body(obj, prog, prog_len, data, n);
	abi_object_release(o);
	return e;
}
