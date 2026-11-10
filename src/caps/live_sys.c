


#define _GNU_SOURCE
#include "util/mutation.h"
#include "caps/live_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int lv_bpf(int cmd, void *attr, unsigned size)
{
	long r;
	do
		r = syscall(__NR_bpf, cmd, attr, size);
	while (r < 0 && errno == EAGAIN && cmd == BPF_PROG_LOAD);
	if (r < 0)
		return -errno;

	if (r == 0 && (cmd == BPF_MAP_CREATE || cmd == BPF_PROG_LOAD || cmd == BPF_BTF_LOAD || cmd == BPF_BTF_GET_FD_BY_ID)) {
		int d = fcntl(0, F_DUPFD_CLOEXEC, 1);
		int e = errno;
		close(0);
		if (d < 0)
			return -e;
		return d;
	}
	return (int)r;
}

void lv_close(int fd)
{
	if (fd >= 0)
		close(fd);
}

void lv_res_free(struct lv_res *r)
{
	for (size_t i = 0; i < r->n_lines; i++)
		free(r->lines[i]);
	free(r->lines);
	r->lines = NULL;
	r->n_lines = 0;
	free(r->text);
	r->text = NULL;
}

static int is_ws(char c)
{
	return c == '\t' || c == '\r' || c == '\v' || c == '\n' || c == ' ';
}

void lv_log_lines(const char *buf, size_t size, char ***lines, size_t *n)
{
	*lines = NULL;
	*n = 0;
	if (!buf)
		return;
	const char *nul = memchr(buf, 0, size);
	size_t len = nul ? (size_t)(nul - buf) : size;
	size_t s = 0, e = len;
	while (s < e && is_ws(buf[s]))
		s++;
	while (e > s && is_ws(buf[e - 1]))
		e--;
	if (s == e)
		return;
	size_t cnt = 1;
	for (size_t i = s; i < e; i++)
		cnt += buf[i] == '\n';
	char **v = calloc(cnt, sizeof *v);
	if (!v)
		return;
	size_t k = 0;
	for (size_t i = s; k < cnt;) {
		size_t j = i;
		while (j < e && buf[j] != '\n')
			j++;
		size_t le = j;
		while (le > i && is_ws(buf[le - 1]))
			le--;
		v[k] = strndup(buf + i, le - i);
		if (!v[k]) {
			for (size_t x = 0; x < k; x++)
				free(v[x]);
			free(v);
			return;
		}
		k++;
		i = j + 1;
	}
	*lines = v;
	*n = cnt;
}

struct lv_memo *lv_memo_get(struct bml_live *l, const char *key)
{
	for (size_t i = 0; i < l->n_memo; i++)
		if (strcmp(l->memo[i].key, key) == 0)
			return &l->memo[i];
	return NULL;
}

int lv_memo_put(struct bml_live *l, const char *key, int rc, int value)
{
	struct lv_memo *m = realloc(l->memo, (l->n_memo + 1) * sizeof *m);
	if (!m)
		return -1;
	l->memo = m;
	m[l->n_memo].key = strdup(key);
	if (!m[l->n_memo].key)
		return -1;
	m[l->n_memo].rc = rc;
	m[l->n_memo].value = value;
	m[l->n_memo].msg = NULL;
	l->n_memo++;
	return 0;
}

enum { MIN_LOG = 64 * 1024, MAX_LOG = 0xffffffffu >> 2 };

static void put32(uint8_t *a, size_t off, uint32_t v)
{
	memcpy(a + off, &v, 4);
}

static void put64(uint8_t *a, size_t off, uint64_t v)
{
	memcpy(a + off, &v, 8);
}

static uint32_t get32(const uint8_t *a, size_t off)
{
	uint32_t v;
	memcpy(&v, a + off, 4);
	return v;
}

static int btf_handle(struct bml_live *l, const uint8_t *btf, size_t len, struct lv_res *r, int reason)
{
	uint8_t attr[40];
	char *log = NULL;
	uint32_t log_size = 0;
	int ret;
	memset(r, 0, sizeof *r);
	r->fd = -1;
	memset(attr, 0, sizeof attr);
	put64(attr, 0, (uint64_t)(uintptr_t)btf);
	put32(attr, 16, (uint32_t)len);
	for (;;) {
		ret = lv_bpf(BPF_BTF_LOAD, attr, sizeof attr);
		if (ret >= 0) {
			free(log);
			r->fd = ret;
			return ret;
		}
		uint32_t true_size = get32(attr, 28);
		if (true_size != 0 && get32(attr, 20) >= true_size)
			break;
		if (get32(attr, 20) != 0 && ret != -ENOSPC)
			break;
		uint32_t ns = log_size * 2 > MIN_LOG ? log_size * 2 : MIN_LOG;
		if (true_size != 0)
			ns = true_size;
		free(log);
		log = calloc(1, ns);
		if (!log) {
			r->err = ENOMEM;
			return -1;
		}
		log_size = ns;
		put64(attr, 8, (uint64_t)(uintptr_t)log);
		put32(attr, 20, ns);
		put32(attr, 24, 1);
	}

	int hb = lv_feat(l, LVF_BTF);
	if (hb == LV_NOTSUP) {
		free(log);
		r->notsup = 1;
		if(reason)r->text=strdup("BTF not supported (requires >= v4.18)");
		return -1;
	}
	if (hb != LV_OK) {
		free(log);
		r->err = hb < -1 ? -hb : 0;
		if(reason)lv_btf_reason(r,0,NULL,0);
		return -1;
	}
	r->err = -ret;
	if(reason)lv_btf_reason(r,1,log,log_size);
	free(log);
	return -1;
}

int lv_btf_handle(struct bml_live *l,const uint8_t *btf,size_t len,struct lv_res *r)
{ return btf_handle(l,btf,len,r,0); }
int lv_btf_handle_reason(struct bml_live *l,const uint8_t *btf,size_t len,struct lv_res *r)
{ return btf_handle(l,btf,len,r,1); }



static int walk_modules(struct lv_res *r)
{
	uint32_t id = 0;
	for (;;) {
		uint8_t a[8] = {0};
		put32(a, 0, id);
		int rc = lv_bpf(BPF_BTF_GET_NEXT_ID, a, sizeof a);
		if (rc == -ENOENT) {
			r->notsup = 1;
			return -1;
		}
		if (rc < 0) {
			r->err = -rc;
			r->notsup = rc == -EPERM;
			return -1;
		}
		id = get32(a, 4);
		uint8_t g[4];
		put32(g, 0, id);
		int fd = lv_bpf(BPF_BTF_GET_FD_BY_ID, g, sizeof g);
		if (fd == -ENOENT)
			continue;
		if (fd < 0) {
			r->err = -fd;
			r->notsup = fd == -EPERM;
			return -1;
		}
		char name[64] = {0};
		uint8_t info[32] = {0}, ia[16] = {0};
		put64(info, 16, (uint64_t)(uintptr_t)name);
		put32(info, 24, sizeof name);
		put32(ia, 0, (uint32_t)fd);
		put32(ia, 4, sizeof info);
		put64(ia, 8, (uint64_t)(uintptr_t)info);
		rc = lv_bpf(BPF_OBJ_GET_INFO_BY_FD, ia, sizeof ia);
		lv_close(fd);
		if (rc < 0) {
			r->err = -rc;
			r->notsup = rc == -EPERM;
			return -1;
		}
		if (get32(info, 28) != 0 && strcmp(name, "vmlinux") != 0) {
			r->err = 0;
			return -1;
		}
	}
}





static int raw_load_pair(const struct lv_prog *p)
{
	return (p->type == BPF_PROG_TYPE_LSM && p->attach_type == BPF_LSM_CGROUP) ||
	       (p->type == BPF_PROG_TYPE_TRACING && p->attach_type == BPF_TRACE_FSESSION);
}

static char *target_text(const struct lv_prog *p)
{
	static const struct {
		uint32_t pt, at;
		const char *pair, *strip, *pre, *suf;
	} t[] = {
		{BPF_PROG_TYPE_LSM, BPF_LSM_MAC, "LSM/LSMMac", "bpf_lsm_", "", " LSM hook"},
		{BPF_PROG_TYPE_TRACING, BPF_TRACE_ITER, "Tracing/TraceIter", "bpf_iter_", "", " iterator"},
		{BPF_PROG_TYPE_TRACING, BPF_TRACE_FENTRY, "Tracing/TraceFEntry", "", "fentry ", ""},
		{BPF_PROG_TYPE_TRACING, BPF_TRACE_FEXIT, "Tracing/TraceFExit", "", "fexit ", ""},
		{BPF_PROG_TYPE_TRACING, BPF_MODIFY_RETURN, "Tracing/ModifyReturn", "", "fmod_ret ", ""},
		{BPF_PROG_TYPE_TRACING, BPF_TRACE_RAW_TP, "Tracing/TraceRawTp", "btf_trace_", "raw_tp ", ""},
	};
	struct bml_buf b = {0};
	if (raw_load_pair(p)) {
		bml_buf_addf(&b, "attach target %s: not found", p->attach_to);
		return bml_buf_take(&b);
	}
	for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
		if (t[i].pt != p->type || t[i].at != p->attach_type)
			continue;
		size_t sl = strlen(t[i].strip);
		const char *name = strncmp(p->attach_to, t[i].strip, sl) == 0 ? p->attach_to + sl : p->attach_to;
		bml_buf_addf(&b, "attach %s: %s%s%s not supported", t[i].pair, t[i].pre, name, t[i].suf);
		return bml_buf_take(&b);
	}
	return NULL;
}

static int resolve(struct bml_live *l, const struct lv_prog *p, uint32_t *btf_id, struct lv_res *r)
{
	const struct bml_kbtf *kb;
	int rc = lv_vmlinux(l, &kb);
	if (rc == -1 || rc == -2) {
		r->notsup = 1;
		r->text = BML_MUT("live.attach_target_errno") || raw_load_pair(p) ? NULL : target_text(p);
		return -1;
	}
	if (rc != 0)
		return -1;
	char *err = NULL;
	rc = bml_kbtf_by_name(kb, p->attach_to, p->attach_kind, btf_id, &err);
	free(err);
	if (rc == 0)
		return 0;
	if (rc == 2)
		return -1;
	if (raw_load_pair(p) && !BML_MUT("live.attach_target_errno")) {
		r->text = target_text(p);
		return -1;
	}
	rc = walk_modules(r);
	if (r->notsup && !BML_MUT("live.attach_target_errno"))
		r->text = target_text(p);
	return rc;
}


static uint8_t *fix_insns(struct bml_live *l, const struct lv_prog *p)
{
	uint8_t *ins = malloc(p->n_insns * 8 + 1);
	if (!ins)
		return NULL;
	memcpy(ins, p->insns, p->n_insns * 8);
	int checked = 0, rewrite = 0;
	for (size_t i = 0; i < p->n_insns; i++) {
		uint8_t *x = ins + 8 * i;
		if (x[0] != 0x85 || x[1] != 0)
			continue;
		if (!checked) {
			checked = 1;
			rewrite = lv_feat(l, LVF_PROBE_READ_KERNEL) != LV_OK && !BML_MUT("live.no_probe_read_rewrite");
		}
		int32_t imm = (int32_t)get32(x, 4);
		if (rewrite && (imm == 112 || imm == 113))
			put32(x, 4, 4);
		else if (rewrite && (imm == 114 || imm == 115))
			put32(x, 4, 45);
	}
	return ins;
}

static int contains(const char *hay, size_t n, const char *needle)
{
	return memmem(hay, n, needle, strlen(needle)) != NULL;
}

int lv_prog_load(struct bml_live *l, const struct lv_prog *p, struct lv_res *r)
{
	uint8_t attr[168];
	uint8_t *ins = NULL;
	char *log = NULL;
	int btf_fd = -1, ret = -1;
	memset(r, 0, sizeof *r);
	r->fd = -1;
	memset(attr, 0, sizeof attr);
	uint32_t kver = 0;
	if (p->type == BPF_PROG_TYPE_KPROBE && lv_kernel_version(l, &kver) != 0)
		return -1;
	char name[16];
	lv_obj_name(l, p->name ? p->name : "", name);
	int ext = lv_feat(l, LVF_EXT_INFOS) == LV_OK;
	if (ext) {
		put32(attr, 76, 8);
		put32(attr, 92, 16);
		if (p->func_info_cnt) {
			put64(attr, 80, (uint64_t)(uintptr_t)p->func_info);
			put32(attr, 88, p->func_info_cnt);
		}
		if (p->btf) {
			struct lv_kmo o;
			lv_kmo(l, &o);
			uint8_t *b = o.strip_func_linkage ? lv_strip_func_linkage(p->btf, p->btf_len) : NULL;
			if (o.strip_func_linkage && !b) {
				r->err = ENOMEM;
				return -1;
			}
			struct lv_res br;
			btf_fd = lv_btf_handle(l, b ? b : p->btf, p->btf_len, &br);
			free(b);
			if (btf_fd < 0) {
				r->err = br.err;
				r->notsup = br.notsup;
				return -1;
			}
			put32(attr, 72, (uint32_t)btf_fd);
		}
	}
	ins = fix_insns(l, p);
	if (!ins) {
		r->err = ENOMEM;
		goto out;
	}
	uint32_t btf_id = p->attach_btf_id, obj_fd = p->attach_prog_fd;
	if (p->attach_to && resolve(l, p, &btf_id, r) != 0)
		goto out;
	put32(attr, 0, p->type);
	put32(attr, 4, (uint32_t)p->n_insns);
	put64(attr, 8, (uint64_t)(uintptr_t)ins);
	put64(attr, 16, (uint64_t)(uintptr_t)p->license);
	put32(attr, 40, kver);
	put32(attr, 44, p->flags);
	memcpy(attr + 48, name, 16);
	put32(attr, 68, p->attach_type);
	put32(attr, 108, btf_id);
	put32(attr, 112, obj_fd);
	uint32_t log_size = 0, log_level = 0;
	if (p->log_mode == LV_LOG_1) {
		log_level = 1;
		log_size = MIN_LOG;
	}
	for (int attempts = 1;; attempts++) {
		if (log_level) {
			free(log);
			log = calloc(1, log_size);
			if (!log) {
				r->err = ENOMEM;
				goto out;
			}
			put64(attr, 32, (uint64_t)(uintptr_t)log);
		}
		put32(attr, 24, log_level);
		put32(attr, 28, log_size);
		ret = lv_bpf(BPF_PROG_LOAD, attr, sizeof attr);
		if (ret >= 0) {
			r->fd = ret;
			goto out;
		}
		if (p->log_mode == LV_LOG_DISABLED)
			break;

		if (log_size == MAX_LOG)
			break;
		if (ret == -ENOSPC) {
			uint32_t ts = get32(attr, 140);
			if (ts != 0)
				log_size = ts;
			else if (log_size >= MAX_LOG / 2)
				log_size = MAX_LOG;
			else
				log_size = (log_size < MIN_LOG ? MIN_LOG : log_size) * 2;
		} else if (log_level == 0) {
			log_level = 1;
			log_size = MIN_LOG;
		} else
			break;
		if (attempts >= 30) {
			r->err = -ret;
			r->suffix = " (bug: hit 30 verifier attempts)";
			goto out;
		}
	}

	r->err = -ret;
	size_t end = 0;
	if (log) {
		const char *nul = memchr(log, 0, log_size);
		end = nul ? (size_t)(nul - log) : log_size;
	}
	const char *tail = log ? log + (end > 256 ? end - 256 : 0) : "";
	size_t tn = log ? (end > 256 ? 256 : end) : 0;
	if (r->err == EPERM && log && log_size > 0 && log[0] == 0) {
		r->suffix = " (MEMLOCK may be too low, consider rlimit.RemoveMemlock)";
		goto out;
	}
	if (r->err == EFAULT) {
		r->suffix = " (hit verifier bug, increase LogSizeStart to fit the log and check dmesg)";
		goto out;
	}
	if (r->err == EINVAL && contains(tail, tn, "invalid func unknown#195896080\n")) {
		r->err = 0;
		r->cause = 1;
	} else if (r->err == EINVAL && contains(tail, tn, "invalid func unknown#233685214\n")) {
		r->err = 0;
		r->cause = 2;
	} else if (r->err == EACCES && contains(tail, tn, "(18) r10 = 0xbad2310\n")) {
		r->err = 0;
		r->cause = 1;
	}
	if ((r->err == EINVAL || r->err == EPERM) && p->bpf2bpf) {
		int b = lv_feat(l, LVF_BPF2BPF);
		if (b != LV_OK) {
			r->notsup = b == LV_NOTSUP;
			r->err = 0;
			goto out;
		}
	}
	r->verifier = 1;
	lv_log_lines(log, log_size, &r->lines, &r->n_lines);
out:
	free(log);
	free(ins);
	lv_close(btf_fd);
	return r->fd >= 0 ? 0 : -1;
}
