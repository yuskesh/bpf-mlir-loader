#define _GNU_SOURCE
#include "caps/live_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util/gostr.h"
#include "util/mutation.h"

#define UNK ": cannot be determined on this target"

static const uint8_t ret_zero[16] = {0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0};


__attribute__((noinline, used)) void bml_live_uprobe_multi_probe_target(void)
{
	__asm__ volatile("" ::: "memory");
}

static int load_kprobe(struct bml_live *l, uint32_t at, struct lv_res *r)
{
	struct lv_prog p = {0};
	p.type = BPF_PROG_TYPE_KPROBE;
	p.attach_type = at;
	p.insns = ret_zero;
	p.n_insns = 2;
	p.license = "GPL";
	p.name = "ebpf_probe";
	p.log_mode = LV_LOG_0;
	return lv_prog_load(l, &p, r);
}

static int link_kprobe_multi(int pfd, uint32_t at, const char *sym)
{
	union bpf_attr a;
	const char *syms[1] = {sym};
	memset(&a, 0, sizeof a);
	a.link_create.prog_fd = (uint32_t)pfd;
	a.link_create.attach_type = at;
	a.link_create.kprobe_multi.cnt = 1;
	a.link_create.kprobe_multi.syms = (uint64_t)(uintptr_t)syms;
	return lv_bpf(BPF_LINK_CREATE, &a, sizeof a);
}

static int link_uprobe_multi(int pfd, const char *path, uint64_t off, uint32_t pid)
{
	union bpf_attr a;
	uint64_t offs[1] = {off};
	memset(&a, 0, sizeof a);
	a.link_create.prog_fd = (uint32_t)pfd;
	a.link_create.attach_type = BPF_TRACE_UPROBE_MULTI;
	a.link_create.uprobe_multi.path = (uint64_t)(uintptr_t)path;
	a.link_create.uprobe_multi.offsets = (uint64_t)(uintptr_t)offs;
	a.link_create.uprobe_multi.cnt = 1;
	a.link_create.uprobe_multi.pid = pid;
	return lv_bpf(BPF_LINK_CREATE, &a, sizeof a);
}


static int have_link(struct bml_live *l, uint32_t at, char **txt)
{
	struct lv_res r;
	*txt = NULL;
	if (load_kprobe(l, at, &r) != 0) {
		int e = r.err;
		*txt = lv_res_text(&r);
		lv_res_free(&r);
		return e == E2BIG ? 1 : -(e ? e : EINVAL);
	}
	int pfd = r.fd, lfd;
	if (at == BPF_TRACE_UPROBE_MULTI) {
		lfd = link_uprobe_multi(pfd, "/", 0, 0);
		lv_close(pfd);
		if (lfd == -EBADF)
			return 0;
		if (lfd == -EINVAL)
			return 1;
		if (lfd >= 0) {
			lv_close(lfd);
			*txt = strdup("successfully attached uprobe_multi to /, kernel bug?");
			return -EINVAL;
		}
	} else {
		lfd = link_kprobe_multi(pfd, at, "vprintk");
		lv_close(pfd);
		if (lfd >= 0) {
			lv_close(lfd);
			return 0;
		}
		if (lfd == -EINVAL || lfd == -EOPNOTSUPP)
			return 1;
	}
	*txt = bml_go_errno_str(-lfd);
	return lfd;
}


static int self_offset(uint64_t pc, uint64_t *off, char **err)
{
	char exe[4096];
	ssize_t k = readlink("/proc/self/exe", exe, sizeof exe - 1);
	if (k < 0) {
		*err = strdup("readlink /proc/self/exe failed");
		return -1;
	}
	exe[k] = 0;
	FILE *f = fopen("/proc/self/maps", "re");
	if (!f) {
		*err = strdup("open /proc/self/maps failed");
		return -1;
	}
	char line[8192];
	int rc = -1;
	while (fgets(line, sizeof line, f)) {
		unsigned long long s, e, o;
		char perms[8];
		int pos = 0;
		if (sscanf(line, "%llx-%llx %7s %llx %*s %*s%n", &s, &e, perms, &o, &pos) < 4 || !strchr(perms, 'x'))
			continue;
		if (pc < s || pc >= e)
			continue;
		char *path = line + pos;
		while (*path == ' ')
			path++;
		path[strcspn(path, "\n")] = 0;
		if (strcmp(path, exe) != 0) {
			if (asprintf(err, "the probe function at %#llx is mapped from \"%s\", not the executable \"%s\"", (unsigned long long)pc, path, exe) < 0)
				*err = NULL;
		} else {
			*off = pc - s + o;
			rc = 0;
		}
		fclose(f);
		return rc;
	}
	fclose(f);
	if (asprintf(err, "the probe function at %#llx is in no executable mapping of /proc/self/maps", (unsigned long long)pc) < 0)
		*err = NULL;
	return -1;
}

int lv_multi_link_probe(struct bml_live *l, const char *pt_name, const char *at_name, uint32_t at, int *val, char **why)
{
	*val = 0;
	struct lv_res r;
	if (load_kprobe(l, at, &r) != 0) {
		lv_res_free(&r);
		return -2;
	}
	int pfd = r.fd, lfd, rc = BML_Q_OK;
	char where[160], *txt = NULL;
	if (at == BPF_TRACE_UPROBE_MULTI) {
		uint64_t off = 0;
		char *oerr = NULL;
		if (self_offset((uint64_t)(uintptr_t)&bml_live_uprobe_multi_probe_target, &off, &oerr) != 0) {
			snprintf(where, sizeof where, "a uprobe.multi link on the probe function of /proc/self/exe");
			txt = oerr ? oerr : strdup("");
			lfd = -EINVAL;
			goto unknown;
		}
		snprintf(where, sizeof where, "a uprobe.multi link on /proc/self/exe at offset %#llx", (unsigned long long)off);
		lfd = BML_MUT("live.multi_link_eopnotsupp") ? -EOPNOTSUPP : link_uprobe_multi(pfd, "/proc/self/exe", off, (uint32_t)getpid());
		if (lfd >= 0)
			goto ok;
		if (lfd == -ESRCH) {
			txt = strdup("file does not exist (specified pid not found?)");
			goto unknown;
		}
		if (lfd == -EINVAL) {
			txt = strdup("invalid argument (invalid pid, missing symbol or prog's AttachType not AttachTraceUprobeMulti?)");
			goto unknown;
		}
	} else {
		int sess = at != BPF_TRACE_KPROBE_MULTI;
		snprintf(where, sizeof where, "a %s link on bpf_fentry_test1", sess ? "kprobe.session" : "kprobe.multi");
		lfd = BML_MUT("live.multi_link_eopnotsupp") ? -EOPNOTSUPP : link_kprobe_multi(pfd, at, "bpf_fentry_test1");
		if (lfd >= 0)
			goto ok;
		if (lfd == -ESRCH) {
			txt = strdup("couldn't find one or more symbols: file does not exist");
			goto unknown;
		}
	}

	char *ft = NULL;
	int h = BML_MUT("live.multi_link_eopnotsupp") ? 1 : have_link(l, at, &ft);
	if (h == 1) {
		free(ft);
		goto out;
	}
	if (h < 0) {
		txt = ft;
		goto unknown;
	}
	free(ft);
	if (lfd == -EINVAL && at != BPF_TRACE_UPROBE_MULTI) {
		char *es = bml_go_errno_str(EINVAL);
		if (asprintf(&txt, "%s (missing kernel symbol or prog's AttachType not %s?)", es ? es : "", at_name) < 0)
			txt = NULL;
		free(es);
		goto unknown;
	}
	if (lfd == -EOPNOTSUPP)
		goto out;
	txt = bml_go_errno_str(-lfd);
unknown:
	if (asprintf(why, "%s with expected attach type %s loads, but creating %s for the link probe failed (%s)" UNK, pt_name, at_name, where,
		     txt ? txt : "") < 0)
		*why = NULL;
	free(txt);
	rc = BML_Q_UNKNOWN;
	goto out;
ok:
	lv_close(lfd);
	*val = 1;
out:
	lv_close(pfd);
	return rc;
}
