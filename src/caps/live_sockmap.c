/* caps/live_sockmap.c — the sockmap link probe for the attach_types of sk_skb and sk_msg. It is a C port of sockmapLinkProbe in
 * kernel/internal/kload/attachctx.go, and live_attach.c calls it. It loads `r0 = 0; exit` with the expected attach type and, if that is
 * accepted, creates a small empty sockmap, attaches with BPF_LINK_CREATE (cilium's link.AttachRawLink, a raw link without fallback) and
 * **closes it at once** (the map is empty, so it affects no socket). If the link can be created the answer is true; EINVAL (before
 * 6.10 link_create has no SK_SKB / SK_MSG) is false; anything else is Unknown. PROG_ATTACH is not used. */
#define _GNU_SOURCE
#include "caps/live_internal.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"
#include "util/mutation.h"

#define UNK ": cannot be determined on this target" /* the ErrUnknown sentence (the %w of unknownf) */

static const uint8_t ret_zero[16] = {0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0};

int lv_sockmap_link_probe(struct bml_live *l, const char *pt_name, uint32_t pt, const char *at_name, uint32_t at, int *val, char **why)
{
	*val = 0;
	struct lv_prog p = {0};
	struct lv_res r;
	p.type = pt;
	p.attach_type = at;
	p.insns = ret_zero;
	p.n_insns = 2;
	p.license = "GPL";
	p.name = "ebpf_probe";
	p.log_mode = LV_LOG_0;
	if (lv_prog_load(l, &p, &r) != 0) {
		lv_res_free(&r);
		return -2; /* a rejected load is left to the caller's paired load */
	}
	int pfd = r.fd;
	/* cilium's NewMap (SockMap: key size 4, value size 4, one entry, name ebpf_probe) */
	union bpf_attr a;
	memset(&a, 0, sizeof a);
	a.map_type = BPF_MAP_TYPE_SOCKMAP;
	a.key_size = 4;
	a.value_size = 4;
	a.max_entries = 1;
	char nm[16];
	lv_obj_name(l, "ebpf_probe", nm);
	memcpy(a.map_name, nm, sizeof a.map_name);
	int mfd = lv_bpf(BPF_MAP_CREATE, &a, sizeof a);
	if (mfd < 0) {
		char *es = bml_go_errno_str(-mfd);
		if (asprintf(why, "%s with expected attach type %s loads, but creating a sockmap for the link probe failed (map create: %s%s)" UNK, pt_name, at_name,
			     es ? es : "", mfd == -EPERM ? " (MEMLOCK may be too low, consider rlimit.RemoveMemlock)" : "") < 0)
			*why = NULL;
		free(es);
		lv_close(pfd);
		return BML_Q_UNKNOWN;
	}
	memset(&a, 0, sizeof a);
	a.link_create.prog_fd = (uint32_t)pfd;
	a.link_create.target_fd = (uint32_t)mfd;
	a.link_create.attach_type = at;
	int lfd = BML_MUT("live.sockmap_link_einval") ? -EINVAL : lv_bpf(BPF_LINK_CREATE, &a, sizeof a);
	int rc = BML_Q_OK;
	if (lfd >= 0) {
		lv_close(lfd);
		*val = 1;
	} else if (lfd != -EINVAL) { /* EINVAL means sockmap has no BPF_LINK_CREATE (before 6.10): false */
		char *es = bml_go_errno_str(-lfd);
		if (asprintf(why, "%s with expected attach type %s loads, but the sockmap link probe failed (create link: %s)" UNK, pt_name, at_name, es ? es : "") < 0)
			*why = NULL;
		free(es);
		rc = BML_Q_UNKNOWN;
	}
	lv_close(mfd);
	lv_close(pfd);
	return rc;
}
