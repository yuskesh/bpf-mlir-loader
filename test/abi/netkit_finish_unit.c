#include "abi/netkit.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PRIMARY 5u
#define PEER_IF 6u
#define PROG 77u

static struct {
	int peer_rc, info_rc, close_rc, closes;
	struct abi_nk_peer peer;
	struct bpf_link_info info;
} s;

static int f_peer(void *c, uint32_t p, struct abi_nk_peer *o) { (void)c, (void)p; *o = s.peer; return s.peer_rc; }
static int f_info(void *c, struct bpf_link_info *o) { (void)c; *o = s.info; return s.info_rc; }
static int f_close(void *c) { (void)c; s.closes++; return s.close_rc; }

static int fails;


static void base(uint32_t want)
{
	memset(&s, 0, sizeof s);
	s.peer.ifindex = PEER_IF;
	s.info.type = BPF_LINK_TYPE_NETKIT;
	s.info.id = 9;
	s.info.prog_id = PROG;
	s.info.netkit.attach_type = want;
	s.info.netkit.ifindex = want == BPF_NETKIT_PEER ? PEER_IF : PRIMARY;
}

static void run(const char *id, uint32_t want, int want_rc, const char *text, const char *text2)
{
	const struct abi_nk_ops ops = {.ctx = NULL, .peer = f_peer, .info = f_info, .close_link = f_close};
	char *msg = NULL;
	int rc = abi_netkit_finish("filter", want, PRIMARY, PROG, &ops, &msg);
	int ok = rc == want_rc && s.closes == (want_rc ? 1 : 0) && (!text || (msg && strstr(msg, text))) && (!text2 || (msg && strstr(msg, text2)));
	printf("%s: %s\n", id, ok ? "PASS" : "FAIL");
	if (!ok)
		fails++, printf("  rc=%d closes=%d msg=%s\n", rc, s.closes, msg ? msg : "(null)");
	free(msg);
}

#define PR BPF_NETKIT_PRIMARY
#define PE BPF_NETKIT_PEER
#define CASE(id, w, wrc, t, t2, ...) do { base(w); __VA_ARGS__; run(id, w, wrc, t, t2); } while (0)

int main(void)
{
	const char *closing = "closing the link also failed";

	CASE("ok-primary", PR, 0, NULL, NULL, );
	CASE("ok-peer", PE, 0, NULL, NULL, );
	CASE("ok-peer-other-netns-same-index", PE, 0, NULL, NULL, s.peer.ifindex = PRIMARY; s.peer.other_netns = 1; s.info.netkit.ifindex = PRIMARY);
	CASE("same-netns-same-index", PR, -1, "reports itself", "(detached)", s.peer.ifindex = PRIMARY);
	CASE("foreign-pair-peer", PE, -1, "ifindex 8", "(detached)", s.info.netkit.ifindex = 8);
	CASE("peer-link-on-primary", PE, -1, "peer is ifindex 6", NULL, s.info.netkit.ifindex = PRIMARY);
	CASE("primary-link-on-peer", PR, -1, "primary is ifindex 5", NULL, s.info.netkit.ifindex = PEER_IF);
	CASE("wrong-type", PR, -1, "of type 1,", NULL, s.info.type = 1);
	CASE("id-zero", PR, -1, "no link ID", NULL, s.info.id = 0);
	CASE("wrong-program", PR, -1, "program ID 78", NULL, s.info.prog_id = 78);
	CASE("wrong-attach-type", PR, -1, "attach type", NULL, s.info.netkit.attach_type = PE);
	CASE("info-fails", PR, -1, "reading the link info", "(detached)", s.info_rc = -EBADF);
	CASE("peer-query-fails", PE, -1, "querying the peer", "(detached)", s.peer_rc = -EPERM);
	CASE("no-ifla-link", PE, -1, "no usable peer", NULL, s.peer_rc = 1);
	CASE("ifla-link-zero", PE, -1, "no usable peer", NULL, s.peer.ifindex = 0);
	CASE("mismatch-close-fails", PR, -1, "ifindex", closing, s.info.netkit.ifindex = PEER_IF; s.close_rc = -EIO);
	CASE("info-fails-close-fails", PR, -1, "reading the link info", closing, s.info_rc = -EBADF; s.close_rc = -EIO);
	CASE("peer-fails-close-fails", PE, -1, "querying the peer", closing, s.peer_rc = -EPERM; s.close_rc = -EIO);


	struct abi_nk_peer o;
	int lo = abi_netkit_query_peer(1, &o), none = abi_netkit_query_peer(0x7ffffff0u, &o);
	printf("query-lo-no-link: %s\n", lo == 1 ? "PASS" : "FAIL");
	printf("query-no-device: %s\n", none == -ENODEV ? "PASS" : "FAIL");
	if (lo != 1 || none != -ENODEV)
		fails++, printf("  lo=%d none=%d\n", lo, none);
	return fails != 0;
}
