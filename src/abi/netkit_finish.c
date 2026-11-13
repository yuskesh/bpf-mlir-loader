#define _GNU_SOURCE
#include "abi/netkit.h"

#include <errno.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "abi/internal.h"
#include "util/mutation.h"

static void check_info(const struct bpf_link_info *i, uint32_t want, uint32_t expect_if, uint32_t prog_id, char *why, size_t n)
{
	if (i->type != BPF_LINK_TYPE_NETKIT && !BML_MUT("attach.netkit_no_type_check"))
		snprintf(why, n, "the link is of type %u, not netkit", i->type);
	else if (i->id == 0 && !BML_MUT("attach.netkit_no_id_check"))
		snprintf(why, n, "the link info has no link ID");
	else if (i->prog_id != prog_id && !BML_MUT("attach.netkit_no_program_check"))
		snprintf(why, n, "the link runs program ID %u, but program ID %u was attached", i->prog_id, prog_id);
	else if (i->netkit.attach_type != want)
		snprintf(why, n, "the kernel attached it with attach type %u, but the ELF declares %u", i->netkit.attach_type, want);
	else if (i->netkit.ifindex != expect_if && !BML_MUT("attach.netkit_no_ifindex_check"))
		snprintf(why, n, "the link is on ifindex %u, but this pair's %s is ifindex %u", i->netkit.ifindex,
			 want == BPF_NETKIT_PEER ? "peer" : "primary", expect_if);
}

int abi_netkit_finish(const char *name, uint32_t want, uint32_t primary, uint32_t prog_id, const struct abi_nk_ops *ops, char **msg)
{
	char why[256] = "";
	struct abi_nk_peer peer = {0};
	int rc = ops->peer(ops->ctx, primary, &peer);
	if (rc < 0)
		snprintf(why, sizeof why, "querying the peer of ifindex %u: %s", primary, abi_errno(-rc));
	else if (rc > 0 || peer.ifindex == 0 || peer.ifindex > INT32_MAX)
		snprintf(why, sizeof why, "ifindex %u reports no usable peer (IFLA_LINK)", primary);
	else if (peer.ifindex == primary && !peer.other_netns && !BML_MUT("attach.netkit_same_index_accepted"))
		snprintf(why, sizeof why, "ifindex %u reports itself as its peer in the same netns", primary);
	else if (peer.ifindex == primary && peer.other_netns && BML_MUT("attach.netkit_netns_index_rejected"))
		snprintf(why, sizeof why, "ifindex %u reports itself as its peer", primary);
	if (!why[0]) {
		struct bpf_link_info info;
		memset(&info, 0, sizeof info);
		rc = ops->info(ops->ctx, &info);
		if (rc != 0 && BML_MUT("attach.netkit_info_error_ignored"))
			return 0;
		if (rc != 0) {
			snprintf(why, sizeof why, "reading the link info: %s", abi_errno(-rc));
		} else {

			if (BML_MUT("attach.netkit_info_forced_mismatch") || BML_MUT("attach.netkit_keep_on_mismatch"))
				info.netkit.attach_type = want == BPF_NETKIT_PEER ? BPF_NETKIT_PRIMARY : BPF_NETKIT_PEER;
			uint32_t expect = want == BPF_NETKIT_PEER && !BML_MUT("attach.netkit_peer_uses_primary") ? peer.ifindex : primary;
			check_info(&info, want, expect, prog_id, why, sizeof why);
		}
	}
	if (!why[0])
		return 0;
	int c = BML_MUT("attach.netkit_keep_on_mismatch") ? 0 : ops->close_link(ops->ctx);
	char buf[512];
	if (c != 0 && !BML_MUT("attach.netkit_close_error_dropped"))
		snprintf(buf, sizeof buf, "bml: attach netkit %s: %s; closing the link also failed: %s", name, why, abi_errno(-c));
	else
		snprintf(buf, sizeof buf, "bml: attach netkit %s: %s (detached)", name, why);
	*msg = strdup(buf);
	return -1;
}

int abi_netkit_query_peer(uint32_t primary, struct abi_nk_peer *out)
{
	memset(out, 0, sizeof *out);
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -errno;
	struct timeval tv = {.tv_sec = 5};
	struct {
		struct nlmsghdr h;
		struct ifinfomsg i;
	} req = {.h = {.nlmsg_len = sizeof req, .nlmsg_type = RTM_GETLINK, .nlmsg_flags = NLM_F_REQUEST, .nlmsg_seq = 1},
		 .i = {.ifi_family = AF_UNSPEC, .ifi_index = (int)primary}};
	struct sockaddr_nl to = {.nl_family = AF_NETLINK};
	int rc = -EIO, found = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0 || sendto(fd, &req, sizeof req, 0, (struct sockaddr *)&to, sizeof to) < 0) {
		rc = -errno;
		goto out;
	}
	static _Thread_local char buf[32768] __attribute__((aligned(NLMSG_ALIGNTO)));
	for (;;) {
		ssize_t n = recv(fd, buf, sizeof buf, MSG_TRUNC);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) {
			rc = -errno;
			goto out;
		}
		if (n == 0 || (size_t)n > sizeof buf) {
			rc = -EMSGSIZE;
			goto out;
		}
		int len = (int)n;
		for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned)len); h = NLMSG_NEXT(h, len)) {
			if (h->nlmsg_seq != 1)
				continue;
			if (h->nlmsg_type == NLMSG_ERROR) {
				const struct nlmsgerr *e = NLMSG_DATA(h);
				rc = e->error ? e->error : -EPROTO;
				goto out;
			}
			if (h->nlmsg_type != RTM_NEWLINK || h->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg)))
				continue;
			const struct ifinfomsg *i = NLMSG_DATA(h);
			if (i->ifi_index != (int)primary)
				continue;
			int al = (int)(h->nlmsg_len - NLMSG_LENGTH(sizeof *i));
			for (struct rtattr *a = IFLA_RTA(i); RTA_OK(a, al); a = RTA_NEXT(a, al)) {
				if (a->rta_type == IFLA_LINK && RTA_PAYLOAD(a) >= sizeof(uint32_t)) {
					memcpy(&out->ifindex, RTA_DATA(a), sizeof(uint32_t));
					found = 1;
				} else if (a->rta_type == IFLA_LINK_NETNSID) {
					out->other_netns = 1;
				}
			}
			rc = found ? 0 : 1;
			goto out;
		}
	}
out:
	close(fd);
	return rc;
}
