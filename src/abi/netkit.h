/* abi/netkit.h — the check made after a netkit attach. The operations that touch the kernel are
 * passed in as ops, so the failure paths can be tested without root (test/abi/netkit_finish_unit.c). */
#ifndef BML_ABI_NETKIT_H
#define BML_ABI_NETKIT_H

#include <stdint.h>

#include <linux/bpf.h>

struct abi_nk_peer {
	uint32_t ifindex;
	int other_netns; /* The reply carries IFLA_LINK_NETNSID: the ifindex space differs from the primary's. */
};

struct abi_nk_ops {
	void *ctx;
	/* 0: *out was filled; 1: the reply has no IFLA_LINK; negative: -errno. */
	int (*peer)(void *ctx, uint32_t primary, struct abi_nk_peer *out);
	int (*info)(void *ctx, struct bpf_link_info *out); /* 0 or -errno */
	int (*close_link)(void *ctx);			   /* 0 or -errno */
};

/* Checks a link whose attach succeeded. 0: everything matches (the link stays open).
 * -1: the link was closed, and *msg (malloc) holds both the main cause and any error from the close. */
int abi_netkit_finish(const char *name, uint32_t want_attach, uint32_t primary, uint32_t prog_id, const struct abi_nk_ops *ops, char **msg);

/* IFLA_LINK and IFLA_LINK_NETNSID from an RTM_GETLINK (by ifindex) in the caller's netns.
 * The return value is the same as that of peer in abi_nk_ops. */
int abi_netkit_query_peer(uint32_t primary, struct abi_nk_peer *out);

#endif
