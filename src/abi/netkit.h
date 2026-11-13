#ifndef BML_ABI_NETKIT_H
#define BML_ABI_NETKIT_H

#include <stdint.h>

#include <linux/bpf.h>

struct abi_nk_peer {
	uint32_t ifindex;
	int other_netns;
};

struct abi_nk_ops {
	void *ctx;

	int (*peer)(void *ctx, uint32_t primary, struct abi_nk_peer *out);
	int (*info)(void *ctx, struct bpf_link_info *out);
	int (*close_link)(void *ctx);
};


int abi_netkit_finish(const char *name, uint32_t want_attach, uint32_t primary, uint32_t prog_id, const struct abi_nk_ops *ops, char **msg);


int abi_netkit_query_peer(uint32_t primary, struct abi_nk_peer *out);

#endif
