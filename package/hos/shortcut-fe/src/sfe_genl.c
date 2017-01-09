#include <linux/skbuff.h>
#include <net/genetlink.h>

#include "sfe_genl.h"
#include "sfe_ipv4.h"

static struct nla_policy sfe_genl_policy[SFE_A_MAX + 1] = {
	[SFE_A_UNSPEC]	= { .type = NLA_UNSPEC },
	[SFE_A_SRC_IP]	= { .type = NLA_U32 },
	[SFE_A_DST_IP]	= { .type = NLA_U32 },
	[SFE_A_SRC_PORT]= { .type = NLA_U16 },
	[SFE_A_DST_PORT]= { .type = NLA_U16 },
	[SFE_A_PROTO]	= { .type = NLA_U8 },
	[SFE_A_DIR]		= { .type = NLA_U8 },
	[SFE_A_FLAG]	= { .type = NLA_U16 },
	[SFE_A_PACKET]	= { .type = NLA_U64 },
	[SFE_A_BYTE]	= { .type = NLA_U64 },
};

static struct genl_family sfe_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = SFE_GENL_FAMILY_NAME,
	.version = SFE_GENL_VERSION,
	.maxattr = SFE_A_MAX,
};

static int sfe_flow_cmd_fill_info(struct sfe_flow *flow,
				  struct sk_buff *skb, u32 portid,
				  u32 seq, u32 flags, u8 cmd)
{
	void *sfe_header;

	sfe_header = genlmsg_put(skb, portid, seq, &sfe_genl_family, flags, cmd);
	if (!sfe_header)
		return -EMSGSIZE;

	if (nla_put_u32(skb, SFE_A_SRC_IP, flow->src_ip) ||
		nla_put_u32(skb, SFE_A_DST_IP, flow->dst_ip) ||
		nla_put_u16(skb, SFE_A_SRC_PORT, flow->src_port) ||
		nla_put_u16(skb, SFE_A_DST_PORT, flow->dst_port) ||
		nla_put_u8(skb, SFE_A_PROTO, flow->protocol) ||
		nla_put_u8(skb, SFE_A_DIR, flow->dir) ||
		nla_put_u16(skb, SFE_A_FLAG, flow->flags) ||
		nla_put_u64(skb, SFE_A_PACKET, flow->rx_packet_count) ||
		nla_put_u64(skb, SFE_A_BYTE, flow->rx_byte_count))
		goto nla_put_failure;

	return genlmsg_end(skb, sfe_header);

nla_put_failure:
	genlmsg_cancel(skb, sfe_header);
	return -EMSGSIZE;;
}

static int sfe_flow_cmd_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct sfe_flow *flow;
	long hash_idx, list_idx;

	int i;

	if (!si)
		return -1;

	hash_idx = cb->args[0];
	list_idx = cb->args[1];

	if (hash_idx >= SFE_FLOW_HASH_SIZE)
		return 0;

	spin_lock_bh(&si->hash_lock);
	for (; hash_idx < SFE_FLOW_HASH_SIZE; ++hash_idx) {
		i = 0;
		hlist_for_each_entry(flow, &si->flow_hash[hash_idx], hnode) {
			if (i >= list_idx && sfe_flow_cmd_fill_info(flow, skb,
						   NETLINK_CB(cb->skb).portid,
						   cb->nlh->nlmsg_seq, NLM_F_MULTI,
						   SFE_FLOW_C_GET) < 0)
				goto out;
			++i;
		}
		list_idx = 0;
	}
out:
	spin_unlock_bh(&si->hash_lock);

	cb->args[0] = hash_idx;
	cb->args[1] = i;

	return skb->len;
}

static struct genl_ops sfe_genl_ops[] = {
	{
		.cmd = SFE_FLOW_C_GET,
		.flags = 0,
		.policy = sfe_genl_policy,
		.doit = NULL,
		.dumpit = sfe_flow_cmd_dump,
	},
};

int sfe_netlink_init(void)
{
	return genl_register_family_with_ops(&sfe_genl_family, sfe_genl_ops, ARRAY_SIZE(sfe_genl_ops));
}

void sfe_netlink_exit(void)
{
	genl_unregister_family(&sfe_genl_family);
}


