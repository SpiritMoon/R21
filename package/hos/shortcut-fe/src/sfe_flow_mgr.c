/*
 * sfe_flow_mgr.c
 *	Shortcut forwarding engine flow manager.
 *
 * Copyright (c) 2013-2015 The Linux Foundation. All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <linux/if_bridge.h>
#include <linux/netfilter_bridge.h>
#include <net/addrconf.h>
#include <net/dsfield.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_ecache.h>

#include "sfe.h"
#include "sfe_backport.h"
#include "sfe_ipv4.h"
#if defined(CONFIG_NETFILTER_XT_MATCH_LAYER7) || \
			defined(CONFIG_NETFILTER_XT_MATCH_LAYER7_MODULE)
#include "xt_layer7_netlink.h"
#endif

/*
 * Expose the hook for the receive processing.
 */
extern int (*athrs_fast_nat_recv)(struct sk_buff *skb);

/*
 * sfe_fm_recv()
 *	Handle packet receives.
 *
 * Returns 1 if the packet is forwarded or 0 if it isn't.
 */
int sfe_fm_recv(struct sk_buff *skb)
{
	const unsigned char *dest = eth_hdr(skb)->h_dest;

	if (is_multicast_ether_addr(dest)
		|| is_broadcast_ether_addr(dest)) {
		return 0;
	}

	/*
	 * We know that for the vast majority of packets we need the transport
	 * layer header so we may as well start to fetch it now!
	 */
	prefetch(skb->data + 32);
	barrier();

	/*
	 * We're only interested in IPv4 packets.
	 */
	if (htons(ETH_P_IP) == skb->protocol) {
		return sfe_ipv4_recv(skb);
	}

	SFE_LOG_DEBUG("not IP packet: %u\n", skb->protocol);
	return 0;
}

int nfct_death_handler(enum ip_conntrack_events event, struct nf_conn *ct)
{
	uint8_t protocol;
	__be32 src_ip;
	__be16 src_port;
	__be32 dst_ip;
	__be16 dst_port;
	struct sfe_flow *flow = NULL;
	struct nf_conntrack_tuple *tuple = NULL;

	/*
	 * If we don't have a conntrack entry then we're done.
	 */
	if (unlikely(!ct)) {
		SFE_LOG_WARN("no ct in conntrack event handler\n");
		return NOTIFY_DONE;
	}

	/*
	 * We're only interested in destroy events.
	 */
	if (event != IPCT_DESTROY) {
		SFE_LOG_DEBUG("ignoring non-destroy event\n");
		return NOTIFY_DONE;
	}

	/*
	 * If this is an untracked connection then we can't have any state either.
	 */
	if (nf_ct_is_untracked(ct)) {
		SFE_LOG_DEBUG("ignoring untracked conn\n");
		return NOTIFY_DONE;
	}

	if (nf_ct_l3num(ct) != AF_INET) {
		SFE_LOG_DEBUG("ignoring non-IPv4 and non-IPv6 connection\n");
		return NOTIFY_DONE;
	}

	tuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	protocol = (int32_t)tuple->dst.protonum;
	/*
	 * Extract information from the conntrack connection.  We're only interested
	 * in nominal connection information (i.e. we're ignoring any NAT information).
	 */
	if (protocol != IPPROTO_UDP && protocol != IPPROTO_TCP) {
		SFE_LOG_DEBUG("unhandled protocol: %d\n", protocol);
		return NOTIFY_DONE;
	}
	src_ip = tuple->src.u3.ip;
	dst_ip = tuple->dst.u3.ip;
	src_port = tuple->src.u.tcp.port;
	dst_port = tuple->dst.u.tcp.port;

	flow = sfe_flow_find(protocol, src_ip, src_port, dst_ip, dst_port);
	if (flow == NULL) {
		tuple = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
		src_ip = tuple->src.u3.ip;
		dst_ip = tuple->dst.u3.ip;
		src_port = tuple->src.u.tcp.port;
		dst_port = tuple->dst.u.tcp.port;
		flow = sfe_flow_find(protocol, src_ip, src_port, dst_ip, dst_port);
	}
	if (flow != NULL) {
		sfe_flow_delete(flow);
	}

#if defined(CONFIG_NETFILTER_XT_MATCH_LAYER7) || \
			defined(CONFIG_NETFILTER_XT_MATCH_LAYER7_MODULE)
	if (ct->mark & L7_MATCH_MARK) {
		l7nl_notify_send(ct, 1, L7_MSG_CT_NOTIFY_DEATH, 0);
	}
#endif

	return NOTIFY_DONE;
}

static struct nf_ct_event_notifier_sfe nfct_event_notifier_sfe = {
	.fcn = nfct_death_handler,
};

/*
 * sfe_fm_post_routing()
 *	Called for packets about to leave the box - either locally generated or forwarded from another interface
 */
static unsigned int sfe_fm_post_routing(struct sk_buff *skb, int is_v4)
{
	struct sfe_flow *flow = NULL;
	uint8_t dir;
	uint16_t flags = 0;
	struct net_device *in = NULL;
	struct net_device *dst_dev = NULL;

	struct nf_conn *ct = NULL;
	enum ip_conntrack_info ctinfo;
	SFE_NF_CONN_ACCT(acct);

	const struct iphdr *iph;
	struct iphdr _iph;
	const struct tcphdr *tcph;
	struct tcphdr _tcph;
	const struct udphdr *udph;
	struct udphdr _udph;
	const struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;

	__be16 src_port;
	__be16 dst_port;

	/*
	 * Don't process broadcast or multicast packets.
	 */
	if (unlikely(skb->pkt_type == PACKET_BROADCAST)) {
		SFE_EXP_STAT_INC(SFE_EXP_FM_PACKET_BROADCAST);
		return NF_ACCEPT;
	}
	if (unlikely(skb->pkt_type == PACKET_MULTICAST)) {
		SFE_EXP_STAT_INC(SFE_EXP_FM_PACKET_MULTICAST);
		return NF_ACCEPT;
	}

#ifdef CONFIG_XFRM
	/*
	 * Packet to xfrm for encapsulation, we can't process it
	 */
	if (unlikely(skb_dst(skb)->xfrm)) {
		SFE_LOG_DEBUG("packet to xfrm, ignoring\n");
		return NF_ACCEPT;
	}
#endif

	/*
	 * Don't process locally generated packets.
	 */
	if (skb->sk) {
		SFE_EXP_STAT_INC(SFE_EXP_FM_LOCAL_OUT);
		return NF_ACCEPT;
	}

	/*
	 * Don't process packets that are not being forwarded.
	 */
	in = dev_get_by_index(&init_net, skb->skb_iif);
	if (!in) {
		SFE_EXP_STAT_INC(SFE_EXP_FM_NO_IIF);
		return NF_ACCEPT;
	}
	dev_put(in);

	iph = skb_header_pointer(skb, skb_network_offset(skb), sizeof(_iph), &_iph);
	if (iph == NULL) {
		SFE_EXP_STAT_INC(SFE_EXP_FM_IP_HEADER_INCOMPLETE);
		return NF_ACCEPT;
	}
	if (ipv4_is_lbcast(iph->saddr) || ipv4_is_lbcast(iph->daddr)
		|| ipv4_is_loopback(iph->saddr) || ipv4_is_loopback(iph->daddr)
		|| ipv4_is_local_multicast(iph->saddr) || ipv4_is_local_multicast(iph->daddr)
		|| ipv4_is_multicast(iph->saddr) || ipv4_is_multicast(iph->daddr)) {
		SFE_EXP_STAT_INC(SFE_EXP_FM_IP_MUTILCAST);
		return NF_ACCEPT;
	}

	/*
	 * Don't process packets that aren't being tracked by conntrack.
	 */
	if (iph->protocol == IPPROTO_TCP) {
		tcph = skb_header_pointer(skb, skb_network_offset(skb) + (iph->ihl << 2), 8, &_tcph);
		src_port = tcph->source;
		dst_port = tcph->dest;
	} else if (iph->protocol == IPPROTO_UDP) {
		udph = skb_header_pointer(skb, skb_network_offset(skb) + (iph->ihl << 2), 8, &_udph);
		src_port = udph->source;
		dst_port = udph->dest;
	} else {
		SFE_EXP_STAT_INC(SFE_EXP_FM_UNSUPPORTED_PROTOCOL);
		return NF_ACCEPT;
	}

	if ((ntohs(src_port) == 53 || ntohs( dst_port) == 53)
		|| (ntohs(src_port) == 67 && ntohs(dst_port) == 68)
		|| (ntohs(src_port) == 68 && ntohs(dst_port) == 67)) {
		/* some protocol like DHCP, DNS is short connection */
		return NF_ACCEPT;
	}

	ct = nf_ct_get(skb, &ctinfo);
	if (unlikely(!ct)) {
		memset(&tuple, 0, sizeof(tuple));
		tuple.src.l3num = PF_INET;
		tuple.src.u3.ip = iph->saddr;
		tuple.src.u.tcp.port = src_port;
		tuple.dst.u3.ip = iph->daddr;
		tuple.dst.u.tcp.port = dst_port;
		tuple.dst.protonum = iph->protocol;
		h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
		if (!h) {
			SFE_EXP_STAT_INC(SFE_EXP_FM_NO_CT);
			return NF_ACCEPT;
		}
		ct = nf_ct_tuplehash_to_ctrack(h);
		if (NF_CT_DIRECTION(h) == IP_CT_DIR_REPLY) {
			ctinfo = IP_CT_ESTABLISHED_REPLY;
		} else {
			if (test_bit(IPS_SEEN_REPLY_BIT, &ct->status)) {
				ctinfo = IP_CT_ESTABLISHED;
			} else if (test_bit(IPS_EXPECTED_BIT, &ct->status)) {
				ctinfo = IP_CT_RELATED;
			} else {
				ctinfo = IP_CT_NEW;
			}
		}
	}

	/*
	 * Don't process untracked connections.
	 */
	if (unlikely(nf_ct_is_untracked(ct))) {
		SFE_EXP_STAT_INC(SFE_EXP_FM_CT_UNTRACK);
		return NF_ACCEPT;
	}

	/*
	 * Unconfirmed connection may be dropped by Linux at the final step,
	 * So we don't process unconfirmed connections.
	 */
	if (!nf_ct_is_confirmed(ct)) {
		SFE_EXP_STAT_INC(SFE_EXP_FM_CT_UNCONFIRMED);
		return NF_ACCEPT;
	}

	/*
	 * Don't process connections that require support from a 'helper' (typically a NAT ALG).
	 */
	if (unlikely(nfct_help(ct))) {
		SFE_EXP_STAT_INC(SFE_EXP_FM_CT_HAS_HELPER);
		return NF_ACCEPT;
	}

#if defined(CONFIG_NETFILTER_XT_MATCH_LAYER7) || \
    defined(CONFIG_NETFILTER_XT_MATCH_LAYER7_MODULE)
	if (ct->layer7.app_data != NULL && ct->layer7.app_proto == NULL) { /* == NULL means DPI work has not FINISHED */
		SFE_EXP_STAT_INC(SFE_EXP_FM_DPI_UNFINISHED);
		return NF_ACCEPT;
	}
#endif

	dir = CTINFO2DIR(ctinfo);
	/*
	 * Check if the acceleration of a flow could be rejected quickly.
	 */
	acct = nf_conn_acct_find(ct);
	if (acct) {
		long long packets = atomic64_read(&SFE_ACCT_COUNTER(acct)[dir].packets);
		if ((packets > 0xff) && (packets & 0xff)) {
			/*
			 * Connection hits slow path at least 256 times, so it must be not able to accelerate.
			 * But we also give it a chance to walk through ECM every 256 packets
			 */
			return NF_ACCEPT;
		}
	}

	if (iph->protocol == IPPROTO_TCP) {
		/*
		 * Don't try to manage a non-established connection.
		 */
		if (!test_bit(IPS_ASSURED_BIT, &ct->status)) {
			SFE_EXP_STAT_INC(SFE_EXP_FM_TCP_UNASSURED);
			SFE_LOG_DEBUG("non-established connection\n");
			return NF_ACCEPT;
		}

		/*
		 * If the connection is shutting down do not manage it.
		 * state can not be SYN_SENT, SYN_RECV because connection is assured
		 * Not managed states: FIN_WAIT, CLOSE_WAIT, LAST_ACK, TIME_WAIT, CLOSE.
		 */
		spin_lock_bh(&ct->lock);
		if (ct->proto.tcp.state != TCP_CONNTRACK_ESTABLISHED) {
			spin_unlock_bh(&ct->lock);
			SFE_EXP_STAT_INC(SFE_EXP_FM_TCP_UNESTABLISHED);
			SFE_LOG_DEBUG("connection in termination state\n");
			return NF_ACCEPT;
		}
		spin_unlock_bh(&ct->lock);
	}

	dst_dev = skb->dev;
	SFE_LOG_DEBUG("xmit_dst_dev: %s\n", dst_dev->name);

	if (!(dst_dev->flags & IFF_POINTOPOINT)) {
		flags |= SFE_FLOW_FLAG_WRITE_L2_HDR;
	}

	flow = sfe_flow_find(iph->protocol, iph->saddr, src_port, iph->daddr, dst_port);
	if (flow) {
		SFE_LOG_DEBUG("sfe flow has exist in flow table!\n");
		return NF_ACCEPT;
	}

	flow = sfe_flow_alloc();
	if (!flow) {
		SFE_LOG_ERROR("sfe flow alloc failed!\n");
		return NF_ACCEPT;
	}
	memset(flow, 0, sizeof(struct sfe_flow));

	/*
	 * Get QoS information
	 */
	flow->dscp = ipv4_get_dsfield(iph) >> DSCP_SHIFT;
	if (flow->dscp) {
		flags |= SFE_FLOW_FLAG_DSCP;
	}
	if (skb->priority) {
		flow->priority = skb->priority;
		flags |= SFE_FLOW_FLAG_PRIORITY;
	}
	if (skb->mark) {
		flow->mark = skb->mark;
		flags |= SFE_FLOW_FLAG_MARK;
	}
	flow->src_ip = iph->saddr;
	flow->dst_ip = iph->daddr;
	flow->protocol = iph->protocol;
	flow->src_port = src_port;
	flow->dst_port = dst_port;
	flow->flags = flags;
	memcpy(flow->dst_mac, eth_hdr(skb)->h_dest, ETH_ALEN);
	flow->dir = dir;
	flow->nfct = ct;
	flow->ctinfo = ctinfo;

	if (likely(is_v4)) {
		sfe_flow_add(flow);
		SFE_LOG_DEBUG("sfe_flow_add: s: %pI4:%u, d: %pI4:%u\n", 
					&flow->src_ip, ntohs(flow->src_port), 
					&flow->dst_ip, ntohs(flow->dst_port));
	} else {
		;
	}

#if defined(CONFIG_NETFILTER_XT_MATCH_LAYER7) || \
		defined(CONFIG_NETFILTER_XT_MATCH_LAYER7_MODULE)
	if (ct->layer7.app_proto != NULL && strcmp(ct->layer7.app_proto, "unknown")
			&& !(ct->mark & L7_MATCH_MARK)) {
		spin_lock_bh(&ct->lock);
		ct->mark = (ct->mark & ~L7_MATCH_MARK) ^ L7_MATCH_MARK;
		spin_unlock_bh(&ct->lock);
		if (l7nl_notify_send(ct, 1, L7_MSG_CT_NOTIFY_MATCH, 0)) {
			SFE_LOG_ERROR("layer7 netlink send error");
		}
	}
#endif

	return NF_ACCEPT;
}

/*
 * sfe_fm_ipv4_post_routing_hook()
 *	Called for packets about to leave the box - either locally generated or forwarded from another interface
 */
sfe_fm_ipv4_post_routing_hook(hooknum, ops, skb, in_unused, out, okfn)
{
	return sfe_fm_post_routing(skb, true);
}

/*
 * Structure to establish a hook into the post routing netfilter point - this
 * will pick up local outbound and packets going from one interface to another.
 *
 * Note: see include/linux/netfilter_ipv4.h for info related to priority levels.
 * We want to examine packets after NAT translation and any ALG processing.
 */
static struct nf_hook_ops sfe_fm_ops_post_routing[] __read_mostly = {
	{
		.hook = __sfe_fm_ipv4_post_routing_hook,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_NAT_SRC + 1,
	},
};

/*
 * sfe_fm_init()
 */
int sfe_fm_init(void)
{
	int result = -1;

	SFE_LOG_INFO("SFE CM init\n");

#if defined(CONFIG_NETFILTER_XT_MATCH_LAYER7) || \
			defined(CONFIG_NETFILTER_XT_MATCH_LAYER7_MODULE)
	result = layer7_init_netlink();
	if (result < 0) {
		return result;
	}	
#endif

	/*
	 * Register our netfilter hooks.
	 */
	result = nf_register_hooks(sfe_fm_ops_post_routing, ARRAY_SIZE(sfe_fm_ops_post_routing));
	if (result < 0) {
		SFE_LOG_ERROR("can't register nf post routing hook: %d\n", result);
		goto exit;
	}

	/*
	 * Register Netfilter conntrack event notifier
	 */
	result = nf_ct_register_notifier_sfe(&init_net, &nfct_event_notifier_sfe);
	if (result < 0) {
		SFE_LOG_ERROR("can't register nfct event notifier: %d\n", result);
		goto exit2;
	}

	/*
	 * Hook the receive path in the network stack.
	 */
	BUG_ON(athrs_fast_nat_recv != NULL);
	RCU_INIT_POINTER(athrs_fast_nat_recv, sfe_fm_recv);

	return 0;
exit2:
	nf_unregister_hooks(sfe_fm_ops_post_routing, ARRAY_SIZE(sfe_fm_ops_post_routing));
exit:
#if defined(CONFIG_NETFILTER_XT_MATCH_LAYER7) || \
			defined(CONFIG_NETFILTER_XT_MATCH_LAYER7_MODULE)
	layer7_cleanup_netlink();
#endif

	return result;
}

/*
 * sfe_fm_exit()
 */
void sfe_fm_exit(void)
{
	SFE_LOG_INFO("SFE CM exit\n");

	/*
	 * Unregister our receive callback.
	 */
	RCU_INIT_POINTER(athrs_fast_nat_recv, NULL);

	/*
	 * Wait for all callbacks to complete.
	 */
	rcu_barrier();

	nf_ct_unregister_notifier_sfe(&init_net, &nfct_event_notifier_sfe);

	nf_unregister_hooks(sfe_fm_ops_post_routing, ARRAY_SIZE(sfe_fm_ops_post_routing));

	/*
	 * Destroy all connections.
	 */
	sfe_flow_flush();

#if defined(CONFIG_NETFILTER_XT_MATCH_LAYER7) || \
			defined(CONFIG_NETFILTER_XT_MATCH_LAYER7_MODULE)
	layer7_cleanup_netlink();
#endif

}

