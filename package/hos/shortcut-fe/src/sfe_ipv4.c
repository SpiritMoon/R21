/*
 * sfe_ipv4.c
 *	Shortcut forwarding engine - IPv4 edition.
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

#include <linux/types.h>
#include <linux/timer.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/etherdevice.h>
#include <linux/compiler.h>
#include <linux/list.h>
#include <net/netns/conntrack.h>
#include <net/tcp.h>


#include "sfe.h"
#include "sfe_ipv4.h"
#include "sfe_genl.h"

extern int br_forward_skb(struct sk_buff *skb);

static struct sfe_ipv4 __si;
struct sfe_ipv4 *si = NULL;

/*
 * sfe_ipv4_gen_ip_csum()
 *	Generate the IP checksum for an IPv4 header.
 *
 * Note that this function assumes that we have only 20 bytes of IP header.
 */
static inline uint16_t sfe_ipv4_gen_ip_csum(struct sfe_ipv4_ip_hdr *iph)
{
	uint32_t sum;
	uint16_t *i = (uint16_t *)iph;

	iph->check = 0;

	/*
	 * Generate the sum.
	 */
	sum = i[0] + i[1] + i[2] + i[3] + i[4] + i[5] + i[6] + i[7] + i[8] + i[9];

	/*
	 * Fold it to ones-complement form.
	 */
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);

	return (uint16_t)sum ^ 0xffff;
}


struct sfe_flow *sfe_flow_alloc(void)
{
	struct sfe_flow *flow;

	flow = kmem_cache_alloc(si->flow_cache, GFP_ATOMIC);

	return flow;
}
EXPORT_SYMBOL(sfe_flow_alloc);


void sfe_flow_free(struct sfe_flow *flow)
{
	kmem_cache_free(si->flow_cache, flow);
}
EXPORT_SYMBOL(sfe_flow_free);


static inline unsigned int sfe_flow_hash(uint8_t protocol,
							__be32 src_ip, __be16 src_port,
							__be32 dst_ip, __be16 dst_port)
{
	uint32_t hash = ntohl(src_ip ^ dst_ip) ^ protocol ^ ntohs(src_port ^ dst_port);
	return ((hash >> SFE_FLOW_HASH_SHIFT) ^ hash) & SFE_FLOW_HASH_MASK;
}

struct sfe_flow *sfe_flow_find(uint8_t protocol,
									    __be32 src_ip, __be16 src_port,
									    __be32 dst_ip, __be16 dst_port)
{
	struct sfe_flow *flow;
	struct hlist_head *head;

	unsigned int hash_idx = sfe_flow_hash(protocol, src_ip, src_port, dst_ip, dst_port);
	head = &si->flow_hash[hash_idx];

	spin_lock_bh(&si->hash_lock);
	hlist_for_each_entry(flow, head, hnode) {
		if (protocol == flow->protocol
			&& src_ip == flow->src_ip && src_port == flow->src_port
			&& dst_ip == flow->dst_ip && dst_port == flow->dst_port) {
			spin_unlock_bh(&si->hash_lock);
			return flow;
		}
	}
	spin_unlock_bh(&si->hash_lock);

	return NULL;
}
EXPORT_SYMBOL(sfe_flow_find);

void sfe_flow_add(struct sfe_flow *new_flow)
{
	struct hlist_head *hash_head;
	unsigned int hash_idx;
	struct sfe_flow *counter;

	if (atomic_read(&si->count) >= SFE_FLOW_MAX) {
		SFE_LOG_ERROR("The max number of flows has been reached\n");
		return;
	}

	counter = sfe_flow_find(new_flow->protocol,
						new_flow->dst_ip, new_flow->dst_port,
						new_flow->src_ip, new_flow->src_port);
	if (counter != NULL) {
		new_flow->counter = counter;
		counter->counter = new_flow;
	}

	atomic_set(&new_flow->use, 1);

	hash_idx = sfe_flow_hash(new_flow->protocol,
						new_flow->src_ip, new_flow->src_port,
						new_flow->dst_ip, new_flow->dst_port);
	hash_head = &si->flow_hash[hash_idx];
	spin_lock_bh(&si->hash_lock);
	hlist_add_head(&new_flow->hnode, hash_head);
	spin_unlock_bh(&si->hash_lock);

	SFE_STAT_INC(flow_add);
	atomic_inc(&si->count);
}
EXPORT_SYMBOL(sfe_flow_add);

static inline void __sfe_flow_delete(struct sfe_flow *flow)
{
	hlist_del(&flow->hnode);
	sfe_flow_free(flow);
	SFE_STAT_INC(flow_delete);
	atomic_dec(&si->count);
}

static inline void sfe_flow_get(struct sfe_flow *flow)
{
	if (flow)
		atomic_inc(&flow->use);
}

static inline void sfe_flow_put(struct sfe_flow *flow)
{
	if (flow && atomic_dec_and_test(&flow->use))
		__sfe_flow_delete(flow);
}

void sfe_flow_delete(struct sfe_flow *flow)
{
	struct sfe_flow *counter = flow->counter;

	spin_lock_bh(&si->hash_lock);

	sfe_flow_put(flow);

	if (NULL != counter) {
		sfe_flow_put(counter);
	}

	spin_unlock_bh(&si->hash_lock);
}
EXPORT_SYMBOL(sfe_flow_delete);

void sfe_flow_flush(void)
{
	unsigned int hash_idx;

	spin_lock_bh(&si->hash_lock);

	for (hash_idx = 0; hash_idx < SFE_FLOW_HASH_SIZE; ++hash_idx) {
		struct sfe_flow *flow;
		struct hlist_node *n;
		hlist_for_each_entry_safe(flow, n, &si->flow_hash[hash_idx], hnode) {
			sfe_flow_put(flow);
		}
	}

	spin_unlock_bh(&si->hash_lock);
}
EXPORT_SYMBOL(sfe_flow_flush);

static struct sfe_flow *sfe_flow_find_get(uint8_t protocol,
									    __be32 src_ip, __be16 src_port,
									    __be32 dst_ip, __be16 dst_port)
{
	struct sfe_flow *flow;
	struct hlist_head *head;

	unsigned int hash_idx = sfe_flow_hash(protocol, src_ip, src_port, dst_ip, dst_port);
	head = &si->flow_hash[hash_idx];

	spin_lock_bh(&si->hash_lock);
	hlist_for_each_entry(flow, head, hnode) {
		if (protocol == flow->protocol
			&& src_ip == flow->src_ip && src_port == flow->src_port
			&& dst_ip == flow->dst_ip && dst_port == flow->dst_port) {
			sfe_flow_get(flow);
			spin_unlock_bh(&si->hash_lock);
			return flow;
		}
	}
	spin_unlock_bh(&si->hash_lock);

	return NULL;
}

/*
 * sfe_ipv4_recv()
 *	Handle packet receives and forwaring.
 *
 * Returns 1 if the packet is forwarded or 0 if it isn't.
 */
bool sfe_ipv4_recv(struct sk_buff *skb)
{
	struct sfe_ipv4_ip_hdr *iph = NULL;
	unsigned int ihl;
	unsigned int tot_len;
	unsigned int frag_off;
	bool delete_on_find = 0;
	bool rcsum = 0;
	const struct sfe_ipv4_udp_hdr *udph = NULL;
	const struct sfe_ipv4_tcp_hdr *tcph = NULL;
	uint8_t protocol;
	__be16 src_port;
	__be16 dst_port;
	__be32 tcp_flags = 0;
	unsigned long timeout = 5*60*HZ;
	struct sfe_flow *flow = NULL;

	if (unlikely(!pskb_may_pull(skb, sizeof(struct sfe_ipv4_ip_hdr)))) {
		goto exit_drop;
	}

	iph = (struct sfe_ipv4_ip_hdr *)skb->data;
	if (unlikely(iph->version != 4)) {
		goto exit_drop;
	}

	tot_len = ntohs(iph->tot_len);
	if (unlikely(tot_len > skb->len || tot_len < sizeof(struct sfe_ipv4_ip_hdr))) {
		goto exit_drop;
	}

	/*
	 * Do we have a non-initial fragment?
	 */
	frag_off = ntohs(iph->frag_off);
	if (unlikely(frag_off & IP_OFFSET)) {
		SFE_EXP_STAT_INC(SFE_EXP_IPV4_NON_INITIAL_FRAGMENT);
		goto exit_false;
	}

	/*
	 * If we have a (first) fragment then mark it to cause any connection to flush.
	 */
	if (unlikely(frag_off & IP_MF)) {
		SFE_EXP_STAT_INC(SFE_EXP_IPV4_IP_FRAGMENT);
		delete_on_find = true;
	}

	/*
	 * Do we have any IP options?  That's definite a slow path!
	 */
	ihl = iph->ihl << 2;
	if (unlikely(ihl != sizeof(struct sfe_ipv4_ip_hdr))) {
		SFE_EXP_STAT_INC(SFE_EXP_IPV4_IP_OPTIONS);
		delete_on_find = true;
	}

	if (ipv4_is_loopback(iph->saddr) || ipv4_is_loopback(iph->daddr)) {
		SFE_EXP_STAT_INC(SFE_EXP_IPV4_LOOPBACK);
		goto exit_false;
	}

	if (ipv4_is_multicast(iph->saddr) || ipv4_is_multicast(iph->daddr)) {
		SFE_EXP_STAT_INC(SFE_EXP_IPV4_MULTICAST);
		goto exit_false;
	}

	/*
	 * Is our packet too short to contain a valid UDP header?
	 */
	protocol = iph->protocol;
	switch (protocol) {
	case IPPROTO_UDP:
		if (unlikely(!pskb_may_pull(skb, (sizeof(struct sfe_ipv4_udp_hdr) + ihl)))) {
			SFE_EXP_STAT_INC(SFE_EXP_IPV4_UDP_HEADER_INCOMPLETE);
			goto exit_false;
		}
		udph = (struct sfe_ipv4_udp_hdr *)(skb->data + ihl);
		src_port = udph->source;
		dst_port = udph->dest;
		timeout = init_net.ct.nf_ct_proto.udp.timeouts[UDP_CT_REPLIED];
		break;
	case IPPROTO_TCP:
		if (unlikely(!pskb_may_pull(skb, (sizeof(struct sfe_ipv4_tcp_hdr) + ihl)))) {
			SFE_EXP_STAT_INC(SFE_EXP_IPV4_TCP_HEADER_INCOMPLETE);
			goto exit_false;
		}
		tcph = (struct sfe_ipv4_tcp_hdr *)(skb->data + ihl);
		src_port = tcph->source;
		dst_port = tcph->dest;
		tcp_flags = tcp_flag_word(tcph);
		timeout = init_net.ct.nf_ct_proto.tcp.timeouts[TCP_CONNTRACK_ESTABLISHED];
		break;
	default:
		SFE_EXP_STAT_INC(SFE_EXP_IPV4_UNSUPPORTED_PROTOCOL);
		goto exit_false;
	}

	if (protocol == IPPROTO_TCP) {
		/*
		 * Look at our TCP flags.  Anything missing an ACK or that has RST, SYN or FIN
		 * set is not a fast path packet.
		 */
		if (unlikely((tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_FIN | TCP_FLAG_ACK)) != TCP_FLAG_ACK)) {
			SFE_EXP_STAT_INC(SFE_EXP_IPV4_TCP_FLAGS);
			SFE_LOG_DEBUG("TCP flags: 0x%x are not fast\n",
				    tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_FIN | TCP_FLAG_ACK));
			goto exit_false;
		}
	}

	/*
	 * Look for a connection match.
	 */
	flow = sfe_flow_find_get(protocol, iph->saddr, src_port, iph->daddr, dst_port);

	if (!flow) {
		if (protocol == IPPROTO_UDP) {
			SFE_EXP_STAT_INC(SFE_EXP_IPV4_UDP_NO_FLOW);
		} else {
			/*
			 * We didn't get a connection but as TCP is connection-oriented that
			 * may be because this is a non-fast connection (not running established).
			 * For diagnostic purposes we differentiate this here.
			 */
			if ((tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_FIN | TCP_FLAG_ACK)) == TCP_FLAG_ACK) {
				SFE_EXP_STAT_INC(SFE_EXP_IPV4_TCP_NO_FLOW_FAST_FLAGS);
			} else {
				SFE_EXP_STAT_INC(SFE_EXP_IPV4_TCP_NO_FLOW_SLOW_FLAGS);
			}
		}
		SFE_STAT_INC(flow_match_miss);
		goto exit_false_put;
	}
	SFE_STAT_INC(flow_match_hits);

	/*
	 * For some scene like DHCP Offer, same src/dst ip/port, but different dst mac.
	 * So we must match the dst mac.
	 */
	if (!ether_addr_equal(flow->dst_mac, eth_hdr(skb)->h_dest)) {
		SFE_EXP_STAT_INC(SFE_EXP_IPV4_DST_MAC);
		goto exit_false_put;
	}

	/*
	 * If our packet has beern marked as "flush on find" we can't actually
	 * forward it in the fast path, but now that we've found an associated
	 * connection we can flush that out before we process the packet.
	 */
	if (unlikely(delete_on_find)) {
		sfe_flow_delete(flow);
		goto exit_false_put;
	}

	/*
	 * From this point on we're good to modify the packet.
	 */

	/*
	 * Update DSCP
	 */
	if (flow->flags & SFE_FLOW_FLAG_DSCP) {
		iph->tos = (iph->tos & ~DSCP_MASK) | (flow->dscp << DSCP_SHIFT);
		rcsum = 1;
	}

	/*
	 * Update priority of skb.
	 */
	if (flow->flags & SFE_FLOW_FLAG_PRIORITY) {
		skb->priority = flow->priority;
		rcsum = 1;
	}

	/*
	 * Mark outgoing packet.
	 */
	if (flow->flags & SFE_FLOW_FLAG_MARK) {
		skb->mark = flow->mark;
		rcsum = 1;
	}

	if (rcsum) {
		iph->check = sfe_ipv4_gen_ip_csum(iph);
	}

	/*
	 * Update traffic stats.
	 */
	flow->rx_packet_count++;
	flow->rx_byte_count += skb->len;
	if (flow->nfct) {
		nf_ct_refresh_acct(flow->nfct, flow->ctinfo, skb, timeout);
	} else {
		SFE_LOG_ERROR("flow->nfct is NULL\n");
	}

	sfe_flow_put(flow);
	if (br_forward_skb(skb)) {
		SFE_STAT_INC(packets_forwarded);
		return true;
	} else {
		goto exit_false;
	}

exit_false_put:
	sfe_flow_put(flow);
exit_false:
	SFE_STAT_INC(packets_not_forwarded);
	return false;

exit_drop:
	kfree_skb(skb);
	return true;
}
EXPORT_SYMBOL(sfe_ipv4_recv);


/*
 * sfe_ipv4_init()
 */
static int __init sfe_ipv4_init(void)
{
	int result = -1;

	SFE_LOG_INFO("SFE IPv4 init\n");

	si = &__si;
	memset(si, 0, sizeof(struct sfe_ipv4));

	spin_lock_init(&si->hash_lock);

	si->flow_cache = kmem_cache_create("sfe_flow_cache",
						sizeof(struct sfe_flow),
						0,
						SLAB_HWCACHE_ALIGN, NULL);
	if (!si->flow_cache) {
		result = -ENOMEM;
		goto exit;
	}

	si->stat = alloc_percpu(struct sfe_stat);
	if (!si->stat) {
		result = -ENOMEM;
		goto exit1;
	}

	result = sfe_debug_init(si);
	if (result < 0) {
		goto exit2;
	}

	result = sfe_netlink_init();
	if (result < 0)
		goto exit3;

	result = sfe_fm_init();
	if (result < 0) {
		goto exit4;
	}

	return 0;

exit4:
	sfe_netlink_exit();
exit3:
	sfe_debug_exit(si);
exit2:
	free_percpu(si->stat);
exit1:
	kmem_cache_destroy(si->flow_cache);
exit:
	return result;
}

/*
 * sfe_ipv4_exit()
 */
static void __exit sfe_ipv4_exit(void)
{
	SFE_LOG_INFO("SFE IPv4 exit\n");

	sfe_fm_exit();

	sfe_netlink_exit();

	sfe_debug_exit(si);

	/*
	 * Destroy all connections.
	 */
	sfe_flow_flush();

	free_percpu(si->stat);

	kmem_cache_destroy(si->flow_cache);
}

module_init(sfe_ipv4_init);
module_exit(sfe_ipv4_exit);

MODULE_AUTHOR("Qualcomm Atheros Inc.");
MODULE_DESCRIPTION("Shortcut Forwarding Engine - IPv4 edition");
MODULE_LICENSE("Dual BSD/GPL");

