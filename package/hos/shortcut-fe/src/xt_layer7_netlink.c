#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/net_namespace.h>
#include <net/netlink.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack.h>

#include "sfe.h"
#include "xt_layer7_netlink.h"

struct sock *l7_nl_sock = NULL;
EXPORT_SYMBOL_GPL(l7_nl_sock);

int layer7_init_netlink(void)
{
	struct netlink_kernel_cfg cfg = {
		.groups = 1
	};

	l7_nl_sock = netlink_kernel_create(&init_net, NETLINK_LAYER7, &cfg);
	if (!l7_nl_sock) {
		SFE_LOG_ERROR("Failed to create netlink socket for layer7\n");
		return -ENOMEM;
	}

	return 0;
}

void layer7_cleanup_netlink(void)
{
	if (l7_nl_sock) {
		netlink_kernel_release(l7_nl_sock);
	}
}

#define master_ct(conntr) (conntr->master)
#define ct_tuple(ct) &(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)

int l7nl_notify_send(struct nf_conn *ct, int group, int type, int flags)
{
	struct net *net = nf_ct_net(ct);
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	struct nf_conn *master = ct;
	__be32 *ip = NULL;

	if (!l7_nl_sock) {
		return 0;
	}

	if (!netlink_has_listeners(l7_nl_sock, group)) {
		return 0;
	}

	while (master_ct(master) != NULL) {
		master = master_ct(master);
	}
	if (!master->layer7.app_proto
		|| !strcmp(master->layer7.app_proto, "unknown")) {
		return 0;
	}

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (skb == NULL)
		return -1;
	nlh = nlmsg_put(skb, 0, 0, type, sizeof(__be32)*2, 0);
	if (nlh == NULL)
		goto nlmsg_failure;

	rcu_read_lock();
	ip = nlmsg_data(nlh);
	*ip = master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
	*(++ip) = master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	rcu_read_unlock();

	nlmsg_end(skb, nlh);
	nlmsg_multicast(l7_nl_sock, skb, 0, group, GFP_ATOMIC);

	return 0;

nlmsg_failure:
	kfree_skb(skb);
	return -1;
}

