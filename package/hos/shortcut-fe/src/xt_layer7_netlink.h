#ifndef _LAYER7_NETLINK_H
#define _LAYER7_NETLINK_H

#include <net/netfilter/nf_conntrack.h>

#define NETLINK_LAYER7		25	/* l7-filter netlink unit */

enum L7_msg_types {
	L7_MSG_CT_NOTIFY_MATCH,
	L7_MSG_CT_NOTIFY_DEATH,
	__L7_MSG_MAX
};

enum l7attr_type {
	L7A_APP_PROTO,
	L7A_SRC_IP,
	L7A_DST_IP,
	L7A_PROTO_NUM,
	L7A_PROTO_SRC_PORT,
	L7A_PROTO_DST_PORT,
	__L7A_MAX
};

#define L7_MATCH_MARK 0x01000000

int layer7_init_netlink(void);

void layer7_cleanup_netlink(void);

int l7nl_notify_send(struct nf_conn *ct, int group, int type, int flags);

#endif /* _LAYER7_NETLINK_H */

