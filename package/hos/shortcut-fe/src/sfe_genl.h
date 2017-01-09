#ifndef _SFE_NETLINK_H
#define _SFE_NETLINK_H

/*
 * generic netlink interface
 */
enum {
	SFE_A_UNSPEC,
	SFE_A_PROTO,
	SFE_A_SRC_IP,
	SFE_A_DST_IP,
	SFE_A_SRC_PORT,
	SFE_A_DST_PORT,
	SFE_A_DIR,
	SFE_A_FLAG,
	SFE_A_PACKET,
	SFE_A_BYTE,
	__SFE_A_MAX,
};
#define SFE_A_MAX (__SFE_A_MAX - 1)

enum {
	SFE_FLOW_C_UNSPEC,
	SFE_FLOW_C_GET,
	__SFE_FLOW_C_MAX,
};
#define SFE_FLOW_C_MAX (__SFE_FLOW_C_MAX - 1)

#define SFE_GENL_FAMILY_NAME	"SFE"
#define SFE_GENL_VERSION		1

#endif /* _SFE_NETLINK_H */

