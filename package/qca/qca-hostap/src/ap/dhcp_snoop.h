/*
 * DHCP snooping for Proxy ARP
 * Copyright (c) 2014, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef DHCP_SNOOP_H
#define DHCP_SNOOP_H

typedef enum {
	NET_RT,
	HOST_RT,
}RtMode;

typedef enum {
	ADD_RT,
	DEL_RT,
}RtOp;

int sta_route_set(u32 dst, u32 subnet_mask, char *if_dev, RtMode rt_mode, RtOp rt_op);

#ifdef CONFIG_PROXYARP

int dhcp_snoop_init(struct hostapd_data *hapd);
void dhcp_snoop_deinit(struct hostapd_data *hapd);

#else /* CONFIG_PROXYARP */

static inline int dhcp_snoop_init(struct hostapd_data *hapd)
{
	return 0;
}

static inline void dhcp_snoop_deinit(struct hostapd_data *hapd)
{
}

#endif /* CONFIG_PROXYARP */

#endif /* DHCP_SNOOP_H */
