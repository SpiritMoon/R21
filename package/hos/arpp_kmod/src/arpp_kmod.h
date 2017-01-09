/*
 * arp-proxy / driver function
 * Copyright (c) 2016-2017, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef _ARPP_KMOD_H_
#define _ARPP_KMOD_H_

#define ARP_PKT_MIN_LEN 42

struct arppm_nl_msg
{
	char ifname[IFNAMSIZ];
	u8 arp_req_pkt[ARP_PKT_MIN_LEN];
};

#endif
