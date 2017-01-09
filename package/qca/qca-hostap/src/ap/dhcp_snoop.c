/*
 * DHCP snooping for Proxy ARP
 * Copyright (c) 2014, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/route.h>

#include "utils/common.h"
#include "l2_packet/l2_packet.h"
#include "hostapd.h"
#include "sta_info.h"
#include "ap_drv_ops.h"
#include "x_snoop.h"
#include "dhcp_snoop.h"
#include "ap_config.h"
#include "sta_sync.h"

#ifndef SIOCADDRT
#define SIOCADDRT	0x890B		/* add routing table entry	*/
#endif
#ifndef SIOCDELRT
#define SIOCDELRT	0x890C		/* delete routing table entry	*/
#endif


struct bootp_pkt {
	struct iphdr iph;
	struct udphdr udph;
	u8 op;
	u8 htype;
	u8 hlen;
	u8 hops;
	be32 xid;
	be16 secs;
	be16 flags;
	be32 client_ip;
	be32 your_ip;
	be32 server_ip;
	be32 relay_ip;
	u8 hw_addr[16];
	u8 serv_name[64];
	u8 boot_file[128];
	u8 exten[312];
} STRUCT_PACKED;

#define DHCPACK	5
static const u8 ic_bootp_cookie[] = { 99, 130, 83, 99 };

struct arp_pkt {
	struct ethhdr ethh;
	struct ether_arp arph;
} STRUCT_PACKED;


static const char * ipaddr_str(u32 addr)
{
	static char buf[17];

	os_snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
		    (addr >> 24) & 0xff, (addr >> 16) & 0xff,
		    (addr >> 8) & 0xff, addr & 0xff);
	return buf;
}

static void printPacketBuffer(unsigned char *buffer,unsigned long buffLen)
{
	unsigned int i;

	if(!buffer)
		return;
	wpa_printf_new(MSG_DEBUG, ":::::::::::::::::::::::::::::::::::::::::::::::\n");
	
	for(i = 0;i < buffLen ; i++)
	{
		wpa_printf_new(MSG_DEBUG, "%02x ",buffer[i]);
		if(0==(i+1)%16) {
			wpa_printf_new(MSG_DEBUG, "\n");
		}
	}
	if((buffLen%16)!=0)
	{
		wpa_printf_new(MSG_DEBUG, "\n");
	}
	wpa_printf_new(MSG_DEBUG, ":::::::::::::::::::::::::::::::::::::::::::::::\n");
}

void arp_pkt_print(const struct arp_pkt *p)
{
	if (NULL == p)
		return ;
	wpa_printf_new(MSG_DEBUG, ":::::::::::::::::::::::::::::::::::::::::::::::\n");
	wpa_printf_new(MSG_DEBUG, "ethh.h_dest: " MACSTR "\n", MAC2STR(p->ethh.h_dest));
	wpa_printf_new(MSG_DEBUG, "ethh.h_source: " MACSTR "\n", MAC2STR(p->ethh.h_source));
	wpa_printf_new(MSG_DEBUG, "ethh.h_proto: %04x\n", p->ethh.h_proto);

	wpa_printf_new(MSG_DEBUG, "arph.ea_hdr.ar_hrd: %02x\n", p->arph.ea_hdr.ar_hrd);
	wpa_printf_new(MSG_DEBUG, "arph.ea_hdr.ar_pro: %02x\n", p->arph.ea_hdr.ar_pro);
	wpa_printf_new(MSG_DEBUG, "arph.ea_hdr.ar_hln: %04x\n", p->arph.ea_hdr.ar_hln);
	wpa_printf_new(MSG_DEBUG, "arph.ea_hdr.ar_pln: %04x\n", p->arph.ea_hdr.ar_pln);
	wpa_printf_new(MSG_DEBUG, "arph.ea_hdr.ar_op: %02x\n", p->arph.ea_hdr.ar_op);

	wpa_printf_new(MSG_DEBUG, "arph.arp_sha: " MACSTR "\n", MAC2STR(p->arph.arp_sha));
	wpa_printf_new(MSG_DEBUG, "arph.arp_spa: %d.%d.%d.%d\n", p->arph.arp_spa[0], 
														p->arph.arp_spa[1],
														p->arph.arp_spa[2],
														p->arph.arp_spa[3]);
	wpa_printf_new(MSG_DEBUG, "arph.arp_tha: " MACSTR "\n", MAC2STR(p->arph.arp_tha));
	wpa_printf_new(MSG_DEBUG, "arph.arp_tpa: %d.%d.%d.%d\n",  p->arph.arp_tpa[0], 
														p->arph.arp_tpa[1],
														p->arph.arp_tpa[2],
														p->arph.arp_tpa[3]);
	wpa_printf_new(MSG_DEBUG, ":::::::::::::::::::::::::::::::::::::::::::::::\n");

	return ;
}

static inline int set_address(const char *address, struct sockaddr *sa) {
    return inet_aton(address, &((struct sockaddr_in *)sa)->sin_addr);
}

/*
* ADD/DEL net/host route to kernel
* route add&del -net 192.168.1.0 netmask 255.255.255.0 dev br-vlan100
* route add&del -host 192.168.1.100 dev br-vlan100
*/
int sta_route_set(u32 dst, u32 subnet_mask, char *if_dev, RtMode rt_mode, RtOp rt_op)
{
	struct rtentry rt = {
		.rt_dst = {.sa_family = AF_INET},
		.rt_genmask = {.sa_family = AF_INET},
		.rt_gateway = {.sa_family = AF_INET},
	};
	int s = -1;
	errno = EINVAL;
	unsigned int retry_time = 0;

	if (dst == 0x0 || if_dev == NULL)
		return errno;
	
	if (rt_op == ADD_RT) 
		rt.rt_dev = if_dev;

	if (rt_mode == NET_RT) {
		if ((0x0 == subnet_mask) || (0xffff == subnet_mask))
			return errno;
		rt.rt_flags = RTF_UP | RTF_GATEWAY;
		if (set_address(ipaddr_str(dst), &rt.rt_dst) &&
            set_address(ipaddr_str(subnet_mask), &rt.rt_genmask)) {
            errno = 0;
        }
        goto apply;
	}
	else if (rt_mode == HOST_RT) {
		rt.rt_flags = RTF_UP | RTF_HOST;
		if (set_address(ipaddr_str(dst), &rt.rt_dst)) {
            errno = 0;
        }
        goto apply;
	}

	return errno;

apply:
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s != -1 && (ioctl(s, rt_op ? SIOCDELRT : SIOCADDRT, &rt) != -1)) {
		wpa_printf(MSG_DEBUG, "route_set success: DST[%s] SUBNET_MASK[%s] "
			"RtMode[%d] RtOp[%d]", ipaddr_str(dst), ipaddr_str(subnet_mask), rt_mode, rt_op);
	    return 0;
	}

	if ((rt_op == ADD_RT) && (errno == EEXIST) && (retry_time++ < 3)) {
		if (s != -1 && (ioctl(s, SIOCDELRT, &rt) != -1)) {
			wpa_printf(MSG_INFO, "route_set delete exist route entry, ADD route again.",
				ipaddr_str(dst), ipaddr_str(subnet_mask), rt_mode, rt_op);
		}
		
		goto apply;
	}
	
	wpa_printf(MSG_INFO, "route_set failed: DST[%s] SUBNET_MASK[%s] "
		"RtMode[%d] RtOp[%d], %s", ipaddr_str(dst), ipaddr_str(subnet_mask), rt_mode, rt_op, strerror(errno));


	return errno;
}

static void handle_arp(void *ctx, const u8 *src_addr, const u8 *buf,
			size_t len)
{
	struct hostapd_data *hapd = ctx;
	struct sta_info *sta;
	const struct arp_pkt *b;
	char *s;
	u32 ipaddr = 0, l;
	u8 *tmp;
	int i, res;

	

	//printPacketBuffer(buf, len);
	b = (const struct arp_pkt *)buf;

	//arp_pkt_print(b);

#if 0
	if ((b->arph.arp_spa[0] == b->arph.arp_tpa[0]) &&
		(b->arph.arp_spa[1] == b->arph.arp_tpa[1]) &&
		(b->arph.arp_spa[2] == b->arph.arp_tpa[2]) &&
		(b->arph.arp_spa[3] == b->arph.arp_tpa[3])) {
		/* gratuitous arp, ignore */
		return ;
	}
#endif

	sta = ap_get_sta(hapd, b->arph.arp_sha);
	if (!sta)
		return;

	ipaddr = ((b->arph.arp_spa[0] & 0xff) << 24) | ((b->arph.arp_spa[1] & 0xff) << 16)
				| ((b->arph.arp_spa[2] & 0xff) << 8) | ((b->arph.arp_spa[3] & 0xff) << 0);

	if ((ipaddr == 0x0) || (sta->ipaddr == ipaddr))
			return;

	if (!hapd->conf->ieee802_1x && !hapd->conf->wpa &&hapd->br_ipaddr == 0x0)
		sta_route_set(sta->ipaddr, 0, hapd->conf->bridge, HOST_RT, DEL_RT);	
	
	sta->ipaddr = ipaddr;
	if (!hapd->conf->ieee802_1x && !hapd->conf->wpa &&hapd->br_ipaddr == 0x0)
		sta_route_set(sta->ipaddr, 0, hapd->conf->bridge, HOST_RT, ADD_RT);
	
	wpa_printf(MSG_DEBUG, "arp_snoop: Found ARP for " MACSTR
		   " @ IPv4 address %s",
		   MAC2STR(b->arph.arp_sha), ipaddr_str(ntohl(ipaddr)));

}

static void handle_dhcp(void *ctx, const u8 *src_addr, const u8 *buf,
			size_t len)
{
	struct hostapd_data *hapd = ctx;
	const struct bootp_pkt *b;
	struct sta_info *sta;
	int exten_len;
	const u8 *end, *pos;
	int res, msgtype = 0, prefixlen = 32;
	u32 subnet_mask = 0;
	u16 tot_len;
	unsigned int lease_time;
	u8 *tmp;
	
	/*
	printPacketBuffer(buf, len);
	*/

	exten_len = len - ETH_HLEN - (sizeof(*b) - sizeof(b->exten));
	if (exten_len < 4)
		return;

	b = (const struct bootp_pkt *) &buf[ETH_HLEN];
	tot_len = ntohs(b->iph.tot_len);
	if (tot_len > (unsigned int) (len - ETH_HLEN))
		return;

	if (os_memcmp(b->exten, ic_bootp_cookie, ARRAY_SIZE(ic_bootp_cookie)))
		return;

	printf("dhcp_snoop: Found DHCP IPv4 address %s/%d",
		ipaddr_str(ntohl(b->your_ip)),
		prefixlen);

	/* Parse DHCP options */
	end = (const u8 *) b + tot_len;
	pos = &b->exten[4];
	while (pos < end && *pos != 0xff) {
		const u8 *opt = pos++;

		if (*opt == 0) /* padding */
			continue;

		pos += *pos + 1;
		if (pos >= end)
			break;

		switch (*opt) {
		case 1:  /* subnet mask */
			if (opt[1] == 4)
				subnet_mask = WPA_GET_BE32(&opt[2]);
			if (subnet_mask == 0)
				return;
			while (!(subnet_mask & 0x1)) {
				subnet_mask >>= 1;
				prefixlen--;
			}
			break;
		case 51:/*lease time*/
			if (opt[1] == 4)
				lease_time = opt[2];
			break;
		case 53: /* message type */
			if (opt[1])
				msgtype = opt[2];
			break;
		default:
			break;
		}
	}

	if (msgtype == DHCPACK) {
		if (b->your_ip == 0)
			return;

		/* DHCPACK for DHCPREQUEST */
		sta = ap_get_sta(hapd, b->hw_addr);
		if (!sta)
			return;

		wpa_printf(MSG_DEBUG, "dhcp_snoop: Found DHCPACK for " MACSTR
			   " @ IPv4 address %s/%d",
			   MAC2STR(sta->addr), ipaddr_str(ntohl(b->your_ip)),
			   prefixlen);

		if (sta->ipaddr == b->your_ip)
			return;

		if (!hapd->conf->ieee802_1x && !hapd->conf->wpa &&hapd->br_ipaddr == 0x0)
			sta_route_set(sta->ipaddr, 0, hapd->conf->bridge, HOST_RT, DEL_RT);
		
		sta->ipaddr = b->your_ip;
		sta->lease_time = lease_time;
		if (!hapd->conf->ieee802_1x && !hapd->conf->wpa &&hapd->br_ipaddr == 0x0)
			sta_route_set(sta->ipaddr, 0, hapd->conf->bridge, HOST_RT, ADD_RT);

#if 0 /* temporarily close  */
		if (sta->ipaddr != 0) {
			wpa_printf(MSG_DEBUG,
				   "dhcp_snoop: Removing IPv4 address %s from the ip neigh table",
				   ipaddr_str(be_to_host32(sta->ipaddr)));
			hostapd_drv_br_delete_ip_neigh(hapd, 4,
						       (u8 *) &sta->ipaddr);
		}

		res = hostapd_drv_br_add_ip_neigh(hapd, 4, (u8 *) &b->your_ip,
						  prefixlen, sta->addr);
		if (res) {
			wpa_printf(MSG_DEBUG,
				   "dhcp_snoop: Adding ip neigh table failed: %d",
				   res);
			return;
		}
		sta->ipaddr = b->your_ip;
#endif
		send_msg_to_eag(hapd, sta, STA_ADD);
		send_msg_to_arpp(hapd, sta);
		send_user_sync_info(hapd, sta, SYNC_STA_ADD);
	}

	if ((hapd->conf->disable_dgaf || hapd->conf->dhcp_unicast) && is_broadcast_ether_addr(buf)) {
		for (sta = hapd->sta_list; sta; sta = sta->next) {
			if (!(sta->flags & WLAN_STA_AUTHORIZED))
				continue;
			x_snoop_mcast_to_ucast_convert_send(hapd, sta,
							    (u8 *) buf, len);
		}
	}
}


int dhcp_snoop_init(struct hostapd_data *hapd)
{
	char brname[IFNAMSIZ];

	hapd->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (hapd->ioctl_sock < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}
	if (linux_br_get(brname, hapd->conf->iface) == 0) {
		if (linux_get_ifaddr(hapd->ioctl_sock, brname, &(hapd->br_ipaddr))== 0) {
			wpa_printf(MSG_DEBUG, "Bridge %s IP " IPSTR " ", 
				brname, IP2STR(hapd->br_ipaddr));
		}
	}
	
	hapd->sock_dhcp = x_snoop_get_l2_packet(hapd, handle_dhcp,
						L2_PACKET_FILTER_DHCP);

	if (hapd->sock_dhcp == NULL) {
		wpa_printf(MSG_DEBUG,
			   "dhcp_snoop: Failed to initialize L2 packet processing for DHCP packet: %s",
			   strerror(errno));
		return -1;
	}

	hapd->sock_arp = x_snoop_get_l2_packet(hapd, handle_arp,
						L2_PACKET_FILTER_ARP);

	if (hapd->sock_arp == NULL) {
		wpa_printf(MSG_DEBUG,
			   "dhcp_snoop: Failed to initialize L2 packet processing for ARP packet: %s",
			   strerror(errno));
		return -1;
	}

	return 0;
}


void dhcp_snoop_deinit(struct hostapd_data *hapd)
{
	l2_packet_deinit(hapd->sock_dhcp);
	l2_packet_deinit(hapd->sock_arp);
}
