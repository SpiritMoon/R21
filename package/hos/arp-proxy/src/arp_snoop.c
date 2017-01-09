/*
 * ARP snooping for ARP Proxy
 * Copyright (c) 2016, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include "common.h"
#include "debug.h"
#include "l2_packet.h"
#include "arp_proxy.h"
#include "arp_snoop.h"
#include "arpp_tbl.h"


struct arp_pkt {
	struct ethhdr ethh;
	struct ether_arp arph;
} STRUCT_PACKED;


#define DHCPACK	5
static const u8 ic_bootp_cookie[] = { 99, 130, 83, 99 };
extern int golbal_arp_proxy_switch;
void printPacketBuffer(unsigned char *buffer,unsigned long buffLen)
{
	unsigned int i;

	if(!buffer)
		return;
	arpp_printf(ARPP_DEBUG, ":::::::::::::::::::::::::::::::::::::::::::::::\n");
	
	for(i = 0;i < buffLen ; i++)
	{
		arpp_printf(ARPP_DEBUG, "%02x ",buffer[i]);
		if(0==(i+1)%16) {
			arpp_printf(ARPP_DEBUG, "\n");
		}
	}
	if((buffLen%16)!=0)
	{
		arpp_printf(ARPP_DEBUG, "\n");
	}
	arpp_printf(ARPP_DEBUG, ":::::::::::::::::::::::::::::::::::::::::::::::\n");
}

static const char * ipaddr_str(u32 addr)
{
	static char buf[17];

	os_snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
		    (addr >> 24) & 0xff, (addr >> 16) & 0xff,
		    (addr >> 8) & 0xff, addr & 0xff);
	return buf;
}

void arp_pkt_print(const struct arp_pkt *p)
{
	if (NULL == p)
		return ;
	arpp_printf(ARPP_DEBUG, ":::::::::::::::::::::::::::::::::::::::::::::::\n");
	arpp_printf(ARPP_DEBUG, "ethh.h_dest: " MACSTR "\n", MAC2STR(p->ethh.h_dest));
	arpp_printf(ARPP_DEBUG, "ethh.h_source: " MACSTR "\n", MAC2STR(p->ethh.h_source));
	arpp_printf(ARPP_DEBUG, "ethh.h_proto: %04x\n", p->ethh.h_proto);

	arpp_printf(ARPP_DEBUG, "arph.ea_hdr.ar_hrd: %02x\n", p->arph.ea_hdr.ar_hrd);
	arpp_printf(ARPP_DEBUG, "arph.ea_hdr.ar_pro: %02x\n", p->arph.ea_hdr.ar_pro);
	arpp_printf(ARPP_DEBUG, "arph.ea_hdr.ar_hln: %04x\n", p->arph.ea_hdr.ar_hln);
	arpp_printf(ARPP_DEBUG, "arph.ea_hdr.ar_pln: %04x\n", p->arph.ea_hdr.ar_pln);
	arpp_printf(ARPP_DEBUG, "arph.ea_hdr.ar_op: %02x\n", p->arph.ea_hdr.ar_op);

	arpp_printf(ARPP_DEBUG, "arph.arp_sha: " MACSTR "\n", MAC2STR(p->arph.arp_sha));
	arpp_printf(ARPP_DEBUG, "arph.arp_spa: %d.%d.%d.%d\n", p->arph.arp_spa[0], 
														p->arph.arp_spa[1],
														p->arph.arp_spa[2],
														p->arph.arp_spa[3]);
	arpp_printf(ARPP_DEBUG, "arph.arp_tha: " MACSTR "\n", MAC2STR(p->arph.arp_tha));
	arpp_printf(ARPP_DEBUG, "arph.arp_tpa: %d.%d.%d.%d\n",  p->arph.arp_tpa[0], 
														p->arph.arp_tpa[1],
														p->arph.arp_tpa[2],
														p->arph.arp_tpa[3]);
	arpp_printf(ARPP_DEBUG, ":::::::::::::::::::::::::::::::::::::::::::::::\n");

	return ;
}

int handle_nl_arp(struct arpp_interfaces *interfaces, struct arppm_nl_msg *nl_msg)
{
	char brname[IFNAMSIZ];;
	const struct arp_pkt *b = (const struct arp_pkt *)nl_msg->arp_req_pkt;
	struct arp_pkt *r;
	arpp_item_t *item = NULL;
	u32 ipaddr = 0, l, id;
	char *s;
	int i, res;

	if ((b->arph.arp_spa[0] == b->arph.arp_tpa[0]) &&
		(b->arph.arp_spa[1] == b->arph.arp_tpa[1]) &&
		(b->arph.arp_spa[2] == b->arph.arp_tpa[2]) &&
		(b->arph.arp_spa[3] == b->arph.arp_tpa[3])) {
		/* gratuitous arp, ignore */
		return 1;
	}

	ipaddr = ((b->arph.arp_tpa[0] & 0xff) << 24) | ((b->arph.arp_tpa[1] & 0xff) << 16)
				| ((b->arph.arp_tpa[2] & 0xff) << 8) | ((b->arph.arp_tpa[3] & 0xff) << 0);

	item = arpp_tbl_item_find_by_ip(ipaddr);

	if (NULL == item) {
		arpp_printf(ARPP_DEBUG, "Failed to find user mac by ip %s\n", u32ip2str(ipaddr));
		return 1;
	}

	r = os_malloc(sizeof(struct arp_pkt));
	if (NULL == r) {
		arpp_printf(ARPP_ERROR, "%s: Failed to malloc!!!\n", __func__);
		return -1;
	}
	os_memset(r, 0, sizeof(struct arp_pkt));

	os_memcpy(r->ethh.h_dest, b->ethh.h_source, ETH_ALEN);
	os_memcpy(r->ethh.h_source, item->chaddr, ETH_ALEN);
	r->ethh.h_proto = htons(0x0806);
	r->arph.ea_hdr.ar_hrd = htons(0x1);
	r->arph.ea_hdr.ar_pro = htons(0x0800);
	r->arph.ea_hdr.ar_hln = 0x6;
	r->arph.ea_hdr.ar_pln = 0x4;
	r->arph.ea_hdr.ar_op = htons(0x2);
	os_memcpy(r->arph.arp_sha, item->chaddr, ETH_ALEN);
	os_memcpy(r->arph.arp_tha, b->ethh.h_source, ETH_ALEN);
	for (i = 0; i < 4; i++) {
		r->arph.arp_spa[i] = b->arph.arp_tpa[i];
		r->arph.arp_tpa[i] = b->arph.arp_spa[i];
	}

	//arp_pkt_print(r);
	s = os_malloc(sizeof(struct arp_pkt) + 12);
	if (NULL == s) {
		arpp_printf(ARPP_ERROR, "%s: Failed to malloc!!!\n", __func__);
		return ;
	}
	os_memset(s, 0, sizeof(struct arp_pkt) + 12);

	os_memcpy(s, r, sizeof(struct arp_pkt));
	l = sizeof(struct arp_pkt);
	s[l+1] = 0x11;
	s[l+2] = 0x22;
	s[l+3] = 0x33;

	if (linux_br_get(brname, nl_msg->ifname)) {
		arpp_printf(ARPP_DEBUG, "Failed to get br with %s\n", nl_msg->ifname);
		return 1;
	}
	
	if (arpp_find_iface(interfaces, brname, &id)) {
		arpp_printf(ARPP_DEBUG, "Failed to get iface with %s\n", brname);
		return 1;
	}

	if (interfaces->iface[id]->sock_arp) {
		res = l2_packet_send(interfaces->iface[id]->sock_arp, NULL, 0,
								(u8 *)s, sizeof(struct arp_pkt) + 12);
		if (res < 0) {
			arpp_printf(ARPP_DEBUG,
				   "%s: Failed to send ARP reply packet to "
				   MACSTR, MAC2STR(r->ethh.h_source));

			return 1;
		}
	}

	if (r)
		os_free(r);

	if (s)
		os_free(s);

	return 0;
}

static void handle_arp(void *ctx, const u8 *src_addr, const u8 *buf,
			size_t len)
{
	struct arpp_iface *arpp_if = ctx;
	const struct arp_pkt *b;
	struct arp_pkt *r;
	char *s;
	u32 ipaddr = 0, l;
	arpp_item_t *item = NULL;
	u8 *tmp;
	int i, res;
	
	if( !golbal_arp_proxy_switch ){
		//sleep(500);
		return;
	}
	
	//printPacketBuffer(buf, len);
	b = (const struct arp_pkt *)buf;

	//arp_pkt_print(b);

	if ((b->arph.arp_spa[0] == b->arph.arp_tpa[0]) &&
		(b->arph.arp_spa[1] == b->arph.arp_tpa[1]) &&
		(b->arph.arp_spa[2] == b->arph.arp_tpa[2]) &&
		(b->arph.arp_spa[3] == b->arph.arp_tpa[3])) {
		/* gratuitous arp, ignore */
		return ;
	}

	ipaddr = ((b->arph.arp_tpa[0] & 0xff) << 24) | ((b->arph.arp_tpa[1] & 0xff) << 16)
				| ((b->arph.arp_tpa[2] & 0xff) << 8) | ((b->arph.arp_tpa[3] & 0xff) << 0);

	item = arpp_tbl_item_find_by_ip(ipaddr);

	if (NULL == item) {
		arpp_printf(ARPP_DEBUG, "Failed to find user mac by ip %s\n", u32ip2str(ipaddr));
		return ;
	}

	r = os_malloc(sizeof(struct arp_pkt));
	if (NULL == r) {
		arpp_printf(ARPP_ERROR, "%s: Failed to malloc!!!\n", __func__);
		return ;
	}
	os_memset(r, 0, sizeof(struct arp_pkt));

	os_memcpy(r->ethh.h_dest, b->ethh.h_source, ETH_ALEN);
	os_memcpy(r->ethh.h_source, item->chaddr, ETH_ALEN);
	r->ethh.h_proto = htons(0x0806);
	r->arph.ea_hdr.ar_hrd = htons(0x1);
	r->arph.ea_hdr.ar_pro = htons(0x0800);
	r->arph.ea_hdr.ar_hln = 0x6;
	r->arph.ea_hdr.ar_pln = 0x4;
	r->arph.ea_hdr.ar_op = htons(0x2);
	os_memcpy(r->arph.arp_sha, item->chaddr, ETH_ALEN);
	os_memcpy(r->arph.arp_tha, b->ethh.h_source, ETH_ALEN);
	for (i = 0; i < 4; i++) {
		r->arph.arp_spa[i] = b->arph.arp_tpa[i];
		r->arph.arp_tpa[i] = b->arph.arp_spa[i];
	}

	//arp_pkt_print(r);
	s = os_malloc(sizeof(struct arp_pkt) + 12);
	if (NULL == s) {
		arpp_printf(ARPP_ERROR, "%s: Failed to malloc!!!\n", __func__);
		return ;
	}
	os_memset(s, 0, sizeof(struct arp_pkt) + 12);

	os_memcpy(s, r, sizeof(struct arp_pkt));
	l = sizeof(struct arp_pkt);
	s[l+1] = 0x11;
	s[l+2] = 0x22;
	s[l+3] = 0x33;

	res = l2_packet_send(arpp_if->sock_arp, NULL, 0, (u8 *)s, sizeof(struct arp_pkt) + 12);
	if (res < 0) {
		arpp_printf(ARPP_DEBUG,
			   "%s: Failed to send ARP reply packet to "
			   MACSTR, MAC2STR(r->ethh.h_source));
	}

	//os_free(r);
	
#if 0
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
		case 6: /* dns */
			dns_flag = 1;
			if (opt[1] == 4) {
				dns1 = WPA_GET_BE32(&opt[2]);
				tmp = (u8 *)&dns1;
				wpa_printf(MSG_DEBUG, "%d.%d.%d.%d\n", tmp[0], tmp[1], tmp[2], tmp[3]);
			}
			if (opt[1] == 8) {
				dns1 = WPA_GET_BE32(&opt[2]);
				dns2 = WPA_GET_BE32(&opt[6]);
			
				tmp = (u8 *)&dns1;
				wpa_printf(MSG_DEBUG, "dns1 %d.%d.%d.%d\n", tmp[0], tmp[1], tmp[2], tmp[3]);
				tmp = (u8 *)&dns2;
				wpa_printf(MSG_DEBUG, "dns2 %d.%d.%d.%d\n", tmp[0], tmp[1], tmp[2], tmp[3]);
			}
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

		sta->ipaddr = b->your_ip;
		if (dns_flag) {
			sta->dns[0] = dns1;
			sta->dns[1] = dns2;
		}

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
	}

	if ((hapd->conf->disable_dgaf || hapd->conf->dhcp_unicast) && is_broadcast_ether_addr(buf)) {
		for (sta = hapd->sta_list; sta; sta = sta->next) {
			if (!(sta->flags & WLAN_STA_AUTHORIZED))
				continue;
			x_snoop_mcast_to_ucast_convert_send(hapd, sta,
							    (u8 *) buf, len);
		}
	}
#endif
}


int arp_snoop_init(struct arpp_iface *arpp_if)
{
	struct l2_packet_data *l2;

	l2 = l2_packet_init(arpp_if->ifname, NULL, ETH_P_ALL, handle_arp, arpp_if, 1);
	if (l2 == NULL) {
		arpp_printf(ARPP_DEBUG,
			   "arp_snoop: Failed to initialize L2 packet processing %s",
			   strerror(errno));
		return -1;
	}

	if (l2_packet_set_packet_filter(l2, L2_PACKET_FILTER_ARP)) {
		arpp_printf(ARPP_DEBUG,
			   "arp_snoop: Failed to set L2 packet filter for type: %d",
			   L2_PACKET_FILTER_ARP);
		l2_packet_deinit(l2);
		return -1;
	}

	if (l2 == NULL) {
		arpp_printf(ARPP_DEBUG,
			   "arp_snoop: Failed to initialize %s L2 packet processing for ARP packet: %s",
			   arpp_if->ifname, strerror(errno));
		return -1;
	}else {
		arpp_if->sock_arp = l2;
	}

	return 0;
}


void arp_snoop_deinit(struct arpp_iface *arpp_if)
{
	l2_packet_deinit(arpp_if->sock_arp);
}

