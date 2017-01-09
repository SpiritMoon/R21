/*
 * arp-proxy
 * Copyright (c) 2016-2017, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <linux/types.h>
#include <net/sock.h>
#include <net/netlink.h> 
#include <linux/ip.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/etherdevice.h>

#include "arpp_kmod.h"

#define ARPPM_OFF 0

static struct sock *arppm_sock = NULL;

int arppm_switch = 0;
module_param(arppm_switch,int,0644);

int arppm_debug = 0;
module_param(arppm_debug,int,0644);

extern void (*arppm_filter_skb_cb)(struct sk_buff *skb, int *ret);

void printPacketBuffer(unsigned char *buffer,unsigned long buffLen)
 {
	 unsigned int i;
 
	 if(!buffer)
		 return;
	 printk(":::::::::::::::::::::::::::::::::::::::::::::::\n");
	 
	 for(i = 0;i < buffLen ; i++)
	 {
		 printk("%02x ",buffer[i]);
		 if(0==(i+1)%16) {
			 printk("\n");
		 }
	 }
	 if((buffLen%16)!=0)
	 {
		 printk("\n");
	 }
	 printk(":::::::::::::::::::::::::::::::::::::::::::::::\n");
 }

static int arppm_netlink_send(const void *data, int date_len)
{	
	struct sk_buff *skb;   
	struct nlmsghdr *nlh;  
	int size = NLMSG_SPACE(date_len);
	int ret = -1;
	
	if(NULL == arppm_sock || NULL == data){   
		return -1;   
	}	

	/* Allocate a new sk_buffer */	
	skb = alloc_skb(size, GFP_ATOMIC);	 
	if(!skb){	
		printk("[arppm_netlink_send]: alloc_skb Error.\n");   
		return -1;   
	}

	/* Initialize the header of netlink message */	
	nlh = nlmsg_put(skb, 0, 0, 0, size - sizeof(struct nlmsghdr), 0);	
  
	NETLINK_CB(skb).portid = 0;   
	NETLINK_CB(skb).dst_group = 1;	 
	
	memcpy(NLMSG_DATA(nlh), data, date_len);
	
	/* send message by broadcast */  
	if (netlink_broadcast(arppm_sock, skb, 0, 1, GFP_ATOMIC))
		return -1;

	return 0;
	
nlmsg_failure: 
	if(skb)
		kfree_skb(skb);
	return -1;
}


/******************************************************************************
  Function Name    : kdrm_filter_packet
  Author           : lhc
  Date             : 20160302
  Description      : drm kernel filter packet
  Param            : struct sk_buff  *skb          network packet struct
  return Code      : 
******************************************************************************/
void arppm_filter_skb(struct sk_buff *skb, int *ret)
{
    if (ARPPM_OFF == arppm_switch) {
        return;
	}

	struct arphdr *arph;
	struct arppm_nl_msg arp_req;
	const unsigned char *dest;
    
    if ((NULL == skb) || 
		(skb->len < ARP_PKT_MIN_LEN)) {
        return;
    }
	
	if ((skb->protocol != ETH_P_ARP) || 
		(NULL == rcu_dereference(skb->dev->rx_handler))) {
		return;
	}
	
	if (arppm_debug) {
		printk("[arpp-kmod]: dev->name = %s, protocol = %x\n", 
			skb->dev->name, skb->protocol);
		printk("[arpp-kmod]: skb->vlan_proto = %d\n", skb->vlan_proto);
		printk("[arpp-kmod]: skb->mac_header = %x, skb->network_header = %x\n",
				skb->mac_header, skb->network_header);
		printPacketBuffer(skb->data, skb->len);
	}
    
    arph = (struct arphdr *)(skb->data);
	dest = skb->data - ETH_HLEN;
	if ((arph->ar_op == ARPOP_REQUEST) &&
		is_broadcast_ether_addr(dest)) {
		memcpy(arp_req.ifname, skb->dev->name, IFNAMSIZ);
		memcpy(arp_req.arp_req_pkt, skb->data - ETH_HLEN, ARP_PKT_MIN_LEN);
		if (arppm_debug) {
			printk("[arpp-kmod]: arp_req.ifname = %s\n", arp_req.ifname);
			printPacketBuffer(&arp_req, IFNAMSIZ + ARP_PKT_MIN_LEN);
		}

		if (!arppm_netlink_send(&arp_req, sizeof(struct arppm_nl_msg))) {
			if (arppm_debug)
				printk("[arpp-kmod]: arppm_netlink_send success\n");
			*ret = 1;
			return;
		}
	}

#if 0
    if (DRM_DNS_PROTOCOL != (int)(udpptr->dstport))
    {
        return;
    }
    
    buf = (unsigned char *)(skb->data + sizeof(struct iphdr) + sizeof(struct udpstruct));
    if (0 != (*(buf + 2) >> 7))
    {
        return;
    }

    if (0 != strcmp(g_ap_mgmt_url, buf + 12))
    {
        return;
    }
    
    printk(KERN_DEBUG "[drm kmod]: strcmp url sucess\r\n");
    
    kdrm_sendmsg(skb->data, skb->len);

    /* set reponse */
    *buf = 0;
    *(buf + 1) = 1;
#endif
    return;
}

void arppm_send_arp_pkt(struct arppm_nl_msg *nl_msg)
{
	char *ifname = NULL;
	struct sk_buff *skb;
	struct net_device *dev;

	if (nl_msg == NULL) {
		return;
	}

	if (arppm_debug)
		printk("[arppm_send_arp_pkt]: nl_msg->ifname = %s\n", nl_msg->ifname);

	dev = dev_get_by_name(&init_net, nl_msg->ifname);
	if (!dev) {
		printk("[arppm_send_arp_pkt]: dev_get_by_name %s Error.\n", nl_msg->ifname); 
	}
	
	/* Allocate a new sk_buffer */	
	skb = dev_alloc_skb(64);	 
	if(!skb){	
		printk("[arppm_send_arp_pkt]: alloc_skb Error.\n");   
		return -1;   
	}

	skb->dev = dev;
	skb->protocol = 0x806;
	memcpy(skb->data, (char *)nl_msg->arp_req_pkt, ARP_PKT_MIN_LEN);
	skb->len = 64 - ETH_HLEN;
	skb->mac_header = skb->data;
	skb->tail = skb->data + 64;
	skb->data += ETH_HLEN;

	if (arppm_debug) {
		printk("[arppm_send_arp_pkt]: dev->name = %s\n", dev->name);
		printPacketBuffer(skb->data, skb->len);
	}

	//kfree_skb(skb);

	__netif_receive_skb(skb);
	
	return;
}

/**
 * 
 * 
 *
 * @return Zero on success
 */
static void arppm_nl_receive(struct sk_buff  *skb)
{
	int nlmsglen, skblen;
	struct nlmsghdr *nlh;
	struct arppm_nl_msg *nl_msg;
	int ret;

	skblen = skb->len;
	if (skblen < sizeof(*nlh))
		return;

	nlh = nlmsg_hdr(skb);
	nlmsglen = nlh->nlmsg_len;
	if (nlmsglen < sizeof(*nlh) || skblen < nlmsglen)
		return;

	nl_msg = (struct arppm_nl_msg *)NLMSG_DATA(nlh);

	if (arppm_debug)
		printPacketBuffer(nl_msg, IFNAMSIZ + ARP_PKT_MIN_LEN);

	arppm_send_arp_pkt(nl_msg);
	
    return;
}

/**
 * Module/ driver initialization. Creates the linux network
 * devices.
 *
 * @return Zero on success
 */
static int __init arppm_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input = arppm_nl_receive,
	};
	
	arppm_sock = netlink_kernel_create(&init_net, NETLINK_ARPPM, &cfg);
    if (NULL == arppm_sock) {
        printk(KERN_ERR "[arpp-kmod]: netlink create failed, kmod exit\r\n");
        return -1;
	}
	
    arppm_filter_skb_cb = arppm_filter_skb;

    return 0;
}

/**
 * Module / driver shutdown
 *
 * @return Zero on success
 */
static void __exit arppm_exit(void)
{   
    arppm_filter_skb_cb = NULL;

	if (NULL != arppm_sock) {
        netlink_kernel_release(arppm_sock);
	}
}

subsys_initcall(arppm_init);
module_exit(arppm_exit);

MODULE_LICENSE("HAN");
MODULE_AUTHOR("HAN");
MODULE_DESCRIPTION("ARP Proxy");
