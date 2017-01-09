/******************************************************************************
  File Name    : dnsrd_kmod.c
  Author       : lhc
  Date         : 20160302
  Description  : kernel proc msg
******************************************************************************/
#include <linux/types.h>
#include <net/sock.h>
#include <net/netlink.h> 
#include <linux/ip.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/kobject.h>

#include "dnsrd_kmod.h"

#define KDNSRD_ON               0
#define KDNSRD_OFF              1
#define KDNSRD_UDP_PROTOCOL     17
#define DNSRD_DNS_PROTOCOL      53
#define DNSRD_APURLLEN          128

DEFINE_SPINLOCK(dnsrd_lock);

struct dnsrd_msghdr{
	char ifname[20];
	unsigned char src_mac[6];
	unsigned char dst_mac[6];
};

static int g_dnsrdpid = -1;
static int kdnsrd_switch = KDNSRD_ON;
static struct sock *kdnsrd_sockfd = NULL;
char g_ap_mgmt_url[DNSRD_APURLLEN];

extern void (*kdrm_filter_packet_cb)(struct sk_buff *skb);

/******************************************************************************
  Function Name    : kdnsrd_sendmsg
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd kernel mod send msg
  Param            : const void *data     send date
                     int datelen          date len
                     struct dnsrd_msghdr *msgpst	message head
  return Code      : 
******************************************************************************/
static void kdnsrd_sendmsg(const void *data, int datelen, struct dnsrd_msghdr *msgpst)
{
    struct sk_buff *skb = NULL;
    struct nlmsghdr *nlmhdr = NULL;
    unsigned int len = 0;
    int sendret = 0;

    if (NULL == kdnsrd_sockfd || NULL == data)
    {
        return;
    }

    len = datelen + sizeof(struct nlmsghdr) + sizeof(struct dnsrd_msghdr);
    skb = alloc_skb(len, GFP_KERNEL);
    if (NULL == skb)
    {
        printk(KERN_WARNING "[dnsrd_kmod]: skb Malloc Failed!\r\n");
        return;
    }

    nlmhdr = nlmsg_put(skb, 0, 0, 0, len - sizeof(struct nlmsghdr), 0);
    NETLINK_CB(skb).portid = g_dnsrdpid;
    NETLINK_CB(skb).dst_group = 0;
    memcpy(nlmsg_data(nlmhdr), msgpst, sizeof(struct dnsrd_msghdr));
	memcpy(nlmsg_data(nlmhdr) + sizeof(struct dnsrd_msghdr), data, datelen);
    sendret = netlink_unicast(kdnsrd_sockfd, skb, g_dnsrdpid, MSG_DONTWAIT);
    
    return;
}

/******************************************************************************
  Function Name    : kdnsrd_filter_packet
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd kernel filter packet
  Param            : struct sk_buff  *skb          network packet struct
  return Code      : 
******************************************************************************/
void kdnsrd_filter_packet(struct sk_buff *skb)
{
    if (KDNSRD_ON != kdnsrd_switch)
    {
        return;
    }

	struct ethhdr *machdr;
    struct iphdr *ipptr = NULL;
    struct udpstruct *udpptr;
    unsigned char *buf;
	struct dnsrd_msghdr msghdr;
    
    if (NULL == skb || NULL == skb->dev)
    {
        return;
    }

    if (skb->len < sizeof(struct iphdr))
    {
        return;
    }
    
    ipptr = (struct iphdr *)(skb->data);
    if (KDNSRD_UDP_PROTOCOL != ipptr->protocol)
    {
        return;
    }
    
    udpptr = (struct udpstruct *)(skb->data + sizeof(struct iphdr));

    if (skb->len - sizeof(struct iphdr) < sizeof(struct udpstruct))
    {
        return;
    }

    if (DNSRD_DNS_PROTOCOL != (int)(udpptr->dstport))
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
    
    printk(KERN_DEBUG "[dnsrd_kmod]: strcmp url sucess,dev_name:[%s]\r\n", skb->dev->name);

	machdr = (struct ethhdr *)(skb->mac_header);
	memset(&msghdr, 0, sizeof(msghdr));
	memcpy(msghdr.ifname, skb->dev->name, strlen(skb->dev->name));
	memcpy(msghdr.src_mac, machdr->h_source, sizeof(msghdr.src_mac));
	memcpy(msghdr.dst_mac, machdr->h_dest, sizeof(msghdr.src_mac));
    
    kdnsrd_sendmsg(skb->data, skb->len, &msghdr);

    /* set reponse */
    *buf = 0;
    *(buf + 1) = 1;

    return;
}

/******************************************************************************
  Function Name    : kdnsrd_receive_skb
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd kernel mod recv msg
  Param            : struct sk_buff  *skb          network packet struct
  return Code      : 
******************************************************************************/
static void kdnsrd_receive_skb(struct sk_buff *skb)
{
    struct nlmsghdr *nlmhdr = NULL;
    char *ap_mgmt_url = NULL;
    
    if (skb->len >= 0)
    {
        nlmhdr = nlmsg_hdr(skb);
        g_dnsrdpid = NETLINK_CB(skb).portid;
        
        ap_mgmt_url = nlmsg_data(nlmhdr);
        spin_lock(&dnsrd_lock);
        memcpy(g_ap_mgmt_url, ap_mgmt_url, DNSRD_APURLLEN);
        printk(KERN_DEBUG "[dnsrd_kmod]: dnsrd_kmod receive msg from dnsrd_umod\r\n");
        spin_unlock(&dnsrd_lock);
    }
    
    return;
}

/******************************************************************************
  Function Name    : kdnsrd_receive
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd kernel mod recv msg
  Param            : struct sk_buff  *skb          network packet struct
  return Code      : 
******************************************************************************/
static void kdnsrd_receive(struct sk_buff  *skb)
{
	kdnsrd_receive_skb(skb);

    return;
}

/******************************************************************************
  Function Name    : kdnsrd_switchshow
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd kernel mod switct value show
  Param            : struct kobject *kobj 
                     struct kobj_attribute 
  return Code      : 
******************************************************************************/
static ssize_t kdnsrd_switchshow(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%u\r\n", kdnsrd_switch);
}

/******************************************************************************
  Function Name    : kdnsrd_switchset
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd kernel mod switct set
  Param            : struct kobject *kobj 
                     struct kobj_attribute *attr 
                     size_t size 
                     const char *buf                set value
  return Code      :
******************************************************************************/
static ssize_t kdnsrd_switchset(struct kobject *kobj, struct device_attribute *attr, const char *buf, size_t size)
{
    unsigned int state;
    unsigned long ret;
 	ret = kstrtoul(buf, 10, &state);
    if (ret == 0)
    {
        kdnsrd_switch = state;
    }

    return 1;
}

static struct kobj_attribute kdnsrd_state = __ATTR(kdnsrd_disable, 0644, kdnsrd_switchshow, kdnsrd_switchset); 
static struct attribute *kdnsrd_control[] = {
    &kdnsrd_state.attr,
    NULL,
};
static struct attribute_group kdnsrd_group = {
    .attrs = kdnsrd_control,
};

static int sysfs_status = 0 ;
struct kobject *soc_kobj = NULL;
/******************************************************************************
  Function Name    : kdnsrd_switch_init
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd kernel mod switct exit
  Param            : 
  return Code      : == 0  init suc
                     != 0   init fail
******************************************************************************/
int kdnsrd_switch_init(void)
{
    int ret = 0;
    
    soc_kobj = kobject_create_and_add("kdnsrd_control", NULL);
    if (0 == soc_kobj)
    {
        return -1;
    }
    
    ret = sysfs_create_group(soc_kobj, &kdnsrd_group);
    if (0 != ret)
    {
        sysfs_remove_group(soc_kobj, &kdnsrd_group);
        kobject_put(soc_kobj);
        return -1;
    }
    
    sysfs_status = 1;
    
    return 0;
}


/******************************************************************************
  Function Name    : kdnsrd_switch_exit
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd kernel mod switct exit
  Param            : 
  return Code      :
******************************************************************************/
void kdnsrd_switch_exit(void)
{
    sysfs_remove_group(soc_kobj, &kdnsrd_group);
    kobject_put(soc_kobj);
       
    return;
}

/******************************************************************************
  Function Name    : kdnsrd_init
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd kernel mod init
  Param            : 
  return Code      : == 0  init suc
                     != 0   init fail
******************************************************************************/
static int __init kdnsrd_init(void)
{
 	struct netlink_kernel_cfg cfg = {
		.input	= kdnsrd_receive,
	};

    if (0 != kdnsrd_switch_init())
    {
        printk(KERN_ERR "[dnsrd_kmod]: mod switch init failed, kmod exit\r\n");
        return -1;
    }
    
    kdnsrd_sockfd = netlink_kernel_create(&init_net, NETLINK_DRM, &cfg);
    if (NULL == kdnsrd_sockfd)
    {
        kdnsrd_switch_exit();
        printk(KERN_ERR "[dnsrd_kmod]: netlink create failed, kmod exit\r\n");
        return -1;
    }

    kdrm_filter_packet_cb = kdnsrd_filter_packet;

    return 0;
}

/******************************************************************************
  Function Name    : kdnsrd_exit
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd kernel mod exit
  Param            :
  return Code      :
******************************************************************************/
static void __exit kdnsrd_exit(void)
{
    if (NULL != kdnsrd_sockfd)
    {
        netlink_kernel_release(kdnsrd_sockfd);
    }
    
    kdnsrd_switch_exit();
    
    kdrm_filter_packet_cb = NULL;
}

subsys_initcall(kdnsrd_init);
module_exit(kdnsrd_exit);
MODULE_LICENSE("GPL");
