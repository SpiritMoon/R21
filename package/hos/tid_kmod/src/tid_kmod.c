/******************************************************************************
  �� �� ��   : kernel_tid.c
  ��    ��   : wenjue
  ��������   : 2014��11��19��
  ��������   : �ն�ʶ��ģ�������Ӧ���Ĳ����豸��Ϣ���͸�UMģ��
******************************************************************************/
#include <linux/types.h>
#include <net/sock.h>
#include <net/netlink.h> 
#include <linux/ip.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include "tid_kmod.h"

#define KTID_IP 0X800
#define KTID_ON 0
#define KTID_OFF 1

#define KTID_HTTP_PROTOCOL 1
#define KTID_DHCP_PROTOCOL 2
#define KTID_NETBIOS_PROTOCOL 3
#define KTID_BONJOUR_PROTOCOL 4

#define KTID_TCP_PROTOCOL     6
#define KTID_UDP_PROTOCOL     17
#define KTID_HTTPSERVER_PORT  80
#define KTID_DHCPSERVER_PORT  67
#define KTID_DHCPCLIENT_PORT  68
#define KTID_NETBIOSSERVER_PORT  138
#define KTID_BONJOURSERVER_PORT  5353

#define KTID_BONJOUR_RESPONSE 33792 /*0X8400*/
#define KTID_NETBIOS_REQUEST  17
#define KTID_BONJOUR_HINFOMSG 13
#define KTID_NETBIOS_MSGLEN   168
#define KTID_NETBIOS_COMMANDTYPE 2

static int g_tidpid = -1;
static int ktid_switch = KTID_ON;
static struct timer_list ktid_timer;
static struct sock *ktid_sockfd = NULL;
static struct tidtablehead g_sttidtabhd = {
    .next = NULL,
};

extern void (*ktid_filter_packet_cb)(struct sk_buff *skb);
DEFINE_SPINLOCK(tid_lock);

struct tidmachdr{
    unsigned char mac[6];
    unsigned short portocoltype;
    unsigned int datalen;
};

/*****************************************************************************
 �� �� ��  : ktid_set_flag
 ��������  : ���ù��˱����нڵ�����˵�Э������
 �������  : char flagtype, ����˵�Э�����ͱ�ʶ
 �������  : struct tidtable *psttidtabnode, ��Ҫ���ù��˱�ʶ�Ľڵ�
 �� �� ֵ  : ��
 ��   ��   : wenjue
*****************************************************************************/
static void ktid_set_flag(struct tidtable *psttidtabnode, char flagtype)
{
    if (KTID_HTTP_PROTOCOL == flagtype)
    {
        psttidtabnode->httpflag = 1;
    }
    if (KTID_NETBIOS_PROTOCOL == flagtype)
    {
        psttidtabnode->netbiosflag = 1;
    }
    if (KTID_BONJOUR_PROTOCOL == flagtype)
    {
        psttidtabnode->bonjourflag = 1;
    }

    return;
}

/*****************************************************************************
 �� �� ��  : ktid_get_httpflag
 ��������  : ��ȡ�ն�httpЭ��Ĺ��˱�ʶ
 �������  : const char *mac, ��ʶ�ն˵�mac��ַ
 �������  : ��
 �� �� ֵ  : == 0 ����Ҫ����, �˱��ķ��͸��û��ռ�
             != 0 ��Ҫ����, �˱��Ĳ����͸��û��ռ�
 ��   ��   : wenjue
*****************************************************************************/
static unsigned char ktid_get_httpflag(const char *mac)
{
    struct tidtable *psttidtabnode = NULL;
    unsigned char httpflag = 0;
    
    if (NULL == mac)
    {
        return 1;
    }

    psttidtabnode = g_sttidtabhd.next;
    while (NULL != psttidtabnode)
    {
        if (0 == memcmp(psttidtabnode->mac, mac, sizeof(psttidtabnode->mac)))
        {
            httpflag = psttidtabnode->httpflag;
            break;
        }
        psttidtabnode = psttidtabnode->next;
    }
    
    return httpflag;
}

/*****************************************************************************
 �� �� ��  : ktid_get_netbiosflag
 ��������  : ��ȡ�ն�netbiosЭ��Ĺ��˱�ʶ
 �������  : const char *mac, ��ʶ�ն˵�mac��ַ
 �������  : ��
 �� �� ֵ  : == 0 ����Ҫ����, �˱��ķ��͸��û��ռ�
             != 0 ��Ҫ����, �˱��Ĳ����͸��û��ռ�
 ��   ��   : wenjue
*****************************************************************************/
static unsigned char ktid_get_netbiosflag(const char *mac)
{
    struct tidtable *psttidtabnode = NULL;
    unsigned char netbiosflag = 0;
    
    if (NULL == mac)
    {
        return netbiosflag;
    }

    psttidtabnode = g_sttidtabhd.next;
    while (NULL != psttidtabnode)
    {
        if (0 == memcmp(psttidtabnode->mac, mac, sizeof(psttidtabnode->mac)))
        {
            netbiosflag = psttidtabnode->netbiosflag;
            break;
        }
        psttidtabnode = psttidtabnode->next;
    }
    
    return netbiosflag;
}

/*****************************************************************************
 �� �� ��  : ktid_get_bonjourflag
 ��������  : ��ȡ�ն�bonjourЭ��Ĺ��˱�ʶ
 �������  : const char *mac, ��ʶ�ն˵�mac��ַ
 �������  : ��
 �� �� ֵ  : == 0 ����Ҫ����, �˱��ķ��͸��û��ռ�
             != 0 ��Ҫ����, �˱��Ĳ����͸��û��ռ�
 ��   ��   : wenjue
*****************************************************************************/
static unsigned char ktid_get_bonjourflag(const char *mac)
{
    struct tidtable *psttidtabnode = NULL;
    unsigned char bonjourflag = 0;
    
    if (NULL == mac)
    {
        return bonjourflag;
    }

    psttidtabnode = g_sttidtabhd.next;
    while (NULL != psttidtabnode)
    {
        if (0 == memcmp(psttidtabnode->mac, mac, sizeof(psttidtabnode->mac)))
        {
            bonjourflag = psttidtabnode->bonjourflag;
            break;
        }
        psttidtabnode = psttidtabnode->next;
    }
    
    return bonjourflag;
}

/*****************************************************************************
 �� �� ��  : ktid_destroy_table
 ��������  : ɾ�����˱���, tid_kmod�ᶨʱ����
 �������  : ��
 �������  : ��
 �� �� ֵ  : ��
 ��   ��   : wenjue
*****************************************************************************/
static void ktid_destroy_table(void)
{
    struct tidtable *pstcurnode = NULL;
    struct tidtable *pstnextnode = NULL;

    pstcurnode = g_sttidtabhd.next;
    while (NULL != pstcurnode)
    {   
        pstnextnode = pstcurnode->next;
        kfree(pstcurnode);
        pstcurnode = pstnextnode;
    }
    g_sttidtabhd.next = NULL;
}

/*****************************************************************************
 �� �� ��  : ktid_update_table
 ��������  : ��ʱ���¹��˱���, �˺������ݶ�ʱʱ�䷴������
 �������  : unsigned long data, �붨ʱ��ִ�еĴ���������, �˴���������
 �������  : ��
 �� �� ֵ  : ��
 ��   ��   : wenjue
*****************************************************************************/
static void ktid_update_table(unsigned long data)
{
    spin_lock(&tid_lock);
    ktid_destroy_table();
    spin_unlock(&tid_lock);
    ktid_timer.expires = jiffies + 10*HZ;
    add_timer(&ktid_timer);
    
    return;
}

/*****************************************************************************
 �� �� ��  : ktid_modify_tablenode
 ��������  : �޸Ĺ��˱����еĹ�������
 �������  : const char *mac, ��ʶ���˱������ն˽ڵ��mac��ַ
             char flagtype, ��Ҫ�޸ĵĹ���Э�����ͱ�ʶ
 �������  : ��
 �� �� ֵ  : == 0, �ɹ��޸Ĺ�������
             != 0, δ�ҵ��޸ĵĽڵ�, ��Ҫ�����Ӵ�mac��ʶ�Ĺ��˽ڵ�
 ��   ��   : wenjue
*****************************************************************************/
static int ktid_modify_tablenode(const char *mac, char flagtype)
{
    struct tidtable *psttidtabnode = NULL;
    int ret = -1;

    if (NULL == mac)
    {
        return ret;
    }
    
    psttidtabnode = g_sttidtabhd.next;
    while (NULL != psttidtabnode)
    {
        if (0 == memcmp(psttidtabnode->mac, mac, sizeof(psttidtabnode->mac)))
        {
            ktid_set_flag(psttidtabnode, flagtype);
            ret = 0;
            break;
        }
        psttidtabnode = psttidtabnode->next;
    }

    return ret;
}

/*****************************************************************************
 �� �� ��  : ktid_add_tablenode
 ��������  : �������˽ڵ�
 �������  : const char *mac, ��ʶ�����ն˽ڵ��mac��ַ
             char flagtype, ��Ҫ���˵�Э�����ͱ�ʶ
 �������  : ��
 �� �� ֵ  : ��
 ��   ��   : wenjue
*****************************************************************************/
static void ktid_add_tablenode(const char *mac, char flagtype)
{
    struct tidtable *psttidtabnode = NULL;
    
    if (NULL == mac)
    {
        return;
    }

    psttidtabnode = kmalloc(sizeof(struct tidtable), GFP_KERNEL);
    if (NULL == psttidtabnode)
    {
        printk(KERN_ERR "[tid_kmod]: unable to allocate memory for tidfilternode");
        
        return;
    }
    memset(psttidtabnode, 0, sizeof(struct tidtable));
    memcpy(psttidtabnode->mac, mac, sizeof(psttidtabnode->mac));
    ktid_set_flag(psttidtabnode, flagtype);
    psttidtabnode->next = g_sttidtabhd.next;
    g_sttidtabhd.next = psttidtabnode;

    return;
}

/*****************************************************************************
 �� �� ��  : ktid_get_httpmsglen
 ��������  : ��ȡhttp�����ײ�����
 �������  : const unsigned char *data, ָ��http����ͷ
             int maxlen, �˱�����󳤶�, ��ֹ����Խ��
 �������  : ��
 �� �� ֵ  : unsigned int ��ȡ�õ��ı����ײ�����
 ��   ��   : wenjue
*****************************************************************************/
static unsigned int ktid_get_httpmsglen(const unsigned char *data, int maxlen)
{
    unsigned int len = 0;

    if (0 != memcmp(data, "GET ", 4))
    {
        return len;
    }
    while (1)
    {
        /*judge httpmsg prelude ending*/
        if ((*(data + len) == 13) && (*(data + len + 2) == 13))
        {
            break;
        }
        len++;
        if (len + 4 > maxlen)
        {
            return 0;
        }
    }
    len += 4;

    return len;
}

/*****************************************************************************
 �� �� ��  : ktid_filter_tcppacket
 ��������  : tcp��������
 �������  : const char *data, ָ��tcp��ͷ
             int len, �˱�����󳤶�, ��ֹ����Խ��
 �������  : struct tidmachdr *pstmachdr, tidģ�鶨�����̫���ײ�, �˴���ȡ�ı��ĳ���
 �� �� ֵ  : == 0, �˱�����Ҫ�������û��ռ�
             != 0, �˱����ѱ�����,����Ҫ�����û��ռ�
 ��   ��   : wenjue
*****************************************************************************/
static int ktid_filter_tcppacket(struct tidmachdr *pstmachdr, const char *data, int len)
{
    int ret = -1;
    struct tcphead *tcpptr = NULL;

    if (len < sizeof(struct tcphead))
    {
        return ret;
    }
    
    tcpptr = (struct tcphead *)data;
    if (len < tcpptr->headlen / 4)/*tcpotr->headlen << 2*/
    {
        return ret;
    }
    if (KTID_HTTPSERVER_PORT == tcpptr->dstport)
    {   
        pstmachdr->datalen = ktid_get_httpmsglen(data + tcpptr->headlen / 4, len - tcpptr->headlen / 4);   
    }
    if (0 != pstmachdr->datalen)
    {         
        spin_lock(&tid_lock);
        ret = ktid_get_httpflag(pstmachdr->mac);
        spin_unlock(&tid_lock);
        pstmachdr->portocoltype = KTID_HTTP_PROTOCOL;
    }  
    pstmachdr->datalen += tcpptr->headlen / 4;

    return ret;
}

/*****************************************************************************
 �� �� ��  : ktid_ishinfomsg
 ��������  : bonjour���Ĵ�����
 �������  : const char *data, ָ��bonjour����ͷ
             int maxlen, �˱�����󳤶�, ��ֹ����Խ��
 �������  : ��
 �� �� ֵ  : == 0, �˱�����Ҫ�������û��ռ�
             != 0, �˱����ѱ�����,����Ҫ�����û��ռ�
 ��   ��   : wenjue
*****************************************************************************/
static int ktid_ishinfomsg(const char *data, int maxlen)
{
    int i = 0;
    struct bonjourhead bonjourhd;

    memset(&bonjourhd, 0, sizeof(bonjourhd));
    if (maxlen < sizeof(bonjourhd))
    {
        return -1;
    }

    if (KTID_BONJOUR_RESPONSE != *((unsigned short *)(data + 2)))
    {
        return -1;
    }
    i += sizeof(bonjourhd);
    while (0 != *(data + i))
    {
        i++;
        if (maxlen < i + 1)
        {
            return -1;
        }
    }
    if (KTID_BONJOUR_HINFOMSG == *((unsigned short *)(data + 1 + i)))
    {
        return 0;
    }

    return -1;
}

/*****************************************************************************
 �� �� ��  : ktid_isconnetreq
 ��������  : netbios���Ĵ�����
 �������  : const char *data, ָ��netbios����ͷ
             int maxlen, �˱�����󳤶�, ��ֹ����Խ��
 �������  : ��
 �� �� ֵ  : == 0, �˱�����Ҫ�������û��ռ�
             != 0, �˱����ѱ�����,����Ҫ�����û��ռ�
 ��   ��   : wenjue
*****************************************************************************/
static int ktid_isconnetreq(const unsigned char *data, int maxlen)
{
    if (maxlen < KTID_NETBIOS_MSGLEN)
    {
        return -1;
    }
    
    if ((KTID_NETBIOS_REQUEST == *data) && (KTID_NETBIOS_COMMANDTYPE == *(data + KTID_NETBIOS_MSGLEN)))
    {
        return 0;
    }

    return -1;
}

/*****************************************************************************
 �� �� ��  : ktid_filter_udppacket
 ��������  : udp��������
 �������  : const char *data, ָ���ͷ
             int len, �˱�����󳤶�, ��ֹ����Խ��
 �������  : ��
 �� �� ֵ  : == 0, �˱�����Ҫ�������û��ռ�
             != 0, �˱����ѱ�����,����Ҫ�����û��ռ�
 ��   ��   : wenjue
*****************************************************************************/
static int ktid_filter_udppacket(unsigned int len, struct tidmachdr *pstmachdr, const char *data)
{
    int ret = -1;
    struct udpstruct *udpptr = (struct udpstruct *)data;

    if (len < sizeof(struct udpstruct))
    {
        return ret;
    }

    if (KTID_NETBIOSSERVER_PORT == udpptr->dstport)
    {    
        if (0 == ktid_isconnetreq(data + sizeof(struct udpstruct), len - sizeof(struct udpstruct)))
        {
            spin_lock(&tid_lock);
            ret = ktid_get_netbiosflag(pstmachdr->mac);
            spin_unlock(&tid_lock);
            pstmachdr->portocoltype = KTID_NETBIOS_PROTOCOL;
        }
    }
    if (KTID_BONJOURSERVER_PORT == udpptr->dstport)
    {   
        if (0 == ktid_ishinfomsg(data + sizeof(struct udpstruct), len - sizeof(struct udpstruct)))
        {   spin_lock(&tid_lock);
            ret = ktid_get_bonjourflag(pstmachdr->mac);
            spin_unlock(&tid_lock);
            pstmachdr->portocoltype = KTID_BONJOUR_PROTOCOL;
        }
    }
    if (KTID_DHCPSERVER_PORT == udpptr->dstport)
    {
        ret = 0;
        pstmachdr->portocoltype = KTID_DHCP_PROTOCOL;
    }
    if (KTID_DHCPCLIENT_PORT == udpptr->dstport)
    {
        ret = 0;
        pstmachdr->portocoltype = KTID_DHCP_PROTOCOL;
    }

    return ret;
}

/*****************************************************************************
 �� �� ��  : ktid_sendmsg
 ��������  : tid_kmod���û��ռ�ķ�װ�����ͺ���
 �������  : const char *data, �˴���һ��ip��
             const struct tidmachdr *pstmachdr, tid_kmod�Զ����װ��macͷ
 �������  : ��
 �� �� ֵ  : ��
 ��   ��   : wenjue
*****************************************************************************/
static void ktid_sendmsg(const void *data, const struct tidmachdr *pstmachdr)
{
    struct sk_buff *skb = NULL;
    struct nlmsghdr *nlmhdr = NULL;
    unsigned int len = 0;
    int sendret = 0;

    if (NULL == ktid_sockfd || NULL == data || NULL == pstmachdr)
    {
        return;
    }

    len = pstmachdr->datalen + sizeof(struct tidmachdr) + sizeof(struct nlmsghdr);
    skb = alloc_skb(len, GFP_KERNEL);
    if (NULL == skb)
    {
        printk(KERN_WARNING "[tid_kmod]: skb Malloc Failed!\r\n");
        return;
    }

    nlmhdr = nlmsg_put(skb, 0, 0, 0, len - sizeof(struct nlmsghdr), 0);
    NETLINK_CB(skb).portid = g_tidpid;
    NETLINK_CB(skb).dst_group = 0;
    memcpy(nlmsg_data(nlmhdr), pstmachdr, sizeof(struct tidmachdr));
    memcpy(nlmsg_data(nlmhdr) + sizeof(struct tidmachdr), data, pstmachdr->datalen);
    sendret = netlink_unicast(ktid_sockfd, skb, g_tidpid, MSG_DONTWAIT);
    
    return;
}

/*****************************************************************************
 �� �� ��  : ktid_filter_packet
 ��������  : ���Ӻ���, ���ڴ�������·�㹳������ip����802.3��̫��ͷ��skb�������ݰ�
             ���Դ���������д���(���������޸ġ��������ж�ȡ���жϡ���������)
 �������  : struct sk_buff *skb, ���Ӻ����������������ݰ�
 �������  : ��
 �� �� ֵ  : ��
 ��   ��   : wenjue
*****************************************************************************/
void ktid_filter_packet(struct sk_buff *skb)
{
    if (KTID_ON != ktid_switch)
    {
        return;
    }

    struct machead *macptr = NULL;
    struct iphdr *ipptr = NULL;
    int flag = -1;
    unsigned char mac[6] = {0};
    unsigned char broadcastmsg[6] = {255, 255, 255, 255, 255, 255};
    struct tidmachdr stmachdr;

    if (NULL == skb || NULL == skb->dev)
    {
        return;
    }

	if (skb->len < sizeof(struct iphdr))
    {
        return;
    }

	ipptr = (struct iphdr *)(skb->data);

	if ((KTID_TCP_PROTOCOL != ipptr->protocol) && (KTID_UDP_PROTOCOL != ipptr->protocol))
	{
		return;
	}

    if (0 == strncmp(skb->dev->name, "ath", 3))		// station-ap-internet
    {
		macptr = (struct machead *)(skb->mac_header);
		memset(&stmachdr, 0, sizeof(stmachdr));
		memcpy(stmachdr.mac, macptr->src_mac, 6);
	}
	else	// lo && br-wan && athscan
	{
		return;
	}

    if (KTID_TCP_PROTOCOL == ipptr->protocol)
    {
        flag = ktid_filter_tcppacket(&stmachdr, (const char *)(skb->data + sizeof(struct iphdr)), skb->len - sizeof(struct iphdr));
        stmachdr.datalen = stmachdr.datalen + sizeof(struct iphdr);
    }
    else if (KTID_UDP_PROTOCOL == ipptr->protocol)
    {
        flag = ktid_filter_udppacket(skb->len - sizeof(struct iphdr), &stmachdr, (const char *)(skb->data + sizeof(struct iphdr)));
        stmachdr.datalen = skb->len;
    }

    if (0 == flag)
    {
        ktid_sendmsg(skb->data, &stmachdr);
    }

    return;
}

/*****************************************************************************
 �� �� ��  : ktid_receive_skb
 ��������  : tid_kmod������յ����û��ռ䷢�͵�netlink��Ϣ
 �������  : struct sk_buff  *skb, ���յ�������ָ��
 �������  : ��
 �� �� ֵ  : ��
 ��   ��   : wenjue
*****************************************************************************/
static void ktid_receive_skb(struct sk_buff  *skb)
{
    struct nlmsghdr *nlmhdr = NULL;
    struct tidmachdr *machdr = NULL;

    if (skb->len >= 0)
    {
        nlmhdr = nlmsg_hdr(skb);
        g_tidpid = NETLINK_CB(skb).portid;
        machdr = nlmsg_data(nlmhdr);
        spin_lock(&tid_lock);
        if(ktid_modify_tablenode(machdr->mac, machdr->portocoltype) < 0)
        {
            ktid_add_tablenode(machdr->mac, machdr->portocoltype);
        }
        spin_unlock(&tid_lock);
    }
    
    return;
}

/*****************************************************************************
 �� �� ��  : ktid_receive
 ��������  : tid_kmod�����û��ռ�netlink��Ϣ�ĺ���ָ��
 �������  : struct sk_buff  *skb, ���յ�������ָ��
 �������  : ��
 �� �� ֵ  : ��
 ��   ��   : wenjue
*****************************************************************************/
static void ktid_receive(struct sk_buff  *skb)
{
	ktid_receive_skb(skb);

    return;
}

/*****************************************************************************
 �� �� ��  : ktid_init_timer
 ��������  : ��ʱ����ʼ������
 �������  : ��
 �������  : ��
 �� �� ֵ  : ��
 ��   ��   : wenjue
*****************************************************************************/
static void ktid_init_timer(void)
{
    init_timer(&ktid_timer);
    ktid_timer.function = ktid_update_table;
    ktid_timer.expires = jiffies + 10*HZ;
    add_timer(&ktid_timer);

    return;
}

/*****************************************************************************
 �� �� ��  : ktid_switchshow
 ��������  : ktid_switch�ں˱�����show����
 �������  : struct kobject *kobj, ���ݺ����ӿ�, �˴���������
             struct kobj_attribute *attr, ���ݺ����ӿ�, �˴���������
 �������  : char *buf, ���������
 �� �� ֵ  : ssize_t, ���ݺ����ӿ�, �˴���������
 ��   ��   : wenjue
*****************************************************************************/
static ssize_t ktid_switchshow(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%u\r\n", ktid_switch);
}

/*****************************************************************************
 �� �� ��  : ktid_switchset
 ��������  : ktid_switch�ں˱�����store����
 �������  : struct kobject *kobj, ���ݺ����ӿ�, �˴���������
             struct kobj_attribute *attr, ���ݺ����ӿ�, �˴���������
             size_t size, ���ݺ����ӿ�, �˴���������
             const char *buf, �޸ĵ��ں˱���ֵ
 �������  : ��
 �� �� ֵ  : ssize_t, ���ݺ����ӿ�, �˴���������
 ��   ��   : wenjue
*****************************************************************************/
static ssize_t ktid_switchset(struct kobject *kobj, struct device_attribute *attr, const char *buf, size_t size)
{
    unsigned int state;
    int ret;
 	ret = kstrtoul(buf, 10, &state);
    if (ret == 0)
    {
        ktid_switch = state;
    }

    return 1;
}

static struct kobj_attribute ktid_state = __ATTR(ktid_disable, 0644, ktid_switchshow, ktid_switchset); 
static struct attribute *ktid_control[] = {
    &ktid_state.attr,
    NULL,
};
static struct attribute_group ktid_group = {
    .attrs = ktid_control,
};

static int sysfs_status = 0 ;
struct kobject *soc_kobj = NULL;
/*****************************************************************************
 �� �� ��  : tid_switch_init
 ��������  : �ṩ���û��ռ俪���ر�tid_kmod���ܵĿ��س�ʼ��
 �������  : ��
 �������  : ��
 �� �� ֵ  : == 0, ��ʼ���ɹ�
             != 0, ��ʼ��ʧ��
 ��   ��   : wenjue
*****************************************************************************/
int tid_switch_init(void)
{
    int ret = 0;
    soc_kobj = kobject_create_and_add("ktid_control", NULL);
    if (0 == soc_kobj)
    {
        return -1;
    }
    ret = sysfs_create_group(soc_kobj, &ktid_group);
    if (0 != ret)
    {
        sysfs_remove_group(soc_kobj, &ktid_group);
        kobject_put(soc_kobj);
        return -1;
    }
    sysfs_status = 1;
    return 0;
}

/*****************************************************************************
 �� �� ��  : tid_switch_exit
 ��������  : �ṩ���û��ռ俪���ر�tid_kmod���ܵĿ���ȥ��ʼ��
 �������  : ��
 �������  : ��
 �� �� ֵ  : ��
 ��   ��   : wenjue
*****************************************************************************/
void tid_switch_exit(void)
{
    sysfs_remove_group(soc_kobj, &ktid_group);
    kobject_put(soc_kobj);
       
    return;
}

/*****************************************************************************
 �� �� ��  : ktid_init
 ��������  : tid_kmod��ʼ������
 �������  : ��
 �������  : ��
 �� �� ֵ  : == 0, ��ʼ���ɹ�
             != 0, ��ʼ��ʧ��
 ��   ��   : wenjue
*****************************************************************************/
static int __init ktid_init(void)
{

 	struct netlink_kernel_cfg cfg = {
		.input	= ktid_receive,
	};

    if (0 != tid_switch_init())
    {
        printk(KERN_ERR "[tid_kmod]: mod switch init failed, kmod exit\r\n");
        return -1;
    }
    ktid_sockfd = netlink_kernel_create(&init_net, NETLINK_TID, &cfg);
    if (NULL == ktid_sockfd)
    {
        tid_switch_exit();
        printk(KERN_ERR "[tid_kmod]: netlink create failed, kmod exit\r\n");
        return -1;
    }

    ktid_init_timer();
    ktid_filter_packet_cb = ktid_filter_packet;

    return 0;
}

/*****************************************************************************
 �� �� ��  : ktid_exit
 ��������  : tid_kmodȥ��ʼ������
 �������  : ��
 �������  : ��
 �� �� ֵ  : ��
 ��   ��   : wenjue
*****************************************************************************/
static void __exit ktid_exit(void)
{
    if (NULL != ktid_sockfd)
    {
        netlink_kernel_release(ktid_sockfd);
    }
    tid_switch_exit();
    del_timer(&ktid_timer);
    spin_lock(&tid_lock);
    ktid_destroy_table();
    spin_unlock(&tid_lock);
    ktid_filter_packet_cb = NULL;
}

subsys_initcall(ktid_init);
module_exit(ktid_exit);
MODULE_LICENSE("GPL");
