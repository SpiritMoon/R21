/******************************************************************************
  File Name    : dnsrd_parse.c
  Author       : lhc
  Date         : 20160302
  Description  : proc msg
******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>  
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h> 
#include <unistd.h>
#include <linux/ip.h>
#include <linux/sockios.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <asm/types.h>
#include <malloc.h>

#include <netpacket/packet.h>


#include "dnsrd_parse.h"
#include "dnsrd_debug.h"

struct dnsrd_msghdr{
	char ifname[20];
	unsigned char src_mac[6];
	unsigned char dst_mac[6];
};

/* ap mgmt interface */
#define DNSRDMGMTINTER   "br-wan"

/******************************************************************************
  Function Name    : checksum
  Author           : lhc
  Date             : 20160302
  Description      : add udp checknum
  Param            : unsigned short *buffer 
                     int size
  return Code      :
******************************************************************************/
unsigned short checksum(unsigned short *buffer, int size)
{
    unsigned long cksum = 0;
    
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(unsigned short);   
    }
    
    if (size)
    {
        cksum += *(unsigned char *)buffer;   
    }
    
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);

    return (unsigned short)(~cksum); 
}

/******************************************************************************
  Function Name    : CalculateCheckSum
  Author           : lhc
  Date             : 20160302
  Description      : add udp checknum
  Param            : void *iphdr 
                     struct udphdr *udphdr 
                     unsigned char *payload 
                     int payloadlen
  return Code      :
******************************************************************************/
void CalculateCheckSum(void *iphdr, struct udphdr *udphdr, unsigned char *payload, int payloadlen)
{   
    int chksumlen = 0;
    int i = 0;
    struct iphdr   *v4hdr = NULL;
    unsigned long  zero = 0;
    unsigned char  buf[1000];
    unsigned char  *ptr = NULL;
    
    ptr = buf;
    v4hdr = (struct iphdr *)iphdr;
    
    // Include the source and destination IP addresses
    memcpy(ptr, &v4hdr->saddr,  sizeof(v4hdr->saddr));  
    ptr += sizeof(v4hdr->saddr);
    chksumlen += sizeof(v4hdr->saddr);
    memcpy(ptr, &v4hdr->daddr, sizeof(v4hdr->daddr)); 
    ptr += sizeof(v4hdr->daddr);
    chksumlen += sizeof(v4hdr->daddr);
    
    // Include the 8 bit zero field
    memcpy(ptr, &zero, 1);
    ptr++;
    chksumlen += 1;
    
    // Protocol
    memcpy(ptr, &v4hdr->protocol, sizeof(v4hdr->protocol)); 
    ptr += sizeof(v4hdr->protocol);
    chksumlen += sizeof(v4hdr->protocol);
    
    // UDP length
    memcpy(ptr, &udphdr->len, sizeof(udphdr->len)); 
    ptr += sizeof(udphdr->len);
    chksumlen += sizeof(udphdr->len);
    
    // UDP source port
    memcpy(ptr, &udphdr->source, sizeof(udphdr->source)); 
    ptr += sizeof(udphdr->source);
    chksumlen += sizeof(udphdr->source);
    
    // UDP destination port
    memcpy(ptr, &udphdr->dest, sizeof(udphdr->dest)); 
    ptr += sizeof(udphdr->dest);
    chksumlen += sizeof(udphdr->dest);
    
    // UDP length again
    memcpy(ptr, &udphdr->len, sizeof(udphdr->len)); 
    ptr += sizeof(udphdr->len);
    chksumlen += sizeof(udphdr->len);
   
    // 16-bit UDP checksum, zero 
    memcpy(ptr, &zero, sizeof(unsigned short));
    ptr += sizeof(unsigned short);
    chksumlen += sizeof(unsigned short);
    
    // payload
    memcpy(ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;
    
    // pad to next 16-bit boundary
    for(i=0 ; i < payloadlen%2 ; i++, ptr++)
    {
        dnsrd_debug_trace("[DNSRD]: udp checknum pad one byte");
        *ptr = 0;
        ptr++;
        chksumlen++;
    }
    
    // Compute the checksum and put it in the UDP header
    udphdr->check = checksum((unsigned short *)buf, chksumlen);

	// calculate ip header checksum
	int ip_len = 20 + sizeof(struct udphdr) + payloadlen;
	v4hdr->tot_len = htons(ip_len);
	unsigned char tmp_head[1024];
	memset(tmp_head, 0, sizeof(tmp_head));
	memcpy(tmp_head, v4hdr, sizeof(struct iphdr));
	v4hdr->check = htons(checksum((unsigned short *)tmp_head, ip_len/2));
    
    return;
}

/******************************************************************************
  Function Name    : dnsrd_send_response
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd send response
  Param            : unsigned char *buffer    send date
                     int buffer_size          date len
                     struct iphdr *ip         
                     struct udphdr *udp
                     char *ifname	interface name
  return Code      :
******************************************************************************/
static void dnsrd_send_response(unsigned char *buffer, int buffer_size, struct iphdr *ip, struct udphdr *udp, char *ifname)
{
    int sock = -1;
    int ret = -1;
    struct sockaddr_ll sll;
	struct ifreq ethreq;

    /* creat sock_row socket */
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0)
    {
        dnsrd_debug_waring("[DNSRD]: creat socket(SOCK_RAW) fail");
        return;
    }

	dnsrd_debug_trace("[DNSRD]: assign ifname:[%s]", ifname);
	strncpy(ethreq.ifr_name, ifname, 16);
	if(ioctl(sock, SIOCGIFINDEX, (char *)&ethreq) < 0)
	{
		dnsrd_debug_waring("[DNSRD]: ioctl failed ifname:[%s]", ethreq.ifr_name);
		goto err;
	}

	bzero(&sll, sizeof(sll));
	sll.sll_ifindex = ethreq.ifr_ifindex;

	ret = sendto(sock, buffer, buffer_size, 0, (struct sockaddr*)&sll, sizeof(sll));

    if (ret < 0) 
    {
        dnsrd_debug_waring("[DNSRD]: send dns response fail");
    }
    else
    {
		unsigned char *dst_ip = (unsigned char *)(&ip->daddr);
        dnsrd_debug_trace("[DNSRD]: send dns response successful to dst_ip[%d.%d.%d.%d]\n", *dst_ip,*(dst_ip+1),*(dst_ip+2),*(dst_ip+3));
    }

err:
    close(sock);

    return;
}

/******************************************************************************
  Function Name    : dnsrd_assemble_response_ip
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd assemble response ip    
  Param            : struct iphdr *response_ip   response packet ip head point
                     int response_buf_len        response buf len
                     struct iphdr *query_ip      query packet ip head point
  return Code      :
******************************************************************************/
static void dnsrd_assemble_response_ip(struct iphdr *response_ip, int response_buf_len, struct iphdr *query_ip)
{
    response_ip->version = 4;
    response_ip->ihl = 5;
    response_ip->tot_len = response_buf_len;
    response_ip->id = htonl(random());
    response_ip->ttl = 255;
    response_ip->protocol = IPPROTO_UDP;
    response_ip->check = 0;
    response_ip->saddr = query_ip->daddr;
    response_ip->daddr = query_ip->saddr;

    return;
}

/******************************************************************************
  Function Name    : dnsrd_assemble_response_udp
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd assemble response udp
  Param            : struct udphdr *response_udp  response packet udp head point
                     int response_buf_len         response buf len 
                     struct udphdr *query_udp     query packet udp head point
  return Code      :
******************************************************************************/
static void dnsrd_assemble_response_udp(struct udphdr *response_udp, int response_buf_len, struct udphdr *query_udp)
{
    response_udp->source = query_udp->dest;
    response_udp->dest = query_udp->source;
    response_udp->len = htons(response_buf_len - sizeof(struct iphdr));
    response_udp->check = 0;

    return;
}

/******************************************************************************
  Function Name    : dnsrd_get_mgmt_ip
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd get mgmt ip
  Param            : void
  return Code      : mgmt ip = 0   fail
                            != 0   success
******************************************************************************/
static unsigned int dnsrd_get_mgmt_ip()
{    
    int mgmt_ip_sock = -1;
    unsigned int mgmt_ip = 0;
    struct sockaddr_in *sin;
    struct ifreq ifr_ip;

    /* creat socket */
    mgmt_ip_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (mgmt_ip_sock < 0)
    {  
         dnsrd_debug_waring("[DNSRD]: creat sock for get mgmt ip fail");
         return 0;
    }
    
    memset(&ifr_ip, 0, sizeof(ifr_ip));
    strncpy(ifr_ip.ifr_name, DNSRDMGMTINTER, sizeof(ifr_ip.ifr_name) - 1);

    /* get ip */
    if (ioctl(mgmt_ip_sock, SIOCGIFADDR, &ifr_ip) < 0)
    {
        dnsrd_debug_waring("[DNSRD]: ioctl get mgmt ip fail");
    }
    else
    {
        sin = (struct sockaddr_in *)&ifr_ip.ifr_addr;
        mgmt_ip = (sin->sin_addr).s_addr;
        dnsrd_debug_trace("[DNSRD]: ioctl get local ip %s", inet_ntoa(sin->sin_addr));
    }
    
    close(mgmt_ip_sock);
      
    return mgmt_ip;
}

/******************************************************************************
  Function Name    : dnsrd_assemble_response_dns
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd assemble response dns
  Param            : unsigned char *response_dns    dns response packet 
                     unsigned char *query_dns       dns query packet
                     int query_dns_len              query packet dns part len
                     unsigned int drm_mgmt_ip       mgmt ip
  return Code      :
******************************************************************************/
static void dnsrd_assemble_response_dns(unsigned char *response_dns, unsigned char *query_dns, 
                                        int query_dns_len, unsigned int dnsrd_mgmt_ip)
{
    struct dnsmsghead dnsmsg_head;
    struct dnsmsganswear dnsmsg_answear;
    unsigned char *dnsmsg_queries = NULL;
    int dnsmsg_queries_len = 0;
    
    /* dns head */
    memset(&dnsmsg_head, 0, sizeof(dnsmsg_head));
    dnsmsg_head.transid = *((unsigned short *)query_dns);
    dnsmsg_head.flag = 0x8580;
    dnsmsg_head.questcont = 0x0001;
    dnsmsg_head.answercont = 0x0001;

    /* dns queries */
    dnsmsg_queries = query_dns + sizeof(dnsmsg_head);
    dnsmsg_queries_len = query_dns_len - sizeof(dnsmsg_head);

    /* dns answears */
    memset(&dnsmsg_answear, 0, sizeof(dnsmsg_answear));
    dnsmsg_answear.name = 0xc00c;
    dnsmsg_answear.type = 0x0001;
    dnsmsg_answear.Class = 0x0001;
    dnsmsg_answear.time1 = 0;
    dnsmsg_answear.time2 = 0x018b;
    dnsmsg_answear.datelen = 0x0004;
    dnsmsg_answear.addr = dnsrd_mgmt_ip;

    memcpy(response_dns, &dnsmsg_head, sizeof(dnsmsg_head));
    memcpy(response_dns + sizeof(dnsmsg_head), dnsmsg_queries, dnsmsg_queries_len);
    memcpy(response_dns + sizeof(dnsmsg_head) + dnsmsg_queries_len, &dnsmsg_answear, sizeof(dnsmsg_answear));

    return;
}

/******************************************************************************
  Function Name    : Dnsrd_recvmsg_form_kernel
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd reply qurery
  Param            : const void *packet    dns packet
  return Code      :
******************************************************************************/
static void dnsrd_reply_qurery(const void *packet)
{
    struct iphdr  *query_ip;
    struct udphdr *query_udp;
    unsigned char *query_dns = NULL;
    int query_dns_len = 0;
    struct iphdr  *response_ip;
    struct udphdr *response_udp;
    unsigned char *response_dns = NULL;
    unsigned char *response_buf = NULL;
    int response_dns_len = 0;
    int response_buf_len = 0;
    unsigned int dnsrd_mgmt_ip = 0;

	char* ifname = NULL;
	struct dnsrd_msghdr *msghdr;
	void *data = NULL;
    
    if (NULL == packet)
    {
        dnsrd_debug_waring("[DNSRD]: dns qurery packet NULL");
        return;
    }

    /* get mgmt ip */
    dnsrd_mgmt_ip = dnsrd_get_mgmt_ip();
    if (0 == dnsrd_mgmt_ip)
    {
        dnsrd_debug_waring("[DNSRD]: get mgmt ip fail");
        return;
    }

	msghdr = (struct dnsrd_msghdr *)(packet);
	ifname = msghdr->ifname;
	dnsrd_debug_trace("[DNSRD]: packet from [%s]", ifname);

	data = (void *)(packet + sizeof(struct dnsrd_msghdr));
    
    /* parse query */
	query_ip = (struct iphdr *)(data);
	query_udp = (struct udphdr *)(data + sizeof(struct iphdr));
	query_dns = (unsigned char *)(data + sizeof(struct iphdr) + sizeof(struct udphdr));
    query_dns_len = query_udp->len - sizeof(struct udphdr);
    
    /* creat response */
    //response_dns_len = sizeof(struct dnsmsghead) + strlen(query_dns + 12) + 1 + 2 + 2 + sizeof(struct dnsmsganswear);
    response_dns_len = query_dns_len + sizeof(struct dnsmsganswear);
    response_buf_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + response_dns_len;
    response_buf = malloc(response_buf_len);
    if (NULL == response_buf)
    {
        dnsrd_debug_waring("[DNSRD]: alloc memory for dns response fail");
        return;
    }
    memset(response_buf, 0, response_buf_len);

	struct ethhdr *eth_hdr = NULL;
	eth_hdr = (struct ethhdr *)response_buf;
	memcpy(eth_hdr->h_dest, msghdr->src_mac, 6);
	memcpy(eth_hdr->h_source, msghdr->dst_mac, 6);
	eth_hdr-> h_proto = htons(0x0800);

    /* assemble response ip */
    response_ip = (struct iphdr *)(response_buf + sizeof(struct ethhdr));
    dnsrd_assemble_response_ip(response_ip, response_buf_len - sizeof(struct ethhdr), query_ip);
    
    /* assemble response udp */
    response_udp = (struct udphdr *)(response_buf + sizeof(struct ethhdr) + sizeof(struct iphdr));
    dnsrd_assemble_response_udp(response_udp, response_buf_len - sizeof(struct ethhdr) , query_udp);

    /* assemble response dns */
    response_dns = response_buf + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    dnsrd_assemble_response_dns(response_dns, query_dns, query_dns_len, dnsrd_mgmt_ip);

    /* CheckSum response */
    CalculateCheckSum(response_ip, response_udp, response_dns, response_dns_len);

    /* send response */
    dnsrd_send_response(response_buf, response_buf_len, response_ip, response_udp, ifname);

    /* destory response */
    free(response_buf);
    
    return;
}

/******************************************************************************
  Function Name    : Dnsrd_recvmsg_form_kernel
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd recv msg_form kernel
  Param            : socketfd  netlink socket
  return Code      :
******************************************************************************/
void Dnsrd_recvmsg_form_kernel(int socketfd)
{   
    socklen_t len = 0;
    int ret = -1;
    unsigned char buf[4096]= {0};
    struct sockaddr_nl src_addr;

    /* recv msg from kernel */
    ret = recvfrom(socketfd, buf, sizeof(buf), 0, (struct sockaddr *)&src_addr, &len);
    if (ret < 0 || ret >= sizeof(buf))
    {
        dnsrd_debug_waring("[DNSRD]: recv msg from dnsrd_kmod fail");

        return;
    }
    
    dnsrd_debug_trace("[DNSRD]: recv msg from dnsrd_kmod success");

    /* reply qurery */
    dnsrd_reply_qurery(buf + sizeof(struct nlmsghdr));

    return;
}

/******************************************************************************
  Function Name    : Dnsrd_sendmsg_to_kernel
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd send msg to kernel
  Param            : int socketfd    netlink socket
                     void *data      send date
                     int date_len    date len
  return Code      : ret = 0         send date sucess
                     ret != 0        send date fail
******************************************************************************/
int Dnsrd_sendmsg_to_kernel(int socketfd, void *data, int date_len)
{
    int msg_len = 0;
    int sendlen = 0;
    int ret= -1;
    struct sockaddr_nl dst_addr;
    struct msghdr msg;
    struct iovec iov;
    struct nlmsghdr *nlh = NULL;

    /* malloc nlmsghdr */
    msg_len += sizeof(struct nlmsghdr);
    msg_len += date_len;
    nlh = malloc(msg_len);
    if (NULL == nlh)
    {
        dnsrd_debug_waring("[DNSRD]: unable to allocate memory for nlh");
        return -1;
    }

    /* init nlmsghdr */
    nlh->nlmsg_len = msg_len;
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    memcpy(NLMSG_DATA(nlh), data, date_len);

    /* init iov */
    iov.iov_base = (void *)nlh;
    iov.iov_len = msg_len;

    /* init sockaddr_nl */
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.nl_family = AF_NETLINK;
    dst_addr.nl_pid = 0;
    dst_addr.nl_groups = 0;

    /* init msg */
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dst_addr;
    msg.msg_namelen = sizeof(dst_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    /* send msg */
    sendlen = sendmsg(socketfd, &msg, 0);
    if (sendlen < 0)
    {
        dnsrd_debug_trace("[DNSRD]: send msg to dnsrd_kmod failed");
        ret = -1;
    }
    else
    {
        dnsrd_debug_trace("[DNSRD]: send msg to dnsrd_kmod success");
        ret = 0;
    }
    
    free(nlh);

    return ret;
}
