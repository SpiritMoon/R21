/******************************************************************************
  �� �� ��   : tid_parse.c
  ��    ��   : wenjue
  ��������   : 2014��11��19��
  ��������   : �ն�ʶ��ģ�������Ӧ���Ĳ����豸��Ϣ���͸�UMģ��
******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/ip.h>
#include <unistd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>

#include "tid_parse.h"
#include "tid_debug.h"

#define TID_PORT 5600
#define TID_CMD_MAX_LEN 128
#define TID_HOSTIP_MAX_LEN 20
#define TID_USER_AGENT_MAXLEN 128
#define ITD_HTTP_METHOD_MAXLEN 8

#define TID_HTTP_PROTOCOL 1
#define TID_DHCP_PROTOCOL 2
#define TID_NETBIOS_PROTOCOL 3
#define TID_BONJOUR_PROTOCOL 4

#define TIDALECLIENT  "Handset"
//#define TIDALECLIENTFLAG  "1.3.6.1.4.1.27614.2.2"
#define TIDALECLIENTFLAG  "alcatel.mipt.1"
/*****************************************************************************
 �� �� ��  : create_client
 ��������  : ����udp socket�ͻ��ˡ����ڸ�UMģ��ͨ�š�
             ע��, ÿ���߳̾���ע��һ���ͻ���
 �������  : ��
 �������  : struct sockaddr_in *serv_addr
 �� �� ֵ  : int >= 0 ���سɹ������سɹ�ע���socket������
                 <  0 ����ʧ��
 ��   ��   : wenjue
*****************************************************************************/
int create_client(struct sockaddr_in *serv_addr)
{
    int socketfd = -1;

    socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketfd < 0)
    {
        tid_debug_waring("[tid]: socket client failed!");
        return -1;
    }
    
    serv_addr->sin_family = AF_INET;
    serv_addr->sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr->sin_port = htons(TID_PORT);

    return socketfd;
}

/*****************************************************************************
 �� �� ��  : parse_dhcp_callback
 ��������  : ���ݸ�libpcap�ӿ��û��������ݰ��Ļص�����
             ��������dhcp���ģ���ȡ�豸��������MAC��ַ��Ϣ
             ���������õ������ݷ��͸�UMģ��
 �������  : u_char *userless, ����������UMģ��ͨ�ŵ�udp socket
                               ����˵Ķ˿ںż���ַ��Ϣ
             const struct pcap_pkthdr *pkthdr, �ص������������˴�������
             const u_char *packet, dhcp��·�����ݰ�
 �������  : ��
 �� �� ֵ  : ��
 ��   ��   : wenjue
*****************************************************************************/
static int tid_parse_dhcpmsg(const void *packet, struct usrtidmachdr *machdr, struct socket_clientinfo *socket)
{
    struct dhcphead *dhcphdr = NULL;
    struct devinfo stdevinfo;
    char *dataoption = NULL;
    int datalen = 0;
    int sendret = -1;
    int len = 0;
    int i = 0; 
 
    if (packet == NULL || NULL == machdr || NULL == socket)
    {
        return -1;
    }

    len += sizeof(struct iphdr);
    len += sizeof(struct udpstruct);
    dhcphdr = (struct dhcphead *)(packet + len);
    memset(&stdevinfo, 0, sizeof(stdevinfo));

    i = 0;
    sprintf(stdevinfo.mac, "%02x", dhcphdr->clientmac[i]);
    while (i < 5)
    {
        i++;
        sprintf(stdevinfo.mac, "%s:%02x", stdevinfo.mac, dhcphdr->clientmac[i]);
    }

    if (2 == dhcphdr->messagetype)		// dhcp reply
    {
		if (dhcphdr->yourip[0] == 0)
		{
			return -1;
		}
        i = 0;
        sprintf(stdevinfo.ipaddr, "%d", dhcphdr->yourip[i]);
        while (i < 3)
        {
            i++;
            sprintf(stdevinfo.ipaddr, "%s.%d", stdevinfo.ipaddr, dhcphdr->yourip[i]);
        }

        /* ale-v MAC OUI is 00-01-3E type: WLAN Handset */
        if (0x00 == dhcphdr->clientmac[0] && 0x01 == dhcphdr->clientmac[1] && 0x3E == dhcphdr->clientmac[2])
        {
            memcpy(stdevinfo.devtype, TIDALECLIENT, sizeof(stdevinfo.devtype));
            tid_debug_notice("[tid]: find WLAN Handset by mac");
        }
        
        sendret = sendto(socket->socketfd, (void *)&stdevinfo, sizeof(stdevinfo), 0,
               (struct sockaddr*)&socket->serv_addr, sizeof(socket->serv_addr));
    }
    else if (1 != dhcphdr->messagetype)
    {
        return -1;
    }

	/* dhcphdr->messagetype=1: dhcp request option */
    len += sizeof(struct dhcphead);
    dataoption = (char *)(packet + len);
    while (0 != *dataoption && 0xff != *dataoption)
    {
        if (12 == *dataoption)
        {
            dataoption += 1;
            datalen = *dataoption;
            dataoption += 1;
            memcpy(stdevinfo.hostname, dataoption, datalen);
			if (stdevinfo.hostname[0] != 0)
			{
				if (strstr(stdevinfo.hostname, "android"))
				{
					memcpy(stdevinfo.devtype, "Mobile", sizeof(stdevinfo.devtype));
					memcpy(stdevinfo.ostype, "Android", sizeof(stdevinfo.ostype));
				}
				else if (strstr(stdevinfo.hostname, "iPhone"))
				{
					memcpy(stdevinfo.devtype, "iPhone", sizeof(stdevinfo.devtype));
					memcpy(stdevinfo.ostype, "IOS", sizeof(stdevinfo.ostype));
				}
				else if (strstr(stdevinfo.hostname, "iPad"))
				{
					memcpy(stdevinfo.devtype, "iPad", sizeof(stdevinfo.devtype));
					memcpy(stdevinfo.ostype, "IOS", sizeof(stdevinfo.ostype));
				}
				else if (strstr(stdevinfo.hostname, "MacBook"))
				{
					memcpy(stdevinfo.devtype, "Mac PC", sizeof(stdevinfo.devtype));
					memcpy(stdevinfo.ostype, "Mac OS", sizeof(stdevinfo.ostype));
				}
			}
			dataoption -= 2;
        }

        if (60 == *dataoption)
        {         
            dataoption += 1;
            datalen = *dataoption;
            dataoption += 1;
            if (0 == memcmp(dataoption, TIDALECLIENTFLAG, datalen))
            {
                tid_debug_notice("[tid]: find WLAN Handset by dhcp 60");
                memset(stdevinfo.devtype, 0, sizeof(stdevinfo.devtype));
                memcpy(stdevinfo.devtype, TIDALECLIENT, sizeof(stdevinfo.devtype));
            }
			dataoption -= 2;
        }

		dataoption += 1;
		datalen = *dataoption;
		dataoption += datalen + 1;
    }

	sendret = sendto(socket->socketfd, (void *)&stdevinfo, sizeof(stdevinfo), 0,
		(struct sockaddr*)&socket->serv_addr, sizeof(socket->serv_addr));

    if (sendret == sizeof(stdevinfo))
    {
		tid_debug_notice("[tid]: [TID_DHCP_PROTOCOL] ip:[%s], mac:[%s], hostname:[%s], ostype:[%s]",
			stdevinfo.ipaddr, stdevinfo.mac, stdevinfo.hostname, stdevinfo.ostype);
        tid_debug_trace("[tid]: send devinfo to um success!");
    }
    
    return sendret;
}

/*****************************************************************************
 �� �� ��  : tid_parse_devstr
 ��������  : ����http���ĵ�User-Agent�ֶΡ���ȡ�豸��Ϣ
 �������  : const char *devstr��User-Agent�ֶ��ַ���
 �������  : struct devinfo *devinfo, �����洢�豸��Ϣ�Ļ���,��������ṩ�ռ�
 �� �� ֵ  : int == 0 �����ɹ�
                 != 0 ����ʧ��
 ��   ��   : wenjue
*****************************************************************************/
static int tid_parse_devstr(struct devinfo *devinfo, const char *devstr)
{
    char tmp[TID_USER_AGENT_MAXLEN] = {0};
    char *option = NULL;
    
    if (devstr == NULL || devinfo == NULL)
    {
        return -1;
    }

    memcpy(tmp, devstr, sizeof(tmp) - 1);
    option = strtok(tmp, " ");
    if (NULL == option)
    {
        return -1;
    }

    ////////////////////////// phone & pad //////////////////////////////////////
    if (0 == strncasecmp(option, "iPhone;", strlen(option)))
    {
        memcpy(devinfo->devtype, "iPhone", sizeof(devinfo->devtype));
        memcpy(devinfo->ostype, "IOS", sizeof(devinfo->ostype));
        return 0;
    }
    if (0 == strncasecmp(option, "iPad;", strlen(option)))
    {
        memcpy(devinfo->devtype, "iPad", sizeof(devinfo->devtype));
        memcpy(devinfo->ostype, "IOS", sizeof(devinfo->ostype));
        return 0;
    }
    if (0 == strncasecmp(option, "Linux;", strlen(option)))
    {
        if (NULL != strstr(devstr, "Android"))
        {
			memcpy(devinfo->devtype, "Mobile", sizeof(devinfo->devtype));
            memcpy(devinfo->ostype, "Android", sizeof(devinfo->ostype));
            return 0;
        }
    }
    if (0 == strncasecmp(option, "BlackBerry;", strlen(option)))
    {
        memcpy(devinfo->devtype, "Mobile", sizeof(devinfo->devtype));
        memcpy(devinfo->ostype, "BlackBerry", sizeof(devinfo->ostype));
        return 0;
    }
    ////////////////////////// pc //////////////////////////////////////
    if (0 == strncasecmp(option, "X11;", strlen(option)))
    {
        if (NULL != strstr(devstr, "Linux"))
        {
            memcpy(devinfo->ostype, "Linux", sizeof(devinfo->ostype));
            memcpy(devinfo->devtype, "PC", sizeof(devinfo->devtype));
            return 0;
        }
    }
    if (0 == strncasecmp(option, "Macintosh;", strlen(option)))
    {
        memcpy(devinfo->devtype, "Mac PC", sizeof(devinfo->devtype));
        memcpy(devinfo->ostype, "Mac OS", sizeof(devinfo->ostype));
        return 0;
    }
    if ((0 == strncasecmp(option, "Windows", strlen(option))) || 
        (0 == strncasecmp(option, "Windows;", strlen(option))) ||
        (0 == strncasecmp(option, "compatible;", strlen(option))))
    {
        if (NULL != strstr(devstr, "ME"))
        {
            memcpy(devinfo->ostype, "Windows ME", sizeof(devinfo->ostype));
        }
        else if (NULL != strstr(devstr, "Windows NT 5.1"))
        {
            memcpy(devinfo->ostype, "Windows XP", sizeof(devinfo->ostype));
        }
        else if (NULL != strstr(devstr, "Windows NT 5.2"))
        {
            memcpy(devinfo->ostype, "Windows Server", sizeof(devinfo->ostype));
        }
        else if (NULL != strstr(devstr, "Windows NT 6.0"))
        {
            memcpy(devinfo->ostype, "Windows Vista", sizeof(devinfo->ostype));
        }
		else if ((NULL != strstr(devstr, "compatible")) && (NULL == strstr(devstr, "MSIE")))
		{
			return -1;
		}
        else if (NULL != strstr(devstr, "Windows NT 6.1"))
        {
            memcpy(devinfo->ostype, "Windows 7/Server 2008", sizeof(devinfo->ostype));
        }
        else if (NULL != strstr(devstr, "Windows NT 6.2"))
        {
            memcpy(devinfo->ostype, "Windows 8", sizeof(devinfo->ostype));
        }
		else if (NULL != strstr(devstr, "Windows NT 6.3"))
        {
            memcpy(devinfo->ostype, "Windows 8", sizeof(devinfo->ostype));
        }
        else if (NULL != strstr(devstr, "Windows NT 6.4"))
        {
            memcpy(devinfo->ostype, "Windows 10", sizeof(devinfo->ostype));
        }
        else if (NULL != strstr(devstr, "Windows NT 10.0"))
        {
            memcpy(devinfo->ostype, "Windows 10", sizeof(devinfo->ostype));
        }
		else
		{
			return -1;
		}
        memcpy(devinfo->devtype, "PC", sizeof(devinfo->devtype));
        return 0;
    }
    
    return -1;
}

/*****************************************************************************
 �� �� ��  : tid_parse_useragent
 ��������  : �����ݰ��в�ֳ�User-Agent�ֶ�
 �������  : const char *ua, ����User-Agent�ֶε����ݰ�
 �������  : struct devinfo *devinfo, �����洢�豸��Ϣ�Ļ���,��������ṩ�ռ�
 �� �� ֵ  : int == 0 �����ɹ�
                 != 0 ����ʧ��
 ��   ��   : wenjue
*****************************************************************************/
static int tid_parse_useragent(struct devinfo *devinfo, const char *ua)
{
    char tmp[TID_USER_AGENT_MAXLEN] = {0};
    char *devstr = NULL;
    int ret = -1;
    
    if (ua == NULL || devinfo == NULL)
    {
        return -1;
    }

    memcpy(tmp, ua, sizeof(tmp) - 1);
    devstr = strtok(tmp, "(");
    if (devstr == NULL)
    {
        return -1;
    }
    devstr = strtok(NULL, ")");
    if (devstr == NULL)
    {
        return -1;    
    }

    ret = tid_parse_devstr(devinfo, devstr);	// parse User-Agent
    
    return ret;
}

/*****************************************************************************
 �� �� ��  : tid_parse_ishttptail
 ��������  : �����ж�http�����Ƿ��Ѿ���������β,������ʷǷ��ڴ�
 �������  : const char *data, http���ݰ�
 �������  : ��
 �� �� ֵ  : int == 1 �ѵ����β
                 == 0 δ�����β
 ��   ��   : wenjue
*****************************************************************************/
static int tid_parse_ishttptail(const char *data)
{
    int i = 0;
    int istail = 0;

    while (i <= 10)
    {
        if ((10 == *(data + i)) && (10 == *(data + i + 2)))
        {
            istail = 1;
            break;
        }
        i ++;
    }

    return istail;
}

/*****************************************************************************
 �� �� ��  : parse_http_callback
 ��������  : ���ݸ�libpcap�ӿ��û��������ݰ��Ļص�����
             ��������http���ģ���ȡ�豸��̬(PC��iphone��ipad��)��MAC��ַ
             ���������õ������ݷ��͸�UMģ��
 �������  : u_char *userless, ����������UMģ��ͨ�ŵ�udp socket
                               ����˵Ķ˿ںż���ַ��Ϣ
             const struct pcap_pkthdr *pkthdr, �ص������������˴�������
             const u_char *packet, http��·�����ݰ�
 �������  : ��
 �� �� ֵ  : ��
 ��   ��   : wenjue
*****************************************************************************/
static int tid_parse_httpmsg(const void *packet, struct usrtidmachdr *machdr, struct socket_clientinfo *socket)
{
    struct tcphead *tcpptr = NULL;
    struct devinfo stdevinfo;
    struct iphdr *ipptr = NULL;
    char reqmethod[ITD_HTTP_METHOD_MAXLEN] = {0};
    char *data = NULL;
    unsigned int ipaddr = 0;
    int ret = -1;
    int sendret = -1;
    int len = 0;
    int i = 0;

    if (packet == NULL || NULL == machdr || NULL == socket)
    {
        return -1;
    }

    memset(&stdevinfo, 0, sizeof(stdevinfo));
    i = 0;
    sprintf(stdevinfo.mac, "%02x", machdr->mac[i]);
    while (i < 5)
    {
        i++;
        sprintf(stdevinfo.mac, "%s:%02x", stdevinfo.mac, machdr->mac[i]);
    }
    ipptr = (struct iphdr *)(packet + len);
    i = 0;
    ipaddr = ntohl(ipptr->saddr);
    sprintf(stdevinfo.ipaddr, "%d", *((unsigned char *)&ipaddr));
    while (i < 3)
    {
        i++;
        sprintf(stdevinfo.ipaddr, "%s.%d", stdevinfo.ipaddr, *(((unsigned char *)&ipaddr) + i));
    }

    len += sizeof(struct iphdr);
    data = (char *)(packet + len);
    tcpptr = (struct tcphead *)data;
    len += tcpptr->headlen/4;
    
    data = (char *)(packet + len);
    memcpy(reqmethod, data, 4);
    if (0 != strncasecmp(reqmethod, "GET ", 4))
    {
        return -1;
    }

    i = 0;
    while(1)
    {
        if (*(data + i) == 10)
        {
            if (0 == strncasecmp(data + i + 1, "User-Agent:", 11))
            {
                ret = tid_parse_useragent(&stdevinfo, data + i + 13);
				if (strncasecmp(stdevinfo.ostype, "Windows", 7) == 0)
				{
					if (!strstr(data, "Referer:") || !strstr(data, "Cookie:"))		// we need the Web request packet
					{
						ret = -1;
					}

					if (strstr(data, "Referer: \r\n") || strstr(data, "Cookie: \r\n"))
					{
						ret = -1;
					}
				}
				break;
            }
        }
        if (tid_parse_ishttptail(data + i))
        {
            break;
        }
        i++;
    }
    if (0 == ret)
    {
        sendret = sendto(socket->socketfd, (void *)&stdevinfo, sizeof(stdevinfo), 0,
               (struct sockaddr*)&socket->serv_addr, sizeof(socket->serv_addr));
    }
    if (sendret == sizeof(stdevinfo))
    {
		tid_debug_notice("[tid]: [TID_HTTP_PROTOCOL] ip:[%s], mac:[%s], os type:[%s]", stdevinfo.ipaddr, stdevinfo.mac, stdevinfo.ostype);
        tid_debug_trace("[tid]: send devinfo to um success!");
    }
  
    return sendret;
}

/*****************************************************************************
 �� �� ��  : parse_netbios_callback
 ��������  : ���ݸ�libpcap�ӿ��û��������ݰ��Ļص�����
             ��������netbios���ģ���ȡ�豸����ϵͳ����������MAC��ַ
             ���������õ������ݷ��͸�UMģ��
 �������  : u_char *userless, ����������UMģ��ͨ�ŵ�udp socket
                               ����˵Ķ˿ںż���ַ��Ϣ
             const struct pcap_pkthdr *pkthdr, �ص������������˴�������
             const u_char *packet, netbios��·�����ݰ�
 �������  : ��
 �� �� ֵ  : ��
 ��   ��   : wenjue
*****************************************************************************/
static int tid_parse_netbiosmsg(const void *packet, struct usrtidmachdr *machdr, struct socket_clientinfo *socket)
{
    struct iphdr *ipptr = NULL;
    struct mwbpreq *mwbpptr = NULL;
    struct devinfo stdevinfo;
    unsigned char *data = NULL;
    unsigned int ipaddr = 0;
    int len = 0;
    int sendret = -1;
    int i = 0;
 
    if (packet == NULL || NULL == machdr || NULL == socket)
    {
        return -1;
    }

    memset(&stdevinfo, 0, sizeof(stdevinfo)); 
    i = 0;
    sprintf(stdevinfo.mac, "%02x", machdr->mac[i]);
    while (i < 5)
    {
        i++;
        sprintf(stdevinfo.mac, "%s:%02x", stdevinfo.mac, machdr->mac[i]);
    }
    
    ipptr = (struct iphdr *)(packet + len);
    i = 0;
    ipaddr = ntohl(ipptr->saddr);
    sprintf(stdevinfo.ipaddr, "%d", *((unsigned char *)&ipaddr));
    while (i < 3)
    {
        i++;
        sprintf(stdevinfo.ipaddr, "%s.%d", stdevinfo.ipaddr, *(((unsigned char *)&ipaddr) + i));
    }
    len += sizeof(struct iphdr);
    len += sizeof(struct udpstruct);
    data = (unsigned char *)(packet + len);
    if (*data != 17)
    {
        return -1;
    }
    len += 168;
    
    mwbpptr = (struct mwbpreq*)(packet + len);
    if (2 == mwbpptr->commondtype)
    {
        memcpy(stdevinfo.hostname, mwbpptr->hostname, sizeof(stdevinfo.hostname));
        memcpy(stdevinfo.devtype, "PC", sizeof(stdevinfo.devtype));
        sendret = sendto(socket->socketfd, (void *)&stdevinfo, sizeof(stdevinfo), 0,
               (struct sockaddr*)&socket->serv_addr, sizeof(socket->serv_addr));
    }
    if (sendret == sizeof(stdevinfo))
    {
		tid_debug_notice("[tid]: [TID_NETBIOS_PROTOCOL] ip:[%s], mac:[%s], hostname:[%s]", stdevinfo.ipaddr, stdevinfo.mac, stdevinfo.hostname);
        tid_debug_trace("[tid]: send devinfo to um success!");
    }
    
    return sendret;
}

/*****************************************************************************
 �� �� ��  : tid_parse_hostinfo
 ��������  : ��������bonjour�����а����豸��Ϣ���ֶ� 
 �������  : const char *deviceinfo,�����豸��Ϣ���ֶ�
 �������  : struct devinfo *hostinfo,�����õ����豸��Ϣ���桢������߿��ٿռ�
 �� �� ֵ  : ��
 ��   ��   : wenjue
*****************************************************************************/
static void tid_parse_hostinfo(struct devinfo *hostinfo, const char *deviceinfo)
{
    unsigned char modelen = 0;
    const char *modeinfo = NULL;
    unsigned short len = 0;

    modelen = *(deviceinfo + len);
    modeinfo = deviceinfo + len + 1;
    memcpy(hostinfo->cputype, modeinfo, modelen);
    len += modelen + 1;
    modelen = *(deviceinfo + len);
    modeinfo = deviceinfo + len + 1;
    memcpy(hostinfo->ostype, modeinfo, modelen);

    return;
}

/*****************************************************************************
 �� �� ��  : parse_bonjour_callback
 ��������  : ���ݸ�libpcap�ӿ��û��������ݰ��Ļص�����
             ��������bonjour���ģ���ȡ�豸����ϵͳ��CPU���͡�MAC��ַ
             ���������õ������ݷ��͸�UMģ��
 �������  : u_char *userless, ����������UMģ��ͨ�ŵ�udp socket
                               ����˵Ķ˿ںż���ַ��Ϣ
             const struct pcap_pkthdr *pkthdr, �ص������������˴�������
             const u_char *packet, bonjour��·�����ݰ�
 �������  : ��
 �� �� ֵ  : ��
 ��   ��   : wenjue
*****************************************************************************/
static int tid_parse_bonjourmsg(const void *packet, struct usrtidmachdr *machdr, struct socket_clientinfo *socket)
{
    unsigned short *devinfolen = NULL;
    unsigned short *answertype = NULL;
    struct dnsmsghead *dptr = NULL;
    struct iphdr *ipptr = NULL;
    struct devinfo stdevinfo;
    char hostname[TID_HOSTNAME_MAXLEN] = {0};
    char *deviceinfo = NULL;
    char *data = NULL;  
    char hostnamelen = 0;
    unsigned int ipaddr = 0;
    int sendret = -1;
    int len = 0;
    int i = 0;
 
    if (NULL == packet || NULL == machdr || NULL == socket)
    {
        return -1;
    }
    
    memset(&stdevinfo, 0, sizeof(stdevinfo));
    i = 0;
    sprintf(stdevinfo.mac, "%02x", machdr->mac[i]);
    while (i < 5)
    {
        i++;
        sprintf(stdevinfo.mac, "%s:%02x", stdevinfo.mac, machdr->mac[i]);
    }
    
    ipptr = (struct iphdr *)(packet + len);
    i = 0;
    ipaddr = ntohl(ipptr->saddr);
    sprintf(stdevinfo.ipaddr, "%d", *((unsigned char *)&ipaddr));
    while (i < 3)
    {
        i++;
        sprintf(stdevinfo.ipaddr, "%s.%d", stdevinfo.ipaddr, *(((unsigned char *)&ipaddr) + i));
    }
    len += sizeof(struct iphdr);
    len += sizeof(struct udpstruct);
    dptr = (struct dnsmsghead *)(packet + len);
    if (33792 != dptr->flag)
    {
        return -1;
    }
    
    len += sizeof(struct dnsmsghead);
    data = (char *)(packet + len);
    hostnamelen = *data;
    if (hostnamelen > TID_HOSTNAME_MAXLEN - 1)
    {
        hostnamelen = TID_HOSTNAME_MAXLEN - 1;
    }
    
    i = 1;
    while (0 != *(data + i))
    {
        if (i <= hostnamelen)
        {
            sprintf(hostname, "%s%c", hostname, *(data + i));
        }
        i++;
    };
    i++;   
    
    len += i;
    answertype = (unsigned short *)(packet + len);

    len += 8;
    devinfolen = (unsigned short *)(packet + len);
    len += 2;
    data = (char *)(packet + len);
    deviceinfo = malloc((*devinfolen) + 1);
    if (NULL == deviceinfo)
    {
        return -1;
    }
    snprintf(deviceinfo, *devinfolen + 1, "%s", data);

    if (13 == *answertype)
    {
        memcpy(stdevinfo.hostname, hostname, hostnamelen);
        tid_parse_hostinfo(&stdevinfo, deviceinfo);
        sendret = sendto(socket->socketfd, (void *)&stdevinfo, sizeof(stdevinfo), 0,
                  (struct sockaddr*)&socket->serv_addr, sizeof(socket->serv_addr));
    }
    
    free(deviceinfo);
    deviceinfo = NULL;
    if (sendret == sizeof(stdevinfo))
    {
		tid_debug_notice("[tid]: [TID_BONJOUR_PROTOCOL] ip:[%s], mac:[%s], hostname:[%s]", stdevinfo.ipaddr, stdevinfo.mac, stdevinfo.hostname);
        tid_debug_trace("[tid]: send devinfo to um success!");
    }
    
    return sendret;
}

static void tid_parse_packet(const void *packet, struct usrtidmachdr *machdr, struct socket_clientinfo *socket)
{
    int ret = -1;

    if (TID_HTTP_PROTOCOL == machdr->portocoltype)
    {
        ret = tid_parse_httpmsg(packet, machdr, socket);
    }
    else if (TID_DHCP_PROTOCOL == machdr->portocoltype)
    {
        ret = tid_parse_dhcpmsg(packet, machdr, socket);
    }
    else if (TID_NETBIOS_PROTOCOL == machdr->portocoltype)
    {
        ret = tid_parse_netbiosmsg(packet, machdr, socket);
    }
    else if (TID_BONJOUR_PROTOCOL == machdr->portocoltype)
    {
        ret = tid_parse_bonjourmsg(packet, machdr, socket);
    }
    
    if (ret > 0)
    {
        tid_sendmsg(sock, machdr);    
    }
    
    return;
}

void tid_recvmsg(struct socket_clientinfo *udpsocket, int socketfd)
{   
    socklen_t len;
    int ret;
    char buf[4096]= {0};
    struct sockaddr_nl src_addr;
    struct usrtidmachdr *machdr = NULL;

    ret = recvfrom(socketfd, buf, sizeof(buf), 0, (struct sockaddr *)&src_addr, &len);
    if (ret < 0 || ret >= sizeof(buf))
    {
        tid_debug_waring("[tid]: recv msg from tid_kmod error");

        return;
    }

    tid_debug_trace("[tid]: recv msg from tid_kmod success");
    machdr = (struct usrtidmachdr *)(buf + sizeof(struct nlmsghdr));
    tid_parse_packet(buf + sizeof(struct nlmsghdr) + sizeof(struct usrtidmachdr), machdr, udpsocket);

    return;
}

void tid_sendmsg(int socketfd, void *data)
{
    struct sockaddr_nl dst_addr;
    struct msghdr msg;
    struct iovec iov;
    struct nlmsghdr *nlh = NULL;
    int datalen = 0;
    int sendlen = 0;

    datalen += sizeof(struct nlmsghdr);
    datalen += sizeof(struct usrtidmachdr);
    nlh = malloc(datalen);
    if (NULL == nlh)
    {
        tid_debug_waring("[tid]: unable to allocate memory for nlh");

        return;
    }
    
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.nl_family = AF_NETLINK;
    dst_addr.nl_pid = 0;
    dst_addr.nl_groups = 0;

    nlh->nlmsg_len = datalen;
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    memcpy(NLMSG_DATA(nlh), data, sizeof(struct usrtidmachdr));

    iov.iov_base = (void *)nlh;
    iov.iov_len = datalen;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dst_addr;
    msg.msg_namelen = sizeof(dst_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    sendlen = sendmsg(socketfd, &msg, 0);
    if (sendlen > 0)
    {
        tid_debug_trace("[tid]: send msg to tid_kmod success");
    }
    free(nlh);

    return;
}
