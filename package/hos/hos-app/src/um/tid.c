/******************************************************************************
  文 件 名   : tid.c
  作    者   : wenjue
  生成日期   : 2014年11月19日
  功能描述   : um模块接收、存储、维护、删除设备信息
******************************************************************************/
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils.h"
#include "tid.h"
#include "um.h"

#define ITD_PORT 5600
#define TID_RECV_BUF_MAXLEN 256

extern int um_open_voice;
extern int um_open_bgs;


static int mac_str_to_bin(char *str, unsigned char *mac)
{
    int i;
    char *s, *e;

    if ((mac == NULL) || (str == NULL))
    {
        return -1;
    }

    s = (char *) str;
    for (i = 0; i < 6; ++i)
    {
        mac[i] = s ? strtoul (s, &e, 16) : 0;
        if (s)
           s = (*e) ? e + 1 : e;
    }
    return 0;
}

static void devinfo_update(bool created, struct apuser *dst, struct apuser *src)
{
    int flag = -1;
    struct devinfo *pstdevinfo_dst;
    struct devinfo *pstdevinfo_src;
    pstdevinfo_dst = &(dst->stdevinfo);
    pstdevinfo_src = &(src->stdevinfo);

    if (0 != src->ip)
    {
        dst->ip = src->ip;
    }

    {
        if ((pstdevinfo_src->hostname[0] != 0) && (0 != strcasecmp(pstdevinfo_dst->hostname, pstdevinfo_src->hostname)))
        {
            memcpy(pstdevinfo_dst->hostname, pstdevinfo_src->hostname, sizeof(pstdevinfo_dst->hostname));
            flag = 0;
        }
        if ((pstdevinfo_src->cputype[0] != 0) && (0 != strcasecmp(pstdevinfo_dst->cputype, pstdevinfo_src->cputype)))
        {
            memcpy(pstdevinfo_dst->cputype, pstdevinfo_src->cputype, sizeof(pstdevinfo_dst->cputype));
            flag = 0;
        }
        if ((pstdevinfo_src->devtype[0] != 0) && (0 != strcasecmp(pstdevinfo_dst->devtype, pstdevinfo_src->devtype)))
        {
            memcpy(pstdevinfo_dst->devtype, pstdevinfo_src->devtype, sizeof(pstdevinfo_dst->devtype));
            flag = 0;
        }
        if ((pstdevinfo_src->devmodel[0] != 0) && (0 != strcasecmp(pstdevinfo_dst->devmodel, pstdevinfo_src->devmodel)))
        {
            memcpy(pstdevinfo_dst->devmodel, pstdevinfo_src->devmodel, sizeof(pstdevinfo_dst->devmodel));
            flag = 0;
        }
        if ((pstdevinfo_src->ostype[0] != 0) && (0 != strcasecmp(pstdevinfo_dst->ostype, pstdevinfo_src->ostype)))
        {
            memcpy(pstdevinfo_dst->ostype, pstdevinfo_src->ostype, sizeof(pstdevinfo_dst->ostype));
            flag = 0;
        }
        if ((pstdevinfo_src->mac[0] != 0) && (0 != strcasecmp(pstdevinfo_dst->mac, pstdevinfo_src->mac)))
        {
            memcpy(pstdevinfo_dst->mac, pstdevinfo_src->mac, sizeof(pstdevinfo_dst->mac));
            flag = 0;
        }
        if ((pstdevinfo_src->ipaddr[0] != 0) && (0 != strcasecmp(pstdevinfo_dst->ipaddr, pstdevinfo_src->ipaddr)))
        {
            memcpy(pstdevinfo_dst->ipaddr, pstdevinfo_src->ipaddr, sizeof(pstdevinfo_dst->ipaddr));
            flag = 0;
        }
    }
    
    return;
}

/*****************************************************************************
 函 数 名  : tid_pthreadhandle
 功能描述  : um模块的线程处理函数，用来收集并存储设备信息
 输入参数  : void *data，线程处理函数的数据参数
 输出参数  : 无
 返 回 值  : void *线程处理函数返回值
 作   者   : wenjue
*****************************************************************************/
void *tid_pthreadhandle(void *data)
{
    struct sockaddr_in serv_addr;
    struct devinfo *pdevinfo = NULL;
    char buf[TID_RECV_BUF_MAXLEN] = {0};
    int socketfd = -1;
    int recvlen = 0;
    
    if((socketfd = socket(AF_INET,SOCK_DGRAM,0)) < 0)
    {
        debug_tid_waring("[um]: socket create failed!\r\n");
		return NULL;
    } 
    
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(ITD_PORT);
    if(bind(socketfd,(struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        debug_tid_waring("[um]: socket bind failed!\r\n");
        close(socketfd);     
		return NULL;
    }

    while (1)
    {
        recvlen = recvfrom(socketfd, buf, sizeof(buf), 0, NULL, NULL);
        if (recvlen == sizeof(struct devinfo))
        {
            pdevinfo = (struct devinfo *)buf;
            debug_tid_trace("[um]: RecvMsg From Tid mac:%s ip:%s devtype:%s\r\n", 
                        pdevinfo->mac, pdevinfo->ipaddr, pdevinfo->devtype);
            
            struct apuser info;
            memset(&info, 0, sizeof(struct apuser));
            mac_str_to_bin(pdevinfo->mac, info.mac);
            if ((pdevinfo->ipaddr[0] != 0))
            {
                info.ip = ntohl(inet_addr(pdevinfo->ipaddr));
            }
            
            debug_tid_trace("[um]:2 RecvMsg From Tid mac: %x:%x:%x:%x:%x:%x ip:%s devtype:%s\r\n", 
                        info.mac[0], info.mac[1],info.mac[2],info.mac[3],info.mac[4],info.mac[5],
                        os_ipstring(info.ip), pdevinfo->devtype);

            memcpy(&(info.stdevinfo), pdevinfo, sizeof(struct devinfo));
            cli_rwlock_wrlock();
		    um_user_update(&info, devinfo_update);
            cli_rwlock_unlock();
        }
        else
        {
            debug_tid_trace("[um]: RecvMsg From Tid Failed!\r\n");
        }
    }
    
    close(socketfd);

    return NULL;
}

#define NETLINK_LAYER7 25
void um_connect_statics_add(uint32_t ip)
{
    struct apuser *user = NULL;

    user = um_user_getbyip(ip);
    if (NULL == user) 
    {
        debug_tid_waring("[um]: um_connect_statics_add no found sta ip:%s\r\n", os_ipstring(ip));
        return;
    }

    /* pause scanning */
    if (1 == um_open_voice && 1 == um_open_bgs)
    {
		um_open_bgs = 0;
        system("bg-s -x pause_scanning=1");
        debug_tid_waring("[um]: bg-s -x pause_scanning=1 close bg-s\r\n");
    }
    user->con_statics ++; 
    debug_tid_trace("[um]: um_connect_statics_add ip:%s con_statics=%d \r\n",os_ipstring(ip), user->con_statics);
}

void um_connect_statics_del(uint32_t ip)
{
    struct apuser *user = NULL;

    user = um_user_getbyip(ip);
    if (NULL == user) 
    {
        debug_tid_waring("[um]: um_connect_statics_del no found sta ip:%s\r\n", os_ipstring(ip));
        return;
    }
    
    user->con_statics --; 
    debug_tid_trace("[um]: um_connect_statics_del ip:%s con_statics=%d \r\n",os_ipstring(ip), user->con_statics);
}

void um_connect_statics_set(uint32_t ip, int count)
{
    struct apuser *user = NULL;

    user = um_user_getbyip(ip);
    if (NULL == user) 
    {
        debug_tid_waring("[um]: um_connect_statics_set no found sta ip:%s\r\n", os_ipstring(ip));
        return;
    }

    /* pause scanning */
    user->con_statics = count; 
    debug_tid_trace("[um]: um_connect_statics_set ip:%s con_statics=%d \r\n",os_ipstring(ip), user->con_statics);
}

void l7_recvmsg(int socketfd)
{   
    socklen_t len;
    struct sockaddr_nl src_addr;
    int ret = -1;
    char buf[4096]= {0};
    int type = 0;
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    
    ret = recvfrom(socketfd, buf, sizeof(buf), 0, (struct sockaddr *)&src_addr, &len);
    if (ret < 0 || ret >= sizeof(buf))
    {
        debug_tid_waring("[um]: recv msg from l7 error");

        return;
    }
    
    struct nlmsghdr *pnlmsghdr = NULL;
    pnlmsghdr = (struct nlmsghdr *)buf;
    type = pnlmsghdr->nlmsg_type;

    src_ip = *(uint32_t *)(buf + sizeof(struct nlmsghdr));
    dst_ip = *(uint32_t *)(buf + sizeof(struct nlmsghdr) + sizeof(uint32_t));

    /* connect begin */
    if(0 == type)
    {
        cli_rwlock_wrlock();
        um_connect_statics_add(src_ip);
        um_connect_statics_add(dst_ip);
        cli_rwlock_unlock();
    }
    /* connect end */
    else if(1 == type)
    {
        cli_rwlock_wrlock();
        um_connect_statics_del(src_ip);
        um_connect_statics_del(dst_ip);
        cli_rwlock_unlock();
    }
    else
    {
        debug_tid_waring("[um]: recv msg from l7 type error");
    }

    return;
}

/*****************************************************************************
 函 数 名  : tid_pthreadhandle
 功能描述  : um模块的线程处理函数，用来收集并存储设备信息
 输入参数  : void *data，线程处理函数的数据参数
 输出参数  : 无
 返 回 值  : void *线程处理函数返回值
 作   者   : wenjue
*****************************************************************************/
void *l7_pthreadhandle(void *data)
{
    struct sockaddr_nl src_addr;
    int sock = -1;

    sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_LAYER7);
	if (sock < 0)
	{
	    debug_tid_waring("[um]: netlink socket creat failed");
        return NULL;
	}
	
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
    src_addr.nl_groups = 1;
    
	if (bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) 
	{
        debug_tid_waring("[um]: tid bind failed");
        close(sock);
        return NULL;
	}

    while(1)
    {
        l7_recvmsg(sock);
    }

    close(sock);
    
    return NULL;
}

