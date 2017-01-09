/******************************************************************************
  File Name    : netlink.c
  Author       : zhaoej
  Date         : 20160225
  Description  : netlink msg function
******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>         
#include <sys/socket.h>
#include <linux/socket.h>
#include <linux/netlink.h>

#include "rogue_utils.h"

#define USER_BROADCAST	1
#define BROADCADT_ID  	12
#define MAX_PAYLOAD 	2048 /*max msg payload type*/

#define NETLINK_GENERIC 16
#define NETLINK_DETECTOR_ROGURAP (NETLINK_GENERIC + 8)  /*rogueap netlink id */
#define ROGUE_AP_PID	0x03
#define CREATE_TRY		3

int nl_sock = 0;


/*create netlink and send netlink msg function*/
Bool init_nl_sock(void){
	struct sockaddr_nl nladdr;
	int i;
	
	//create netlink socket
	for(i=0; i<CREATE_TRY;i++){
		nl_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_DETECTOR_ROGURAP);
		if (nl_sock < 0)			 
			continue;		 
		else			
			break;
	}
	if(nl_sock<0){
		perror("[ERROR] can't create netlink socket!\n");
		rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_ERR,"create netlink socket failed!");
		rogue_debug_error("[ROGUEAP]: create netlink socket failed");
		return FALSE;
	}
	memset(&nladdr,0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pad = 0;

	#ifdef USER_BROADCAST
		nladdr.nl_pid = 0;
		nladdr.nl_groups = BROADCADT_ID;
	#else
		nladdr.nl_pid = ROGUE_AP_PID;//local process pid
		nladdr.nl_groups = 0;
	#endif
	
	if(-1 == bind(nl_sock,(struct sockaddr *)&nladdr, sizeof(nladdr))){
		perror("[ERROR] can't bind sockfd with sockaddr_nl!\n");
		rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_ERR,"bind sockfd with sockaddr_nl failed!");
		rogue_debug_error("[ROGUEAP]: bind netlink sockfd with sockaddr_nl failed");
		close(nl_sock);
		return FALSE;
	}
	return TRUE;
}

/*the common netlink send message*/
int nl_send_msg(char *buf,int buflen){
	struct sockaddr_nl dest_addr;
	struct nlmsghdr * nlh;
	struct msghdr msg;
	struct iovec iov;
	int ret=0;

	char str[STR_BUF];
	memset(str, 0, STR_BUF);
	if(NULL==(nlh=(struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD)))){
		perror("alloc mem failed!");
		rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_ERR,"alloc mem failed!");
		rogue_debug_error("[ROGUEAP]: Malloc netlink mem failed!");
		return FALSE;
	}
	memset(&dest_addr,0,sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;//发送给内核的
#ifdef USER_BROADCAST
	dest_addr.nl_groups = BROADCADT_ID;
#else
	dest_addr.nl_groups = 0;
#endif
	memset(nlh,0,NLMSG_SPACE(MAX_PAYLOAD));
	/*insert netlink msg header*/
	nlh->nlmsg_len = NLMSG_SPACE(buflen);
	nlh->nlmsg_pid = ROGUE_AP_PID; //We hope to get the responses of the other modules, so tell our pid to other modules
	nlh->nlmsg_type = NLMSG_NOOP;
	nlh->nlmsg_flags = 0;

	/*set Netlink msg payload check*/
	memcpy(NLMSG_DATA(nlh), buf, buflen);
	packet_dump(NLMSG_DATA(nlh),buflen);
	memset(&iov,0,sizeof(iov));
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&msg, 0,sizeof(msg));
	msg.msg_name = &dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if((ret=sendmsg(nl_sock, &msg, 0))==-1){//Netlink socket, send msg to other module
		sprintf(str,"send to kernel----function:%s,line:%d,ret=%d\n",__func__,__LINE__,ret);
		rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_ERR,str);		
		rogue_debug_error("[ROGUEAP]: send netlink packet to kernel failed!");
		free(nlh);
		return FALSE;
	}
	free(nlh);
	return TRUE;
}






