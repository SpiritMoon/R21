/******************************************************************************
  File Name    : clusterap.c
  Author       : zhaoej
  Date         : 20160227
  Description  : cluster management interface receive
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <err.h>

#include "parse_message.h"
#include "rogue_utils.h"


#define MESSAGE_PROCOTOL_VERSION	0
#define MESSAGE_PROCOTOL_RESERVED	0

extern char CLASTER_PATH[PATH_LEN];

int rg_send_clusterap(void){
	
	unsigned char sendbuf[BUF_MAX_LEN];
	struct sockaddr_un cluster_addr;
	struct protocolHeader *msg;
	int buflen;
	int ret=0;
	msg = (struct protocolHeader*)malloc(sizeof(struct protocolHeader));
	buflen = sizeof(struct protocolHeader);
	if(NULL == msg){
		rogue_debug(MODULE_CLUSTER,ROGUEAP_LOG_LEVEL_ERR,"malloc memory for cluster management error!");	
		rogue_debug_error("[ROGUEAP]: malloc memory for cluster management req failed");
		return FALSE;
	}

	//padding msg header
 	msg->version = MESSAGE_PROCOTOL_VERSION;
	msg->op = OP_REQUEST;
	msg->reserved = MESSAGE_PROCOTOL_RESERVED; 
	msg->msg_type = ROGUE_MSG_TYPE_VALUE_CLUSTER_MEMBER_STATE; 
	msg->msg_len = 0;

	//padding sendbuf
	memset(sendbuf, 0, BUF_MAX_LEN);//send message length 
	memcpy(sendbuf, msg, sizeof(struct protocolHeader));

	//padding cluser addr
	cluster_addr.sun_family = AF_UNIX;
	strncpy(cluster_addr.sun_path, CLASTER_PATH,sizeof(cluster_addr.sun_path)-1);
	ret=rg_sendmsg(sendbuf, buflen, cluster_addr);
	free(msg);
	return ret;

}

void cluster_apinfo(unsigned char *msg, unsigned int len){
	elementmsg elemsg;
	elemsg.msg = msg;
	elemsg.offset = 0;
	char str[STR_BUF];
	time_t c_time;
	P_CLUSTER_LIST node = NULL;
	u_int8_t mac[MAC_ADDR_LEN]={0};
	memset(str, 0, STR_BUF);
	
	while(elemsg.offset < len){
		u_int8_t type=0;
		u_int8_t sublen=0;
		parse_format_element(&elemsg,&type,&sublen);
		switch(type){
			case ROGUE_MSG_ELEMENT_TYPE_WTP_INFO:
				//nothing to do
				break;
			case ROGUE_MSG_ELEMENT_TYPE_WTP_MAC:
				//update CT_AP info
				memcpy(mac, &elemsg.msg[elemsg.offset], sublen);//elemsg=6 bytes
				node=rg_find_cm_member(mac);
				node->t_stamp = time(&c_time);
				elemsg.offset += sublen;
				
				break;
			default:
				elemsg.offset += sublen;
				//sprintf(str,"Unrecognized Cluster AP Message Element Type=%02x",type);
				//rogue_debug(MODULE_CLUSTER, ROGUEAP_LOG_LEVEL_WARNING,str);
				break;
		}
	}
	dump_cluster_info();
}


