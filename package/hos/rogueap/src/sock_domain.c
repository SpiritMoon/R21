/******************************************************************************
  File Name    : sock_domain.c
  Author       : zhaoej
  Date         : 20160216
  Description  : local socket handle
******************************************************************************/
#include <sys/types.h>      
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rogue_utils.h"

int local_sock = -1;
char RG_PATH[PATH_LEN] 		= "/tmp/rogue";
char CLASTER_PATH[PATH_LEN] = "/tmp/cluster_mgt_socket";
char BKSCAN_PATH[PATH_LEN] 	= "/tmp/unix-bgscan";


//init local socket 
Bool init_socket(){
	struct sockaddr_un addr;
	int ret = 0;
	//create socket
	local_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(local_sock < 0){
		perror("cannot create communication socket!");
		rogue_debug(MODULE_ROGUE, ROGUEAP_LOG_LEVEL_ERR,"cannot create communication socket!");
		rogue_debug_error("[ROGUEAP]: Create socket failed");
		return FALSE; 
	}
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, RG_PATH,sizeof(addr.sun_path)-1);

	//delete the old server socket link
	unlink(RG_PATH);
	//bind socket with the local file  
	if((ret = bind(local_sock,(struct sockaddr*)&addr,sizeof(addr))) < 0){
		perror("cannot bind server socket");
		rogue_debug(MODULE_ROGUE, ROGUEAP_LOG_LEVEL_ERR,"cannot bind server socket!");
		rogue_debug_error("[ROGUEAP]: Bind server socket failed");
		close(local_sock);
		unlink(RG_PATH);
		return FALSE;
	}
	return TRUE;
}


Bool rg_sendmsg(unsigned char *sendbuf,int buflen,struct sockaddr_un desaddr){
	//check legal sendbuf, desaddr
	if(NULL == sendbuf){
		rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_ERR,"local socket send message buf is NULL!");
		rogue_debug_error("[ROGUEAP]: local socket send message buf is NULL");
		return FALSE;
	}
	buf_dump(sendbuf,buflen,&desaddr,1);
	if(sendto(local_sock, sendbuf, buflen, MSG_DONTWAIT, (struct sockaddr *)&desaddr,sizeof(desaddr))<0){
		perror("rogueap local socket send message error\n");
		rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_WARNING,"rogueap local socket send message failed,please check bg-s/or cluster_mgt process start!");
		rogue_debug_trace("[ROGUEAP]: local socket send req to '%s' error!",desaddr.sun_path);
		return FALSE;
	}
	return TRUE;
}

int rg_recvmsg(unsigned char *recvbuf,int buflen){
	//check legal sendbuf, desaddr
	socklen_t addrlen;
	struct sockaddr_un srcaddr;
	if(NULL == recvbuf){
		rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_ERR,"local socket receive message buf is NULL!");
		rogue_debug_error("[ROGUEAP]: local socket receive message buf is NULL");
		return FALSE;
	}
	addrlen = sizeof(srcaddr);
	if((buflen = recvfrom(local_sock, recvbuf,buflen, 0, (struct sockaddr *)&srcaddr, &addrlen))<0){
		rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_ERR,"local socket recv message error!");
		rogue_debug_error("[ROGUEAP]: local socket receive message error");
		return FALSE;
	}

	buf_dump(recvbuf,buflen,&srcaddr,0);
	return buflen;
}

int handle_recvmsg(unsigned char *buf,unsigned int buflen){
	elementmsg elemsg;
	struct protocolHeader msgheader; 	
	elemsg.msg = buf;
	elemsg.offset = 0;
	char str[STR_BUF];

	memset(str, 0, STR_BUF);
	if(!parse_msg_header(&elemsg,&msgheader)){
		rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_ERR,"parsing message header error!");
		rogue_debug_error("[ROGUEAP]: parsing message header error");
		return FALSE;
	}
	
	if((msgheader.op == OP_RESPONSE) && (msgheader.msg_len < buflen)){
		switch(msgheader.msg_type){
			case ROGUE_MSG_TYPE_VALUE_CLUSTER_MEMBER_STATE:
				cluster_apinfo(elemsg.msg+elemsg.offset, msgheader.msg_len);
				break;
			case ROGUE_MSG_TYPE_VALUE_SCANNING_AP_INFO:
				bkscan_apinfo(elemsg.msg+elemsg.offset,msgheader.msg_len);
				break;
			case ROGUE_MSG_TYPE_VALUE_SCANNING_STA_INFO:
				dump_ap_info();
				bkscan_stainfo(elemsg.msg+elemsg.offset,msgheader.msg_len);
				break;
			default:
			//	sprintf(str,"Unrecognized AP Message Element Type =%d",msgheader.msg_type );
			//	rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_WARNING,str);
				break;
		}
		return TRUE;
	}
	else{
		return FALSE;
	}
}






