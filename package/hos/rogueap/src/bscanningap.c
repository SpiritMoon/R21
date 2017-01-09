/******************************************************************************
  File Name    : bscanningap.c
  Author       : zhaoej
  Date         : 20160227
  Description  : background scanning interface receive
******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <err.h>

#include "rogue_utils.h"

extern char BKSCAN_PATH[PATH_LEN];
int rg_send_scanreq(u_int16_t msg_type){

	unsigned char sendbuf[BUF_MAX_LEN];
	struct sockaddr_un bkscan_addr;
	struct protocolHeader *msg = NULL;
	int buflen,ret;

	msg = (struct protocolHeader*)malloc(sizeof(struct protocolHeader));
	buflen = sizeof(struct protocolHeader);
	if(NULL == msg){
		rogue_debug(MODULE_BACKGROUND, ROGUEAP_LOG_LEVEL_ERR, "malloc memory for background scanning error!");
		rogue_debug_error("[ROGUEAP]: malloc memory for background scanning req failed");
		return FALSE;
	}
	
	//padding msg header
	msg->version = MESSAGE_PROCOTOL_VERSION;
	msg->op = OP_REQUEST;
	msg->reserved = MESSAGE_PROCOTOL_RESERVED; 
	msg->msg_type = msg_type; 
	msg->msg_len = 0;
	
	//padding sendbuf
	memset(sendbuf, 0, BUF_MAX_LEN);//send message length 
	memcpy(sendbuf, msg, sizeof(struct protocolHeader));
	free(msg);
	//padding background scanning addr
	bkscan_addr.sun_family = AF_UNIX;
	strncpy(bkscan_addr.sun_path, BKSCAN_PATH, sizeof(bkscan_addr.sun_path)-1);
	ret=rg_sendmsg(sendbuf, buflen, bkscan_addr);
	return ret;

}
void rg_scanap_req(){
	int ret = FALSE;
	ret = rg_send_scanreq(ROGUE_MSG_TYPE_VALUE_SCANNING_AP_INFO);
	if(!ret){
		rogue_debug_trace("[ROGUEAP]: send to background scanning ap reqest failed!");
	}
}
void rg_scansta_req(){
	int ret = FALSE;
	ret = rg_send_scanreq(ROGUE_MSG_TYPE_VALUE_SCANNING_STA_INFO);
	if(!ret){
		rogue_debug_trace("[ROGUEAP]: send to background scanning sta reqest failed!");
	}
}
u_int8_t mac[6] = {0};
void bkscan_apinfo(unsigned char *msg, unsigned int len){
	elementmsg elemsg;
	elemsg.msg = msg;
	elemsg.offset = 0;
	time_t c_time;
	u_int8_t mac_zero[MAC_ADDR_LEN] ={0};
	P_RGAP_LIST node = NULL;
	int ap_mark = GENERAL_AP;
	char str[STR_BUF];
	memset(str, 0, STR_BUF);
	//analysis background scaning ap info
	if(memcmp(mac, mac_zero, MAC_ADDR_LEN)){
		node = rg_find_ap_member(mac);	
	}
	while(elemsg.offset < len){
		u_int8_t type=0;
		u_int8_t sublen=0;
		parse_format_element(&elemsg,&type,&sublen);
		switch(type){
			case ROGUE_MSG_ELEMENT_TYPE_AP_MAC: //The first case must be AP mac(the two sides agreed)
				memcpy(mac,&elemsg.msg[elemsg.offset], sublen);
				ap_mark = scan_ap_filter(mac);
				node = rg_find_ap_member(mac);	
				if(node){
					node->t_stamp = time(&c_time);
					if(node->rgmac_sign){
						node->mark = ROGUE_AP;
					}else{
						node->mark = ap_mark;
					}
				}
				elemsg.offset += sublen;
				break;
			case ROGUE_MSG_ELEMENT_TYPE_SSID:
				if(node){
					if (sublen > MAX_SSID_LEN-1){
						memcpy(node->ssid, &elemsg.msg[elemsg.offset], MAX_SSID_LEN-1);
					}
					else{	
						memcpy(node->ssid, &elemsg.msg[elemsg.offset], sublen);
					}
					rg_ssid_filter(node);
					elemsg.offset += sublen;
				}
				break;
			case ROGUE_MSG_ELEMENT_TYPE_CHANNEL:
				if(node)
					node->channel = ProtocolRetrieve8(&elemsg);	//default channel 1-13
				break;
			case ROGUE_MSG_ELEMENT_TYPE_ENCRYPT:
				if(node){
					node->encrypt_type = ProtocolRetrieve8(&elemsg);//four bytes
					memset(mac, 0, MAC_ADDR_LEN);
				}
				break;
			case ROGUE_MSG_ELEMENT_TYPE_RSSI:
				if(node)
					node->rssi = (unsigned char)ProtocolRetrieve8(&elemsg);//rssi a byte character variables
				break;
			default:
				//sprintf(str,"Unrecognized AP Message Element Type=%02x",type);
				//rogue_debug(MODULE_BACKGROUND,ROGUEAP_LOG_LEVEL_WARNING,str);
				elemsg.offset += sublen;
				break;
		}
		
		
	}	
	
}

void bkscan_stainfo(unsigned char *msg, unsigned int len){

	elementmsg elemsg;
	elemsg.msg = msg;
	elemsg.offset = 0;
	int sta_mark = -1;
	time_t c_time;
	u_int8_t mac_zero[MAC_ADDR_LEN] ={0};
	P_RGSTA_LIST node =NULL;
	
	char str[STR_BUF];
	memset(str, 0, STR_BUF);
	if(memcmp(mac, mac_zero, MAC_ADDR_LEN)){
		node = rg_find_sta_member(mac);
	}
	while(elemsg.offset < len){
		u_int8_t type=0;
		u_int8_t sublen=0;
		parse_format_element(&elemsg,&type,&sublen);
		switch(type){
			case ROGUE_MSG_ELEMENT_TYPE_STA_MAC:
				memcpy(mac,&elemsg.msg[elemsg.offset], sublen);
				node = rg_find_sta_member(mac);
				if(node){
					elemsg.offset += sublen;
					node->t_stamp = time(&c_time);
				}
				break;
			case ROGUE_MSG_ELEMENT_TYPE_STA_IP:
				if(node){
					memcpy(node->ipaddr, &elemsg.msg[elemsg.offset], sublen);
					elemsg.offset += sublen;
				}
				break;
			case ROGUE_MSG_ELEMENT_TYPE_AP_MAC:
				if(node){
					memcpy(node->apmac, &elemsg.msg[elemsg.offset], sublen);//elemsg=6 bytes
					sta_mark = scan_sta_filter(node);
					elemsg.offset += sublen;
					node->index = sta_mark;
				}
				break;
			case ROGUE_MSG_ELEMENT_TYPE_STA_QOS:
				if(node)
				{
					node->qos=ProtocolRetrieve8(&elemsg);
					memset(mac, 0, MAC_ADDR_LEN);
				}
				break;
			default:
				//sprintf(str,"Unrecognized STA Message Element Type=%02x",type);
				//rogue_debug(MODULE_BACKGROUND,ROGUEAP_LOG_LEVEL_WARNING,str);
				elemsg.offset += sublen;
				break;
		}
		
	}
	dump_sta_info();
}

