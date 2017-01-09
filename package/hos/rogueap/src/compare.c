/******************************************************************************
  File Name    : compare.c
  Author       : zhaoej
  Date         : 20160308
  Description  : rogueap module core algorithm
******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "rogue_utils.h"


int g_ap_num = 0;
int g_sta_num = 0;
int g_fdb_num = 0;

LIST_HEAD(cluster_member_list);

void init_hasi_list(){
	int i = 0;
	
	for (i=0; i<RG_NODE_HASHSIZE; i++) {
		list_head_init(&ap_hasi_table[i].head);
	}
	
	for (i=0; i<RG_NODE_HASHSIZE; i++) {
		list_head_init(&sta_hasi_table[i].head);
	}
} 
u_int8_t * get_scanap_bmac(u_int8_t *mac){
	static u_int8_t mac1[6] = {0};
	mac1[0] = mac[0];
	mac1[1] = mac[1];
	mac1[2] = mac[2];
	mac1[3] = mac[3];
	mac1[4] = mac[4];
	mac1[5] = RG_SCAN_AP_BMAC(mac);
	return mac1;
	
}

//scanning AP and cluster AP compare /white wildcard ===>interference AP list
int scan_ap_filter(u_int8_t * apmac){

	P_CLUSTER_LIST pos = NULL;
	u_int8_t * bmac = NULL;
	int i,mark = 0;
	int len = 0;
	
	/*compare with cluster_member*/
	bmac = get_scanap_bmac(apmac);
	list_for_each(&cluster_member_list,pos,list){
		if(memcmp(bmac, pos->macaddr, MAC_ADDR_LEN)){
			mark = 0;
		}
		else{
			#if 0
			printf("%s-%d: 111111111111node_mac--%02x:%02x:%02x:%02x:%02x:%02x,cluster_mac--%02x:%02x:%02x:%02x:%02x:%02x!\n",__func__,__LINE__,
				mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],pos->macaddr[0],
				pos->macaddr[1],pos->macaddr[2],pos->macaddr[3],pos->macaddr[4],pos->macaddr[5]);
			#endif
			mark = -1;
			break;
		}	
	}
	
	/*compare with white wildcard*/
	for(i = 0; i<conf.wildcard_num && i<WILDCARD_MAX_NUM; i++){
		len =  conf.wildcard[i].hmac_len;
		if(INTERFERENCE_AP == mark){
			if(memcmp(apmac, conf.wildcard[i].hmac,len)){
				mark = 0;//interference AP
			}
			else{
				mark = -1;
				break;
			}
		}
	}

	/*scanap compare with fdb form ==>interference and rogueap*/
	if(INTERFERENCE_AP == mark){
		for(i=0;i<g_fdb_num;i++){
			if(0 == memcmp(apmac, FDB[i].mac_addr, MAC_ADDR_LEN)){
				mark = 1;
				break;
			}
		}
	}
	return mark;	
}

void rg_ssid_filter(P_RGAP_LIST node){

	int i;
	/*scanap essid compare with valid ssid list*/
	if(INTERFERENCE_AP == node->mark){
		for(i=0;i<MAX_SSID_LEN;i++){
			if(*SSID[i].essid!=0 && 0 == strcmp(SSID[i].essid, node->ssid)){
				node->mark = 1;
				break;
			}
		}
	}
	if(auto_black_debug && ROGUE_AP == node->mark){
		node->black_sign = 1;
	}
}
int scan_sta_filter(	P_RGSTA_LIST ni){
	int i;
	u_int8_t * mac = ni->apmac;
	P_RGAP_LIST node = NULL;
	int hasi = 0;
	hasi = RG_NODE_HASH(mac);
	list_for_each(&ap_hasi_table[hasi].head,node,list){
		if(0 == memcmp(mac, node->macaddr,MAC_ADDR_LEN)){
			ni->index = node->mark;
			if(0 == ni->index){
				for(i=0;i<g_fdb_num;i++){
					if(0 == memcmp(ni->stamac, FDB[i].mac_addr, MAC_ADDR_LEN)){
						ni->index = 1;
						node->mark = 1;
						if(auto_black_debug){
							node->black_sign = 1;
						}
						break;
					}	
				}
			}
			break;
		}
		else{
				ni->index = -1;
		}
	}
	return ni->index;
}


/*
** get rogue AP list and interference AP list
*/
void get_ap_list(void){
	int apid = 0;
	int i,j,k;
	P_RGAP_LIST ap = NULL;
	P_RGSTA_LIST sta = NULL;
	
	struct display_node ap_arr[RG_MAX_AP];
	memset(ap_arr, 0, sizeof(struct display_node)*RG_MAX_AP);
	
	for(i=0;i<RG_NODE_HASHSIZE;i++){	
		list_for_each(&ap_hasi_table[i].head,ap,list){

			if((INTERFERENCE_AP == ap->mark)||(ROGUE_AP == ap->mark)){
				k = 0;
				for(j=0;j<RG_NODE_HASHSIZE;j++){
					list_for_each(&sta_hasi_table[j].head,sta,list){
						if(0 == memcmp(sta->apmac,ap->macaddr,MAC_ADDR_LEN)){
							if(k >= MAX_STA){
								break;
							}
							ap_arr[apid].sta_num ++;
							memcpy(ap_arr[apid].sta_mac[k],sta->stamac, MAC_ADDR_LEN);
							k++;
						}
					}
				}
				memcpy(ap_arr[apid].mac, ap->macaddr, MAC_ADDR_LEN);
				if(ap_arr->ssid){
					strncpy(ap_arr[apid].ssid, ap->ssid, strlen(ap->ssid));
				}
				ap_arr[apid].channel = ap->channel;
				ap_arr[apid].auth_type = ap->encrypt_type;
				ap_arr[apid].rssi = ap->rssi;
				ap_arr[apid].type = ap->mark;
				ap_arr[apid].black_sign = ap->black_sign;
				
				apid ++;
			}
		}
		
	}
	display_ap_node_command(ap_arr,apid);
}

/*
** get AP black list
*/
void get_black_list(void){
	int apid = 0;
	int i;
	P_RGAP_LIST ap = NULL;
	struct black_node ap_arr[RG_MAX_AP];
	memset(ap_arr, 0, sizeof(struct black_node)*RG_MAX_AP);
	for(i=0;i<RG_NODE_HASHSIZE;i++){	
		list_for_each(&ap_hasi_table[i].head,ap,list){
			if(1 == ap->black_sign){
				memcpy(ap_arr[apid].mac, ap->macaddr, MAC_ADDR_LEN); 
				apid ++;
			}
		}
	}
	display_black_list_command(ap_arr,apid);
}

void rg_auto_blacklist(){
	#define MAC_MAX_BLACK 5
	P_RGAP_LIST ap = NULL;
	int i,j=0,k;
	int curlen = 0;
	char buf[128] = {0};
	char * cmdPtr = NULL;
	char cmdstr[128];
	cmdPtr = buf;
	u_int8_t mac_arr[MAC_MAX_BLACK][MAC_ADDR_LEN]={{0}};
	for(i=0;i<RG_NODE_HASHSIZE;i++){	
		list_for_each(&ap_hasi_table[i].head,ap,list){
			if(ROGUE_AP == ap->mark){
				if(0 == auto_black_debug){
					ap->black_sign = 0;
				}
				else{
					ap->black_sign = 1;
				}
				memcpy(mac_arr[j], ap->macaddr, MAC_ADDR_LEN);
				j++;	
				if(j==MAC_MAX_BLACK){
					memset(cmdstr, 0, 128);
					for(k=0;k<MAC_MAX_BLACK;k++){
						curlen += sprintf(cmdPtr,"%02x:%02x:%02x:%02x:%02x:%02x ",mac_arr[k][0],mac_arr[k][1],mac_arr[k][2],mac_arr[k][3],mac_arr[k][4],mac_arr[k][5]);
						cmdPtr = buf + curlen;
					}
					if(0 == auto_black_debug){
						sprintf(cmdstr,"/usr/sbin/rg_black del %s &",buf);
						system(cmdstr);

					}else{
						sprintf(cmdstr,"/usr/sbin/rg_black add %s &",buf);
						system(cmdstr);
					}
					memset(mac_arr, 0, sizeof(mac_arr));
					j=0;
					curlen=0;
					memset(buf, 0, 128);
					cmdPtr = buf;
				}
			}
			
		}
	}
	if(j != 0){
		memset(cmdstr, 0 ,128);
		for(k=0;k<j;k++){
			curlen += sprintf(cmdPtr, "%02x:%02x:%02x:%02x:%02x:%02x ",mac_arr[k][0],mac_arr[k][1],mac_arr[k][2],mac_arr[k][3],mac_arr[k][4],mac_arr[k][5]);
			cmdPtr = buf + curlen;
		}
		if(0 == auto_black_debug){
			sprintf(cmdstr,"/usr/sbin/rg_black del %s &",buf);
			system(cmdstr);
		}
		else{
			sprintf(cmdstr,"/usr/sbin/rg_black add %s &",buf);
			system(cmdstr);
		}	
	}
}
void rg_modify_mac(u_int8_t *mac){
	P_RGAP_LIST pos = NULL;
	int hash = 0;
	char cmdstr[64] ={0};
	hash = RG_NODE_HASH(mac);
	list_for_each(&ap_hasi_table[hash].head,pos,list) {
		if(memcmp(pos->macaddr,mac,MAC_ADDR_LEN) == 0){
			if(add_rogue_mac){
				pos->mark = ROGUE_AP;
				pos->rgmac_sign = 1;
			}else{
				pos->mark = INTERFERENCE_AP;
				pos->rgmac_sign = 0;
				if(auto_black_debug){
					pos->black_sign = 0;
					sprintf(cmdstr,"/usr/sbin/rg_black del %02x:%02x:%02x:%02x:%02x:%02x &",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	 				system(cmdstr);
				}
			}
		}
	}	
}
/*test code*/
void get_ap_info(void){
	int apid = 0;
	int i,j,k;
	P_RGAP_LIST ap = NULL;
	P_RGSTA_LIST sta = NULL;
	
	struct display_node ap_arr[RG_MAX_AP];
	memset(ap_arr, 0, sizeof(struct display_node)*RG_MAX_AP);
	
	for(i=0;i<RG_NODE_HASHSIZE;i++){	
		list_for_each(&ap_hasi_table[i].head,ap,list){
			if((INTERFERENCE_AP == ap->mark)||(ROGUE_AP == ap->mark)){
				k = 0;
				for(j=0;j<RG_NODE_HASHSIZE;j++){
					list_for_each(&sta_hasi_table[j].head,sta,list){
						if(0 == memcmp(sta->apmac,ap->macaddr,MAC_ADDR_LEN)){
							if(k >= MAX_STA){
								break;
							}
							ap_arr[apid].sta_num ++;
							memcpy(ap_arr[apid].sta_mac[k],sta->stamac, MAC_ADDR_LEN);
							k++;
						}
					}
				}
				memcpy(ap_arr[apid].mac, ap->macaddr, MAC_ADDR_LEN);
				if(ap_arr->ssid){
					strncpy(ap_arr[apid].ssid, ap->ssid, strlen(ap->ssid));
				}
				ap_arr[apid].channel = ap->channel;
				ap_arr[apid].auth_type = ap->encrypt_type;
				ap_arr[apid].rssi = ap->rssi;
				ap_arr[apid].type = ap->mark;
				ap_arr[apid].t_stamp = ap->t_stamp;
				ap_arr[apid].black_sign = ap->black_sign;
				apid ++;
			}
		}
		
	}
	printf("apid=%d\n",apid);
	printf("%-8s %-20s %-34s %-10s %-10s %-10s %-10s %-10s %-10s %-15s %-10s\n",
			"APID", "MAC", "SSID", "CHANNEL", "AUTH_TYPE", "RSSI", "STA_NUM", "TYPE", "BLACK", "C_Time", "STAMAC");
	for(i = 0; i < apid; i++)
	{
		printf("%-8d %02x:%02x:%02x:%02x:%02x:%02x\t %-34s %-10u %-10u %-10d %-10d %-10d %-10u %-15s\t", i, ap_arr[i].mac[0], ap_arr[i].mac[1],
		ap_arr[i].mac[2], ap_arr[i].mac[3], ap_arr[i].mac[4], ap_arr[i].mac[5], ap_arr[i].ssid, ap_arr[i].channel,
		ap_arr[i].auth_type,ap_arr[i].rssi, ap_arr[i].sta_num,ap_arr[i].type,ap_arr[i].black_sign, asctime(localtime(&(ap_arr[i].t_stamp))));
		
		for(j = 0; j < ap_arr[i].sta_num; j++)
		{
			printf("%02x:%02x:%02x:%02x:%02x:%02x",ap_arr[i].sta_mac[j][0], ap_arr[i].sta_mac[j][1], ap_arr[i].sta_mac[j][2], 
				ap_arr[i].sta_mac[j][3], ap_arr[i].sta_mac[j][4], ap_arr[i].sta_mac[j][5]);
			if((j+1) < ap_arr[i].sta_num){
				printf(",");
			}	
		}
		printf("\n");
	}
}
void rg_essid_list(){
	#define MAX_LEN 34
	char cmd_str[128];
	FILE *fp_str;
	int i = 0,j;
	int has_flag = 0;
	char result_buf[MAX_LEN];
	memset(cmd_str, 0, 128);
	sprintf(cmd_str, "cat /etc/config/wireless |grep -r \"ssid\" |awk -F \"'\" '{print $2}'");
	fp_str = popen(cmd_str, "r");
	if(NULL == fp_str)
	{
		perror("popen read failed!");
		exit(1);
	}
	memset(SSID, 0, MAX_ESSID_NUM);
	while(fgets(result_buf,sizeof(result_buf),fp_str)){
		if('\n' == result_buf[strlen(result_buf)-1]){
			result_buf[strlen(result_buf)-1] = '\0';
		}
		if(strcmp(result_buf,"athscan0")!=0 && strcmp(result_buf,"athscan1")!=0){
			if(*SSID[0].essid != 0){
				for(j = 0;j < i; j++){
					if(strcmp(SSID[j].essid, result_buf) == 0){
						has_flag = 1;
						break;
					}else{
						has_flag = 0;
					}
				}
				if(!has_flag && i<MAX_ESSID_NUM){
					strncpy(SSID[i].essid,result_buf,strlen(result_buf));
					i++;
				}
			}else{
				strncpy(SSID[i].essid,result_buf,strlen(result_buf));
				i++;
			}
		}
	}
	pclose(fp_str);
	if(list_debug){
		dump_file_open("a+");
		fprintf(DUMP_FILE, "\n==========ESSID Form Information=============\n");
		fprintf(DUMP_FILE,"ID\tESSID\t\tID\tESSID\n");
		for(j = 0; j< i; j++){	
			if(j%2==0 && j!=0){
				fprintf(DUMP_FILE, "\n");
			}
			fprintf(DUMP_FILE, "%d\t%s\t\t",j,SSID[j].essid);
		}
		fprintf(DUMP_FILE,"\n");
		dump_file_close();
	}
}
void rg_get_info(){

	g_fdb_num=get_fdb_form();
	if(g_fdb_num<0){
		rogue_debug(MODULE_ROGUE, ROGUEAP_LOG_LEVEL_WARNING,"Get FDB form is NULL!");
		rogue_debug_waring("[ROGUEAP]:Get FDB form is NULL!");
	}
	rg_essid_list();
	rg_send_clusterap();
	rg_scanap_req();
	rg_scansta_req();
	//get_ap_info();
	if(auto_black_debug){
		rg_auto_blacklist();
	}
	if(conf.suppress_switch){
		rg_suppress_element();	
	}
	
}


P_RGAP_LIST rg_create_ap_list_node(u_int8_t * mac)
{
	P_RGAP_LIST node = NULL;
	int hash = 0;
	node = (P_RGAP_LIST) malloc(sizeof(RGAP_LIST));
	if(node){
		memset(node, 0, sizeof(RGAP_LIST));
		memcpy(node->macaddr,mac,MAC_ADDR_LEN);
		hash = RG_NODE_HASH(node->macaddr);
		list_add_tail(&ap_hasi_table[hash].head,&node->list);
		g_ap_num++;
	}
	return node;
}
P_RGAP_LIST  rg_find_ap_member(u_int8_t * mac)
{
	P_RGAP_LIST pos = NULL;
	P_RGAP_LIST tmp=NULL,nxt=NULL;
	int hash = 0;
	int i;
	
	hash = RG_NODE_HASH(mac);
	list_for_each(&ap_hasi_table[hash].head,pos,list) {
		if(memcmp(pos->macaddr,mac,MAC_ADDR_LEN) == 0){
			return pos;
		}
	}
	if(g_ap_num >= RG_MAX_AP){	
		for(i=0;i<RG_NODE_HASHSIZE;i++){
			list_for_each_safe(&ap_hasi_table[i].head,pos,nxt,list){
				if(NULL == tmp){
					tmp = pos;
					continue;
				}
				if(tmp->t_stamp > pos->t_stamp){
					tmp = pos;
				}
			}
		}
		rg_del_ap_member(tmp);
	}
	return rg_create_ap_list_node(mac);
}

P_RGSTA_LIST rg_create_sta_list_node(u_int8_t * mac)
{
	P_RGSTA_LIST ni = NULL;
	int hash = 0;
	ni = (P_RGSTA_LIST) malloc(sizeof(RGSTA_LIST));

	if(ni){
		memset(ni,0,sizeof(RGSTA_LIST));
		memcpy(ni->stamac,mac,MAC_ADDR_LEN);
		hash = RG_NODE_HASH(ni->stamac);
		list_add_tail(&sta_hasi_table[hash].head,&ni->list);
		g_sta_num ++;
	}
	return ni;
}

P_RGSTA_LIST  rg_find_sta_member(u_int8_t * mac)
{
	P_RGSTA_LIST pos = NULL;
	P_RGSTA_LIST tmp = NULL,nxt = NULL;
	int hash = 0;
	int i;
	hash = RG_NODE_HASH(mac);
	list_for_each(&sta_hasi_table[hash].head,pos,list) {
		if(memcmp(pos->stamac,mac,MAC_ADDR_LEN) == 0){
			return pos;
		}
	}
	
	if(g_sta_num >= RG_MAX_STA){
		for(i=0;i<RG_NODE_HASHSIZE;i++){
			list_for_each_safe(&sta_hasi_table[i].head,pos,nxt,list){
				if(NULL == tmp){
					tmp = pos;
					continue;
				}
				if(tmp->t_stamp > pos->t_stamp){
					tmp = pos;
				}
			}
		}
		rg_del_sta_member(tmp);
	}
	return rg_create_sta_list_node(mac);
}

P_CLUSTER_LIST rg_create_cm_list_node(u_int8_t * mac)
{
	P_CLUSTER_LIST cluster_member = NULL;
	cluster_member = (P_CLUSTER_LIST) malloc(sizeof(CLUSTER_LIST));
	if(cluster_member){
		memset(cluster_member, 0, sizeof(CLUSTER_LIST));
		memcpy(cluster_member->macaddr,mac,MAC_ADDR_LEN);
		list_add_tail(&cluster_member_list,&cluster_member->list);
	}
	return cluster_member;
}
P_CLUSTER_LIST rg_find_cm_member(u_int8_t * mac)
{
	P_CLUSTER_LIST pos = NULL;
	list_for_each(&cluster_member_list,pos,list) {
		if(memcmp(pos->macaddr,mac,MAC_ADDR_LEN) == 0){
			return pos;
		}
	}	
	return rg_create_cm_list_node(mac);
}


void rg_del_ap_member(P_RGAP_LIST node){
	char buf[64]={0};
	if(node){
		if(node->black_sign){
			sprintf(buf,"/usr/sbin/rg_black del %02x:%02x:%02x:%02x:%02x:%02x &",node->macaddr[0],
				node->macaddr[1],node->macaddr[2],node->macaddr[3],node->macaddr[4],node->macaddr[5]);
			system(buf);
		}
		list_del(&node->list);
		free(node);
		g_ap_num--;
		node=NULL;
	}
}
void rg_del_sta_member(P_RGSTA_LIST ni){
	if(ni){
		list_del(&ni->list);
		free(ni);
		g_sta_num--;
		ni=NULL;
	}
}

void rg_del_cluster_member(P_CLUSTER_LIST ni){
	if(ni){
		list_del(&ni->list);
		free(ni);
		ni=NULL;
	}
}

void  rg_find_aging_member(u_int8_t sign){
	int i;
	P_RGAP_LIST node = NULL,nxt=NULL;
	P_RGSTA_LIST ni = NULL,ni_nxt = NULL;
	P_CLUSTER_LIST cm = NULL,cm_nxt=NULL;
	time_t c_time;
	int t_interval = 0;
	if(SCAN_AP_SIGN == sign){
		
		for(i=0;i<RG_NODE_HASHSIZE;i++){
			list_for_each_safe(&ap_hasi_table[i].head,node,nxt,list) {
				t_interval = time(&c_time)-node->t_stamp;
				if(t_interval > MAX_AGING_TIME){
					#if 0
					printf("%02x:%02x:%02x:%02x:%02x:%02x\t %-32s %-10u %-10u %-10u %-10d %-15s", node->macaddr[0], node->macaddr[1],
						node->macaddr[2], node->macaddr[3], node->macaddr[4], node->macaddr[5],
						node->ssid,node->channel,node->encrypt_type,node->rssi,node->mark,asctime(localtime(&(node->t_stamp))));
					#endif
					rg_del_ap_member(node);
				}
			}
		}
	}else if(SCAN_STA_SIGN == sign){	
		
		for(i=0;i<RG_NODE_HASHSIZE;i++){
			list_for_each_safe(&sta_hasi_table[i].head,ni,ni_nxt,list){
				t_interval = time(&c_time)-ni->t_stamp;
				if(t_interval > MAX_AGING_TIME){
					#if 0
					printf("%02x:%02x:%02x:%02x:%02x:%02x\t%-3d.%-3d.%-3d.%-3d  %02x:%02x:%02x:%02x:%02x:%02x\t %-10d %-10d %-15s",ni->stamac[0], ni->stamac[1],
						ni->stamac[2], ni->stamac[3], ni->stamac[4], ni->stamac[5],ni->ipaddr[0],ni->ipaddr[1],ni->ipaddr[2],ni->ipaddr[3],
						ni->apmac[0], ni->apmac[1],ni->apmac[2], ni->apmac[3], ni->apmac[4], ni->apmac[5],ni->qos,ni->index,asctime(localtime(&(ni->t_stamp))));
					#endif
					rg_del_sta_member(ni);
				}
			}
		}
	}else if(CLUSTER_MEMBER_SIGN == sign){
		list_for_each_safe(&cluster_member_list,cm,cm_nxt,list){
			t_interval = time(&c_time)-cm->t_stamp;
			if(t_interval > MAX_AGING_TIME){
				#if 0
				printf("del----%02x:%02x:%02x:%02x:%02x:%02x\t %-15s",cm->macaddr[0], cm->macaddr[1],
					cm->macaddr[2], cm->macaddr[3], cm->macaddr[4],cm->macaddr[5],asctime(localtime(&(cm->t_stamp))));
				#endif
				rg_del_cluster_member(cm);
			}
		}
	}
}



void dump_ap_info()
{
	int i;
	int ap_num = 0;
	P_RGAP_LIST node = NULL;
	if(list_debug){
		dump_file_open("a+");
		fprintf(DUMP_FILE,"\n================================================ Scanning AP Original Information =====================================\n");
		fprintf(DUMP_FILE,"%-8s %-23s %-34s %-10s %-10s %-10s %-10s %-15s\n",
					"APID", "MAC", "SSID", "CHANNEL", "AUTH_TYPE", "RSSI", "TYPE", "C_Time");
		for(i=0;i<RG_NODE_HASHSIZE;i++){
			list_for_each(&ap_hasi_table[i].head,node,list){
				fprintf(DUMP_FILE,"%-8d %02x:%02x:%02x:%02x:%02x:%02x\t %-34s %-10u %-10u %-10u %-10d %-15s", ap_num, node->macaddr[0], node->macaddr[1],
				node->macaddr[2], node->macaddr[3], node->macaddr[4], node->macaddr[5],
				node->ssid,node->channel,node->encrypt_type,node->rssi,node->mark,asctime(localtime(&(node->t_stamp))));	
				ap_num++;
			}
		}
		dump_file_close();
	}
}
void  dump_sta_info()
{
	int i;
	P_RGSTA_LIST node = NULL;
	int sta_num  = 0;
	if(list_debug){
		dump_file_open("a+");
		fprintf(DUMP_FILE,"\n======================================Scanning STA Original Information=========================================\n");
		fprintf(DUMP_FILE,"%-8s %-20s  %-18s %-20s %-10s %-12s %-15s\n",
				"STA_ID", "STA_MAC", "STA_IP", "AP_MAC", "STA_QOS", "STA_INDEX", "C_Time");
		for(i=0;i<RG_NODE_HASHSIZE;i++){
			list_for_each(&sta_hasi_table[i].head,node,list){
				fprintf(DUMP_FILE,"%-8d%02x:%02x:%02x:%02x:%02x:%02x\t%-3d.%-3d.%-3d.%-3d  %02x:%02x:%02x:%02x:%02x:%02x\t %-10d %-10d %-15s", sta_num, node->stamac[0], node->stamac[1],
				node->stamac[2], node->stamac[3], node->stamac[4], node->stamac[5],node->ipaddr[0],node->ipaddr[1],node->ipaddr[2],node->ipaddr[3],
				node->apmac[0], node->apmac[1],node->apmac[2], node->apmac[3], node->apmac[4], node->apmac[5],node->qos,node->index,asctime(localtime(&(node->t_stamp))));	
				sta_num++;
			}
		}
		dump_file_close();
	}
}
void dump_cluster_info()
{
	P_CLUSTER_LIST node = NULL;
	int cluster_num = 0;
	if(list_debug){
		dump_file_open("a+");
		fprintf(DUMP_FILE,"\n=======================Cluster Members(AP)Information========================\n");
		fprintf(DUMP_FILE,"AP_ID\tAP_MAC\n");
		list_for_each(&cluster_member_list,node,list){
			fprintf(DUMP_FILE,"%d\t%02x:%02x:%02x:%02x:%02x:%02x\t%-15s",cluster_num,node->macaddr[0],node->macaddr[1],
				node->macaddr[2],node->macaddr[3],node->macaddr[4],node->macaddr[5],asctime(localtime(&(node->t_stamp))));
			cluster_num++;
		}
		dump_file_close();
	}
}


