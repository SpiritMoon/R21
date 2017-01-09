/******************************************************************************
  File Name    : rogue_ap.c
  Author       : zhaoej
  Date         : 20160216
  Description  : rogue ap module main func
******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include<unistd.h>
#include <sys/time.h>
#include "rogue_utils.h"
#include "control.h"
#include "timer.h"

int suppress_switch;
unsigned char rogue_debug_level = 3;



struct config conf = {
	.debug		= 0,
	.suppress_switch = 0 ,
	.wildcard_num   = 0,
	.control_pipe	= DEFAULT_ROGUEAP_PIPE,
	.open_arp		= 1,
	.open_deauth	= 0,
	.open_disassoc	= 0,
	.encrypt_deauth	= 1,
	.encrypt_disassoc = 0,
	.dump_file 	="/tmp/rg_ap.log",

};

/*use description*/
void rg_usage(char **argv){
	printf("\nRogue AP Usage: %s [-D] [-h] [-s switch] [-x command] [-C conf-file]\n"
		"General Options: Description (default value)\n"
		"  -h			 \tHelp\n"
		"  -D			 \tShow lots of debug output,debug switch turn on\n"
		"  -s <switch>	 \tContain rouge AP packet switch,default turn off\n"
		"  -x <command>	 \tGet rogueap and interference ap information\n"
		"  -C <conf-file>\tSpecify configuration file\n"
		
		,argv[0]);
	exit(0);
}

static void get_options(int argc, char** argv){
	int opt = 0;
	
	while((opt = getopt(argc, argv, "Dhs:x:C:")) > 0) {
		switch (opt) {
			case 'D':
				conf.debug = 1;
				break;
			case 's':
				conf.suppress_switch = atoi(optarg);
				break;
			case 'C':
				conf.conf_file = optarg;
				break;
			case 'x':
				control_send_command(optarg);
				exit(0);

			case 'h':
			default:
				rg_usage(argv);
		}
	}
}

char * os_strchr(const char *s, int c)
{
	while (*s) {
		if (*s == c)
			return (char *) s;
		s++;
	}
	return NULL;
}

int os_strcmp(const char *s1, const char *s2)
{
	while (*s1 == *s2) {
		if (*s1 == '\0')
			break;
		s1++;
		s2++;
	}

	return *s1 - *s2;
}

void parse_str_mac(char  *str){

	char delims[] = " ";
	char buf[1024];
	char *result = NULL;
	char *ret = NULL;
	char strbuf[STR_BUF];
	
	int i=0,j,k;
	int mac_num=0;


	char mac[32][20] ={{0}};
	struct white_wildcard wcd[WILDCARD_MAX_NUM];
	memset(strbuf, 0, STR_BUF);
	memset(buf,0,1024);
	memset(wcd,0,WILDCARD_MAX_NUM*sizeof(struct white_wildcard));
	strcpy(buf,str);

	result = strtok(buf, delims);
	for(j=0; result != NULL; j++)
	{
		sprintf(strbuf,"white wildcard:\t%s\tlen=%d", result,strlen(result));
		rogue_debug(MODULE_WEB, ROGUEAP_LOG_LEVEL_DEBUG,strbuf);
		rogue_debug_trace("[ROGUEAP]: white wildcard:\t%s\tlen=%d", result,strlen(result));
		memcpy(mac[j],result,strlen(result));
		result = strtok( NULL, delims);
		mac_num ++;
		if(mac_num == WILDCARD_MAX_NUM)
			break;
	}

	for(j=0; j<mac_num; j++){
		ret=strtok(mac[j],":");
		k=0;
		while(ret != NULL){
			if(*ret == '*'){
				break;
			}
			wcd[j].hmac[k] = strtoul(ret,0,16);
			k++;
			wcd[j].hmac_len = k;
			ret=strtok(NULL,":");
			
			
		}
	}
	
	for(j=0;j<mac_num;j++){
		memcpy(conf.wildcard[i].hmac,wcd[j].hmac,sizeof(wcd[j].hmac));
		conf.wildcard[i].hmac_len = wcd[j].hmac_len;
		i++;		
	}
	conf.wildcard_num = mac_num;	
}



static void rogueap_config_fill(int typeid, char *buf, char *pos)
{
	if(typeid == OPEN){
		if (os_strcmp(buf, "ARP") == 0) {
			conf.open_arp = atoi(pos);
		} else if (os_strcmp(buf, "Deauth") == 0) {
			conf.open_deauth = atoi(pos);
		}else if (os_strcmp(buf, "Disassoc") == 0) {
			conf.open_disassoc = atoi(pos);
		}
		else{
			rogue_debug(MODULE_ROGUE, ROGUEAP_LOG_LEVEL_ERR,"open mode doesn't exist configuration items!");
			rogue_debug_waring("[ROGUEAP]: Open type doesn't exist configuration items!");
			
		}
	
	} else if (typeid == ENCRYPT) {
		if (os_strcmp(buf, "Deauth") == 0) {
			conf.encrypt_deauth = atoi(pos);
		
		}else if (os_strcmp(buf, "Disassoc") == 0) {
			conf.encrypt_disassoc = atoi(pos);	
		}
		else{
			rogue_debug(MODULE_ROGUE, ROGUEAP_LOG_LEVEL_ERR,"encrypt mode doesn't exist configuration items!");
			rogue_debug_waring("[ROGUEAP]: Encrypt type doesn't exist configuration items!");
		}
		
	}else if(typeid == SWITCH){
		if (os_strcmp(buf, "BlackSwitch") == 0) {
			auto_black_debug = atoi(pos);
		}
	}else if(typeid == WILDCARD){
		if(os_strcmp(buf, "wildcard") == 0){	
			parse_str_mac(pos);
		}
	}

}

int rogue_parse_head(char *pos)
{

	int len = 0;
	char * ps;
	char buf[128];
	int id = -1;
	
	memset(buf, 0 ,sizeof(buf));
	if(pos == NULL){
		rogue_debug(MODULE_ROGUE, ROGUEAP_LOG_LEVEL_ERR,"Parsing configure file head error!");
		rogue_debug_error("[ROGUEAP]: Parsing configure file head error");
		return FALSE;
	}
	if(*pos == '['){
		pos++;
		ps = pos;

		while (*pos != '\0') 
		{
			if (*pos == ']') {
				*pos = '\0';
				break;
			}
			len++;
			pos++;
		}	
	}
	memcpy(buf, ps, len);
	if(os_strcmp(buf, "OPEN")== 0){
		id = 0;
	}
	else if(os_strcmp(buf, "ENCRYPT")== 0){
		id = 1;
	}
	else if(os_strcmp(buf, "WildCard")== 0){
		id = 2;
	}
	else if (os_strcmp(buf, "Switch") == 0){
		id = 3;
	}
	return id;
	
}

Bool rogueap_config_read(const char *fname){
	
	FILE *fp;
	char buf[1024], *pos;
	int typeid=-1,line = 0;
	char str[STR_BUF];

	memset(str, 0, STR_BUF);
	fp = fopen(fname, "rb");
	if (fp == NULL) {
		sprintf(str,"Could not open configuration file '%s' for reading.", fname);
		rogue_debug(MODULE_WEB, ROGUEAP_LOG_LEVEL_ERR,str); 
		rogue_debug_error("[ROGUEAP]: Could not open config file '%s' for reading.",fname);
		return FALSE;
	}
	while (fgets(buf, sizeof(buf), fp)) {
		
		line++;
		if (buf[0] == ';')
			continue;
		if (buf[0] == '['){
			pos = buf;
			typeid = rogue_parse_head(pos);
			continue;
		}
		pos = buf;
		while (*pos != '\0') {
			if (*pos == '\n') {
				*pos = '\0';
				break;
			}
			pos++;
		}
		if (buf[0] == '\0')
			continue;

		pos = os_strchr(buf, '=');
		if (pos == NULL) {
			sprintf(str, "Line %d: invalid line '%s'",line, buf);
			rogue_debug(MODULE_WEB, ROGUEAP_LOG_LEVEL_ERR,str);
			rogue_debug_waring("[ROGUEAP]: Line %d: invalid line '%s'",line, buf);
			continue;
		}
		*pos = '\0';
		pos++;
		
	 	rogueap_config_fill(typeid, buf, pos);
	}

	fclose(fp);

	return TRUE;
}

Bool rg_suppress_packet(P_RGSTA_LIST ni, int type,unsigned char channel){
	int i;
	if(NULL == ni){
		rogue_debug(MODULE_ROGUE, ROGUEAP_LOG_LEVEL_WARNING, "No sta associated to attack!");		
		rogue_debug_error("[ROGUEAP]: No sta associated to attack!");
		return FALSE;
	}
	
	if(type == 0){
		for(i=0;i<ATTACK_PACKET_NUM;i++){
			if(conf.open_arp){
				if(ni->ipaddr[0]==0 && ni->ipaddr[1]==0 &&ni->ipaddr[2]==0&& ni->ipaddr[3]==0){
					rg_nl_send_deauth(ni,channel);
				}
				else{
					rg_nl_send_arp(ni,channel,i);
					rg_nl_send_deauth(ni,channel);
				}
			}else if(conf.open_deauth){
			
				rg_nl_send_deauth(ni,channel);
			}else if(conf.open_disassoc){
				rg_nl_send_disassoc(ni,channel);
			}
		}
		
	}else if(type == 1){
		for(i=0;i<ATTACK_PACKET_NUM;i++){
			if(conf.encrypt_deauth){
				rg_nl_send_deauth(ni,channel);
			}else if(conf.encrypt_disassoc){
				rg_nl_send_disassoc(ni,channel);
			}
		}
	}else{
		rogue_debug(MODULE_ROGUE, ROGUEAP_LOG_LEVEL_WARNING,"Not a packet type to assemble!");
		rogue_debug_error("[ROGUEAP]: Unrecognized packet type to assemble!");
		return FALSE;
    }
	return TRUE;
}

void local_receive(){
	int len = 0;
	unsigned char recvbuf[BUF_MAX_LEN];
	memset(recvbuf, 0, BUF_MAX_LEN);
	
	len = rg_recvmsg(recvbuf,BUF_MAX_LEN);
	if(len > 0)
	{
		handle_recvmsg(recvbuf,len);
	}
}

fd_set read_fds;
struct timeval tv;

int max( int a, int b)
{
	return a >= b ? a : b;
}
void rg_suppress_element(){
	
	int i;
	int hasi = 0;
	int type;
	P_RGSTA_LIST ni = NULL;
	P_RGAP_LIST  ap = NULL;
	for(i=0;i<RG_NODE_HASHSIZE;i++){
		list_for_each(&sta_hasi_table[i].head,ni,list){
			if(1 == ni->index){
				hasi = RG_NODE_HASH(ni->apmac);
				list_for_each(&ap_hasi_table[hasi].head,ap, list){
					if(0 == memcmp(ni->apmac, ap->macaddr, MAC_ADDR_LEN)){
						if(AUTH_OPEN == ap->encrypt_type){
							type = 0;
						}
						else{
							type = 1;
						}
						rg_suppress_packet(ni, type,ap->channel);
					}
				}
			}
		}
	}
}
void rg_init_log(){
	
	time_t rawtime;
	rawtime=time(&rawtime);
	dump_file_open("w+");
	fprintf(DUMP_FILE,"******************* Rogue AP Process Start ********************\n");
	fprintf(DUMP_FILE,"Data\tTime:%s",asctime(localtime(&rawtime)));
	dump_file_close();
	rogue_debug_trace("[ROGUEAP]: Rogue AP Process Start---Time:%s",asctime(localtime(&rawtime)));
}

int  main(int argc,char **argv){

	get_options(argc,argv);
	rg_init_log();
	if(conf.conf_file == NULL){
		rogue_debug(MODULE_ROGUE, ROGUEAP_LOG_LEVEL_ERR,"get config file path error!");
		rogue_debug_error("[ROGUEAP]: Rogue AP config file is not Exist");
		return FALSE;
	}
	rogueap_config_read(conf.conf_file);
	
	if(0==init_socket()){
		exit(1);
	}
	if(0==init_nl_sock()){
		exit(1);
	}
	if(0==br_init()){
		exit(1);
	}
	control_init_pipe();
	init_hasi_list();
	init_timer();
	init_sigaction();
	while(1)
	{
		int ret = -1, mfd = -1;
		struct timeval tv;
		
		FD_ZERO(&read_fds);	
		FD_SET(ctlpipe, &read_fds);
		FD_SET(local_sock, &read_fds);
		
		mfd =max(ctlpipe,local_sock)+1;
		tv.tv_sec = 1;
		tv.tv_usec = 100;
	
		ret = select(mfd, &read_fds, NULL, NULL, &tv);
		if (ret > 0)
		{
			if(FD_ISSET(ctlpipe, &read_fds))
			{
				control_receive_command();
			}
			if(FD_ISSET(local_sock, &read_fds)){
				local_receive();
			}
		}
	}

	
}





