/******************************************************************************
  File Name    : control.c
  Author       : zhaoej
  Date         : 20160309
  Description  : pipe file and command parse
******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>

#include "control.h"
#include "rogue_utils.h"

#define MAX_CMD 65535


/* FIFO (named pipe) */
int ctlpipe = -1;
int dispipe = -1;

int buf_debug = 0;
int list_debug = 0;
int packet_debug = 0;
int auto_black_debug = 0;
int add_rogue_mac = 0;
int del_black_mac = 0;


#define DEFAULT_DISPLAY_PIPE  "/tmp/rogue_display_pipe" 
char *display_pipe = DEFAULT_DISPLAY_PIPE;
void control_init_pipe(void)
{
	int v = 0;
	unlink(conf.control_pipe);
	mkfifo(conf.control_pipe, 0666);
	ctlpipe = open(conf.control_pipe, O_RDWR|O_NONBLOCK);
	if(ctlpipe < 0){
		err(1, "Could not open cmd pile '%s'", conf.control_pipe);
	}
	#if 1
	v = fcntl(ctlpipe, F_GETFL, 0);
	if (v | O_NONBLOCK){
		v &= ~O_NONBLOCK;
		fcntl(ctlpipe, F_SETFL, v);
	}
	#endif
	printf( "control pipe file %d\n", ctlpipe);
	unlink(display_pipe);
	mkfifo(display_pipe, 0666);
}

void master_init_pipe(void)
{
	int v = 0;
	//mkfifo(display_pipe, 0666);
	dispipe = open(display_pipe, O_RDWR|O_NONBLOCK);
	if(dispipe < 0){
		err(1, "Could not open display pipe '%s'",display_pipe);
	}
	if(flock(dispipe,LOCK_EX)<0){
		err(1,"flock dispipe file failed!");
	}

	#if 1
	v = fcntl(dispipe, F_GETFL, 0);
	if (v | O_NONBLOCK){
		v &= ~O_NONBLOCK;
		fcntl(dispipe, F_SETFL, v);
	}
	#endif
}


void display_ap_node(struct display_node *ap,int buflen){
	int apnum;
	int i,j;
	apnum = buflen/sizeof(struct display_node);
	printf("APID\tMAC\t\t\tSSID\t\t    CHANNEL  AUTH_TYPE  RSSI  STA_NUM  TYPE\tBLACK\tSTAMAC\n");
	for(i = 0; i < apnum; i++){
			
		printf("%d\t%02x:%02x:%02x:%02x:%02x:%02x\t%-20s\t%u\t%u\t%u\t%d\t%d\t%u\t", i, ap->mac[0], ap->mac[1],
		ap->mac[2], ap->mac[3], ap->mac[4], ap->mac[5], ap->ssid, ap->channel,
		ap->auth_type,ap->rssi, ap->sta_num,ap->type,ap->black_sign);
		
		for(j = 0; j < ap->sta_num; j++){
			printf("%02x:%02x:%02x:%02x:%02x:%02x",ap->sta_mac[j][0], ap->sta_mac[j][1], ap->sta_mac[j][2], ap->sta_mac[j][3], ap->sta_mac[j][4], ap->sta_mac[j][5]);
			if((j+1) < ap->sta_num){
				printf(",");
			}	
		}
		printf("\n");
		ap = ap+1;
	}
}

void display_black_node(struct black_node *ap,int buflen){
	int apnum,i;
	apnum = buflen/sizeof(struct black_node);
	printf("AUTO_BlACK_LIST:MAC\n");
	for(i = 0; i < apnum; i++){		
		printf("\t\t%02x:%02x:%02x:%02x:%02x:%02x\n",ap->mac[0], ap->mac[1],ap->mac[2], ap->mac[3], ap->mac[4], ap->mac[5]);
		ap = ap+1;
	}
}


void control_send_command(char* cmd)
{
	int len = 0;
	int buflen;
	char buf[MAX_CMD*2];
	if(NULL == cmd){
			return;
	}
	len = strlen(cmd);
	char new[len+1];
	int msg_type=-1;
	memset(buf, 0, MAX_CMD*2);
	while (access(conf.control_pipe, F_OK) < 0) {
		printf("Waiting for control pipe...\n");
		sleep(1);
	}

	ctlpipe = open(conf.control_pipe, O_WRONLY);
	if (ctlpipe < 0)
		err(1, "Could not open control socket '%s'", conf.control_pipe);

	/* always terminate command with newline */
	strncpy(new, cmd, len);
	new[len] = '\n';
	new[len+1] = '\0';


	write(ctlpipe, new, len+1);
	close(ctlpipe);
	master_init_pipe();
	buflen = read(dispipe, buf, MAX_CMD*2);
	//printf("buflen=%d,buf[0]=%d\n",buflen,buf[0]);
	if (buflen > 0){
		msg_type=buf[0];
		buf[buflen] = '\0';
		if(RG_AP_INFO==msg_type){
			display_ap_node((struct display_node *)(buf+1),buflen);
		}
		else if (BLACK_AP_INFO==msg_type){
			display_black_node((struct black_node*)(buf+1),buflen);
		}
		else if(DUMP_INFO == msg_type){
			printf("%s",buf+1);
		}
	}
	flock(dispipe,LOCK_UN);
	close(dispipe);
	

	
	
}

void display_ap_node_command(struct display_node *ap,int apnum){

	int len = sizeof(struct display_node)*apnum;
	printf("display_ap_node_command len:%d,rogue_apnum:%d\n",len,apnum);
	unsigned char new[len+1];
	while (access(display_pipe, F_OK) < 0) {
		printf("Waiting for display pipe...\n");
		sleep(1);
	}
	dispipe = open(display_pipe, O_WRONLY);
	if (dispipe < 0)
		err(1, "Could not open display socket '%s'", display_pipe);

	/* always terminate command with newline */
	new[0] = RG_AP_INFO;
	memcpy(new+1,(unsigned char *)ap, len);
	//packet_dump(new,len);
	printf("Sending command\n");
	write(dispipe, new, len+1);
	close(dispipe);
	
}

void display_black_list_command(struct black_node *ap,int apnum){
	
	int len = sizeof(struct black_node)*apnum;
	printf("black_ap_node_command len:%d,black_apnum:%d\n",len,apnum);
	unsigned char new[len+1];
	while (access(display_pipe, F_OK) < 0) {
		printf("Waiting for display pipe...\n");
		sleep(1);
	}
	dispipe = open(display_pipe, O_WRONLY);
	if (dispipe < 0)
		err(1, "Could not open display socket '%s'", display_pipe);

	/* always terminate command with newline */
	
	new[0] = BLACK_AP_INFO;
	memcpy(new+1,(unsigned char *)ap, len);
	//packet_dump(new,len);
	printf("Sending black list command\n");
	write(dispipe, new, len+1);
	close(dispipe);
	
}


void dump_debug(char * cmd){
	int len = 0;
	if(NULL != cmd){
		len = strlen(cmd);
	}
	unsigned char new[len+1];
	while (access(display_pipe, F_OK) < 0) {
		printf("Waiting for dump display pipe...\n");
		sleep(1);
	}
	dispipe = open(display_pipe, O_WRONLY);
	if (dispipe < 0)
		err(1, "Could not open dump display socket '%s'", display_pipe);

	/* always terminate command with newline */
	new[0] = DUMP_INFO;
	memcpy(new+1, cmd, len);
	printf("Sending command,len=%d\n",len);
	write(dispipe, new, len+1);
	close(dispipe);

}

static inline void parse_string_mac(char  *str){
	char *buf = str; 
	char *result = NULL;
	int k=0;
	u_int8_t mac[6] ={0};
	result=strtok(buf,":");
	while(result != NULL){
		mac[k] = strtoul(result,0,16);
		k++;
		result=strtok(NULL,":");	
	}
	rg_modify_mac(mac);
}
static inline void parse_black_mac(char  *str){
	char *buf = str; 
	char *result = NULL;
	int k=0;
	int hash = 0;
	char cmdstr[64] ={0};
	u_int8_t mac[6] ={0};
	P_RGAP_LIST pos = NULL;
	
	result=strtok(buf,":");
	while(result != NULL){
		mac[k] = strtoul(result,0,16);
		k++;
		result=strtok(NULL,":");	
	}
	hash = RG_NODE_HASH(mac);
	list_for_each(&ap_hasi_table[hash].head,pos,list) {
		if(memcmp(pos->macaddr,mac,MAC_ADDR_LEN) == 0){
			if(del_black_mac){
				pos->black_sign = 0;
				sprintf(cmdstr,"/usr/sbin/rg_black del %02x:%02x:%02x:%02x:%02x:%02x &",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
				system(cmdstr);
				del_black_mac = 0;
			}
		}
	}
}




static void parse_command(char* in) {

	char *cmd = NULL;
	char *val = NULL;
	//cmd = in;
	cmd = strsep(&in, "=");
	val = in;
	char str[32]={0};
	if (strcmp(cmd, "get_apinfo") == 0){
		printf("parse command\n");
		get_ap_list();
	}else if(strcmp(cmd, "get_blacklist")== 0){
		printf("parse black list command\n");
		get_black_list();
	}
	else{
		if(strcmp(cmd, "buf_dump") == 0){
			if(val){
				buf_debug = atoi(val);
				sprintf(str,"buf_debug=%d\n",buf_debug);
			}
			else{
				sprintf(str,"invalid command\n");
			}
		}
		else if(strcmp(cmd, "display") == 0){
			if(val){
				list_debug = atoi(val);
				sprintf(str,"list_debug=%d\n",list_debug);
			}
			else{
				sprintf(str,"invalid command\n");
			}
		}
		else if(strcmp(cmd, "packet_dump") == 0){
			if(val){
				packet_debug = atoi(val);
				sprintf(str,"packet_debug=%d\n",packet_debug);
			}
			else{
				sprintf(str,"invalid command\n");
			}
		}
		else if(strcmp(cmd, "black_switch") == 0){
			if(val){
				auto_black_debug = atoi(val);
				rg_auto_blacklist();
				sprintf(str, "auto_black_debug=%d\n",auto_black_debug);
			}else{
				sprintf(str,"%d\n",auto_black_debug);
			}
		}
		else if(strcmp(cmd, "add_rgmac") == 0){
			add_rogue_mac = 1;
			if(val){
				sprintf(str,"add RG_MAC %s\n",val);
				parse_string_mac(val);
			}else{
				sprintf(str,"invalid command\n");
			}
		}
		else if(strcmp(cmd, "del_rgmac")== 0){
			add_rogue_mac = 0;
			if(val){
				sprintf(str,"del RG_MAC %s\n",val);
				parse_string_mac(val);
				
			}else{
				sprintf(str,"invalid command\n");
			}
		}
		else if(strcmp(cmd, "del_blackmac")== 0){
			del_black_mac = 1;
			if(val){
				sprintf(str,"del BK_MAC %s\n",val);
				parse_black_mac(val);
				
			}else{
				sprintf(str,"invalid command\n");
			}
		}
		else{
			sprintf(str,"invalid command\n");
		}
		dump_debug(str);
	}
}


void control_receive_command(void){
	char buf[MAX_CMD];
	char *pos = buf;
	char *end;
	int len;

	len = read(ctlpipe, buf, MAX_CMD);
	if (len > 0){
		buf[len] = '\0';
		while ((end = strchr(pos, '\n')) != NULL) {
			*end = '\0';
			printf("recv command\n");
			parse_command(pos);
			pos = end + 1;
		}
	}
}


void control_finish(int fd,char* pipe)
{
	if (fd == -1)
		return;

	close(fd);
	unlink(pipe);
}

