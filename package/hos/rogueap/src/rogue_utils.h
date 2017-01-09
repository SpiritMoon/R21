/******************************************************************************
  File Name    : rogue_utils.h
  Author       : zhaoej
  Date         : 20160202
  Description  : the common header file
******************************************************************************/
#ifndef _ROGUEAP_UTIL_H_
#define _ROGUEAP_UTIL_H_

#include <net/if.h>
#include "debug.h"
#include "parse_message.h"
#include "wireless_header.h"
#include <ccan/list/list.h>

/*Table of node instances*/
#define	RG_NODE_HASHSIZE	32
#define	RG_NODE_HASH(addr)   \
    (((const u_int8_t *)(addr))[MAC_ADDR_LEN - 1] % RG_NODE_HASHSIZE)
    
#define RG_CLUSTER_BMAC    0xF0
#define RG_SCAN_AP_BMAC(addr)   \
	(((const u_int8_t *)(addr))[MAC_ADDR_LEN - 1] & RG_CLUSTER_BMAC)

struct rg_hasi_head{
	struct list_head head;
};  

struct rg_hasi_head ap_hasi_table[RG_NODE_HASHSIZE];
struct rg_hasi_head sta_hasi_table[RG_NODE_HASHSIZE];

extern int g_ap_num;
extern int g_sta_num;


#define DEFAULT_ROGUEAP_PIPE	"/tmp/rogue_cmd_pipe"

/*RG MODULE RECV NODE MAX NUM*/
#define CLUSTER_MAX_AP 	16
#define RG_MAX_AP  		512
#define RG_MAX_STA 		1024

/*AGING SIGN*/
#define SCAN_AP_SIGN  	1
#define SCAN_STA_SIGN 	2
#define CLUSTER_MEMBER_SIGN 3
extern int aging_time;  
#define MAX_AGING_TIME 300 //10*30s=5min

/*BR*/
#define MAX_BRIDGES		1024
#define MAX_FDB  		1024

#define UNIX_PATH_MAX 	108
#define PATH_LEN 		64

#define IP_ADDR_LEN    	4
#define MAX_STA 		32

#define ATTACK_PACKET_HEAD	9
#define QOS_LEN 			2
#define ATTACK_PACKET_NUM 	1


typedef enum _auth_mode {
    AUTH_OPEN    	= 0, /* open */
    AUTH_SHARED 	= 1, /* shared-key */
    AUTH_WPA    	= 2, /* WPA */
    AUTH_RSNA       = 3, /* WPA2/RSNA */
    AUTH_WAPI       = 4 /* WAPI */
} auth_mode;

/*classify APs*/
#define ROGUE_AP   			1
#define INTERFERENCE_AP		0
#define GENERAL_AP  	   -1


/*hasi list storage rogue AP information*/
#define MAX_SSID_LEN 34
typedef struct _rogueap_info{
	u_int8_t 		macaddr[MAC_ADDR_LEN];
	char 			ssid[MAX_SSID_LEN];
	u_int8_t		channel;
	u_int8_t      	encrypt_type;
	u_int8_t 		rssi;
	int32_t			mark;
	u_int8_t		black_sign;
	u_int8_t 		rgmac_sign;
	time_t 			t_stamp;
	struct list_node  list;
}RGAP_LIST,*P_RGAP_LIST;

/*hasi list storage rogue sta information*/
typedef struct _rogueap_sta{
	u_int8_t 		stamac[MAC_ADDR_LEN];
	u_int8_t 		ipaddr[IP_ADDR_LEN];
	u_int8_t		apmac[MAC_ADDR_LEN];
	u_int8_t 		qos;
	int32_t 		index;
	time_t 			t_stamp;
	struct list_node list;
}RGSTA_LIST,*P_RGSTA_LIST;

/*list storage cluster member information*/
typedef struct _cluster_info{
	u_int8_t 	macaddr[MAC_ADDR_LEN];
	time_t 		t_stamp;
	struct list_node list;
}CLUSTER_LIST,*P_CLUSTER_LIST;

#define MAX_ESSID_NUM 16
/*array storage essid list information*/
typedef struct _essid_info{
	char 	essid[MAX_SSID_LEN];
}ESSID_LIST;
ESSID_LIST SSID[MAX_ESSID_NUM];

struct display_node{
	u_int8_t	mac[MAC_ADDR_LEN];
	char	 	ssid[MAX_SSID_LEN];
	u_int8_t	channel;
	u_int8_t	auth_type;
	u_int8_t 	rssi;
	int32_t 	sta_num;
	int32_t 	type;
	u_int8_t	black_sign;
	time_t 		t_stamp;
	u_int8_t 	sta_mac[MAX_STA][6];
};

struct black_node{
	u_int8_t	mac[MAC_ADDR_LEN];
};


struct fdb_entry{
	u_int8_t mac_addr[6];
};
struct fdb_entry FDB[MAX_FDB];

struct br_entry{
	char brname[IFNAMSIZ];
};

struct sockaddr_un {
	sa_family_t sun_family; /*PF_UNIX or AF_UNIX */
	char 		sun_path[UNIX_PATH_MAX]; /* path name*/
};


#define WILDCARD_MAX_NUM 32
#define WIlDCARD_MAX_LEN 6

struct white_wildcard{
	u_int8_t hmac[WIlDCARD_MAX_LEN];
	int hmac_len;
};
struct config {
	int debug;
	int suppress_switch;
	struct white_wildcard wildcard[WILDCARD_MAX_NUM];
	int wildcard_num;
	const char *conf_file;
	char*	 control_pipe;
	u_int8_t open_arp;
	u_int8_t open_deauth;
	u_int8_t open_disassoc;
	u_int8_t encrypt_deauth;
	u_int8_t encrypt_disassoc;
	char * 	dump_file;
	
};


enum Type_id{
	OPEN = 0,
	ENCRYPT = 1,
	WILDCARD = 2,
	SWITCH = 3
};

enum msg_type{
	RG_AP_INFO = 0,
	BLACK_AP_INFO = 1,
	DUMP_INFO = 2
};

#define STR_BUF 128
extern int local_sock;
extern fd_set read_fds;
extern struct timeval tv;
extern struct config conf;
extern int buf_debug;
extern int list_debug;
extern int packet_debug;
extern int auto_black_debug;
extern int add_rogue_mac;
extern FILE *DUMP_FILE;




Bool init_socket();
int rg_recvmsg(unsigned char *recvbuf,int buflen);
Bool rg_sendmsg(unsigned char *sendbuf,int buflen,struct sockaddr_un desaddr);
int handle_recvmsg(unsigned char *buf,unsigned int buflen);

void cluster_apinfo(unsigned char *msg, unsigned int len);
void bkscan_apinfo(unsigned char *msg, unsigned int len);
void bkscan_stainfo(unsigned char *msg, unsigned int len);

P_RGAP_LIST rg_create_ap_list_node(u_int8_t * mac);
P_RGAP_LIST  rg_find_ap_member(u_int8_t * mac);
P_RGSTA_LIST rg_create_sta_list_node(u_int8_t * mac);
P_RGSTA_LIST  rg_find_sta_member(u_int8_t * mac);
void rg_del_ap_member(P_RGAP_LIST node);
void rg_del_sta_member(P_RGSTA_LIST ni);
void  rg_find_aging_member(u_int8_t sign);
P_CLUSTER_LIST  rg_create_cm_list_node(u_int8_t * mac);
P_CLUSTER_LIST  rg_find_cm_member(u_int8_t * mac);
void dump_ap_info();
void dump_sta_info();
void dump_cluster_info();
void rg_scansta_req();
void rg_scanap_req();

int rg_send_scanreq(u_int16_t msg_type);
int rg_send_clusterap(void);
void get_ap_list(void);
void get_black_list(void);
int scan_sta_filter(P_RGSTA_LIST ni);
int scan_ap_filter(u_int8_t * apmac);
void rg_ssid_filter(P_RGAP_LIST node);


int get_fdb_form();
void get_rogue_ap(void);

Bool rg_nl_send_arp(P_RGSTA_LIST ni,unsigned char channel,int count);
Bool rg_nl_send_deauth(P_RGSTA_LIST ni,unsigned char channel);
Bool rg_nl_send_disassoc(P_RGSTA_LIST ni,unsigned char channel);
Bool init_nl_sock(void);
Bool br_init(void);
int nl_send_msg(char *buf,int buflen);

void rg_get_info(void);
void rg_suppress_element();
void genrand(unsigned char *buf, int count);
void display_ap_node_command(struct display_node *ap,int apnum);
void display_black_list_command(struct black_node *ap,int apnum);
void init_hasi_list();
void buf_dump(unsigned char *buf, int len, struct sockaddr_un *addr,int sign);

void rg_auto_blacklist();
void rg_modify_mac(u_int8_t *mac);

#endif