#include<sys/types.h> 
#include<sys/socket.h> 
#include<unistd.h> 
#include<arpa/inet.h> 
#include<stdio.h> 
#include<stdlib.h> 
#include<errno.h> 
#include<netdb.h> 
#include<stdarg.h> 
#include<string.h> 
#include<pthread.h>
#include<signal.h>
#include<sys/ioctl.h>
//#include"../../include/list.h"
#include<list.h>
//#include<ccan/list/list.h>
#include <sys/file.h>
#include <asm/types.h>
//#include <linux/if.h>
#include <netinet/ether.h>
#include <netinet/in.h> 


//#include <net/if.h>
#include <linux/types.h>
#include <linux/wireless.h>
#include <net/if_arp.h>   // for ARPHRD_ETHER
#include <errno.h>
#include <limits.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>  
#include <sys/time.h>
//#include "ieee80211_external.h"
#include "libhccp.h"

#define ATH_IOCTL_HAN_PRIV				(SIOCDEVPRIVATE+18)
#pragma pack(push, 1)
enum han_ioctl_priv {
	HAN_IOCTL_PRIV_BANDSTEERING = 0,
	HAN_IOCTL_PRIV_WIRELESSQOS = 1,
	HAN_IOCTL_PRIV_IGMP_SNP = 2,
	HAN_IOCTL_PRIV_UTIL_TIMER_ENBLE = 3, 
	HAN_IOCTL_PRIV_DCM = 5, 
};

#define OP_SET 	0x01
#define OP_GET	0x02
#define AC_MAX_ARGS  8

struct wireless_qos{
		unsigned int subtype;
		unsigned int op;
		unsigned int arg_num;
		union wmm_args {
			/*Switch*/
			u_int8_t wmm_enable;
			u_int8_t dscp_enable;
			u_int8_t vlan_enable;
			u_int8_t debug;
			/*WMM priority to DSCP prioriy*/
			u_int8_t bk_to_dscp;
			u_int8_t be_to_dscp;
			u_int8_t vi_to_dscp;
			u_int8_t vo_to_dscp;
			/*DSCP prioriy to WMM priority*/
			u_int8_t dscp_to_bk[AC_MAX_ARGS];
			u_int8_t dscp_to_be[AC_MAX_ARGS];
			u_int8_t dscp_to_vi[AC_MAX_ARGS];
			u_int8_t dscp_to_vo[AC_MAX_ARGS];
			
			/*WMM priority to 8021p prioriy*/
			u_int8_t bk_to_vlan;
			u_int8_t be_to_vlan;
			u_int8_t vi_to_vlan;
			u_int8_t vo_to_vlan;
			
			/*8021p prioriy to WMM priority*/
			u_int8_t vlan_to_bk[AC_MAX_ARGS];
			u_int8_t vlan_to_be[AC_MAX_ARGS];
			u_int8_t vlan_to_vi[AC_MAX_ARGS];
			u_int8_t vlan_to_vo[AC_MAX_ARGS];
		}wmm_args;
		struct wmm_stat {
			u_int8_t wmm_enable;
			u_int8_t dscp_enable;
			u_int8_t vlan_enable;
			u_int64_t dscp_to_wmm_packets_ok;
			u_int64_t dscp_to_wmm_packets_error;
			u_int64_t wmm_to_dscp_packets_ok;
			u_int64_t wmm_to_dscp_packets_error;
			u_int64_t vlan_to_wmm_packets_ok;
			u_int64_t vlan_to_wmm_packets_error;
			u_int64_t wmm_to_vlan_packets_ok;
			u_int64_t wmm_to_vlan_packets_error;

		}wmm_stat;
};

struct han_igmpsnp{
	unsigned int subtype;
	unsigned int op;
	int value;
};

#define OP_SET 	0x01
#define OP_GET	0x02
#define HAN_IOCTL_DCM_LBD_DELMAC 0
#define HAN_IOCTL_DCM_LBD_ADDMAC 1
#define HAN_IOCTL_DCM_FLUSH 2
#define HAN_IOCTL_DCM_BLANCE_DELMAC 3
#define HAN_IOCTL_DCM_BLANCE_ADDMAC 4
#define HAN_IOCTL_DCM_GET_CLIENT_NUM 8


struct han_ioctl_priv_args {
	enum han_ioctl_priv type;
	union {
		struct {
			unsigned int subtype;
			unsigned int op;
			int value;
			struct  {
				//non 5G capable
				u_int32_t	non_5g_capable;
				//5G capable
				u_int32_t	persist_to_2g;
				u_int32_t	excessive_load_5g_capable_to_5g;
				u_int32_t	excessive_load_5g_capable_to_2g;
				u_int32_t	steer_to_5g;
				u_int32_t	weak_2g_signal;
				//totally
				u_int32_t	total_2g;
				u_int32_t	total_5g;
			} bs_stat;
			
		} bandsteering;
	    struct{
			unsigned int subtype;
			unsigned int op;
			unsigned char enable;	
	    }util_timer_en;
		struct{
			unsigned int subtype;
			unsigned int op;
			unsigned int value;
			unsigned char denycnt ;	
			unsigned char mac[6];
			unsigned char channel;
			struct {
		    unsigned char channel;
			unsigned char occupyflag;
			unsigned char ce_flags;
			}wifi[3];
	    }dcm;
		struct wireless_qos wmm;
		struct han_igmpsnp  igmp;
		/*New cmd struct*/
	} u;
};

#pragma pack(pop)

#define HAN_DCM_STRING_EQ(s1, s2)	(0 == strncmp((s1), (s2), strlen(s2)))


int han_dcm_init() ;
int han_send_ap_info();
int han_dcm_deny_cnt(const unsigned char *mac,unsigned char rssi,unsigned char isDualBand);
int han_dcm_ioctl(const char* interface,
				   unsigned char option,
	               const unsigned char *mac,
	               unsigned char channel,
	               unsigned char denycnt);
int han_flush_black_list(void);
char * han_dcm_bance_get_radioname(  const unsigned char *mac,unsigned char  *channel);
void dcm_log(const char loglvl,const char * fmt, ...);
const char*ether_sprintf(const u_int8_t *mac);
/*Begin:pengdecai added for dcm*/
extern void han_dcm_kickout_lowrssi_staions(void);
/*End;pengdecai added for dcm*/
struct Local_Radio{
		unsigned char valid;
		char ifname[IFNAMSIZ + 1];
		unsigned char  utilization;
		unsigned char  stanum;
		unsigned char  bandtype;
		unsigned char  channelID;
		unsigned char  isoverload;
};
struct Local_AP_Info {
	unsigned char  mac[6];
	unsigned char  radionum;
	struct Local_Radio radio[3];
	unsigned char  rssiThreshold;
	unsigned char  maxNumDiff;
};
struct Local_AP_Info g_own_ap_state;

#define UNIX_DOMAIN "/tmp/lbd.socket"
#define CLUSTER_SERVER "/tmp/cluster_mgt_socket"
#define DEFAULT_CONFIG_FILE  "/etc/config/lbd"

extern int g_begin_deny;
extern int g_max_number_diff;
#define DBG_BUF_SIZE 256

/*as the log mask*/
enum{
    SYSLOG_NORMAL = 0x01,
    SYSLOG_BALANCE = 0x02,
    SYSLOG_5GFIRST = 0x04,
};

typedef struct{
	char type;
	char len;
}TLVHeader;

typedef struct{
	char apver;
	char op;
	short res;
	short type;
	short elm_len;
}ClusterRequest;

typedef struct{
	unsigned char channel;
	unsigned char rssi;
	unsigned char txpower;
}RadioInfo;

typedef struct{
	int ip;
	unsigned char mac[6];
	RadioInfo radio[3];
	struct list_head_t list;
}Clusterlist;

typedef enum{
    SCAN_AP_INFO = 1,
    PVC_STATE_INFO = 2,
    CLUSTER_MEMBER_INFO = 3,
    CLUSTER_ENV_INFO = 4,
}MsgType;

typedef enum{
	MSG_REQUEST = 1,
	MSG_RESPONSE = 2 
}MsgOP;

typedef enum {
    MSG_ELEMENT_TYPE_AP_NUM = 0,
    MSG_ELEMENT_TYPE_AP_INFO = 1,
    MSG_ELEMENT_TYPE_AP_CLUSTERID = 2,
    MSG_ELEMENT_TYPE_AP_IP = 3,
    MSG_ELEMENT_TYPE_AP_MAC = 4,
    MSG_ELEMENT_TYPE_AP_PRIORITY = 5,
    MSG_ELEMENT_TYPE_AP_STATUS = 6,
    
    MSG_ELEMENT_TYPE_AP_RADIOCNT = 29,
    MSG_ELEMENT_TYPE_RADIO_INFO = 30,
	MSG_ELEMENT_TYPE_RADIO_ID = 31,
	MSG_ELEMENT_TYPE_RADIO_CHAN = 32,
    MSG_ELEMENT_TYPE_RADIO_TXP = 33,
    MSG_ELEMENT_TYPE_RADIO_RSSI = 34,

    MSG_ELEMENT_TYPE_SCAN_INFO = 60,
    MSG_ELEMENT_TYPE_VAP_NUM = 61,
    MSG_ELEMENT_TYPE_VAP_INFO = 62,
	MSG_ELEMENT_TYPE_VAP_MAC = 63,
	MSG_ELEMENT_TYPE_VAP_CHAN = 64,
    MSG_ELEMENT_TYPE_VAP_RSSI = 65,
    
}MSG_ELEM;
//char * cmd_system(const char * command);
void dcm_get_clustr_list();
//void drm_config_check_timer();
//void drm_get_channel_txpower(ICM_INFO_T* picm,char * vap_name);
//int acs_control_check_cluster_area(char * mac);
//Clusterlist * atp_find_max_rssi_cluster_member(int radioid,int channel);

time_t han_get_timestamp(void);
void han_dcm_signal_handle_get_rssithreshold(void);



