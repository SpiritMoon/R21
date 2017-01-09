#ifndef __DRM_H__
#define __DRM_H__
#include "ccan/list/list.h"

#define UNIX_DOMAIN "/tmp/DRM.socket"
#define CLUSTER_SERVER "/tmp/cluster_mgt_socket"

enum{
    DRM_LOG_NORMAL = 0,
    DRM_LOG_WRITE_TO_SYSLOG = 1,
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
}Radio_info;

typedef struct{
	char mac[6];
	int ip;
	Radio_info radio[3];
    int update_flag;
	struct list_head list;
}Clusterlist;

typedef struct{
    struct list_head head;
    pthread_mutex_t lock;
}Clusterlist_head;

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
char * cmd_system(const char * command);
char* macaddr_to_str(const unsigned char *addr);
void drm_get_clustr_list();
void drm_config_check_timer();
void drm_get_channel_txpower(ICM_INFO_T* picm,char * vap_name);
int acs_control_check_cluster_area(char * mac);
Clusterlist * atp_find_max_rssi_cluster_member(int radioid,int channel);
/*begin:pengdecai for down up wifi when channnel change*/
void drm_wifi_down(char* ifname);
void drm_wifi_up(char* ifname);
/*end:pengdecai for down up wifi when channnel change*/

#endif
