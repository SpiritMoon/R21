#ifndef __ACS_CONTROL_H__
#define __ACS_CONTROL_H__

#define SERVER_PORT 4567
#define CLIENT_PORT 4568
#define BUFFER_SIZE 1024 
#define FILE_NAME_MAX_SIZE 512

#define ACS_SN_REQUEST 0x01
#define ACS_SN_RESPONSE 0x02 
#define ACS_REQUEST 0x03
#define ACS_RESPONESE 0x04

typedef enum acs_state {
    ACS_INIT_STATE,
    ACS_RUNNING_STATE,
    ACS_WAITING_STATE,
    ACS_SELECT_STATE,
    ACS_INVALID
} ACS_STATE_T;

typedef struct acs_head{
	int type;
	int seq_num;
}ACS_HEAD_T;

typedef struct acs_response_head{
	int type;
	int seq_num;
	char mac[6];
}ACS_RESPONESE_HEAD_T;

extern int acs_control_create_recv_thread();
extern int acs_control_create_scan_thread(ICM_INFO_T* picm);
extern void acs_control_change_state(ACS_STATE_T state);
extern int acs_config_read(ICM_INFO_T *picm, const char* fname);
extern void acs_store_best_channel(ICM_INFO_T *picm,int best_channel);
extern void acs_store_wlan_mode(ICM_INFO_T *picm,char * mode);
extern void acs_control_get_basemac();
extern void acs_control_get_PVC_IP();
extern void acs_control_get_cluster_id();
#endif  /* __ACS_CONTROL_H__ */
