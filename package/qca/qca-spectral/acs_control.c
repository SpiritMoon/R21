/*
 * Copyright (c) 2015 HAN-networks, Inc..
 * All Rights Reserved.
 *
 * =====================================================================================
 *
 *    Filename:  acs_control.c
 *
 *    Description:  auto channel selection control
 *
 *    Version:  1.0
 *    Created:  02/22/2016 15:17:17
 *    Revision:  none
 *    Compiler:  gcc
 *
 *    Author:  Mingzhe Duan
 *
 * =====================================================================================
 */
#include <sys/types.h> 
#include <sys/socket.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <stdarg.h> 
#include <string.h> 
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include "icm.h"
#include "icm_api.h"
#include "drm.h"
#include "acs_control.h"
#include <libhccp/libhccp.h>

unsigned char g_self_mac[6]={0};
unsigned char g_pvc_IP[16] = "0.0.0.0";
unsigned int  g_cluster_id = 0;

#define BEST_CHANNEL_FILE "/tmp/channel"

pthread_t acs_control_recv_thread;
pthread_t acs_control_timer_thread;
/*Current state*/
ACS_STATE_T g_acs_state;
/*Current seqence number*/
int g_seqence_number = 0;
/*Into init state time & aging time*/
time_t g_first_init_time;
#define ACS_INIT_AGING_TIME 5
/*Waiting timer & aging time*/
time_t g_first_waiting_time;
int g_waiting_aging_time = 45;
/*
 *int g_waiting_aging_time = 45;
 */
/*Check condition timer & interval*/
time_t g_first_check_time;
/*
 *int g_acs_check_interval = 3600 / 6;
 */
int g_acs_check_interval = 3600;
int g_acs_area_limit_rssi = 25;
/*muitle radio in select mode*/
extern int g_drm_dbg_level;
extern int g_timeout_random_value;

void acs_control_request_send(int type);
void acs_control_change_state(ACS_STATE_T state);

static inline int OS_MACCMP(const void *_mac1, const void *_mac2)
{
    const char *mac1 = _mac1;
    const char *mac2 = _mac2;
    return ((mac1[0] ^ mac2[0]) | (mac1[1] ^ mac2[1]) | (mac1[2] ^ mac2[2]) | (mac1[3] ^ mac2[3]) | (mac1[4] ^ mac2[4]) | (mac1[5] ^ mac2[5])); 
}

static inline void * OS_MACCPY(void *_mac1, const void *_mac2)
{
    char *mac1 = _mac1;
    const char *mac2 = _mac2;
    mac1[0] = mac2[0];
    mac1[1] = mac2[1];
    mac1[2] = mac2[2];
    mac1[3] = mac2[3];
    mac1[4] = mac2[4];
    mac1[5] = mac2[5];
    return mac1;
}

int mac_str_to_bin( char *str, unsigned char *mac)
{
    int i;
    char *s, *e;

    if ((mac == NULL) || (str == NULL))
    {
        return -1;
    }

    s = (char *) str;
    for (i = 0; i < 6; ++i)
    {
        mac[i] = s ? strtoul (s, &e, 16) : 0;
        if (s)
           s = (*e) ? e + 1 : e;
    }
    return 0;
}


void acs_control_get_basemac()
{
    char * result = "";
    FILE * fpRead;
    char cmd_buf[1024];
    fpRead = popen("showsysinfo | grep MAC | awk -F 'MAC:' '{print $2}'", "r");

    if(fpRead == NULL)
        return;
    
    memset(cmd_buf,'\0',sizeof(cmd_buf));
    while(fgets(cmd_buf,1024-1,fpRead) != NULL){
        result = cmd_buf;
    }
    mac_str_to_bin(result,g_self_mac);
    if(fpRead != NULL){
        pclose(fpRead);
    }
    drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL: get basemac is %s\n",macaddr_to_str(g_self_mac));
}

void acs_control_get_PVC_IP()
{
    char * result = "";
    FILE * fpRead;
    char cmd_buf[1024];
    fpRead = popen("cluster_mgt -x show=pvc | awk 'NR==2' |awk '{print$1}'", "r");
    if(fpRead == NULL)
        return;
    memset(cmd_buf,'\0',sizeof(cmd_buf));
    while(fgets(cmd_buf,1024-1,fpRead) != NULL){
        result = cmd_buf;
    }
    strcpy(g_pvc_IP,result);
    if(fpRead != NULL){
        pclose(fpRead);
    }
    drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL: get PVC-IP is %s\n",g_pvc_IP);
}

void acs_control_get_cluster_id()
{
    char cmd[128];
    sprintf(cmd,"uci get cluster.cluster.cluster_id");
    g_cluster_id= atoi(cmd_system(cmd));
    drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL: get Cluter-ID is %d\n",g_cluster_id);
}


int acs_control_get_radio_user_number(ICM_INFO_T * picm)
{
    int i = 0, cnt = 0;
    int radio_user_cnt = 0;
    char cmd[128];
    for(i = 0; i < picm->numdevs; i++){
        cnt = 0;
        sprintf(cmd,"wlanconfig %s list | wc -l",picm->dev_ifnames_list[i]);
        cnt = atoi(cmd_system(cmd));
        if(cnt > 0){
            radio_user_cnt += (cnt - 1); //ignore title
        }
    }
    drm_log(DRM_LOG_NORMAL,"ACS_CONTROL:Radio[%s] user cnt is %d\n",picm->radio_ifname,radio_user_cnt);
    return radio_user_cnt;
}
/*ACS control test*/

int acs_last_channel_read(ICM_INFO_T *picm, const char* fname)
{
    ICM_CONFIG_T* conf = NULL;
    FILE *f = NULL;
    char buf[256] = {'\0'};
    char *pos = NULL;
    int line = 0;
    int errors = 0;
    /* open the config file */
    f = fopen(fname, "r");

    if (f == NULL) {
        drm_log(DRM_LOG_NORMAL,"ACS_CONTROL:can't open %s\n",fname);
        return -1;
    }

    /* read the config params */
    while (fgets(buf, sizeof(buf), f)) {

        line++;

        if (buf[0] == '#')
            continue;

        pos = buf;

        while(*pos != '\0') {
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
            errors++;
            continue;
        }

        *pos = '\0';
        pos++;


		if (os_strcmp(buf, "wifi0_channel") == 0) {
			if(picm->radio_ifname == NULL)
				continue;
			if(os_strcmp(picm->radio_ifname, "wifi0") == 0){                
				picm->acs_last_channel = atoi(pos);
			}
		}else if(os_strcmp(buf, "wifi1_channel") == 0){            
			if(picm->radio_ifname == NULL)
				continue;
			if(os_strcmp(picm->radio_ifname, "wifi1") == 0){
				picm->acs_last_channel = atoi(pos);
			}
		}
	}
	drm_log(DRM_LOG_WRITE_TO_SYSLOG,"out acs_last_channel_read");

    if(f){
        fclose(f);
    }
    return 0;
}

void acs_store_best_channel(ICM_INFO_T *picm,int best_channel)
{
    FILE *f = NULL;
    char buf[256] = {0};

    f = fopen(BEST_CHANNEL_FILE, "r");

    if (f == NULL) {
        f = fopen(BEST_CHANNEL_FILE, "wt");
        fputs("wifi0_channel=0\n",f);
        fputs("wifi1_channel=0\n",f);
        fputs("wifi0_mode=\n",f);
        fputs("wifi1_mode=\n",f);
    }
    if(f){
        fclose(f);
    }
    if(os_strcmp(picm->radio_ifname, "wifi0") == 0){
        sprintf(buf,"sed -r -i \"s/wifi0_channel=*[0-9]*[0-9]*[0-9]/wifi0_channel=%d/g\" %s",best_channel,BEST_CHANNEL_FILE);
        system(buf);
    }else if(os_strcmp(picm->radio_ifname, "wifi1") == 0){
        sprintf(buf,"sed -r -i \"s/wifi1_channel=*[0-9]*[0-9]*[0-9]/wifi1_channel=%d/g\" %s",best_channel,BEST_CHANNEL_FILE);
        system(buf);
    }
}

void acs_store_wlan_mode(ICM_INFO_T *picm,char * mode)
{
    FILE *f = NULL;
    char buf[256] = {0};

    f = fopen(BEST_CHANNEL_FILE, "r");

    if (f == NULL) {
        f = fopen(BEST_CHANNEL_FILE, "wt");
        fputs("wifi0_channel=0\n",f);
        fputs("wifi1_channel=0\n",f);
        fputs("wifi0_mode=\n",f);
        fputs("wifi1_mode=\n",f);
    }
    if(f){
        fclose(f);
    }
    if(os_strcmp(picm->radio_ifname, "wifi0") == 0){
        sprintf(buf,"sed -r -i \"s/wifi0_mode=(.*)/wifi0_mode=%s/g\" %s",mode,BEST_CHANNEL_FILE);
        system(buf);
    }else if(os_strcmp(picm->radio_ifname, "wifi1") == 0){
        sprintf(buf,"sed -r -i \"s/wifi1_mode=(.*)/wifi1_mode=%s/g\" %s",mode,BEST_CHANNEL_FILE);
        system(buf);
    }
}


int acs_control_area_check()
{
    return 1;
}

#define CONDITION_FAIL 0
#define CONDITION_PASS 1
int acs_control_condition_check()
{
	int i = 0;
	int ret = CONDITION_FAIL;
	time_t now_time = NULL;
    ICM_INFO_T *picm = NULL;
    ICM_DEV_INFO_T* pdev = get_pdev();
	//drm_log(DRM_LOG_NORMAL,"ACS_CONTROL:In acs_condition_check\n");
	for(i = 0; i < MAX_DEV_NUM; i++){
        picm = get_picm(i);
        if(picm == NULL)
            continue;
        /* check switch*/
		if(!picm->acs_enable){
			continue;
		}
		/* check force */
		if(picm->acs_force){
			drm_log(DRM_LOG_NORMAL,"ACS_CONTROL:force is ture! set PASS!");
            drm_log(DRM_LOG_NORMAL,"Radio[%s]\n",picm->radio_ifname);
			picm->acs_selection = 1;
			ret = CONDITION_PASS;
		}    
		/* check interval */
		if(g_first_check_time == NULL){
			drm_log(DRM_LOG_NORMAL,"ACS_CONTROL:Get first check time\n");
			/*
			 *time(&g_first_check_time);
			 */
		}else{
			time(&now_time);
			if((now_time - g_first_check_time) > g_acs_check_interval + g_timeout_random_value){
				drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:************Check interval finished!****************\n");
				/* check user number */
				if(!acs_control_get_radio_user_number(picm))
				{
					picm->acs_selection = 1;
					ret = CONDITION_PASS;
				}
				/*
				 *time(&g_first_check_time);
				 */
			}
		}
        /*check user number*/
	}
	return ret;
}

void acs_control_state_machine_timer()
{
	time_t now_time;
	time(&now_time);
	int tmp = 0;
	switch(g_acs_state){
        case ACS_INIT_STATE:
            /* For a long time, not recv ACS sn response frame send request again */
            if((now_time - g_first_init_time) > ACS_INIT_AGING_TIME){
                /* reload to INIT state */
                acs_control_change_state(ACS_INIT_STATE);
            }
            break;
        case ACS_RUNNING_STATE:
	    	/* check condition */
	    	if(acs_control_condition_check() == CONDITION_PASS){
	    	    /* send acs request*/
				/* reload first_check_time */
				/*
				 *time(&g_first_check_time);
				 */
				/* send request packet && change to WAITING state*/
                acs_control_change_state(ACS_WAITING_STATE);
	    		acs_control_request_send(ACS_REQUEST);
	    	}
	    	break;
    	case ACS_WAITING_STATE:
	    	if((now_time - g_first_waiting_time) >= g_waiting_aging_time + g_timeout_random_value){
				drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:wait out-timed,change into ACS_RUNNING_STATE\n");
				acs_control_change_state(ACS_RUNNING_STATE);
	    	} else {
				/*
				 *drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:Remaining time:%lds\n",(g_waiting_aging_time + g_timeout_random_value - (now_time - g_first_waiting_time)));
				 */
	    	}
	    	break;
    	case ACS_SELECT_STATE:
	    	break;
    	default:
    		break;
	}
}

void acs_control_change_state(ACS_STATE_T state)
{
	ICM_INFO_T *picm = NULL;
	ICM_DEV_INFO_T* pdev = get_pdev();
	drm_log(DRM_LOG_NORMAL,"ACS_CONTROL:Change state to %d\n",state);
	g_acs_state = state;
	switch(g_acs_state){
		case ACS_INIT_STATE:
			{
				int i = 0;
				drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:in ACS_INIT_STATE\n");
				time(&g_first_init_time);
				for(i = 0; i < MAX_DEV_NUM; i++){
					picm = get_picm(i);
					if(picm == NULL)
						continue;
					if(picm->numdevs){
						picm->acs_last_channel = 0;
						acs_last_channel_read(picm,BEST_CHANNEL_FILE);
						if(picm->acs_last_channel == 0){
							picm->acs_force = 1;
							drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:picm init,acs_force=%d\n",picm->acs_force);
						}else{
							int index =0;
							if(picm->best_channel == 0){
								picm->best_channel = picm->acs_last_channel;
								for (index = 0; index < picm->numdevs; index++) {
									ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_SELECTOR,
											"Configuring the best channel %d for %s\n", picm->best_channel, picm->dev_ifnames_list[i]);
									icm_set_width_and_channel(picm, picm->dev_ifnames_list[index]);
								}
							}
							drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:Get last best channel and set %s channel to %d\n",picm->radio_ifname,picm->acs_last_channel);
						}
					}
					drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:In ACS_INIT_STATE Radio[%s], set force = %d,acs_last_channel=%d,picm->numdevs=%d\n",
							picm->radio_ifname,picm->acs_force,picm->acs_last_channel,picm->numdevs);
				}

				drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:out ACS_INIT_STATE\n");
				/* send sn request*/
				acs_control_request_send(ACS_SN_REQUEST);
			}
			break;
		case ACS_RUNNING_STATE:
			drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:Into ACS_RUNNING_STATE\n");
			/* check condition */
			/* send acs request*/
			break;
		case ACS_WAITING_STATE:
			drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:Into ACS_WAITING_STATE\n");
			time(&g_first_waiting_time);
			break;
		case ACS_SELECT_STATE:
			drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:Into ACS_SELECT_STATE\n");
			break;
		default:
			break;
	}
}
void acs_control_response_process(char * response_mac)
{
	int i = 0;
	ICM_INFO_T *picm = NULL;
	ICM_DEV_INFO_T* pdev = get_pdev();
	if(OS_MACCMP(response_mac,g_self_mac) == 0){
		/*
		 *drm_log(DRM_LOG_NORMAL,"ACS_CONTROL:This response is for self.\n");
		 */
		drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:This response is for self.\n");
		/* Set SELECTION state*/
		acs_control_change_state(ACS_SELECT_STATE);

		time(&g_first_check_time);

		/* Start icm algorithm*/
		for(i = 0; i < MAX_DEV_NUM; i++){
			picm = get_picm(i);
			if(picm == NULL)
				continue;

			if(picm->acs_selection){
				drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:Call selection algorithm for radio[%d]\n",i);
				/*
				 *DETAIL,"ACS_CONTROL:Call selection algorithm for radio[%d]",i);
				 */
				if(picm->numdevs == 0) {
					drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:No vap in radio[%d],stop selection algorithm\n",i);
					continue;
				}
				if (icm_scan_and_select_channel(picm, 1) !=
						ICM_SCAN_SELECT_STATUS_SUCCESS) {
					drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:Selection algorithm error in radio[%d].\n",i);
					exit(EXIT_FAILURE);
				}
			}
			/* If force is set clear it */
			picm->acs_force = 0;
			picm->acs_selection = 0;
		}
		acs_control_change_state(ACS_RUNNING_STATE);
		/* Reset state*/
	}else{
		/*
		 *drm_log(DRM_LOG_NORMAL,"ACS_CONTROL:This response is not for self.\n");
		 */
		 drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:This response is not for self.\n");
		/* compare mac with scanning reslut*/
		/* if not in same area, goto RUNNING state*/
		if(acs_control_check_cluster_area(response_mac)/*same area*/){
			if(acs_control_condition_check() == CONDITION_PASS){
				/*In same area, goto WAITING state*/
				drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:In same area with %s, state turn to WAITING state.\n",macaddr_to_str(response_mac));
				acs_control_change_state(ACS_WAITING_STATE);
			}
		}else{
			/*Not in same area, goto RUNNING state, start to new a round*/
			drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:In different area with %s, state turn to RUNNING state.\n",macaddr_to_str(response_mac));
			acs_control_change_state(ACS_RUNNING_STATE);
		}
	}
}

void acs_control_parse_packet(char * buf)
{
	ACS_HEAD_T * pkt_head = (ACS_HEAD_T *)buf;
	unsigned char zero_mac[6]={0};
    Hccp_Protocol_Struct acs_packet;
    Parse_HCCPProtocol(buf, &acs_packet);
    drm_log(DRM_LOG_NORMAL,"ACS_CONTROL:Recv acs_packet.u.acs.msgtype %d\n",acs_packet.u.acs.msgtype);
    if(acs_packet.u.acs.head.clusterID != g_cluster_id){
        drm_log(DRM_LOG_NORMAL,"ACS_CONTROL:Recv acs_packet.u.acs.head.clusterID %d != self ID %d\n",acs_packet.u.acs.head.clusterID,g_cluster_id);
        return;
    }
	switch(acs_packet.u.acs.msgtype){
		case ACS_SN_REQUEST:
			break;
		case ACS_SN_RESPONSE:
			/* Update sn */
			/* Goto running state */
			drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:Recv ACS_SN_RESPONSE,seq_num is %d,mac is %02x:%02x:%02x:%02x:%02x:%02x\n",
					acs_packet.u.acs.seq_num,acs_packet.u.acs.mac[0],acs_packet.u.acs.mac[1],acs_packet.u.acs.mac[2],acs_packet.u.acs.mac[3],acs_packet.u.acs.mac[4],acs_packet.u.acs.mac[5]);
			if(g_seqence_number < acs_packet.u.acs.seq_num)
			{
				g_seqence_number = acs_packet.u.acs.seq_num;
				drm_log(DRM_LOG_NORMAL,"ACS_CONTROL:Update seqence number to %d\n",g_seqence_number);
			}
			if(g_acs_state == ACS_INIT_STATE)
			{
				if(OS_MACCMP(acs_packet.u.acs.mac,g_self_mac) == 0){
					drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:sn response is for me, change to ACS_RUNNING_STATE");
					acs_control_change_state(ACS_RUNNING_STATE);
				} else if(OS_MACCMP(acs_packet.u.acs.mac,zero_mac) == 0){
					drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:sn response is for me, change to ACS_RUNNING_STATE");
					acs_control_change_state(ACS_RUNNING_STATE);
				} else {
					drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:sn response is not for me, change to ACS_WAITING_STATE");
					acs_control_change_state(ACS_WAITING_STATE);
				}
			}
			break;
		case ACS_REQUEST:
			break;
		case ACS_RESPONESE:
		{
			drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:ACS_RESPONESE type is %d, seq_num is %d, mac is %02x:%02x:%02x:%02x:%02x:%02x\n",acs_packet.u.acs.msgtype,acs_packet.u.acs.seq_num,
				acs_packet.u.acs.mac[0],acs_packet.u.acs.mac[1],acs_packet.u.acs.mac[2],acs_packet.u.acs.mac[3],acs_packet.u.acs.mac[4],acs_packet.u.acs.mac[5]);
			/* Update sn */
			if(g_seqence_number < acs_packet.u.acs.seq_num)
			{
				g_seqence_number = acs_packet.u.acs.seq_num;
				drm_log(DRM_LOG_NORMAL,"ACS_CONTROL:Update seqence number to %d\n",g_seqence_number);
			}
			/* Process acs response */
			acs_control_response_process(acs_packet.u.acs.mac);
			break;
		}
		default:
			break;
	}

}

void * acs_control_pkt_recv_process()
{
	int i;
	int opt = 1;	
	struct sockaddr_in clinet_recv_addr; 
	bzero(&clinet_recv_addr, sizeof(clinet_recv_addr)); 
	clinet_recv_addr.sin_family = AF_INET; 
	clinet_recv_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
	clinet_recv_addr.sin_port = htons(CLIENT_PORT); 
  
	int client_recv_socket_fd = socket(AF_INET, SOCK_DGRAM, 0); 
	if(client_recv_socket_fd < 0) 
	{ 
		perror("ACS_CONTROL:Create Socket Failed:"); 
		exit(1); 
	} 
	/* Create socket */
	if(client_recv_socket_fd == -1) 
	{ 
		perror("ACS_CONTROL:Create Socket Failed:"); 
		exit(1); 
	} 
	
 	if((setsockopt(client_recv_socket_fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt))) < 0){
		perror("ACS_CONTROL:Server setsockopt error:");
                exit(1);
	} 
	/* Bind socket */
	if(-1 == (bind(client_recv_socket_fd,(struct sockaddr*)&clinet_recv_addr,sizeof(clinet_recv_addr)))) 
	{ 
		perror("ACS_CONTROL:Server Bind Failed:"); 
		exit(1); 
	} 

	/* Recv pkt from server */
	while(1) 
	{  
		struct sockaddr_in client_addr; 
		socklen_t client_addr_length = sizeof(client_addr); 
		char buffer[BUFFER_SIZE]; 
		bzero(buffer, BUFFER_SIZE); 
		if(recvfrom(client_recv_socket_fd, buffer, BUFFER_SIZE,0,(struct sockaddr*)&client_addr, &client_addr_length) == -1) 
		{ 
			perror("ACS_CONTROL:Receive Data Failed:"); 
			exit(1); 
		} 
		acs_control_parse_packet(buffer);
	}
}

void * acs_control_scan_process(ICM_INFO_T* picm)
{
    if (icm_scan_and_select_channel(picm, 1) !=
            ICM_SCAN_SELECT_STATUS_SUCCESS) {
        exit(EXIT_FAILURE);
    }
    /* If force is set clear it */
    picm->acs_force = 0;
    picm->acs_selection = 0;
}


int acs_control_create_recv_thread()
{
    int pret = 0;
    pret = pthread_create(&acs_control_recv_thread,
                          NULL,
                          acs_control_pkt_recv_process,
                          NULL);
    
    if (pret < 0) {
        perror("ACS_CONTROL: acs_control_create_recv_thread");
        return 0;
    }

    return 1;
}

void * acs_control_timer_process()
{
	/*
     *struct itimerval value;
     *signal(SIGVTALRM, signal_handler);
     *acs_control_change_state(ACS_INIT_STATE);
     *value.it_value.tv_sec = 0;
     *value.it_value.tv_usec = 400000;
     *value.it_interval.tv_sec = 0;
     *value.it_interval.tv_usec = 400000;
     *setitimer(ITIMER_VIRTUAL, &value, NULL);
	 */
    while(1)
    {
        usleep(100000);
		drm_get_cluster_list_timer();
    }
}
int acs_control_create_timer_thread()
{
	int pret = 0;
	
	pret = pthread_create(&acs_control_timer_thread,
						  NULL,
						  acs_control_timer_process,
						  NULL);
	
	if (pret < 0) {
		perror("ACS_CONTROL: acs_control_create_timer_thread");
		return 0;
	}

	return 1;
}

int acs_control_create_scan_thread(ICM_INFO_T* picm)
{
    int pret = 0;
    
    pret = pthread_create(&(picm->acs_control_scan_thread),
                          NULL,
                          acs_control_scan_process,
                          picm);
    
    if (pret < 0) {
        perror("ACS_CONTROL: acs_control_create_timer_thread");
        return 0;
    }

    return 1;
}


void acs_control_assemble_packet(char * buf,int pkt_type)
{
	int *type = (int *)buf;
	*type = htonl(pkt_type);
	drm_log(DRM_LOG_NORMAL,"assembel type is :%d\n",*type);
}

void acs_control_request_send(int type)
{
    ACS_format acs_packet;
    char buffer[BUFFER_SIZE]; 
	/* Set server infomation */
	struct sockaddr_in server_addr; 
	bzero(&server_addr, sizeof(server_addr)); 
	bzero(&acs_packet, sizeof(acs_packet)); 
    acs_control_get_PVC_IP();
    acs_control_get_cluster_id();
    if(memcmp(g_pvc_IP,"0.0.0.0",7) == 0)
    {
        drm_log(DRM_LOG_WRITE_TO_SYSLOG,"Can't get PVC IP\n");
        return;
    }
	server_addr.sin_family = AF_INET; 
	server_addr.sin_addr.s_addr = inet_addr(g_pvc_IP); 
	server_addr.sin_port = htons(SERVER_PORT); 
 
	/* Create socket */
	int client_send_socket_fd = socket(AF_INET, SOCK_DGRAM, 0); 
	if(client_send_socket_fd < 0) 
	{ 
		perror("ACS_CONTROL:Create Socket Failed:");         
        drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:acs_control_request_send socket create failed.\n",g_pvc_IP);
        return;
        //exit(1); 
	} 
    
 	bzero(buffer, BUFFER_SIZE);
    
    if(ACS_SN_REQUEST == type){
        drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:Send SN request to %s\n",g_pvc_IP);
        //acs_packet.clusterID = 0;
		acs_packet.msgtype = Sequence_req;
		acs_packet.seq_num = 0;
        Assemble_ACS_SequenceRequest(buffer,&acs_packet);
    }
    else if(ACS_REQUEST == type){
        drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:Send token request to %s\n",g_pvc_IP);
        //acs_packet.clusterID = 0;
		acs_packet.msgtype = Token_req;
		acs_packet.seq_num = g_seqence_number;
        OS_MACCPY(acs_packet.mac,g_self_mac);
        Assemble_ACS_TokenRequest(buffer,&acs_packet);
    }
 	/* Send packet to server */
    if(sendto(client_send_socket_fd,buffer,BUFFER_SIZE,0,(struct sockaddr*)&server_addr,sizeof(server_addr)) < 0)     
	{ 
		perror("ACS_CONTROL:Send Failed in acs_control_request_send:"); 
        drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:Send failed in acs_control_request_send to %s\n",g_pvc_IP);
        close(client_send_socket_fd);
        return;
        //exit(1); 
	} 
    close(client_send_socket_fd);
}

