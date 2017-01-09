#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdarg.h> 
#include <syslog.h>
#include "icm.h"
#include "drm.h"
#include "acs_control.h"
#include <time.h>
#include <sys/time.h>
#include <string.h>

/*logs of changes:
 *version 1.1.2.3:solve channel selection in the cluster when pow on at almost the same time.
 */

//LIST_HEAD(g_cluster_list);
Clusterlist_head g_cluster_list;
int g_drm_dbg_level = 0;
int g_drm_socket_fd; //communicate with cluster_mgt
time_t g_drm_config_check_time;

extern unsigned char g_self_mac[];
extern int g_acs_check_interval;
extern int g_acs_area_limit_rssi;

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

char* macaddr_to_str(const unsigned char *addr)
{
    /* Similar to ether_ntoa, but use a prettier format
       where leading zeros are not discarded */
    static unsigned char string[32];

    memset(string, 0, sizeof(string));
    
    if (addr != NULL) {

        snprintf(string,
                 sizeof(string),
                 "%02x:%02x:%02x:%02x:%02x:%02x",
                 addr[0],
                 addr[1],
                 addr[2],
                 addr[3],
                 addr[4],
                 addr[5]);
    }

    return string;
}

void drm_log(const char loglvl,const char * fmt, ...)
{
    char buf[256];
    va_list ap; 
    memset(buf,0,256);
    va_start(ap,fmt);
    vsnprintf(buf,256,fmt,ap);
    va_end(ap);
    
    if(g_drm_dbg_level)
        printf("DRM %s\n",buf);

    if(loglvl == DRM_LOG_WRITE_TO_SYSLOG)
    {
        /*WRITE TO SYSLOG*/
        syslog(LOG_NOTICE,buf);
    }
}

int drm_config_read(ICM_INFO_T *picm, const char* fname)
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
            //ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN, "line %d: invalid line '%s'\n", line, buf);
            errors++;
            continue;
        }

        *pos = '\0';
        pos++;


        if (os_strcmp(buf, "wifi0_acs_enable") == 0) {
            if(picm->radio_ifname == NULL)
                continue;
            if(os_strcmp(picm->radio_ifname, "wifi0") == 0){                
                if(atoi(pos) != picm->acs_enable){
                    drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:acs_wifi0_enable switch from %d to %d\n",picm->acs_enable,atoi(pos));
                    picm->acs_enable = atoi(pos);
                }
            }
        }else if(os_strcmp(buf, "wifi1_acs_enable") == 0){            
            if(picm->radio_ifname == NULL)
                continue;
            if(os_strcmp(picm->radio_ifname, "wifi1") == 0){
                if(atoi(pos) != picm->acs_enable){
                    drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:acs_wifi1_enable switch from %d to %d\n",picm->acs_enable,atoi(pos));
                    picm->acs_enable = atoi(pos);
                }
            }
        }if (os_strcmp(buf, "wifi0_atp_enable") == 0) {
            if(picm->radio_ifname == NULL)
                continue;
            if(os_strcmp(picm->radio_ifname, "wifi0") == 0){                
                if(atoi(pos) != picm->atp_enable){
                    drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ATP_CONTROL:atp_wifi0_enable switch from %d to %d\n",picm->atp_enable,atoi(pos));
                    picm->atp_enable = atoi(pos);
                }
            }
        }else if(os_strcmp(buf, "wifi1_atp_enable") == 0){            
            if(picm->radio_ifname == NULL)
                continue;
            if(os_strcmp(picm->radio_ifname, "wifi1") == 0){
                if(atoi(pos) != picm->atp_enable){
                    drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ATP_CONTROL:atp_wifi1_enable switch from %d to %d\n",picm->atp_enable,atoi(pos));
                    picm->atp_enable = atoi(pos);
                }
            }
        }else if(os_strcmp(buf, "drm_dbg_level") == 0){            
                if(atoi(pos) != g_drm_dbg_level){
                    drm_log(DRM_LOG_WRITE_TO_SYSLOG,"DRM:g_drm_dbg_level from %d to %d\n",g_drm_dbg_level,atoi(pos));
                    g_drm_dbg_level = atoi(pos);
                }
        }else if(os_strcmp(buf, "acs_check_interval") == 0){
            if(atoi(pos) != g_acs_check_interval){
                    drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:g_acs_check_interval from %d to %d\n",g_acs_check_interval,atoi(pos));
                    g_acs_check_interval = atoi(pos);
            }
        }else if(os_strcmp(buf, "acs_area_limit_rssi") == 0){
            if(atoi(pos) != g_acs_area_limit_rssi){
                    drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:g_acs_area_limit_rssi from %d to %d\n",g_acs_area_limit_rssi,atoi(pos));
                    g_acs_area_limit_rssi = atoi(pos);
            }
        }
    }
    if(f){
        fclose(f);
    }
    return 0;
}

char * cmd_system(const char * command)
{
    char * result = "";
    FILE * fpRead;
    char cmd_buf[128];
    fpRead = popen(command, "r");
    if(fpRead == NULL){
        printf("%s fpRead is NULL\n",__func__);
        perror("Fail to popen");
        return result;
    }
    memset(cmd_buf,'\0',sizeof(cmd_buf));
    while(fgets(cmd_buf,128-1,fpRead) != NULL){
        result = cmd_buf;
    }
    if(fpRead != NULL){
        pclose(fpRead);
    }
    return result;
}


void drm_get_channel_txpower(ICM_INFO_T* picm,char * vap_name)
{
    char cmd[128]={0};
    int current_txpower = 0;
    int current_channel = 0;
    if(os_strcmp(picm->radio_ifname, "wifi0") == 0){  
        sprintf(cmd,"iwconfig %s | grep Tx-Power | awk -F '[=:]' '{print $3}' | awk '{print $1}'",vap_name);
        current_txpower = atoi(cmd_system(cmd));
        if(current_txpower == 0)
            return;
        if(picm->current_txpower != current_txpower){
            drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ATP_CONTROL: get wifi0(%s) txpower from %d to %d.\n",vap_name,picm->current_txpower,current_txpower);
            picm->current_txpower = current_txpower;
        }
        sprintf(cmd,"iwlist %s channel | grep '(Channel'| awk '{print $5}' | awk -F ')' '{print $1}'",vap_name);
        current_channel = atoi(cmd_system(cmd));
        if(current_channel== 0)
            return;
        if(picm->current_channel != current_channel){            
            drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ATP_CONTROL: get wifi0(%s) current_channel from %d to %d.\n",vap_name,picm->current_channel,current_channel);
            picm->current_channel = current_channel;
        }
    }else if(os_strcmp(picm->radio_ifname, "wifi1") == 0){
        sprintf(cmd,"iwconfig %s | grep Tx-Power | awk -F '[=:]' '{print $3}' | awk '{print $1}'",vap_name);
        current_txpower = atoi(cmd_system(cmd));
        if(current_txpower == 0)
            return;
        if(picm->current_txpower != current_txpower){            
            drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ATP_CONTROL: get wifi1(%s) txpower from %d to %d.\n",vap_name,picm->current_txpower,current_txpower);
            picm->current_txpower = current_txpower;
        }
        sprintf(cmd,"iwlist %s channel | grep '(Channel'| awk '{print $5}' | awk -F ')' '{print $1}'",vap_name);
        current_channel = atoi(cmd_system(cmd));
        if(current_channel== 0)
            return;
        if(picm->current_channel != current_channel){            
            drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ATP_CONTROL: get wifi1(%s) current_channel from %d to %d.\n",vap_name,picm->current_channel,current_channel);
            picm->current_channel = current_channel;
        }
    }

}

#define DRM_CONFIG_CHECK_TIME 10
void drm_config_check_timer()
{
    int i = 0;
    ICM_INFO_T *picm = NULL;
    time_t now_time;
    
    time(&now_time);
    
    if(g_drm_config_check_time == NULL){
        time(&g_drm_config_check_time);
        return;
    }else if((now_time - g_drm_config_check_time) < DRM_CONFIG_CHECK_TIME){
        return;
    }
        
    time(&g_drm_config_check_time);
    for(i = 0; i < MAX_DEV_NUM; i++){
        picm = NULL;
        picm = get_picm(i);
        if(picm == NULL)
            continue;
        drm_config_read(picm,DEFAULT_CONFIG_FILE);
    }
}

Clusterlist * drm_create_cluster_list_node(char * mac)
{
	Clusterlist * node = NULL;
	node = (Clusterlist *) malloc(sizeof(Clusterlist));
	if(node){
		memset(node,0,sizeof(Clusterlist));
		OS_MACCPY(node->mac,mac);
        pthread_mutex_lock(&g_cluster_list.lock);
		list_add_tail(&g_cluster_list.head,&node->list);
        pthread_mutex_unlock(&g_cluster_list.lock);
	}
	return node;
}

void drm_print_cluster_list(int loglvl)
{
	Clusterlist *pos = NULL;
	Clusterlist *client = NULL;
	char tempBuf[100];
    pthread_mutex_lock(&g_cluster_list.lock);
	list_for_each(&g_cluster_list.head,pos,list) {
		drm_log(loglvl,"mac:%s\n",macaddr_to_str(pos->mac));
        drm_log(loglvl,"	radio[0] channel = %d rssi = %d txpower = %d\n",pos->radio[0].channel,pos->radio[0].rssi,pos->radio[0].txpower);
        drm_log(loglvl,"	radio[1] channel = %d rssi = %d txpower = %d\n",pos->radio[1].channel,pos->radio[1].rssi,pos->radio[1].txpower);
        //drm_log(loglvl,"	radio[2] channel = %d rssi = %d txpower = %d\n",pos->radio[2].channel,pos->radio[2].rssi,pos->radio[2].txpower);

		//drm_log(loglvl,"	radio[0].channel = %d\n",pos->radio[0].channel);
		//drm_log(loglvl,"	radio[0].rssi = %d\n",pos->radio[0].rssi);
		//drm_log(loglvl,"	radio[0].txpower = %d\n",pos->radio[0].txpower);
		//drm_log(loglvl,"	radio[1].channel = %d\n",pos->radio[1].channel);
		//drm_log(loglvl,"	radio[1].rssi = %d\n",pos->radio[1].rssi);
		//drm_log(loglvl,"	radio[1].txpower = %d\n",pos->radio[1].txpower);
		//drm_log(loglvl,"	radio[2].channel = %d\n",pos->radio[2].channel);
		//drm_log(loglvl,"	radio[2].rssi = %d\n",pos->radio[2].rssi);
		//drm_log(loglvl,"	radio[2].txpower = %d\n",pos->radio[2].txpower);
	}
    pthread_mutex_unlock(&g_cluster_list.lock);
}
void print_cluster_list()
{
	Clusterlist *pos = NULL;
	Clusterlist *client = NULL;
	char tempBuf[100];

    time_t now;

    struct timeval    tv;  
    struct timezone tz;  
    struct tm         *p;  
    gettimeofday(&tv, &tz);  
    p = localtime(&tv.tv_sec);  
    drm_log(DRM_LOG_WRITE_TO_SYSLOG,"print_cluster_list:%d /%d /%d %d :%d :%d.%3ld\n", 1900+p->tm_year, 1+p->tm_mon, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec, tv.tv_usec);  
	/*
	 *drm_log(DRM_LOG_WRITE_TO_SYSLOG,"	print_cluster_list\n");
	 */
    pthread_mutex_lock(&g_cluster_list.lock);
	list_for_each(&g_cluster_list.head,pos,list) {
		if(OS_MACCMP(pos->mac,g_self_mac) == 0) continue;
		/*
		 *printf("	mac:%s\n",macaddr_to_str(pos->mac));
         *printf("	radio[0] channel = %d rssi = %d txpower = %d\n",pos->radio[0].channel,pos->radio[0].rssi,pos->radio[0].txpower);
         *printf("	radio[1] channel = %d rssi = %d txpower = %d\n",pos->radio[1].channel,pos->radio[1].rssi,pos->radio[1].txpower);
		 */
		drm_log(DRM_LOG_WRITE_TO_SYSLOG,"	mac:%s\n",macaddr_to_str(pos->mac));
        drm_log(DRM_LOG_WRITE_TO_SYSLOG,"	radio[0] channel = %d rssi = %d txpower = %d\n",pos->radio[0].channel,pos->radio[0].rssi,pos->radio[0].txpower);
        drm_log(DRM_LOG_WRITE_TO_SYSLOG,"	radio[1] channel = %d rssi = %d txpower = %d\n",pos->radio[1].channel,pos->radio[1].rssi,pos->radio[1].txpower);
	}
    pthread_mutex_unlock(&g_cluster_list.lock);
}

Clusterlist * drm_find_cluster_member(char * mac)
{
	Clusterlist *pos = NULL;
    pthread_mutex_lock(&g_cluster_list.lock);
	list_for_each(&g_cluster_list.head,pos,list) {
		if(OS_MACCMP(pos->mac,mac) == 0){
            pthread_mutex_unlock(&g_cluster_list.lock);
			return pos;
		}
	}
    pthread_mutex_unlock(&g_cluster_list.lock);
	return drm_create_cluster_list_node(mac);
}

void drm_set_cluster_member_update_flag()
{
	Clusterlist *pos = NULL;
    pthread_mutex_lock(&g_cluster_list.lock);
	list_for_each(&g_cluster_list.head,pos,list) {		
        pos->update_flag = 0;
	}
    pthread_mutex_unlock(&g_cluster_list.lock);
}

void drm_del_noupdate_cluster_member()
{
	Clusterlist *pos = NULL;
    Clusterlist *next = NULL;
    pthread_mutex_lock(&g_cluster_list.lock);
	list_for_each_safe(&g_cluster_list.head,pos,next,list) {		
        if(pos->update_flag == 0){
            list_del(&pos->list);
            drm_log(DRM_LOG_WRITE_TO_SYSLOG,"DRM:del noupdate member(%s)\n",macaddr_to_str(pos->mac));
            free(pos);
        }
	}
    pthread_mutex_unlock(&g_cluster_list.lock);
}


int drm_cluster_info_prase_radio_info_tlv(Clusterlist * node,char * data,int len)
{
	TLVHeader * tlv = data;
	int remaind_len = len;
	unsigned char * radio_id = NULL;
	unsigned char * radio_chan = NULL;
	unsigned char * radio_rssi = NULL;
	unsigned char * radio_txp = NULL;
    
	while(remaind_len >= sizeof(TLVHeader)){
		switch(tlv->type){
			case MSG_ELEMENT_TYPE_RADIO_ID:
				radio_id = (char *)(tlv + 1);
				break;
			case MSG_ELEMENT_TYPE_RADIO_CHAN:
				radio_chan = (char *)(tlv + 1);
				node->radio[*radio_id].channel = *radio_chan;
				/*
				 *drm_log(DRM_LOG_WRITE_TO_SYSLOG,"prase_radio_info_tlv:radio_id=%d,channel=%d\n",*radio_id,*radio_chan);
				 */
				break;
			case MSG_ELEMENT_TYPE_RADIO_TXP:
				radio_txp = (char *)(tlv + 1);
				node->radio[*radio_id].txpower = *radio_txp;
				break;
			case MSG_ELEMENT_TYPE_RADIO_RSSI:
				radio_rssi = (char *)(tlv + 1);
				node->radio[*radio_id].rssi = *radio_rssi;
				break;
			default:
				printf("	error type:%d\n",tlv->type);
				break;		
		}

		if(remaind_len > tlv->len && remaind_len > sizeof(TLVHeader)){
			remaind_len -= tlv->len + sizeof(TLVHeader);
		}else{
			break;
		}
        
		tlv = (TLVHeader *)((char *)tlv + sizeof(TLVHeader) + tlv->len);
	}
}

int drm_cluster_info_prase_tlv(char * data, int len)
{
	TLVHeader * tlv = data;
	uint remaind_len = len;
	char mac[6] = {0};
	int * ip = NULL;
	Clusterlist * node = NULL;
    
	while(remaind_len >= sizeof(TLVHeader)){
		switch(tlv->type){
			case MSG_ELEMENT_TYPE_AP_MAC:
				memcpy(mac,(char *)(tlv + 1),6);
				node = drm_find_cluster_member(mac);
                node->update_flag = 1;
				break;
			case MSG_ELEMENT_TYPE_AP_IP:
				ip = (char *)(tlv + 1);
				char tempBuf[100];
				if (!node)
				{
					node->ip = *ip;
				}
				break;
			case MSG_ELEMENT_TYPE_RADIO_INFO:
				drm_cluster_info_prase_radio_info_tlv(node,(char *)(tlv + 1),tlv->len);
				break;
			default:
				break;		
		}
        
		if(remaind_len > tlv->len && remaind_len > sizeof(TLVHeader)){
			remaind_len -= tlv->len + sizeof(TLVHeader);
		}else{
			break;
		}
        
		tlv = (TLVHeader *)((char *)tlv + sizeof(TLVHeader) + tlv->len);
	}
}
void printf_buffer(unsigned char *buf, int len);
int drm_cluster_info_prase_data(char * data,int len)
{
	TLVHeader * tlv = data;
	int remaind_len = len - sizeof(TLVHeader);
    
	/*
	 *printf_buffer(data,len);
	 */

	while(remaind_len >= sizeof(TLVHeader)){
		switch(tlv->type){
			case MSG_ELEMENT_TYPE_AP_INFO:
				drm_cluster_info_prase_tlv((char *)(tlv + 1),tlv->len);
				break;
			default:
				break;
		}
        
		if(remaind_len > tlv->len && remaind_len > sizeof(TLVHeader)){
			remaind_len -= tlv->len + sizeof(TLVHeader);
		}else{
			break;
		}
        
		tlv = (TLVHeader *)((char *)tlv + sizeof(TLVHeader) + tlv->len);
	}
}

void drm_get_clustr_list()
{
	/*
     *drm_log(DRM_LOG_WRITE_TO_SYSLOG,"GET cluster list start\n");
	 */
    drm_send_request_msg();
    drm_recv_msg();
	/*
     *drm_log(DRM_LOG_WRITE_TO_SYSLOG,"GET cluster list end\n");
	 */
}

int drm_socket_init()
{
    struct sockaddr_un server_addr; 
    
	bzero(&server_addr, sizeof(server_addr)); 
	server_addr.sun_family = AF_UNIX; 
	strncpy(server_addr.sun_path,UNIX_DOMAIN,sizeof(server_addr.sun_path)-1);
	unlink(UNIX_DOMAIN);

	g_drm_socket_fd = socket(PF_UNIX, SOCK_DGRAM, 0); 
	if(g_drm_socket_fd == -1) 
	{ 
		perror("Create Socket Failed:"); 
		//exit(1); 
		drm_log(DRM_LOG_WRITE_TO_SYSLOG,"DRM-MAIN:Create local socket failed.\n");
		return 0;
	} 

	if(-1 == (bind(g_drm_socket_fd,(struct sockaddr*)&server_addr,sizeof(server_addr)))) 
	{ 
		perror("Server Bind Failed:"); 
        drm_log(DRM_LOG_WRITE_TO_SYSLOG,"DRM-MAIN:Create local socket bind failed.\n");
        //exit(1); 
        return 0;
	}
	return 1; 
}

void drm_recv_msg()
{
	int st = 0;
	static fd_set read_fs;
	struct timeval tv;
	struct sockaddr_un client_addr; 
    ClusterRequest * cr = NULL;
	socklen_t client_addr_length = sizeof(client_addr); 
	char buffer[1024]; 
	bzero(buffer, 1024); 
	FD_ZERO(&read_fs);
	tv.tv_sec = 1;
    
	if (g_drm_socket_fd != -1)
    {
        FD_SET(g_drm_socket_fd, &read_fs);
    }
    
	/*
	 *st = select(g_drm_socket_fd+1, &read_fs, NULL, NULL, &tv);
	 */
	st = select(g_drm_socket_fd+1, &read_fs, NULL, NULL, NULL);
	if(st > 0){
		if(recvfrom(g_drm_socket_fd, buffer, 1024,0,(struct sockaddr*)&client_addr, &client_addr_length) == -1) 
		{ 
			perror("Receive Data Failed:"); 
			exit(1); 
		}
	}else{
		drm_log(DRM_LOG_WRITE_TO_SYSLOG,"drv recv msg out of time.\n");
	}

	cr = buffer;
	if(cr->op == MSG_RESPONSE && cr->type == CLUSTER_ENV_INFO){
        drm_set_cluster_member_update_flag();
		drm_cluster_info_prase_data(buffer+sizeof(ClusterRequest),cr->elm_len);	
        drm_del_noupdate_cluster_member();
	}
}

void drm_send_request_msg()
{
    char snd_buf[1024];
    static struct sockaddr_un srv_addr;
    srv_addr.sun_family=AF_UNIX;
    strcpy(srv_addr.sun_path,CLUSTER_SERVER);
    memset(snd_buf,0,1024);
    ClusterRequest * cr = snd_buf;
    cr->apver = 0;
    cr->op = MSG_REQUEST;
    cr->res = 0;
    cr->type = CLUSTER_ENV_INFO;
    cr->elm_len = 0;

    if(sendto(g_drm_socket_fd, snd_buf, 1024,0,(struct sockaddr*)&srv_addr,sizeof(srv_addr)) < 0) 
	{ 
		perror("ATP_CONTROL: Send msg error, "); 
	} 
}

int acs_control_check_cluster_area(char * mac)
{
    Clusterlist *node = NULL;
    pthread_mutex_lock(&g_cluster_list.lock);
	list_for_each(&g_cluster_list.head,node,list) {
		if(OS_MACCMP(node->mac,mac) == 0){
			if(node->radio[0].rssi > g_acs_area_limit_rssi || node->radio[1].rssi > g_acs_area_limit_rssi || node->radio[2].rssi > g_acs_area_limit_rssi){
                drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL: %s %s and self in same area.\n",__func__,macaddr_to_str(mac));
                pthread_mutex_unlock(&g_cluster_list.lock);
                return 1;
            }else{
                drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL: %s %s and self not in same area.\n",__func__,macaddr_to_str(mac));
                pthread_mutex_unlock(&g_cluster_list.lock);
                return 0;
            }
		}
	}
    pthread_mutex_unlock(&g_cluster_list.lock);
    drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL: %s can't found mac:%s in cluster list.\n",__func__,macaddr_to_str(mac));
    return 1;
}

Clusterlist * atp_find_max_rssi_cluster_member(int radioid,int channel)
{
    Clusterlist *node = NULL;
    Clusterlist *max_node = NULL;
    
    if(channel == 0)
        return NULL;
    pthread_mutex_lock(&g_cluster_list.lock);
	list_for_each(&g_cluster_list.head,node,list) {
        if(OS_MACCMP(node->mac,g_self_mac) == 0)
            continue;
        
        if(node->radio[radioid].channel == 0)
            continue;
        
        if(node->radio[radioid].channel == channel){
    		if(max_node == NULL){
                max_node = node;
            }
            else{               
                if(node->radio[radioid].channel == channel){
                    if(node->radio[radioid].rssi == 0)
                        continue;
                    if(node->radio[radioid].rssi > max_node->radio[radioid].rssi)
                        max_node = node;
                }
            }
	    }
    }
    pthread_mutex_unlock(&g_cluster_list.lock);
    if(max_node){
        drm_log(DRM_LOG_NORMAL,"ATP_CONTROL: Find max rssi member[%s] radio[%d]->rssi is %d\n",macaddr_to_str(max_node->mac),radioid,max_node->radio[radioid].rssi);
        return max_node;
    }else{
        return NULL;
    }
	
}

/*begin:pengdecai for down up wifi when channnel change*/
void drm_wifi_down(char* ifname)
{
	if(strcmp(ifname,"wifi0") == 0){
		system("ifconfig wifi0 down");
		drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:ifconfig wifi0 down");
	}
	else if(strcmp(ifname,"wifi1") == 0){
		system("ifconfig wifi1 down");
		drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:ifconfig wifi1 down");
	}

}
void drm_wifi_up(char* ifname)
{
	if(strcmp(ifname,"wifi0") == 0){
		system("ifconfig wifi0 up");
		drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:ifconfig wifi0 up");
	}
	else if(strcmp(ifname,"wifi1") == 0){
		system("ifconfig wifi1 up");
		drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:ifconfig wifi1 up");
	}
}
/*end:pengdecai for down up wifi when channnel change*/

void drm_init()
{
	drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:drm init\n");
    list_head_init(&g_cluster_list.head);
    pthread_mutex_init(&g_cluster_list.lock,NULL);
    acs_control_get_basemac();
    acs_control_get_PVC_IP();
    acs_control_get_cluster_id();
    if(drm_socket_init() == 0){
		drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:drm_socket_init error,line %d,func=%s",__LINE__,__func__);
        return;
    }
    drm_get_clustr_list();

	drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:checking whether cluster is ready,please waiting...\n");
	wait_until_cluster_is_ready();
    drm_print_cluster_list(DRM_LOG_WRITE_TO_SYSLOG);
	system("bg-s -x display=wlan");

    acs_control_create_timer_thread();
    acs_control_change_state(ACS_INIT_STATE);
    acs_control_create_recv_thread();
	/*
	 *printf("run at here line %d,func=%s\n",__LINE__,__func__);
	 */
}

//alan add >>
int g_drm_get_clustr_list_waiting_time = 5;
time_t g_drm_get_clustr_list_time;
/**
 * @synopsis get the ap count of the channel NUM in the cluster 
 *
 * @param chan_num
 * @param head_list
 *
 * @returns  ap count 
 */
int icm_get_ap_num_of_the_chan_in_the_cluster(int chan_num,Clusterlist_head *head_list)
{
	int ret = 0;
	Clusterlist *pos = NULL;

	pthread_mutex_lock(&head_list->lock);
	list_for_each(&head_list->head,pos,list) {
		if(OS_MACCMP(pos->mac,g_self_mac) == 0) continue;
		/*
		 *if(pos->radio[0].channel == chan_num || pos->radio[1].channel == chan_num){
		 *    if(pos->radio[0].rssi == 0 && pos->radio[1].rssi == 0)
		 *        continue;
		 *    ret++;
		 *}
		 */
		if(pos->radio[0].channel == chan_num && pos->radio[0].rssi != 0){
			ret++;
		}else if(pos->radio[1].channel == chan_num && pos->radio[1].rssi != 0){
			ret++;
		}
	}
	pthread_mutex_unlock(&head_list->lock);
	drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:channel %d has %d ap in the cluster\n",chan_num ,ret);
	/*
	 *printf("channel %d has %d ap in the cluster\n",chan_num ,ret);
	 */

	return ret;
}
int __wait_until_cluster_is_ready(Clusterlist_head *head_list)
{
	int ret = 0;
	Clusterlist *pos = NULL;
	int cnt_total = 0,cnt_valid = 0;

	pthread_mutex_lock(&head_list->lock);
	list_for_each(&head_list->head,pos,list) {
		if(OS_MACCMP(pos->mac,g_self_mac) == 0) continue;
		if(pos->radio[0].rssi != 0){
			/*
			 *ret = 1;
			 */
			cnt_valid++;
		}
		cnt_total++;
	}
	pthread_mutex_unlock(&head_list->lock);

	if(cnt_total != 0)
		if((cnt_valid * 100) / cnt_total >= 80) ret = 1;

	return ret;
}
int wait_until_cluster_is_ready()
{
	int cnt_wait = 60 , ret = 0;

	while(!(ret = __wait_until_cluster_is_ready(&g_cluster_list))){
		drm_get_clustr_list();
		if(--cnt_wait == 0) break;

		/*
		 *if(cnt_wait % 6 == 0){
		 *    drm_log(DRM_LOG_WRITE_TO_SYSLOG,"check if cluster is ready ret =%d\n",ret);
		 *} 
		 */
		sleep(1);
	}
	if(ret == 0){
		drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:cluster is not ready,but time is out\n");
	}else{
		drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:cluster is ready\n");
	}
}
/**
 * @synopsis wait for the prerequisites are ok ,then run the code afterwards. 
 *
 * @returns   
 */
int wait_prerequisite_of_vap()
{
	int cnt_in_config = 0,cnt_in_shell = 0,cnt_exclude=0,cnt_wait = 10;
	char cmd[128];

	while(1){
		sprintf(cmd,"iwconfig |grep ath |wc -l");
		cnt_in_shell = atoi(cmd_system(cmd));
		sprintf(cmd,"grep 'ifname' /etc/config/wireless|wc -l");
		cnt_in_config = atoi(cmd_system(cmd));
		sprintf(cmd,"grep \"option enable '0'\" /etc/config/wireless|wc -l");
		cnt_exclude = atoi(cmd_system(cmd));
		cnt_in_config -= cnt_exclude;
		if(cnt_in_shell == cnt_in_config && cnt_in_shell != 0) break;
		if(--cnt_wait == 0) break;
		sleep(1);
	}
	drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ACS_CONTROL:wait_prerequisite_of_vap,cnt_in_shell=%d,cnt_in_config=%d,cnt_exclude=%d,cnt_wait=%d\n",
			cnt_in_shell,cnt_in_config,cnt_exclude,cnt_wait);

	return 1;
}
/**
 * @synopsis drm get_cluster_list_timer call back funtion
 */
void drm_get_cluster_list_timer()
{
    int i = 0;
    time_t now_time;
	static int cnt_get_cluster = 0;
    
    time(&now_time);
    
    if(g_drm_get_clustr_list_time == NULL){
		printf("Get first check time\n");
		time(&g_drm_get_clustr_list_time);
        return;
	}else if((now_time - g_drm_get_clustr_list_time) < g_drm_get_clustr_list_waiting_time){
	    return;
	}
    
    time(&g_drm_get_clustr_list_time);

	drm_get_clustr_list();
	cnt_get_cluster++;
	
	/*
	 *if(cnt_get_cluster % 6 == 0){
	 *    print_cluster_list();
	 *}
	 */
	/*
	 *print_cluster_list();
	 */
}
void print_time_stamp()  
{  
    struct timeval    tv;  
    struct timezone tz;  
    struct tm         *p;  

    gettimeofday(&tv, &tz);  
    p = localtime(&tv.tv_sec);  
    printf("time_now:%d /%d /%d %d :%d :%d.%3ld", 1900+p->tm_year, 1+p->tm_mon, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec, tv.tv_usec);  
}  
void printf_buffer(unsigned char *buf, int len)
{
#define MAX_PRINT_BUFFER_LEN 1024                   
	unsigned char buffer[MAX_PRINT_BUFFER_LEN];                      
	int i;                           
	int buffer_len;

	if(len > MAX_PRINT_BUFFER_LEN){                      
		drm_log(DRM_LOG_WRITE_TO_SYSLOG,"buffer too long\n");               
		return ;                      
	}                            

	memset(buffer,0,MAX_PRINT_BUFFER_LEN);                      
	buffer_len = strlen(buffer);
	
	for(i = 0; i < len; i++) {                   
		snprintf(buffer + buffer_len , MAX_PRINT_BUFFER_LEN,"%x ",buf[i]);               
		buffer_len = strlen(buffer);
	}                           

	snprintf(buffer + buffer_len,MAX_PRINT_BUFFER_LEN, "\n");                      
	drm_log(DRM_LOG_WRITE_TO_SYSLOG,"%s",buffer);              
#undef MAX_PRINT_BUFFER_LEN                    
}
//alan add <<

