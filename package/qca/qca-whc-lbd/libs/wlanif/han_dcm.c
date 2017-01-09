
//#include<net/if.h> //for struct ifreq
#include"han_dcm.h"
#include"wlanif.h"
#include "signal.h"

#define DCM_PORT 4988
#define BUFFER_SIZE 512
 
typedef struct{
	unsigned char  utilization;
	unsigned char  stanum;
	unsigned char  bandtype;
}radio_info;

typedef struct{
	char mac[6];
	unsigned char  radionum;
	radio_info radio[3];
}apinfo;

typedef struct {
	unsigned char  mac[6];
	unsigned char  radionum;
	radio_info     radio[3];
	unsigned char in_cluster;
	unsigned char is_neighbor;
	list_head_t    aplist;
	time_t  ctime; //set the cluseter time when set the in_cluster 1 
}ap_state;



static int g_dbg_all = 0;
static int g_dbg_normal= 0;
static int g_dbg_lbalance = 0;
static int g_dbg_5gfirst= 0;
static int g_dbg_printinfo = 0;
static int g_sysinfo_interval = 20;
static int g_neighbor_rssi_threshold = 15;
static int g_neighbor_enable=0;
int g_5gfirst_enable=0;
int g_loadbalance_enable=0;


int g_begin_deny = 0;
int g_max_number_diff = 5;

static unsigned int g_dbg_mask = 0;
//#define  DBG_NORMAL_MASK  0x01
//#define  DBG_LBALANCE_MASK  0x02
//#define  DBG_5GFIRST_MASK     0x04
//#define  DBG_PRINTALL_MASK    0x07



int udp_socket_fd = 0;
int send_socket_fd = 0;
int g_dcm_socket_fd = 0; //communicate with cluster_mgt
time_t g_dcm_check_time = 0;

pthread_t dcm_recv_thread;
pthread_t dcm_timer_thread;
struct sockaddr_in server_addr;

ap_state ap_list;
Clusterlist cluster_list;
//ap_state g_own_ap_state;

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

/*
 * Format an Ethernet MAC for printing.
 */
const char*ether_sprintf(const u_int8_t *mac)
{
	static char etherbuf[18];
	snprintf(etherbuf, sizeof(etherbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return etherbuf;
}
ap_state * create_list_node(unsigned char *mac)
{
	ap_state * node = NULL;
	node = (ap_state *) malloc(sizeof(ap_state));
	if(node){
		memset(node,0x0,sizeof(ap_state));
		
		OS_MACCPY(node->mac,mac);
		//printf(" create mac:%s\n",macaddr_to_str(node->mac));
		list_insert_entry(&node->aplist,&ap_list.aplist);
	}
	return node;
};
ap_state * __find_ap_member(unsigned char *mac)
{
	list_head_t *iter;
    list_for_each(iter,&ap_list.aplist){
		ap_state *ap = list_entry(iter,ap_state,aplist);
		if(OS_MACCMP(ap->mac,mac) == 0){
			return ap;
		}
     }

     return NULL;
}

ap_state * find_ap_member(unsigned char *mac)
{
      ap_state * ap = __find_ap_member(mac);
      if(ap) 
	return ap;
	else 
	return create_list_node(mac);
}
static int han_ioctl(struct iwreq *iwr, int cmd) 
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		printf("1 function ioctl::socket error ; %s\n", strerror(errno));
		return -1;
	}
	if (ioctl(s, cmd, iwr) < 0) {
		printf("2 function ioctl::ioctl error ; %s %x\n", strerror(errno),(unsigned int)ioctl);
		close(s);
		return -1;
	}
	close(s);
	return 0;
}

int han_dcm_deny_cnt(const unsigned char* mac,unsigned char rssi,unsigned char isDualBand)
{
	int i;
	unsigned char dney_cnt = 0;
	unsigned char ap_total_num = 0;
	unsigned char ap_2L_num = 0;
	unsigned char unit_size = 0;
	unsigned char sta_num_order = 0;
	unsigned char util_2G_order = 0;
	unsigned char util_5G_order = 0;
	unsigned char local_util_2G = 0,local_util_5G = 0,local_sta_num = 0;
	unsigned char neighbor_util_2G ,neighbor_util_5G,neighbor_sta_num;
	unsigned char neighbor_ap_num = 0;
	/*if the station's rssi less than 10 , deny it(denycnt = 10)*/
	if(rssi < 10){
		dcm_log(SYSLOG_BALANCE,"[6/8] STA %s rssi < 10  :denycnt = 10\n",ether_sprintf(mac));
		return 10;
	}
	
	for(i = 0; i < 3;i ++){
		local_sta_num += g_own_ap_state.radio[i].stanum;
		if(g_own_ap_state.radio[i].bandtype == wlanif_band_24g){
			/*because 2G utilization is too high ,so divide 3 part*/
			local_util_2G += g_own_ap_state.radio[i].utilization/3;
		}else {
			local_util_5G += g_own_ap_state.radio[i].utilization;
		}
	}
	
	dcm_log(SYSLOG_BALANCE,"[3/8] STA %s Loacl AP:%s local_sta_num=%d, local_utilization_2G = %d,local_utilization_5G = %d\n",\
			   ether_sprintf(mac), ether_sprintf(g_own_ap_state.mac), local_sta_num,local_util_2G*3,local_util_5G);

	list_head_t *iter;
	list_for_each(iter,&ap_list.aplist){
		ap_state *ap = list_entry(iter,ap_state,aplist);
		ap_2L_num ++;
		if(!ap->in_cluster )
		   continue;
		
		ap_total_num ++;
		if(g_neighbor_enable){
			if(!ap->is_neighbor){
				continue;
			}
		}
		neighbor_ap_num ++;
		
		neighbor_util_2G = neighbor_util_5G =neighbor_sta_num = 0;
		for(i = 0;i < 3; i ++){
			neighbor_sta_num +=ap->radio[i].stanum;
			if(ap->radio[i].bandtype == wlanif_band_24g){
				neighbor_util_2G += ap->radio[i].utilization/3;
			}else {
				neighbor_util_5G += ap->radio[i].utilization;
			}
		}

		dcm_log(SYSLOG_BALANCE,"[4/8] Neighbor AP:%s neighbor_sta_num=%d, neighbor_util_2G = %d,neighbor_util_5G = %d\n",\
			   ether_sprintf(ap->mac), neighbor_sta_num,neighbor_util_2G*3,neighbor_util_5G);

		if(local_sta_num > neighbor_sta_num)
			 sta_num_order ++;
		if(local_util_2G > neighbor_util_2G)
			  util_2G_order ++;
		if(local_util_5G > neighbor_util_5G)
		        util_5G_order ++;
	}

	if(!isDualBand){
		util_5G_order = 0;
	}

	dcm_log(SYSLOG_BALANCE,"[5/8] STA %s  is %s \n",ether_sprintf(mac),isDualBand ? "double band":"single band so 5G_utilization_order set to zero");

	 if(neighbor_ap_num == 0){
	 	dcm_log(SYSLOG_BALANCE,"[6/8] STA %s  No cluster member now! allow\n",ether_sprintf(mac));
		return -1;
	 }
	 
	if(1 == neighbor_ap_num){
		dney_cnt = 0;
		dcm_log(SYSLOG_BALANCE,"[6/8] STA %s Only one ap in cluster now!allow!\n",ether_sprintf(mac));
		return dney_cnt;
	}

	unit_size = neighbor_ap_num / 4;
	
		
	if(neighbor_ap_num % 4 > 1)
		unit_size += 1;
	
	
	if(!unit_size){
		dney_cnt = sta_num_order + util_2G_order + util_5G_order;
	}else {
		dney_cnt = sta_num_order/unit_size + util_2G_order/unit_size + util_5G_order/unit_size;
	}

	if(rssi > 30){  // deny cnt 0
		dney_cnt += 0;
	}else if(rssi > 20){ // deny cnt 1
		dney_cnt += 1;
	}else if(rssi > 15){// deny cnt 2
		dney_cnt += 2;
	}else {              // deny cnt 3
		dney_cnt += 3; 
	}
	
	dcm_log(SYSLOG_BALANCE,"[6/8] STA %s 2L_ap_number = %d,cluster_ap_number = %d, neighbor_ap_num = %d,sta_rssi = %d,sta_num_order = %d,2G_utilization_order = %d,5G_utilization_order = %d,deny_cnt = %d\n",\
		ether_sprintf(mac), ap_2L_num,ap_total_num,neighbor_ap_num,rssi,sta_num_order,util_2G_order,util_5G_order,dney_cnt);

	return dney_cnt;
}

void print_ap_list()
{
	//ap_state *ap = NULL;
//	ap_state *client = NULL;

	//han_list_for_each(&ap_list,ap,list) {
		//ap
		//client = list_entry(pos, Clusterlist, list);
		//printf("mac:%s\n",macaddr_to_str(ap->mac));
	//}
}

int create_udp_send_socket()
{
    /* Set server infomation */
	bzero(&server_addr, sizeof(server_addr)); 
	server_addr.sin_family = AF_INET; 
	server_addr.sin_addr.s_addr = inet_addr("255.255.255.255"); 
	server_addr.sin_port = htons(DCM_PORT); 

	/* Create socket */
	int send_socket_fd = socket(AF_INET, SOCK_DGRAM, 0); 
	if(send_socket_fd < 0) 
	{ 
		perror("Create send_socket_fd Failed:"); 
		exit(7); 
	} 
	//resolve for send to Permission denied
	int on=1;
	setsockopt(send_socket_fd,SOL_SOCKET,SO_BROADCAST,&on,sizeof(on));

	return send_socket_fd;

}

time_t han_get_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ts.tv_sec;
}

int han_flush_black_list(void)
{
	int ret = 0;
	struct iwreq iwr;
	unsigned char buf[1024] = {0};
	struct han_ioctl_priv_args a = {0};
	
	a.type = HAN_IOCTL_PRIV_DCM;
	a.u.dcm.subtype = HAN_IOCTL_DCM_FLUSH;
	a.u.dcm.op = OP_SET;
	a.u.dcm.value = 0;

	memset(buf, 0, sizeof(buf));
	memcpy(buf, &a, sizeof(struct han_ioctl_priv_args));


	memset(&iwr, 0, sizeof(iwr));
	strncpy((iwr.ifr_name), "wifi0", strlen("wifi0"));
	
	iwr.u.data.pointer = (void *) buf;
	iwr.u.data.length = sizeof(buf);

	ret = han_ioctl(&iwr, ATH_IOCTL_HAN_PRIV);
	if (ret < 0 ){
		printf("han dcm ioctl error !\n");	
		return -1;
	}
	
	return 0;
}


unsigned int han_get_local_stanum(char *ifname)
{
	int ret = 0;
	struct iwreq iwr;
	unsigned char buf[1024] = {0};
	struct han_ioctl_priv_args a = {0};
	
	a.type = HAN_IOCTL_PRIV_DCM;
	a.u.dcm.subtype = HAN_IOCTL_DCM_GET_CLIENT_NUM;
	a.u.dcm.op = OP_GET;
	a.u.dcm.value = 0;

	memset(buf, 0, sizeof(buf));
	memcpy(buf, &a, sizeof(struct han_ioctl_priv_args));


	memset(&iwr, 0, sizeof(iwr));
	printf("%s ifname = %s\n",__func__,ifname);
	strncpy((iwr.ifr_name), ifname, strlen(ifname));
	
	iwr.u.data.pointer = (void *) buf;
	iwr.u.data.length = sizeof(buf);

	ret = han_ioctl(&iwr, ATH_IOCTL_HAN_PRIV);
	if (ret < 0 ){
		printf("han dcm ioctl error !\n");	
		return -1;
	}
	
	memcpy(&a, buf, sizeof(struct han_ioctl_priv_args));

	return a.u.dcm.value;
}
int han_send_ap_info()
{
 	char buffer[BUFFER_SIZE]; 
 	bzero(buffer, BUFFER_SIZE);
    
	DCM_format dcm_ap_info;
	memset(&dcm_ap_info,0x0,sizeof(DCM_format));
	dcm_ap_info.radionum = g_own_ap_state.radionum;
	OS_MACCPY(dcm_ap_info.mac,g_own_ap_state.mac);

	int i;
	for(i = 0;i < 3;i ++){
		if(g_own_ap_state.radio[i].valid){
			g_own_ap_state.radio[i].stanum = han_get_local_stanum(g_own_ap_state.radio[i].ifname);
		}
	}

	dcm_ap_info.radio[0].util = g_own_ap_state.radio[0].utilization;
	dcm_ap_info.radio[0].stanum    = g_own_ap_state.radio[0].stanum;
	dcm_ap_info.radio[0].bandtype  = g_own_ap_state.radio[0].bandtype;
	dcm_ap_info.radio[1].util = g_own_ap_state.radio[1].utilization;
	dcm_ap_info.radio[1].stanum    = g_own_ap_state.radio[1].stanum;
	dcm_ap_info.radio[1].bandtype  = g_own_ap_state.radio[1].bandtype;
	dcm_ap_info.radio[2].util = g_own_ap_state.radio[2].utilization;
	dcm_ap_info.radio[2].stanum    = g_own_ap_state.radio[2].stanum;
	dcm_ap_info.radio[2].bandtype  = g_own_ap_state.radio[2].bandtype;

	/*get client num modefied now because above is not accuracy*/

	// dcm_ap_info.radio[0].stanum = han_get_local_stanum();
	 //dcm_ap_info.radio[1].stanum = 0;
	 //dcm_ap_info.radio[2].stanum = 0;
	 
#if 1

    unsigned char *mac = dcm_ap_info.mac;

	printf("send ap info:\n");
	printf("radio_num = %d\n",dcm_ap_info.radionum);
	
	printf("eth_mac:%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    for(i = 0; i < dcm_ap_info.radionum; i ++){
		printf(" g_own_ap_state[%d]utilization= %d\n",i,g_own_ap_state.radio[i].utilization);
		printf(" g_own_ap_state[%d]stanum = %d\n",i,g_own_ap_state.radio[i].stanum);
		printf(" g_own_ap_state[%d]channel = %d\n",i,g_own_ap_state.radio[i].channelID);
		printf(" g_own_ap_state[%d]bandtype= %d\n",i,g_own_ap_state.radio[i].bandtype);
	}
#endif
 	/* Send packet to server */
	Assemble_DCM(buffer,&dcm_ap_info);
	
	if(sendto(send_socket_fd, buffer,sizeof(Hccp_Protocol_Union),0,(struct sockaddr*)(&server_addr),sizeof(struct sockaddr)) < 0) 
	{ 
		perror("Send AP information Failed:"); 
		return -1; 
	}else {
		printf("send ap info OK \n");
	} 

	return 0;
}

void dcm_parse_packet(char * buf)
{
	Hccp_Protocol_Struct dcminfo;

	Parse_HCCPProtocol(buf,&dcminfo);
	DCM_format * info = (DCM_format * )&dcminfo.u.dcm;
	int i = 0;
	ap_state *ap = NULL;

	ap = find_ap_member(info->mac);
	ap->radionum = info->radionum;

	for(i = 0; i < info->radionum; i ++){
		ap->radio[i].stanum = info->radio[i].stanum;

		if(info->radio[i].util){
			ap->radio[i].utilization = info->radio[i].util;
		}

		ap->radio[i].bandtype = info->radio[i].bandtype;
	}
	return ;
}


void * dcm_pkt_recv_process()
{
//    int i;	
	struct sockaddr_in recv_addr; 
	bzero(&recv_addr, sizeof(recv_addr)); 
	recv_addr.sin_family = AF_INET; 
	recv_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
	recv_addr.sin_port = htons(DCM_PORT); 
  
	int recv_socket_fd = socket(AF_INET, SOCK_DGRAM, 0); 
	if(recv_socket_fd < 0) 
	{ 
		perror("Create Socket Failed:"); 
	} 
	/* Create socket */
	if(recv_socket_fd == -1) 
	{ 
		perror("Create Socket Failed:"); 
	} 
  
 	int on=1;
	if((setsockopt(recv_socket_fd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)))<0)
	{
		  perror("dcm setsockopt failed");
		  exit(5);
	}
	
	/* Bind socket */
	if(-1 == (bind(recv_socket_fd,(struct sockaddr*)&recv_addr,sizeof(recv_addr)))) 
	{ 
		perror("Server Bind Failed:"); 
	} 

	/* Recv pkt from server */
	while(1) 
	{  
		struct sockaddr_in client_addr; 
		socklen_t client_addr_length = sizeof(client_addr); 
		char buffer[BUFFER_SIZE]; 
		bzero(buffer, BUFFER_SIZE); 
		
		printf("Wait receive data\n"); 
		if(recvfrom(recv_socket_fd, buffer, BUFFER_SIZE,0,(struct sockaddr*)&client_addr, &client_addr_length) == -1) 
		{ 
			perror("Receive Data Failed:"); 
		} 
		printf("Receive Data success!\n"); 
		dcm_parse_packet(buffer);
	}
}

int dcm_create_recv_thread()
{
    int pret = 0;
    
    pret = pthread_create(&dcm_recv_thread,
                          NULL,
                          dcm_pkt_recv_process,
                          NULL);
    
    if (pret < 0) {
        perror("icm : dcm_recv_thread error!\n");
        return 0;
    }

    return 1;
}


int dcm_socket_init()
{
    struct sockaddr_un server_addr; 
    
	bzero(&server_addr, sizeof(server_addr)); 
	server_addr.sun_family = AF_UNIX; 
	strncpy(server_addr.sun_path,UNIX_DOMAIN,sizeof(server_addr.sun_path)-1);
	unlink(UNIX_DOMAIN);

	g_dcm_socket_fd = socket(PF_UNIX, SOCK_DGRAM, 0); 
	if(g_dcm_socket_fd == -1) 
	{ 
		perror("Create Socket Failed:"); 
		//exit(1); 
		//drm_log(DRM_LOG_WRITE_TO_SYSLOG,"DRM-MAIN:Create local socket failed.\n");
		return 0;
	} 

	if(-1 == (bind(g_dcm_socket_fd,(struct sockaddr*)&server_addr,sizeof(server_addr)))) 
	{ 
		perror("Server Bind Failed:"); 
       // drm_log(DRM_LOG_WRITE_TO_SYSLOG,"DRM-MAIN:Create local socket bind failed.\n");
        //exit(1); 
        return 0;
	}
	return 1; 
}


Clusterlist * dcm_create_cluster_list_node(unsigned char * mac)
{
	Clusterlist * node = NULL;
	node = (Clusterlist *) malloc(sizeof(Clusterlist));
	if(node){
		memset(node,0,sizeof(Clusterlist));
		OS_MACCPY(node->mac,mac);
		list_insert_entry(&node->list,&cluster_list.list);
	}
	return node;	
}

Clusterlist *  __find_cluster_member(unsigned char *mac)
{
	list_head_t *iter;
	list_for_each(iter,&cluster_list.list){
		Clusterlist * node  = list_entry(iter,Clusterlist,list);
		if(OS_MACCMP(node->mac,mac) == 0){
			return node;
		}
	}
	
     return NULL;
}


Clusterlist * dcm_find_cluster_member(unsigned char * mac)
{
	Clusterlist * node = __find_cluster_member(mac);
	if(node){
		return node;
	}
	
	return dcm_create_cluster_list_node(mac);
}


int dcm_cluster_info_prase_radio_info_tlv(Clusterlist * node,char * data,int len)
{
	TLVHeader * tlv = (TLVHeader *)data;
	int remaind_len = len;
	unsigned char * radio_id = NULL;
	unsigned char * radio_chan = NULL;
	unsigned char * radio_rssi = NULL;
	unsigned char * radio_txp = NULL;
    
	while(remaind_len >= sizeof(TLVHeader)){
		switch(tlv->type){
			case MSG_ELEMENT_TYPE_RADIO_ID:
				radio_id = (unsigned char *)(tlv + 1);
				break;
			case MSG_ELEMENT_TYPE_RADIO_CHAN:
				radio_chan = (unsigned char *)(tlv + 1);
				node->radio[*radio_id].channel = *radio_chan;
				break;
			case MSG_ELEMENT_TYPE_RADIO_TXP:
				radio_txp = (unsigned char *)(tlv + 1);
				node->radio[*radio_id].txpower = *radio_txp;
				break;
			case MSG_ELEMENT_TYPE_RADIO_RSSI:
				radio_rssi = (unsigned char *)(tlv + 1);
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

	return 0;
}


int dcm_cluster_info_prase_tlv(char * data, int len)
{
	TLVHeader * tlv = (TLVHeader * )data;
	uint remaind_len = len;
	unsigned char mac[6] = {0};
	int * ip = NULL;
	Clusterlist * node = NULL;
       ap_state * ap = NULL;
	//    printf("%s frecv msg for pvc \n",__func__);

	while(remaind_len >= sizeof(TLVHeader)){
		switch(tlv->type){
			case MSG_ELEMENT_TYPE_AP_MAC:
				memcpy(mac,(char *)(tlv + 1),6);
				node = dcm_find_cluster_member(mac);
				ap = __find_ap_member(mac);
				if(ap){
					ap->in_cluster = 1;
					time(&ap->ctime);
				}
				
				//printf("%s set in_cluster MAC %02X:%02X:%02X:%02X:%02X:%02X\n",__func__,mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
				break;
			case MSG_ELEMENT_TYPE_AP_IP:
				
				#if 1
				ip = (int*)(tlv + 1);
				if (!node)
				{
					node->ip = *ip;
				}
				#endif
				
				break;
			case MSG_ELEMENT_TYPE_RADIO_INFO:
				dcm_cluster_info_prase_radio_info_tlv(node,(char *)(tlv + 1),tlv->len);
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

	return 0;
}


int dcm_cluster_info_prase_data(char * data,int len)
{
	TLVHeader * tlv = (TLVHeader *)data;
	int remaind_len = len - sizeof(TLVHeader);
	//    printf("%s recv msg for pvc \n",__func__);

	while(remaind_len >= sizeof(TLVHeader)){
		switch(tlv->type){
			case MSG_ELEMENT_TYPE_AP_INFO:
				dcm_cluster_info_prase_tlv((char *)(tlv + 1),tlv->len);
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
	return 0;
}

void dcm_recv_msg()
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
    
	if (g_dcm_socket_fd != -1)
    {
        FD_SET(g_dcm_socket_fd, &read_fs);
    }
    
	st = select(g_dcm_socket_fd+1, &read_fs, NULL, NULL, &tv);
	if(st > 0){
		if(recvfrom(g_dcm_socket_fd, buffer, 1024,0,(struct sockaddr*)&client_addr, &client_addr_length) == -1) 
		{ 
			perror("Receive Data Failed:"); 
			exit(1); 
		}
	}
//    printf("%s frecv msg for pvc \n",__func__);

	cr = (ClusterRequest *)buffer;
	if(cr->op == MSG_RESPONSE && cr->type == CLUSTER_ENV_INFO){
		dcm_cluster_info_prase_data(buffer+sizeof(ClusterRequest),cr->elm_len);	
	}
}

void dcm_send_request_msg()
{
    char snd_buf[1024];
    static struct sockaddr_un srv_addr;
    srv_addr.sun_family=AF_UNIX;
    strcpy(srv_addr.sun_path,CLUSTER_SERVER);
    memset(snd_buf,0,1024);
    ClusterRequest * cr = (ClusterRequest *)snd_buf;
    cr->apver = 0;
    cr->op = MSG_REQUEST;
    cr->res = 0;
    cr->type = CLUSTER_ENV_INFO;
    cr->elm_len = 0;

printf("%s send request msg \n",__func__);

    if(sendto(g_dcm_socket_fd, snd_buf, 1024,0,(struct sockaddr*)&srv_addr,sizeof(srv_addr)) < 0) 
	{ 
		perror("ATP_CONTROL: Send msg error, "); 
	} 
}

void dcm_get_clustr_list()
{
//printf("%s get cluster list start  g_dcm_socket_fd = %d\n",__func__,g_dcm_socket_fd);

    //drm_log(DRM_LOG_WRITE_TO_SYSLOG,"GET cluster list start\n");
    if(dcm_socket_init() == 0){
        return;
    }
   // printf("%s get cluster list  has init socket g_dcm_socket_fd = %d\n",__func__,g_dcm_socket_fd);

    dcm_send_request_msg();
    dcm_recv_msg();
    close(g_dcm_socket_fd);
    //drm_log(DRM_LOG_WRITE_TO_SYSLOG,"GET cluster list end\n");
}


int dcm_is_neighbor_ap(Clusterlist * node)
{
	int i = 0;
	int cnt = 0;
	
	if(node == NULL) //
		return 0;

	//printf(" %s Neighbor %s ",__func__,ether_sprintf(node->mac));
	
	for(i = 0;i < 3; i ++){
		if(node->radio[i].rssi >= g_neighbor_rssi_threshold)
			cnt ++;
	//	printf("radio[%d].rssi = %d ",i,node->radio[i].rssi);
		//printf("radio[%d].txpower = %d ",i,node->radio[i].txpower);
	}
	//printf("\n");
	
      /*2 radio rssi bigger than rssi threshold ,we take it as neighbor ap*/
	if(cnt >= 2){
		return 1;
	}else {
		return 0;
	}
	
	return 0;
}

void dcm_sign_neighbor_cluster_member()
{
    list_head_t *iter;
    Clusterlist * node = NULL;
    list_for_each(iter,&ap_list.aplist){
		ap_state *ap = list_entry(iter,ap_state,aplist);
		if(ap && ap->in_cluster){
			node = __find_cluster_member(ap->mac);
			if(node){
				ap->is_neighbor = dcm_is_neighbor_ap(node);
			}else {
			 	ap->is_neighbor = 0;
				ap->in_cluster = 0;
			}
		}
     }
}


void dcm_clear_cluster_ap_list()
{
    time_t now_time;
    list_head_t *iter;
    list_for_each(iter,&ap_list.aplist){
		ap_state *ap = list_entry(iter,ap_state,aplist);
		if(ap && ap->in_cluster){
			time(&now_time);
			if(now_time - ap->ctime > 240) // 4 minute
				ap->in_cluster = 0;
		}
     }
}

static void dcm_print_cluster_info()
{
	list_head_t *iter;
	list_for_each(iter,&cluster_list.list){
		Clusterlist * node  = list_entry(iter,Clusterlist,list);
		if(node){
			dcm_log(SYSLOG_NORMAL,"Cluster_member : %s radio[0]-rssi = %d,channel=%d,txpower = %d \n",\
				ether_sprintf(node->mac),node->radio[0].rssi,node->radio[0].channel,node->radio[0].txpower);
			dcm_log(SYSLOG_NORMAL,"Cluster_member : %s radio[1]-rssi = %d,channel=%d,txpower = %d \n",\
				ether_sprintf(node->mac),node->radio[1].rssi,node->radio[1].channel,node->radio[1].txpower);
			dcm_log(SYSLOG_NORMAL,"Cluster_member : %s radio[2]-rssi = %d,channel=%d,txpower = %d \n",\
				ether_sprintf(node->mac),node->radio[2].rssi,node->radio[2].channel,node->radio[2].txpower);
		}
	}
}
static void dcm_print_ap_info()
{
    list_head_t *iter;
    list_for_each(iter,&ap_list.aplist){
		ap_state *ap = list_entry(iter,ap_state,aplist);
		if(ap){
			dcm_log(SYSLOG_NORMAL,"2L_AP %s\t%s\t%s\n",ether_sprintf(ap->mac),ap->in_cluster ?"in cluster":"",ap->is_neighbor?"is neighbor":"");
		}		
     }
}

#define CMD_LEN 256

static int dcm_get_config_entry(const char* cmd)
{
    FILE *fp;
    char str_tmp_cmd[CMD_LEN];
    char szVal[CMD_LEN];  
    memset( str_tmp_cmd, 0, CMD_LEN );
    memset(szVal, 0x00, sizeof(szVal));
    strcpy(str_tmp_cmd, cmd);	

    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
	  
        pclose(fp);
    }

    return atoi(szVal);
}


static int dcm_upgrade_config_entry_status()
{
	//    igmp_hosttimerout_interval = get_igmpv1_hostinterval();		
	int value = 0;

	value = dcm_get_config_entry("uci get lbd.config.dbg_normal");
	if(value){
		g_dbg_normal = SYSLOG_NORMAL;
		g_dbg_mask |= SYSLOG_NORMAL;
	}else {
		g_dbg_normal = 0;
		g_dbg_mask &= (~SYSLOG_NORMAL);
	}
	
	value = dcm_get_config_entry("uci get lbd.config.dbg_5gfirst");
	if(value){
		g_dbg_5gfirst = SYSLOG_5GFIRST;
		g_dbg_mask |=  SYSLOG_5GFIRST;
	}else {
	      g_dbg_mask &=  (~SYSLOG_5GFIRST);
		g_dbg_5gfirst = 0;
	}

	value = dcm_get_config_entry("uci get lbd.config.dbg_loadbalance");
	if(value){
		g_dbg_lbalance = SYSLOG_BALANCE;
		g_dbg_mask |= SYSLOG_BALANCE;
	}else {
		g_dbg_lbalance = 0;
		g_dbg_mask &= (~SYSLOG_BALANCE);
	}
	
	value = dcm_get_config_entry("uci get lbd.config.dbg_printall");
	if(value){
			g_dbg_all =	value;
	}else {
		g_dbg_all = 0;
	}
	
	value = dcm_get_config_entry("uci get lbd.config.sysinfo_interval");
	if(value){
		if(value > 10) {
			g_sysinfo_interval =	value;
		}
	}else {
		g_sysinfo_interval = 0;
	}
	
      value = dcm_get_config_entry("uci get lbd.config.begin_deny");
	if(value){
		g_begin_deny =	value;
	}else {
		g_begin_deny = 0;
	}
	
	value = dcm_get_config_entry("uci get lbd.config.neighbor_rssithreshold");
	if(value){	
		g_neighbor_rssi_threshold = value;
	}else {
		g_neighbor_rssi_threshold = 15;
	}
	
	value = dcm_get_config_entry("uci get lbd.config.neighbor_enable");
	if(value){	
		g_neighbor_enable = value;
	}else {
		g_neighbor_enable = 0;
	}

	value = dcm_get_config_entry("uci get lbd.config.5gfirst");
	if(value){	
		g_5gfirst_enable = value;
	}else {
		g_5gfirst_enable = 0;
	}

	value = dcm_get_config_entry("uci get lbd.config.loadbalance");
	if(value){	
		g_loadbalance_enable = value;
	}else {
		g_loadbalance_enable = 0;
	}
	
	value = dcm_get_config_entry("uci get lbd.config.max_stanumdiff");
	if(value){	
		g_max_number_diff = value;
	}else {
		g_max_number_diff = 5;
	}

	
	value = dcm_get_config_entry("uci get lbd.config.dbg_printinfo");
	if(value){	
		g_dbg_printinfo = value;
		dcm_print_ap_info();
		dcm_print_cluster_info();
	}else {
		g_dbg_printinfo = 0;
	}

	printf("g_max_number_diff = %d,g_neighbor_rssi_threshold = %d, g_begin_deny = %d, sysinfo_interval = %d ,g_dbg_all = %d ,g_dbg_printinfo = %d, g_dbg_lbalance = %d, g_dbg_5gfirst = %d\n",\
		g_max_number_diff,g_neighbor_rssi_threshold,g_begin_deny,g_sysinfo_interval,g_dbg_all,g_dbg_printinfo,g_dbg_lbalance,g_dbg_5gfirst);
	
	return 0;
}
	 
void dcm_handler_timer()
{
	time_t now_time; 
	time(&now_time);
	static int print_apinfo_interval = 0;
	static int check_lowrssi_interval = 0;

	if(g_dcm_check_time == 0){
		printf("Get first check time\n");
		time(&g_dcm_check_time);
		return;
	}
	check_lowrssi_interval ++;
       if(check_lowrssi_interval > 5){
             han_dcm_kickout_lowrssi_staions();
		check_lowrssi_interval = 0;
      	}	
	   
       /*10 s upgrade configure swtich*/
	  print_apinfo_interval ++;
	if(print_apinfo_interval > 10){
		dcm_upgrade_config_entry_status();
		print_apinfo_interval = 0;
		if(dcm_get_config_entry("uci get lbd.config.rssiThresholdChange")){
			system("uci set lbd.config.rssiThresholdChange=0");
	}

	}
	if((now_time - g_dcm_check_time) < g_sysinfo_interval){
		return;
	}

	time(&g_dcm_check_time);
	han_send_ap_info();
	dcm_get_clustr_list();
	if(g_neighbor_enable){
		dcm_sign_neighbor_cluster_member();
	}
	dcm_clear_cluster_ap_list();

}

/*
 * Function     : signal_handler
 * Description  : handle user/system generated signal
 * Input params : type of signal
 * Return       : void
 *
 */
void dcm_signal_handler(int signals)
{
    switch(signals) {
        case SIGALRM:
            dcm_handler_timer();
            alarm(1);
            break;
        case SIGVTALRM:
            dcm_handler_timer();
            break;
    }
}
void *dcm_timer_process()
{

printf("%s timer process start \n",__func__);

    struct itimerval value;
    signal(SIGALRM, dcm_signal_handler);
    value.it_value.tv_sec = 1;  
    value.it_value.tv_usec = 0;
    value.it_interval.tv_sec = 1;
    value.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &value, NULL);
	
printf("%s timer process end\n",__func__);

    while(1)
    {
        //usleep(100000);
        sleep(2);
	//printf("%s running\n",__func__);
	
    }
}

int dcm_create_timer_thread()
{
    int pret = 0;

    printf("%s creater timer\n",__func__);
	
    pret = pthread_create(&dcm_timer_thread,
                          NULL,
                          dcm_timer_process,
                          NULL);
    
    if (pret < 0) {
        perror("dcm : dcm_create_timer_thread error!\n");
        return 0;
    }

    return 1;
}


int  get_eth_mac(unsigned char *mac)
{
    struct ifreq eth_ifreq;
    int sock;
	
    if ((sock = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror ("socket");
        return -1;
    }
    strcpy (eth_ifreq.ifr_name, "eth0");    //Currently, only get eth0

    if (ioctl (sock, SIOCGIFHWADDR, &eth_ifreq) < 0)
    {
        perror ("ioctl");
        return -1;
    }

	OS_MACCPY(mac,(unsigned char*)&eth_ifreq.ifr_hwaddr.sa_data);

	return 0;
}

#define CMD_LEN 256


void dcm_log(const char loglvl,const char * fmt, ...)
{
    char buf[DBG_BUF_SIZE],*tmp = NULL;
    va_list ap; 
   // memset(buf,0,DBG_BUF_SIZE);

   if((!(loglvl & g_dbg_mask))&&(!g_dbg_all))
   	return;

    if(loglvl == SYSLOG_BALANCE){
    	   tmp = buf + snprintf(buf,DBG_BUF_SIZE,"lbd-LoadBalance: ");
    }else if(loglvl == SYSLOG_5GFIRST){
    	   tmp = buf + snprintf(buf,DBG_BUF_SIZE,"lbd-5GFirst: ");
    }else if(loglvl == SYSLOG_NORMAL){
    	   tmp = buf + snprintf(buf,DBG_BUF_SIZE,"lbd :");
    }else {
	   tmp = buf;
    }

    va_start(ap,fmt);
    vsnprintf(tmp,(DBG_BUF_SIZE - (tmp - buf)),fmt,ap);
    va_end(ap);
    
    if(g_dbg_all)
        printf("%s\n",buf);

    if(loglvl & g_dbg_mask)
    {
        /*WRITE TO SYSLOG*/
        syslog(LOG_NOTICE,buf);
    }
}

void dcm_kill_signal_handler(int nsig)
{
   printf("%s nsig =%d \n",__func__,nsig);
   han_dcm_signal_handle_get_rssithreshold();
	
}

int dcm_signal_init(void)
{
    struct sigaction act, oldact;
    act.sa_handler = dcm_kill_signal_handler;
    sigemptyset(&act.sa_mask); //clear the signal set
    sigaddset(&act.sa_mask, SIGUSR2); 
    act.sa_flags = SA_RESTART | SA_NODEFER;
    act.sa_flags = 0;
    if(sigaction(SIGUSR2, &act, &oldact)==-1){
		printf("%s  fail to set handler for SIGUSR2",__func__);
    }
    return 0;
}

int han_dcm_init() 
{ 	
      memset(&ap_list,0x0,sizeof(ap_state));
	memset(&cluster_list,0x0,sizeof(Clusterlist));
	
	list_set_head(&ap_list.aplist);
	list_set_head(&cluster_list.list);
	
	if(get_eth_mac(g_own_ap_state.mac)){
		printf("get eth mac error!\n");
	}
	unsigned char * mac = g_own_ap_state.mac;
	printf("ap eth_mac:%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

	if(0 == send_socket_fd){
		send_socket_fd = create_udp_send_socket();
		if(0 == send_socket_fd){
			perror("create_udp_send_socket error\n");
	    }
	}
	
	han_send_ap_info();

	dcm_create_recv_thread();
      dcm_create_timer_thread();
	dcm_signal_init();
	return 0;
} 



int han_dcm_ioctl(const char* interface,
				   unsigned char option,
	               const unsigned char *mac,
	               unsigned char channel,
	               unsigned char denycnt)
{

	int ret = 0;
	struct iwreq iwr;
	unsigned char buf[1024] = {0};
	struct han_ioctl_priv_args a = {0};
	
	a.type = HAN_IOCTL_PRIV_DCM;
	a.u.dcm.subtype = option;
	a.u.dcm.op = OP_SET;
	if(NULL != mac)
	OS_MACCPY(a.u.dcm.mac,mac);
	a.u.dcm.channel = channel;
	a.u.dcm.denycnt = denycnt;

	memset(buf, 0, sizeof(buf));
	memcpy(buf, &a, sizeof(struct han_ioctl_priv_args));

#if 0
      if(mac != NULL){
	printf("STA MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
		mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	
	printf("a.u.dcm %02X:%02X:%02X:%02X:%02X:%02X\n",
		a.u.dcm.mac[0],a.u.dcm.mac[1],a.u.dcm.mac[2],a.u.dcm.mac[3],a.u.dcm.mac[4],a.u.dcm.mac[5]);
      	}
	printf("ifname = %s,option = %d,channel = %d,denycnt = %d\n",
		interface,option,channel,denycnt);

#endif
	memset(&iwr, 0, sizeof(iwr));
	strncpy((iwr.ifr_name), interface, strlen(interface));
	
	iwr.u.data.pointer = (void *) buf;
	iwr.u.data.length = sizeof(buf);

	ret = han_ioctl(&iwr, ATH_IOCTL_HAN_PRIV);
	if (ret < 0 ){
		printf("han dcm ioctl error !\n");	
		return -1;
	}
	return 0;
}

