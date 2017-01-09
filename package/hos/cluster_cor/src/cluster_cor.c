#include <sys/types.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <sys/stat.h>


#include "cluster_cor.h"
#include "libhccp.h"


int flags = 0; // pvc :1 ; not pvc :0; svn or  vc
int pvc_switch = 0;
int entry_cnt = 0;
int sock_recv_rsrp= -1;
uint32_t pvc_brast = 0;
uint32_t  g_clusterId=100;
uint32_t  g_vipaddr=0;
uint32_t  g_vip_netmask=0;

uint8_t  g_priority=0;
uint8_t  g_mac_str[64]={0};
uint8_t  g_mac[6]={0};

uint32_t acs_seqnum =1;
uint32_t svc_num =0;
uint32_t ageing_time=2;
unsigned char product_type_cnt = 2;
RISP_format risp_pkt_recv;
char *wan = "br-wan";


pthread_t  thread_check_vc;
//pvc thread
pthread_t thread_rsrp_recv;
pthread_t thread_rscp_send;
pthread_t thread_risp_send;
pthread_t thread_ageing;
pthread_t thread_acs;

#define   TRUE  0
#define   FALSE  1

#define  LIMIT   16
#define  CLUSTER_PORT_RECV 32768
#define  CLUSTER_PORT_SEND 32767
#define  CLUSTER_PORT_SYNC  32769
#define  RSCP_LEN  1024
#define  RSRP_LEN  19


#define MAX_CLUSTER_NAME_LEN 256
#define MAX_AUTH_AP   16
#define MAC_LEN		6
#define MAX_BLACKLIST_CNT 1024
#define MAX_CLUSTER_CFGFILE_LINE 1048
#define PRODUCT_TYPE_LEN 32
typedef enum
{
	MODEL_NOT_EXIST = 0,
	AP101 = 1,	
}PRODUCT_TYPE;


typedef struct
{
	unsigned char product_type[PRODUCT_TYPE_LEN];
	unsigned char type_code;
}Product_Type;

typedef struct
{
	u_int32_t cluster_id;
	char cluster_name[MAX_CLUSTER_NAME_LEN];
	u_int8_t cluster_priority;
	u_int32_t cluster_vip;
	u_int32_t cluster_vip_netmask;
	u_int32_t cluster_member_count;	
	u_int8_t mac[MAX_BLACKLIST_CNT][MAC_LEN];
}Config_File_Struct;


typedef enum cluster_state {
    DISCOVERY,
    JOIN,
    CHECK,
    RUN,
    LOST
} CLUSTER_STATE;

typedef enum cluster_role {
    PVC = 1,
    SVC,
    VC
} ROLE;

typedef enum cluster_cmd {
    SHOW = 1,
    AUTH,
    UNAUTH,
    DEL,
    VIP,
	SET_TIME,
	UCI_DEL
} CLUSTER_CMD;

struct cmd_head {
    uint8_t type;
    uint8_t mac[6];
    uint32_t ip;
	char netmask[32];
};



typedef struct priority {
    u_int8_t overload[2];
    u_int8_t priority;
    u_int8_t config_seq;
    u_int8_t product_type;
    u_int8_t mac_tail[3];
} PRI;

typedef union cluster_priority {
    u_int64_t ap_priority;
    PRI prio;
} CLUSTER_PRI;




// coverage area detect :rirp
struct cluster_nbr {


    uint8_t mac[6];
    uint8_t channel2;
    uint8_t rssi;
    uint8_t channel5;
    uint8_t rssi5;

};





#define   CLUSTER_FIFO "/tmp/cluster_fifo"
#define   CMD_FIFO_SEND  "/tmp/cmd_fifo_send"
#define   CMD_FIFO_RECV  "/tmp/cmd_fifo_recv"
#define   SOCKET_PATH   "/tmp/socket_path"
#define  CLUSTER_CONFIG_PATH  "/etc/cfm/config/config-pub/"
#define  CLUSTER_CONFIG_FILE  "/etc/cfm/config/config-pub/cluster"
#define  CLUSTER_CMD  "cluster-cfg"



Product_Type product_type_table[] = 
{
	{"model not exist", MODEL_NOT_EXIST},
	{"AP101", AP101}	
};



typedef struct cluster_member {

    uint16_t  on;  //  0 is alive  ;1 is delete
    uint8_t state;  // running ? or lost
    uint8_t role;  // pvc /svc/vc ? 1:2:3
    uint8_t mac[6];
    uint32_t ip;
    uint32_t ssid;
    uint32_t cluster_id;
    // uint32_t prio;
    CLUSTER_PRI prio;
	uint8_t radiocnt;
	WTP_RADIO_H WTP_Radio[L_RADIO_NUM];
    uint32_t auth;    //  0 is not ;1 is auth
    pthread_mutex_t entry_mutex;
    uint32_t timer; // ageing time  default 30s
    uint32_t pre_free;
	unsigned char neighbor_cnt;
	Scan_Info rssi_of_others[MAX_CLUSTER_AP];
	uint8_t  ap_name[32];
	uint8_t  ap_version[16];
} cluster_m_t;


typedef struct blacklist  {
	uint16_t  on;
	uint8_t mac[6];
	

}blacklist_t ;


struct table_entry {
    uint32_t entry_cnt;
    uint32_t auth_cnt;
    uint32_t new_free;
    uint32_t free_cnt;
    pthread_mutex_t table_mutex;
};


struct table_auth {
    uint32_t num;
    uint32_t auth;
    uint32_t mac;
};

struct table_entry table;
struct table_auth  auth[16];

#define ENTRY_SIZE  128
#define AUTH_SIZE    16
#define ENTRY_ALL_SIZE   sizeof(struct cluster_member)* ENTRY_SIZE

cluster_m_t entry[ENTRY_SIZE];      //  size  32*64 =2048
cluster_m_t  self_ap;
blacklist_t  blacklist_entry[ENTRY_SIZE];

struct cmd_head  cmd;
Config_File_Struct config_file_data; 
uint32_t get_ipaddr();
uint32_t get_svc_ipaddr();
int  send_ricp(uint8_t op, uint8_t *mac);
int  send_rscp(void);
int elect_svc(void);
#define LOG_MODULE  "cluster_cor"

unsigned char Get_Config_Version();


void cluster_log(int priority, const char * fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap,fmt);
    vsnprintf(buf,2048,fmt,ap);
    va_end(ap);
	openlog(LOG_MODULE,0,LOG_DAEMON);
	syslog(priority,"%s", buf);
    printf("%s\n",buf);
	closelog();
}


char *trim(char *str_org)
{
	if (NULL == str_org)
	{
		cluster_log(LOG_DEBUG,"%s-%d str_org= NULL\n", __func__, __LINE__);
		return NULL;
	}

	if (0 == strlen(str_org))
	{
		cluster_log(LOG_DEBUG,"%s-%d Empty String\n", __func__, __LINE__);
		return str_org;
	}
	
	char *str_dst1 = str_org;
	char *str_dst2 = str_org + strlen(str_org) - 1;
	
	while ((*str_dst1 == ' ') || (*str_dst1 == '\t'))
	{
		str_dst1++;
		if (*str_dst1 == '\0')
		{
			return str_dst1;
		}
	}
	
	while ((*str_dst2 == ' ') || (*str_dst2 == '\t'))
	{
		str_dst2--;
		if (str_dst2 < str_org)
		{
			break;
		}
	}
	
	*(str_dst2 + 1) = '\0';
	
	return str_dst1;
}
HANBool PopenFile(char *cmd_str, char *str, int len)
{
	FILE *fp = NULL;
	
	if (cmd_str == NULL ||str == NULL)
	{
		return HAN_FALSE;
	}
	memset(str, 0, len);
	
	fp = popen(cmd_str, "r");
	if (fp)
	{
		fgets(str, len, fp);
		if (str[strlen(str)-1] == '\n')
		{
			str[strlen(str)-1] = '\0';
		}
		pclose(fp);
		
		return HAN_TRUE;
	}
	else
	{
		cluster_log(LOG_DEBUG,"%s-%d cmd:%s error[%s]\n", __func__, __LINE__, cmd_str, strerror(errno));
		
		return HAN_FALSE;
	}
}

int msg_deal(char *msg_src, char **msg_done,char *str)
{
	int i=0;
	msg_done[i]=strtok(msg_src,str);
	while(msg_done[i]!=NULL)
	{
		i++;
		msg_done[i]=strtok(NULL,str);
	}
	return i;
}
int mac_deal(char *mac[6], unsigned int count)
{
	unsigned char i = 0, j = 0, temp[2] = {0}, p[2] = {0}, temp_mac[MAC_LEN] = {0};
	unsigned int k = 0;
	char cmd[128] = {0};	
	for(i=0;i<6;i++)
	{
		p[0] = *((unsigned char*)mac[i]);
		p[1] = *((unsigned char*)(mac[i] + 1));
		
		for(j=0;j<2;j++)
		{
			if(p[j] >= '0' && p[j] <= '9')
			{
				temp[j] = p[j] - '0';				
			}
			else if(p[j] >= 'A' && p[j] <= 'F')
			{
				temp[j] = p[j] - 'A' + 0x0A;				
			}
			else if(p[j] >= 'a' && p[j] <= 'f')
			{
				temp[j] = p[j] - 'a' + 0x0a;				
			}
			else
			{			
                cluster_log(LOG_DEBUG,"mac error!\n");
			//	return -1;
			}			
		}
		temp_mac[i] = temp[0] * 16 + temp[1];
		//config_file_data.mac[count][i] = temp[0] * 16 + temp[1];		
	}
	
	for(k=0;k<count;k++)
	{
		if(!memcmp(temp_mac, config_file_data.mac[k], MAC_LEN))
		{
			return 1;
		}
	}
	
	memcpy(config_file_data.mac[count], temp_mac, MAC_LEN);
	//send_ricp(UCI_DEL,temp_mac);
	sprintf(cmd, "uci -c %s del_list cluster.cluster.cluster_member='%02x:%02x:%02x:%02x:%02x:%02x' ", CLUSTER_CONFIG_PATH,temp_mac[0],temp_mac[1],temp_mac[2],temp_mac[3],temp_mac[4],temp_mac[5]);
	system(cmd);
	sprintf(cmd, "uci -c %s add_list cluster.cluster.cluster_member='%02x:%02x:%02x:%02x:%02x:%02x' ", CLUSTER_CONFIG_PATH,temp_mac[0],temp_mac[1],temp_mac[2],temp_mac[3],temp_mac[4],temp_mac[5]);
	system(cmd);
	sprintf(cmd, "uci -c %s commit cluster", CLUSTER_CONFIG_PATH);
	system(cmd);
	return 0;
}
int load_config_file(void)
{
	FILE *fp;
	int len;
	unsigned int num,num_, i;
	char *buf, *result[MAX_CLUSTER_CFGFILE_LINE], *result_[16], *_result_[8], *result_mac[6];
	unsigned int count = 0, ret = 0;
	char cmd[256] = {0};

	fp=fopen(CLUSTER_CONFIG_FILE, "r");
	if(fp==NULL)
	{
        cluster_log(LOG_ERR,"Cannot open the file\n");
		return -1;
	}
	fseek(fp,0,2);
	len=ftell(fp);
	buf = (char*)malloc(len+1);
	rewind(fp);
	fread(buf, len, 1, fp);
	*(buf + len)='\0';
	fclose(fp);
	
	num=msg_deal(buf,result,"\r\n");
	
	for(i = 0; i < num && i < MAX_CLUSTER_CFGFILE_LINE; i++)
	{
		
		num_ = msg_deal(result[i], result_, " ");
		msg_deal(result_[2], _result_, "'");
		
		if(!strcmp("cluster_id", result_[1]))
		{			
			config_file_data.cluster_id = atoi(_result_[0]);			
		}		
		else if(!strcmp("cluster_name", result_[1]))
		{
			memcpy(config_file_data.cluster_name, _result_[0], strlen(_result_[0]));			
		}
		else if(!strcmp("cluster_priority", result_[1]))
		{
			config_file_data.cluster_priority = *((unsigned char *)_result_[0]) - 48;
		}
		else if(!strcmp("cluster_vip", result_[1]))
		{
			config_file_data.cluster_vip = inet_addr(_result_[0]);
		}
		else if(!strcmp("cluster_netmask", result_[1]))
		{
			config_file_data.cluster_vip_netmask = inet_addr(_result_[0]);
		}
		else if(!strcmp("cluster_member", result_[1]))
		{			
			msg_deal(_result_[0], result_mac, ":");			
			
			ret = mac_deal(result_mac, count);
			if(ret == 0)
			{
				count++;
			}
			else if(ret == 1)
			{
				continue;
			}			
		}		
	}
	
	config_file_data.cluster_member_count = count;	

	sprintf(cmd, "cd /etc/cfm/config/config-pub/;rm -f pub-cfg-md5;md5sum * > pub-cfg-md5");
	system(cmd);	
	free(buf);
	return 0;
}





void dump_mac(int priority,uint8_t *mac)
{

    cluster_log(priority,"mac:%02x:%02x:%02x:%02x:%02x:%02x \n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);


}



int  delete_entry(uint8_t  *mac)
{

    int i, find = 0;

    //find it
    for(i = 0; i < table.entry_cnt; i++) {

        if(entry[i].on == 0)
            continue;

        if(memcmp(entry[i].mac, mac, 6) != 0)
            continue;
        else {
            find = 1;
            break;
        }

    }


    if(find != 0) {

        pthread_mutex_destroy(&entry[i].entry_mutex);
        entry[i].on = 0; //delete it  and  mutex lock destroy
        //table
        entry[i].pre_free = table.new_free;
        pthread_mutex_lock(&table.table_mutex);
        table.new_free = i;
        table.free_cnt++;
        pthread_mutex_unlock(&table.table_mutex);
        if(entry[i].auth == 1)
		{
			entry[i].auth =0;
            table.auth_cnt--;
		}

        return find;
    } else {

        return find;
    }





}


int unauth_entry(uint8_t *mac)
{

    int i, find = 0;

    //find it
    for(i = 1; i < table.entry_cnt; i++) {

        if(entry[i].on == 0 || entry[i].auth == 0)
            continue;

        if(memcmp(entry[i].mac, mac, 6) != 0)
            continue;
        else {
            find = 1;
            break;
        }

    }


    if(find != 0) {

        table.auth_cnt--;
        entry[i].auth = 0;
		entry[i].role = VC;
		entry[i].state = JOIN;
        return  find;
    } else {

        return find;
    }


}


int delete_auth_entry(uint8_t *mac)
{

    int i, find = 0;

    //find it
    for(i = 1; i < table.entry_cnt; i++) {

        if(entry[i].on == 0 || entry[i].auth == 0)
            continue;

        if(memcmp(entry[i].mac, mac, 6) != 0)
            continue;
        else {
            find = 1;
            break;
        }

    }


    if(find != 0) {

        pthread_mutex_destroy(&entry[i].entry_mutex);
        entry[i].on = 0; //delete it  and  mutex lock destroy
		entry[i].auth = 0;
        //table
        entry[i].pre_free = table.new_free;
        pthread_mutex_lock(&table.table_mutex);
        table.new_free = i;
        table.free_cnt++;
        pthread_mutex_unlock(&table.table_mutex);
        table.auth_cnt--;


        return find;
    } else {

        return find;
    }






}





int  insert_auth_entry(uint8_t *mac)
{


    int i, find = 0;
	uint8_t mac_wrong[MAC_LEN] = {0};
	
	if(memcmp(mac, mac_wrong, 6) == 0)
	{
		cluster_log(LOG_ERR,"%s-%d mac is 00:00:00:00:00:00\n", __func__, __LINE__);
		return 3;
	}

//check auth table is full ?
    if(table.auth_cnt == AUTH_SIZE ) {
        printf("auth table is full!\n");
        return 2;
    }

//find it
    for(i = 0; i < table.entry_cnt; i++) {

        if(entry[i].on == 0)
            continue;

        if(memcmp(entry[i].mac, mac, 6) != 0)
            continue;
        else {
            find = 1;
            break;
        }

    }

    if(find != 0) {
        if(!entry[i].auth) {
            table.auth_cnt++;
            entry[i].auth = 1;
			return 0;
        }
			
        return find;
    }


    //add auth entry
    if(table.free_cnt == 0) {

        pthread_mutex_init(&entry[table.entry_cnt].entry_mutex, NULL);
        memcpy(entry[table.entry_cnt].mac, mac, 6);
		memcpy(entry[table.entry_cnt].prio.prio.mac_tail, &mac[3], 3);
        entry[table.entry_cnt].role = VC;
        entry[table.entry_cnt].state = JOIN;
        entry[table.entry_cnt].auth = 1;

        entry[table.entry_cnt].timer = 3;
        entry[table.entry_cnt].on = 1;
        table.entry_cnt++;
        table.auth_cnt++;

    } else if(table.free_cnt > 0) {
        entry[table.new_free].on = 1;
        pthread_mutex_init(&entry[table.new_free].entry_mutex, NULL);
        memcpy(entry[table.new_free].mac, mac, 6);
		memcpy(entry[table.new_free].prio.prio.mac_tail, &mac[3], 3);
        entry[table.new_free].timer = 3;
        entry[table.new_free].role = VC;
        entry[table.new_free].state = JOIN;
        entry[table.new_free].auth = 1;

        pthread_mutex_lock(&table.table_mutex);
        table.new_free = entry[table.new_free].pre_free;
        table.free_cnt--;
        pthread_mutex_unlock(&table.table_mutex);
        table.auth_cnt++;


    }

    return find;
}




int  insert_entry(RSRP_format *rsrp)
{

    int i, find = 0;
	uint8_t mac_wrong[MAC_LEN] = {0};
		
	if(memcmp(rsrp->mac, mac_wrong, 6) == 0)
	{
		cluster_log(LOG_ERR,"%s-%d mac is 00:00:00:00:00:00\n", __func__, __LINE__);
		return 3;
	}
			



	dump_mac(LOG_DEBUG,rsrp->mac);


    //check table is full ?
    if(table.entry_cnt == ENTRY_SIZE && table.free_cnt == 0) {
        cluster_log(LOG_WARNING,"table is full!\n");
        return  2;
    }

    //find it
    for(i = 0; i < table.entry_cnt; i++) {

        if(entry[i].on == 0)
            continue;

        if(memcmp(entry[i].mac, rsrp->mac, 6) != 0)
            continue;
        else {
            find = 1;
            break;
        }

    }

    if(find != 0) {
        //update ageing
        //lock
        pthread_mutex_lock(&entry[i].entry_mutex);
        entry[i].timer = 3; // lost 3 rsrp  packet;
        pthread_mutex_unlock(&entry[i].entry_mutex);
        //unlock
        // update info ?
        entry[i].cluster_id  = rsrp->head.clusterID;
        if(entry[i].state == LOST)
		{
			entry[i].state  =  rsrp->state;
			elect_svc();
		}
		cluster_log(LOG_DEBUG,"recv rsrp find it  state :%d\n",rsrp->state);	
		entry[i].state = rsrp->state;
        entry[i].prio.prio.product_type = rsrp->product_type;
        entry[i].prio.prio.priority = rsrp->priority;
        entry[i].prio.prio.config_seq = rsrp->config_sequence;
		entry[i].ip  = rsrp->ip; 
        memcpy(entry[i].prio.prio.mac_tail, &rsrp->mac[3], 3);
		//  txpower
		entry[i].radiocnt = rsrp->radiocnt;
		memcpy(entry[i].WTP_Radio,rsrp->WTP_Radio,sizeof(WTP_RADIO_H)*4);
		memcpy(entry[i].ap_name,rsrp->ap_name,32);	
		memcpy(entry[i].ap_version,rsrp->ap_version,16);

        return find;
    }



    //get lock

    if(table.free_cnt == 0) {

        pthread_mutex_init(&entry[table.entry_cnt].entry_mutex, NULL);
        memcpy(entry[table.entry_cnt].mac, rsrp->mac, 6);
        entry[table.entry_cnt].cluster_id  = rsrp->head.clusterID;
        entry[table.entry_cnt].prio.prio.product_type = rsrp->product_type;
        entry[table.entry_cnt].prio.prio.priority = rsrp->priority;
        entry[table.entry_cnt].prio.prio.config_seq = rsrp->config_sequence;
		entry[table.entry_cnt].ip  = rsrp->ip; 
        memcpy(entry[table.entry_cnt].prio.prio.mac_tail, &rsrp->mac[3], 3);
		//txpower
		entry[table.entry_cnt].radiocnt = rsrp->radiocnt;
		memcpy(entry[table.entry_cnt].WTP_Radio,rsrp->WTP_Radio,sizeof(WTP_RADIO_H)*4);
	
		memcpy(entry[table.entry_cnt].ap_name,rsrp->ap_name,32);	
		memcpy(entry[table.entry_cnt].ap_version,rsrp->ap_version,16);



        entry[table.entry_cnt].role = VC;
        entry[table.entry_cnt].state = rsrp->state;
        //entry[table.entry_cnt].auth = 1;
		cluster_log(LOG_DEBUG,"1 recv rsrp  not find  state :%d\n",rsrp->state);
        entry[table.entry_cnt].timer = 3;
        entry[table.entry_cnt].on = 1;
        table.entry_cnt++;
    } else if(table.free_cnt > 0) {
        entry[table.new_free].on = 1;
        pthread_mutex_init(&entry[table.new_free].entry_mutex, NULL);
        memcpy(entry[table.new_free].mac, rsrp->mac, 6);
        entry[table.new_free].cluster_id  = rsrp->head.clusterID;
        entry[table.new_free].prio.prio.product_type = rsrp->product_type;
        entry[table.new_free].prio.prio.priority = rsrp->priority;
        entry[table.new_free].prio.prio.config_seq = rsrp->config_sequence;
		entry[table.new_free].ip  = rsrp->ip; 
        memcpy(entry[table.new_free].prio.prio.mac_tail, &rsrp->mac[3], 3);
		//txpower 
		entry[table.new_free].radiocnt = rsrp->radiocnt;
		memcpy(entry[table.new_free].WTP_Radio,rsrp->WTP_Radio,sizeof(WTP_RADIO_H)*4);
		
		memcpy(entry[table.new_free].ap_name,rsrp->ap_name,32);	
		memcpy(entry[table.new_free].ap_version,rsrp->ap_version,16);


        entry[table.new_free].timer = 3;
        entry[table.new_free].role = VC;
        entry[table.new_free].state = rsrp->state;
        //entry[table.new_free].auth = 1;
		cluster_log(LOG_DEBUG,"2 recv rsrp  not find  state:%d\n",rsrp->state);
        pthread_mutex_lock(&table.table_mutex);
        table.new_free = entry[table.new_free].pre_free;
        table.free_cnt--;
        pthread_mutex_unlock(&table.table_mutex);


    }



    //unlock

    return find;



}

// blacklist  
int  search_blacklist_entry(uint8_t *mac)

{
	int i,find=0;
	
    for(i = 0; i < ENTRY_SIZE  ; i++) {
	
	    if(blacklist_entry[i].on == 0)
	        continue;

	    if(memcmp(blacklist_entry[i].mac, mac, 6) != 0)
	        continue;
	    else {
	        find = 1;
	        return i+1;
	    }
	}
	
	return  find;
}


int  insert_blacklist_entry(uint8_t *mac)

{
	int i, find=0;
	
    find=search_blacklist_entry(mac);
	
	if(!find)
	{
		for(i = 0; i < ENTRY_SIZE ; i++) 
		{
        	if(blacklist_entry[i].on == 0)
        	{
			   memcpy(blacklist_entry[i].mac, mac, 6);
			   blacklist_entry[i].on =1;
			   return i+1;
			}
            	
		}
		  
		return find;	
    }
	else
	{
		return find;
	}
		
}

int  delete_blacklist_entry(uint8_t *mac)

{

    int find = 0;

    find=search_blacklist_entry(mac);

    if(find != 0) {
        blacklist_entry[find-1].on = 0; 
        return find;
    } else {
        return find;
    }
}






void config_pvc_vipaddr(uint32_t ip,char *netmask)
{


    char cmd[256] = {0};
	uint8_t addr_p[20]={0};
	struct in_addr addr_n;

	g_vipaddr = ip;
	g_vip_netmask = inet_addr(netmask);
	addr_n.s_addr =ip;
	inet_ntop(AF_INET,&addr_n,(void *)&addr_p,16);
    cluster_log(LOG_DEBUG,"ip :%s\n",addr_p);
    sprintf(cmd, "ifconfig br-wan:0 %s netmask %s  up", addr_p,netmask);
    cluster_log(LOG_DEBUG,"cmd :%s\n", cmd);
    system(cmd);

}

int elect_svc(void)
{
    int i, j = 0;
    uint64_t prio = 0;
	uint8_t addr_p[20] = {0};
	struct in_addr addr_n;
	

    //pvc ?

    //find it
    for(i = 1; i < table.entry_cnt; i++) {

        if(entry[i].on != 1 || entry[i].auth != 1 || entry[i].state == LOST )
            continue;

        if(entry[i].prio.ap_priority > prio) {
            prio = entry[i].prio.ap_priority;
            j = i;
		}
            entry[i].role = VC;
         
        

    }

	svc_num=j;

	if(j != 0)
	{
		entry[j].role = SVC;
		addr_n.s_addr = entry[j].ip;
		inet_ntop(AF_INET,&addr_n,(void *)&addr_p,16);
		cluster_log(LOG_NOTICE,"elect svc  :%d:%s\n", j,addr_p);
		dump_mac(LOG_NOTICE,entry[j].mac);
		send_rscp();
	}

    return j;

}







int  get_pvc_info(void)
{


    return 0;
}


int get_svc_info(void)
{


    return 0;
}

int get_cluster_member(void)
{


    return 0;
}



int get_cluster_covering(void)
{

    return 0;

}



int  local_sock_interface(void)
{


    int  ret;
    int sock_send, sock_recv;
    struct sockaddr_un srv_addr, client_addr;
    char *buf=NULL;
    int buf_len=0;
    int socklen = sizeof(struct sockaddr_un);

    //local process
    if((sock_send = (socket(AF_UNIX, SOCK_DGRAM, 0))) < 0)
    {
        cluster_log(LOG_ERR,"create rscp send socket failed\n");
        return  -1;
    }


    bzero(&srv_addr, sizeof(srv_addr));

    srv_addr.sun_family = AF_UNIX;
    strcpy(srv_addr.sun_path, SOCKET_PATH);


    sendto(sock_send, buf, buf_len, 0, (struct sockaddr*)&srv_addr, sizeof(struct sockaddr_un));


    //recv:
    //bind ....
    //create socket
    sock_recv = socket(AF_UNIX, SOCK_DGRAM, 0);
    if(sock_recv < 0)
    {
        cluster_log(LOG_ERR,"create socket error\n");
        return -1;
    }
    client_addr.sun_family = AF_UNIX;
    strncpy(client_addr.sun_path, SOCKET_PATH, sizeof(client_addr.sun_path) - 1);
    unlink(SOCKET_PATH);

    //bind socket
    if((ret = bind(sock_recv, (struct sockaddr *)&client_addr, sizeof(client_addr))) < 0)
    {
        cluster_log(LOG_ERR,"cannot bind server socke\n");
        close(sock_recv);
        unlink(SOCKET_PATH);
        return -1;
    }
    recvfrom(sock_recv, buf, buf_len, 0, (struct sockaddr*)&srv_addr, (void *)&socklen);

	
	return 0;


}


int the_same_cluster_id(uint32_t cluster_id)
{
	if (cluster_id != self_ap.cluster_id)
	{
		cluster_log(LOG_DEBUG,"recv cluster id:%d,self cluster id:%d\n",cluster_id,self_ap.cluster_id);
		return 0;
	}
	
	return 1;
}

void *create_check_vc_thread(void)
{
		cluster_log(LOG_DEBUG,"into check vc thread\n");

		while(1)
		{
			if(flags == 1)
			{
				return NULL;

			}

			sleep(2);
		}
}



int  send_ricp(uint8_t op, uint8_t *mac)
{

    int  sock_send;
    u_int8_t buffer[1048];
    struct sockaddr_in recv_addr;
    //char  *send_buf;
    //int send_len;
    RICP_format  ricp;
    int val;
    int so_broadcast = 1;



    if((sock_send = (socket(AF_INET, SOCK_DGRAM, 0))) < 0)
    {
        cluster_log(LOG_ERR,"create ricp send socket failed\n");
        return  -1;
    }

    //send_buf=(uint8_t *)malloc(RSCP_LEN);
    setsockopt(sock_send, SOL_SOCKET, SO_BROADCAST, &so_broadcast, sizeof(so_broadcast));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_addr.s_addr = get_ipaddr();//pvc_brast;
    recv_addr.sin_port = htons(CLUSTER_PORT_SYNC);


    /* init  rscp proto node  */
	memset(&ricp,0,sizeof(RICP_format));
    ricp.head.clusterID = self_ap.cluster_id;
    ricp.head.protocolType =  RICP;
	
	/* count */
	ricp.op = op;  // 1:add 2:del 3:vip
    ricp.count = 1;//table.entry_cnt - table.free_cnt;
	ricp.vip = g_vipaddr;
	ricp.vip_netmask = g_vip_netmask;
	memcpy(ricp.mac[0],mac,6);
#if 0	
    int j = 0;
    for(i = 0; i < table.entry_cnt; i++)
    {
        if(entry[i].on == 0 ||  entry[i].auth == 0)
            continue;
        memcpy(ricp.mac[j], entry[i].mac, 6);
		dump_mac(LOG_DEBUG,ricp.mac[j]);
        j++;

    }
#endif 

    Assemble_RICP((void *)&buffer, &ricp);

    val = sendto(sock_send, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_addr, sizeof(recv_addr));
	cluster_log(LOG_DEBUG,"send ricp:%d ,errno:%d\n",val,errno);

    close(sock_send);

    return val;


}



// svc sync  and  vc config sync
void *create_config_sync_thread(void)
{
    int sock_recv;
    int  bytes, ret;
    int addr_len;
    struct sockaddr_in send_addr;
	struct in_addr addr_n;
	uint8_t addr_p[20]={0};
    fd_set rd;
    Hccp_Protocol_Struct packet;
	int so_reuse =1;
    char buff[5120];
	char cmd[256]={0};
	uint8_t *mac;
	
	//unsigned char j = 0, k = 0;
    //buff = (char *)malloc(2048 * sizeof(char));
    memset(buff, 0, 5120);

    cluster_log(LOG_DEBUG,"config sync  thread \n");
    if((sock_recv = (socket(AF_INET, SOCK_DGRAM, 0))) < 0) {
        cluster_log(LOG_ERR,"create rsrp recv socket failed\n");
        return  NULL;
    }


    send_addr.sin_family = AF_INET;
    send_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    send_addr.sin_port = htons(CLUSTER_PORT_SYNC);
	setsockopt(sock_recv, SOL_SOCKET, SO_REUSEADDR, &so_reuse, sizeof(so_reuse));
	//setsockopt(sock_recv, SOL_SOCKET, SO_REUSEPORT, &so_reuse, sizeof(so_reuse));

   	ret= bind(sock_recv, (struct sockaddr*)&send_addr, sizeof(send_addr));
	if(ret <0)
	{
		cluster_log(LOG_ERR,"create config sync  failed!\n");
		exit(1);

	}
	
    addr_len = sizeof(struct sockaddr_in);


    FD_ZERO(&rd);
    FD_SET(sock_recv, &rd);


    while(1) {

		FD_ZERO(&rd);
		FD_SET(sock_recv, &rd);
		
        ret = select(sock_recv + 1, &rd, NULL, NULL, NULL);
        if(ret > 0)

        {
            if(FD_ISSET(sock_recv, &rd)) {

                bytes = recvfrom(sock_recv, buff, 5120, 0, (struct sockaddr *) &send_addr, (void *)&addr_len);

                Parse_HCCPProtocol(buff, &packet);
                int type = packet.type;

			
				if(!the_same_cluster_id(packet.u.ricp.head.clusterID))
                        continue;

				cluster_log(LOG_DEBUG,"recv  config sync  packet type:%d\n", type);
				
                if(type == RISP) {  // svc


                    // config sync ?  write /etc/config/cluster
                    acs_seqnum =packet.u.risp.ACS_sequence ;
					cluster_log(LOG_DEBUG,"risp recv  acs_seqnum:%d\n",acs_seqnum);
					
					memset(&risp_pkt_recv, 0, sizeof(risp_pkt_recv));
					risp_pkt_recv = packet.u.risp;
			
	
				
					


                } else if(type == RICP)
                {

					
						//sync 
						cluster_log(LOG_DEBUG,"recv  ricp  op:%d\n",packet.u.ricp.op);
						mac=packet.u.ricp.mac[0];
						dump_mac(LOG_DEBUG,packet.u.ricp.mac[0]);

						switch (packet.u.ricp.op)
						{

							case AUTH:
								sprintf(cmd, "%s add_list cluster.cluster.cluster_member='%02x:%02x:%02x:%02x:%02x:%02x' ",CLUSTER_CMD, mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
								system(cmd);
							
							break;
							case DEL:
								sprintf(cmd, "%s del_list cluster.cluster.cluster_member='%02x:%02x:%02x:%02x:%02x:%02x' ",CLUSTER_CMD, mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
								system(cmd);

								break;
							case UCI_DEL:
								sprintf(cmd, "uci-c %s del_list cluster.cluster.cluster_member='%02x:%02x:%02x:%02x:%02x:%02x' ", CLUSTER_CONFIG_PATH,mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
								system(cmd);
								sprintf(cmd, "uci -c %s commit cluster ",CLUSTER_CONFIG_PATH);
								system(cmd);
								break;
							case VIP:
								addr_n.s_addr = packet.u.ricp.vip;
								inet_ntop(AF_INET,&addr_n,(void *)&addr_p,16);
								sprintf(cmd, "%s set cluster.cluster.cluster_vip='%s' ",CLUSTER_CMD,addr_p );
								system(cmd);

								addr_n.s_addr = packet.u.ricp.vip_netmask;
								inet_ntop(AF_INET,&addr_n,(void *)&addr_p,16);
								sprintf(cmd, "%s set cluster.cluster.cluster_netmask='%s' ",CLUSTER_CMD,addr_p );
								system(cmd);

								break;
						}
						
                }

            }
        }
    }

   
    close(sock_recv);
}





void *create_check_pvc_thread(void)
{
    int fd, n, ret;
    char buf[16];
    fd_set rd;
    unlink(CLUSTER_FIFO);
	if(!access(CLUSTER_FIFO,F_OK))
	{
		cluster_log(LOG_ERR,"cluster  fifo  existed!\n");
		system("rm -f /tmp/cluster_fifo ");
		
	}

    if((mkfifo(CLUSTER_FIFO, 0666) < 0) && (errno != EEXIST))
        cluster_log(LOG_ERR,"make fifo fail\n");

    if((fd = open(CLUSTER_FIFO, O_RDWR)) < 0)
        cluster_log(LOG_ERR,"open fifo  fail\n");


    memset(buf, 0, 16);
    FD_ZERO(&rd);
    FD_SET(fd, &rd);


    while(1) {

		FD_ZERO(&rd);
		FD_SET(fd, &rd);

        ret = select(fd + 1, &rd, NULL, NULL, NULL);
        if(ret > 0) {

            if (FD_ISSET(fd, &rd)) {
                n = read(fd, buf, 5);
                if(n > 0) {

                    if(memcmp(buf, "pvc", 3) != 0)
					{
						if(flags == 1  &&  pvc_switch == 1)
						{
							flags = 0;
							// over pvc thread 
							ret=pthread_cancel(thread_rsrp_recv);
							cluster_log(LOG_WARNING,"cancel  pvc rsrp recv:%d\n",ret);
							ret=pthread_cancel(thread_rscp_send);
							cluster_log(LOG_WARNING,"cancel  pvc rscp send:%d\n",ret);
							ret=pthread_cancel(thread_risp_send);
							cluster_log(LOG_WARNING,"cancel  pvc  risp send:%d\n",ret);
							ret=pthread_cancel(thread_ageing);
							cluster_log(LOG_WARNING,"cancel pvc  ageing:%d\n",ret);
							ret=pthread_cancel(thread_acs);
							cluster_log(LOG_WARNING,"cancel pvc acs :%d\n",ret);
						}
					}
                    else
					{
						if(flags == 0 &&  pvc_switch == 0)
						{
							flags = 1;
							//  over  vc thread 
							ret=pthread_cancel(thread_check_vc);
							cluster_log(LOG_WARNING,"cancel  vc thread %d\n",ret);
						}

					}

                    cluster_log(LOG_WARNING,"cluster cor changle work state:%d\n", flags);

                }
            }
        }
    }

    close(fd);

}


/*********************************
 *
 *  show members of vc table interfaces
 *
 *
 *
 *
 *
 ***********************************/

void  show_members_auth(void)
{



}


void show_members_all(void)
{

    int  n;
    // pipe  or  af_local ?
    int fd_s;
    //char *buf;
	
	cluster_log(LOG_DEBUG,"cli: show open\n");
    if((fd_s = open(CMD_FIFO_SEND, O_WRONLY)) < 0)
	{
		cluster_log(LOG_ERR,"open fifo  fail\n");
		return ;
	}

	cluster_log(LOG_DEBUG,"cli: show open ok\n");
	if(flags==0)
		memset(entry,0,ENTRY_ALL_SIZE);
		
    n = write(fd_s, entry, ENTRY_ALL_SIZE);

    if(n > 0)
        cluster_log(LOG_DEBUG,"show  ok!\n");
    else
        cluster_log(LOG_DEBUG,"show failed!\n");

    close(fd_s);

}




void *create_show_members_thread(void)
{

    int ret;
    int n, fd_r;
    //char buf[10];
    //signal ?  msg

    cluster_log(LOG_DEBUG,"init  show interface \n");
    unlink(CMD_FIFO_RECV);
	if(!access(CMD_FIFO_RECV,F_OK))
	{
		cluster_log(LOG_ERR,"cmd fifo recv  existed!\n");
		system("rm -f /tmp/cmd_fifo_recv ");
		
	}

    if((mkfifo(CMD_FIFO_RECV, 0666) < 0) && (errno != EEXIST))
        cluster_log(LOG_ERR,"make fifo fail\n");

    unlink(CMD_FIFO_SEND);
	if(!access(CMD_FIFO_SEND,F_OK))
	{
		cluster_log(LOG_ERR,"cmd fifo send  existed!\n");
		system("rm -f /tmp/cmd_fifo_send ");
		
	}
	

    if((mkfifo(CMD_FIFO_SEND, 0666) < 0) && (errno != EEXIST))
        cluster_log(LOG_ERR,"make fifo fail\n");

    if((fd_r = open(CMD_FIFO_RECV, O_RDWR)) < 0)
        cluster_log(LOG_ERR,"open fifo  fail\n");

    fd_set  rd;
    FD_ZERO(&rd);
    FD_SET(fd_r, &rd);

    while(1)
    {

		FD_ZERO(&rd);
		FD_SET(fd_r, &rd);

        ret = select(fd_r + 1, &rd, NULL, NULL, NULL);
        if(ret > 0)
        {
            if (FD_ISSET(fd_r, &rd))
            {
                n = read(fd_r, (void *)&cmd, sizeof(struct cmd_head));
                if(n > 0)
                {
                    cluster_log(LOG_DEBUG,"cmd:%d  read :%d\n",cmd.type,n);
					if(flags==0 &&  cmd.type !=SHOW)
						continue;

                    switch(cmd.type)
                    {
                    case SHOW:
                        show_members_all();
                        break;
                    case AUTH:
						cluster_log(LOG_NOTICE,"auth entry !\n");
						dump_mac(LOG_NOTICE,cmd.mac);
                        //cmd_back();
                        if(!insert_auth_entry(cmd.mac))
						{
							delete_blacklist_entry(cmd.mac);
							send_ricp(DEL,cmd.mac);
							elect_svc();
						}
                        break;
                    case UNAUTH:
						cluster_log(LOG_NOTICE,"unauth entry !\n");
						dump_mac(LOG_NOTICE,cmd.mac);
                        if(unauth_entry(cmd.mac))
						{
							insert_blacklist_entry(cmd.mac);
							send_ricp(AUTH,cmd.mac);
							elect_svc();
						}
                        break;
                    case DEL:
						cluster_log(LOG_NOTICE,"del entry !\n");
						dump_mac(LOG_NOTICE,cmd.mac);
                        if(delete_auth_entry(cmd.mac))
						{
							//send_ricp(AUTH,cmd.mac);
							cluster_log(LOG_NOTICE,"del entry ok!\n");
							elect_svc();
						}
						break;
                    case VIP:
                        config_pvc_vipaddr(cmd.ip,cmd.netmask);
						send_ricp(VIP,self_ap.mac);
                        break;
					case SET_TIME:
						 ageing_time=cmd.ip;
						 cluster_log(LOG_DEBUG,"set new ageing  time:%d\n",ageing_time);
						 break;
                    default:
                        show_members_all();
                        break;
                    }

                }

            }
        }

    }

}

void update_RF_environment(Hccp_Protocol_Struct *packet)
{
	unsigned char i = 0, j = 0, k = 0, find_result = 0;
	
	for(i = 0; i < table.entry_cnt; i++) 
	{
		if(entry[i].on == 0 || entry[i].auth == 0)
            continue;
		
        if(memcmp(entry[i].mac, packet->u.rirp.mac, 6) != 0)
        {
            continue;
		}
        else 
		{
            find_result = 1;
            break;
        }
    }

	if(find_result == 1)
	{
		entry[i].neighbor_cnt = packet->u.rirp.neighbor_count;
		
		for(j=0;j<entry[i].neighbor_cnt;j++)
		{
			memcpy(entry[i].rssi_of_others[j].ap_base_mac, packet->u.rirp.cluster_neighbor[j].mac, MAC_LEN);
			entry[i].rssi_of_others[j].radiocnt = packet->u.rirp.cluster_neighbor[j].radiocnt;

			for(k=0;k<entry[i].rssi_of_others[j].radiocnt;k++)
			{
				entry[i].rssi_of_others[j].ap_radio[k].radioid = packet->u.rirp.cluster_neighbor[j].WTP_Radio[k].radioid;
				entry[i].rssi_of_others[j].ap_radio[k].channel = packet->u.rirp.cluster_neighbor[j].WTP_Radio[k].channel;
				entry[i].rssi_of_others[j].ap_radio[k].txpower = packet->u.rirp.cluster_neighbor[j].WTP_Radio[k].txpower;
				entry[i].rssi_of_others[j].ap_radio[k].rssi = packet->u.rirp.cluster_neighbor[j].WTP_Radio[k].rssi;
			}			
		}		
	}
	else
	{

	}
}

int under_67_version(char *str)
{
	int ret = 0;
	char software_version = 0;
	char *p = NULL, *q = NULL ;
	char buf_version[VERSION_MAX_LEN] = "2.1.0.67";

	q = str;
	p = str;
	software_version = *p - '0';
	
	cluster_log(LOG_DEBUG,"%s-%d software_version:%d\n", __func__, __LINE__, software_version);

	if(software_version == 2)
	{

	}
	else
	{
		cluster_log(LOG_DEBUG,"%s-%d version:%s is not R21\n", __func__, __LINE__, str);
		return 2;
	}
	
	ret = strncmp(str, buf_version, 5);
	
	cluster_log(LOG_DEBUG,"%s-%d version:%s  str:%s  ret:%d\n", __func__, __LINE__, self_ap.ap_version, str, ret);


	if(ret == 0)
	{
		q += 6;
		ret = atoi(q) - 67;

		cluster_log(LOG_DEBUG,"%s-%d ret:%d\n", __func__, __LINE__, ret);

		if(ret > 0)
		{
			return 0;
		}
		else
		{
			return 1;
		}
	}
	else if(ret > 0)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}



//pvc  update member info  recv  rsrp from vc
void *create_rsrp_recv_thread(void)
{
    
    int bytes, ret, ret_ver;
  //  int fromlen;
    int addr_len;
//	int  i;
    struct sockaddr_in send_addr;
    fd_set rd;
    struct timeval tv;
    Hccp_Protocol_Struct packet;
	
    char buff[1048];
    //buff = (char *)malloc(2048 * sizeof(char));
    memset(buff, 0, 1048);

    cluster_log(LOG_DEBUG,"pvc:  update  member info   from  vc  rsrp\n");


    addr_len = sizeof(struct sockaddr_in);


    FD_ZERO(&rd);
    FD_SET(sock_recv_rsrp, &rd);
    tv.tv_sec = 30;
    tv.tv_usec =  0;

    while(1)
    {

        if(flags == 0)
        {
            //   free(buff);
            //close(sock_recv_rsrp);
            return  NULL;
        }

		memset(buff, 0, 1048);
		memset(&packet, 0, sizeof(Hccp_Protocol_Struct));
		
		FD_ZERO(&rd);
		FD_SET(sock_recv_rsrp, &rd);
        ret = select(sock_recv_rsrp + 1, &rd, NULL, NULL, NULL);
        if(ret > 0)

        {
            if(FD_ISSET(sock_recv_rsrp, &rd))
            {
                bytes = recvfrom(sock_recv_rsrp, buff, 1048, 0, (struct sockaddr *) &send_addr, (void *)&addr_len);

                Parse_HCCPProtocol(buff, &packet);
                int type = packet.type;

                if(!the_same_cluster_id(packet.u.rsrp.head.clusterID))
                    continue;

                cluster_log(LOG_DEBUG,"recv rsrp alive packet type:%d\n", type);

                if(type == RSRP)
                {
					cluster_log(LOG_DEBUG,"recv rsrp ip:%s\n",inet_ntoa(send_addr.sin_addr));
					ret = search_blacklist_entry(packet.u.rsrp.mac);
					if(!ret)
					{
						ret_ver = under_67_version(packet.u.rsrp.ap_version);
						if(ret_ver == 1)
						{
							cluster_log(LOG_ERR,"_GOLSOH_%s with incompatible software is trying to join the group, please upgrade it!\n", packet.u.rsrp.ap_name);
							unauth_entry(packet.u.rsrp.mac);
						}
						else if(ret_ver == 2)
						{
							cluster_log(LOG_ERR,"%s is not R21 version!\n", packet.u.rsrp.ap_name);
							unauth_entry(packet.u.rsrp.mac);
						}
						else
						{						
							
							if(!insert_auth_entry(packet.u.rsrp.mac))  
							{
								cluster_log(LOG_NOTICE,"first auth entry !\n");
								dump_mac(LOG_NOTICE,packet.u.rsrp.mac);
								elect_svc();
							}
						}
                    	ret = insert_entry(&packet.u.rsrp);
				
					}
					else
					{
						ret = insert_entry(&packet.u.rsrp);  // join ?
					}
					
                }
                else if(type == RIRP)     
                {

                    // RIRP
                    cluster_log(LOG_DEBUG,"recv rirp ------\n");
					update_RF_environment(&packet);
					
                }
                else
                {
                    continue;
                }
            }
        }

    }


   // close(sock_recv_rsrp);
	
}


int  send_rscp(void)
{

    int i,sock_send;
    u_int8_t buffer[1048];
    struct sockaddr_in recv_addr;
	//char  *send_buf;
    //int send_len;
    RSCP_format  rscp;
    int val;
    int so_broadcast = 1;

	memset(&rscp,0,sizeof(RSCP_format));

    if((sock_send = (socket(AF_INET, SOCK_DGRAM, 0))) < 0)
    {
        cluster_log(LOG_ERR,"create rscp send socket failed\n");
        return -1;
    }

	
    //send_buf=(uint8_t *)malloc(RSCP_LEN);
    setsockopt(sock_send, SOL_SOCKET, SO_BROADCAST, &so_broadcast, sizeof(so_broadcast));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_addr.s_addr = get_ipaddr();//pvc_brast;//inet_addr("192.168.100.255");//htonl(INADDR_ANY);  //
    recv_addr.sin_port = htons(CLUSTER_PORT_SEND);


    /* init  rscp proto node  */
    rscp.head.clusterID = self_ap.cluster_id;
    rscp.head.protocolType =  RSCP;
    rscp.priority = self_ap.prio.prio.priority;
    rscp.config_sequence = self_ap.prio.prio.config_seq =Get_Config_Version();
    rscp.product_type = self_ap.prio.prio.product_type;
    memcpy(rscp.mac, self_ap.mac, 6);


    /* count */
    rscp.count = table.auth_cnt;

    int j = 0;
    for(i = 0; i < table.entry_cnt; i++)
    {
        if(entry[i].on == 0 ||  entry[i].auth == 0)
            continue;

        rscp.cluster_member[j].role = entry[i].role;
        rscp.cluster_member[j].state = entry[i].state;
		rscp.cluster_member[j].ip = entry[i].ip;
        memcpy(rscp.cluster_member[j].mac, entry[i].mac, 6);

		rscp.cluster_member[j].radiocnt =  entry[i].radiocnt;
		memcpy(rscp.cluster_member[j].WTP_Radio,entry[i].WTP_Radio,sizeof(WTP_RADIO_H)*4);
		
        j++;

    }

    Assemble_RSCP((void *)&buffer, &rscp);
   

    val = sendto(sock_send, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&recv_addr, sizeof(recv_addr));
	cluster_log(LOG_DEBUG,"send rscp:%d ,errno:%d\n",val,errno);

    close(sock_send);

    return val;


}



//keep pvc alive
void *create_rscp_send_thread(void)
{

    int i, sock_send;
    u_int8_t buffer[1048];
    struct sockaddr_in recv_addr;
   // char  *send_buf;
   // int send_len;
    RSCP_format  rscp;
    int val;
    int so_broadcast = 1;
	
	memset(&rscp,0,sizeof(RSCP_format));
	cluster_log(LOG_DEBUG,"pvc: send rscp  alive packet\n");
   

    while(1)
    {


        if(flags == 0)
        {
            return NULL;
        }

		 send_rscp();
		 sleep(8);

		 if((sock_send = (socket(AF_INET, SOCK_DGRAM, 0))) < 0)
	    {
	        cluster_log(LOG_ERR,"create rscp send socket failed\n");
	        continue;
	    }

		setsockopt(sock_send, SOL_SOCKET, SO_BROADCAST, &so_broadcast, sizeof(so_broadcast));
		recv_addr.sin_family = AF_INET;
		recv_addr.sin_addr.s_addr = pvc_brast; //inet_addr("192.168.100.255");//htonl(INADDR_ANY);  //
		recv_addr.sin_port = htons(CLUSTER_PORT_SEND);
        recv_addr.sin_addr.s_addr = get_ipaddr();
		
        /* init  rscp proto node  */
        rscp.head.clusterID = self_ap.cluster_id;
        rscp.head.protocolType = RSCP;
        rscp.priority = self_ap.prio.prio.priority;
        rscp.config_sequence = self_ap.prio.prio.config_seq =Get_Config_Version();
        rscp.product_type = self_ap.prio.prio.product_type;
        memcpy(rscp.mac, self_ap.mac, 6);


        /* count */
        rscp.count = table.auth_cnt;

        int j = 0;
        for(i = 0; i < table.entry_cnt; i++)
        {
            if(entry[i].on == 0 ||  entry[i].auth == 0)
                continue;
            // auth
            rscp.cluster_member[j].role = entry[i].role;
            rscp.cluster_member[j].state = entry[i].state;
			rscp.cluster_member[j].ip = entry[i].ip;
            memcpy(rscp.cluster_member[j].mac, entry[i].mac, 6);

			//  update  txpower  info
			rscp.cluster_member[j].radiocnt =  entry[i].radiocnt;
		    memcpy(rscp.cluster_member[j].WTP_Radio,entry[i].WTP_Radio,sizeof(WTP_RADIO_H)*4);
			/*
					int count =  entry[i].radiocnt;
					for(i=0;i< count ; i++)
					{
							printf("rscp send radio:  %d(channel),%d(rid),%d(txpower)-------------\n",rscp.cluster_member[j].WTP_Radio[i].channel,rscp.cluster_member[j].WTP_Radio[i].radioid,rscp.cluster_member[j].WTP_Radio[i].txpower);

            		}

            */
            j++;

        }

        Assemble_RSCP((void *)&buffer, &rscp);
  		cluster_log(LOG_DEBUG,"pvc: rscp send socket assemble ok\n");
        val = sendto(sock_send, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&recv_addr, sizeof(recv_addr));
		cluster_log(LOG_DEBUG,"send rscp:%d ,errno:%d\n",val,errno);	
		close(sock_send);

    }

    close(sock_send);

}


int send_risp(void)
{
	unsigned char j = 0, k = 0, l = 0, m = 0, count = 0;
    int  sock_send,ret;
    struct sockaddr_in recv_addr;
    uint8_t send_buf[5120]={0};
    //int send_len;
	RISP_format  risp;

		memset(&risp,0,sizeof(RISP_format));
		memset(send_buf, 0, 5120);

	    if((sock_send = (socket(AF_INET, SOCK_DGRAM, 0))) < 0)
	    {
	        cluster_log(LOG_ERR,"create risp send socket failed\n");
	        return  NULL;
	    }


	    recv_addr.sin_family = AF_INET;
	    recv_addr.sin_addr.s_addr = get_svc_ipaddr();
	    recv_addr.sin_port = htons(CLUSTER_PORT_SYNC);

		risp.ACS_sequence = acs_seqnum;
		risp.head.clusterID = self_ap.cluster_id;
		
		count = 0;
		for(j=0;j<table.entry_cnt;j++)
		{
			if(entry[j].on == 0 || entry[j].auth == 0)
				continue;
			if(count > 15)
			{
				break;	
			}
			memcpy(risp.WTP_RF[count].ap_base_mac, entry[j].mac, MAC_LEN);
			risp.WTP_RF[count].ipaddr = entry[j].ip;
			risp.WTP_RF[count].neighbor_cnt = entry[j].neighbor_cnt;
			risp.WTP_RF[count].priority = (unsigned int)entry[j].prio.prio.priority;
			risp.WTP_RF[count].radiocnt = entry[j].radiocnt;
			risp.WTP_RF[count].role = entry[j].role;

			for(l=0;l<risp.WTP_RF[count].radiocnt;l++)
			{
				risp.WTP_RF[count].WTP_Radio[l].radioid = entry[j].WTP_Radio[l].radioid;
				risp.WTP_RF[count].WTP_Radio[l].channel = entry[j].WTP_Radio[l].channel;
				risp.WTP_RF[count].WTP_Radio[l].txpower = entry[j].WTP_Radio[l].txpower;
			}
			
			for(k=0;k<risp.WTP_RF[count].neighbor_cnt;k++)
			{
				memcpy(risp.WTP_RF[count].rssi_of_others[k].ap_base_mac, entry[j].rssi_of_others[k].ap_base_mac, MAC_LEN);
				risp.WTP_RF[count].rssi_of_others[k].radiocnt = entry[j].rssi_of_others[k].radiocnt;
				
				for(m=0;m<risp.WTP_RF[count].rssi_of_others[k].radiocnt;m++)
				{
					risp.WTP_RF[count].rssi_of_others[k].ap_radio[m].radioid = entry[j].rssi_of_others[k].ap_radio[m].radioid;
					risp.WTP_RF[count].rssi_of_others[k].ap_radio[m].channel = entry[j].rssi_of_others[k].ap_radio[m].channel;
					risp.WTP_RF[count].rssi_of_others[k].ap_radio[m].rssi = entry[j].rssi_of_others[k].ap_radio[m].rssi;
					risp.WTP_RF[count].rssi_of_others[k].ap_radio[m].txpower = entry[j].rssi_of_others[k].ap_radio[m].txpower;
				}
			}
			count++;			
		}
		
		risp.Mem_num = count;
		
        //assembe packet  risp
		Assemble_RISP((void *)&send_buf, &risp);
		
       ret= sendto(sock_send, send_buf, sizeof(send_buf), MSG_DONTWAIT, (struct sockaddr *)&recv_addr, sizeof(recv_addr));

		cluster_log(LOG_DEBUG,"pvc send risp :%d,errno:%d\n",ret,errno);
		close(sock_send);
		
		return ret;


}



// sysn  pvc info to svc
void *create_risp_send_thread(void)
{


    cluster_log(LOG_DEBUG,"pvc: send risp  sync packet\n");

    while(1)
    {


        if(flags == 0)
            return NULL;

		send_risp();
        sleep(60);
    }

   

}

void *create_cluster_ageing_thread(void)
{

    int i, ret;
	uint8_t addr_p[20]={0};
	struct in_addr addr_n;

    cluster_log(LOG_DEBUG,"into  cluster ageing \n");

    while(1)
    {
    
        if(flags == 0)
            return NULL;

        //check  entry timer
        for(i = 1; i < table.entry_cnt; i++)
        {
            if(entry[i].on == 1)
            {
                if(entry[i].timer > 0)
                {
                    entry[i].timer--;
                }
                else
                {

					addr_n.s_addr = entry[i].ip;
					inet_ntop(AF_INET,&addr_n,(void *)&addr_p,16);
                    // vc is lost ,and not auth to delete it !
                    if(entry[i].auth != 1)
                    {

                        pthread_mutex_destroy(&entry[i].entry_mutex);
                        entry[i].on = 0; //delete it  and  mutex lock destroy
                        //table
                        entry[i].pre_free = table.new_free;
						cluster_log(LOG_WARNING,"pvc ageing timeout to del it :%s!\n",addr_p);
						dump_mac(LOG_WARNING,entry[i].mac);
                        pthread_mutex_lock(&table.table_mutex);
                        table.new_free = i;
                        table.free_cnt++;
                        pthread_mutex_unlock(&table.table_mutex);
                    }
                    else
                    {
                        cluster_log(LOG_DEBUG,"ap is  offline:%s \n",addr_p);
						dump_mac(LOG_DEBUG,entry[i].mac);
                        if(entry[i].role == SVC)
                        {
                            entry[i].state = LOST; //lost
                            entry[i].role = VC;
                            ret = elect_svc();
                        }
                        else
                        {
                            entry[i].state = LOST; //lost
                            entry[i].role = VC;
                        }
                    }
                }

            }
        }


        sleep(ageing_time*10);
    }

}




void *create_cluster_acs_thread(void)
{
    int bytes = 0, ret;
    int sock_recv;
    struct sockaddr_un srv_addr, client_addr;
    int socklen = sizeof(struct sockaddr_un);
    char buf[256] = {0};
    uint32_t val = 0;
    char cmd[256] = {0};
    uint8_t cnt = 0;

    fd_set rd;
    struct timeval tv;

	cluster_log(LOG_DEBUG,"into  acs thread\n");    

    sprintf(cmd, "/sbin/acs_mgt -d -s %d  & ", acs_seqnum);
    ret = system(cmd);
    
    bzero(&srv_addr, sizeof(srv_addr));

    sock_recv = socket(AF_UNIX, SOCK_DGRAM, 0);
    if(sock_recv < 0)
    {
        cluster_log(LOG_ERR,"create socket error\n");
        return NULL;
    }
    client_addr.sun_family = AF_UNIX;
    strncpy(client_addr.sun_path, SOCKET_PATH, sizeof(client_addr.sun_path) - 1);
    unlink(SOCKET_PATH);

    if((ret = bind(sock_recv, (struct sockaddr *)&client_addr, sizeof(client_addr))) < 0)
    {
        cluster_log(LOG_ERR,"cannot bind server socke\n");
        close(sock_recv);
        unlink(SOCKET_PATH);
        return NULL;
    }

    FD_ZERO(&rd);
    FD_SET(sock_recv, &rd);
    tv.tv_sec = 30;
    tv.tv_usec =  0;

	while(1)
	{
		tv.tv_sec = 10;
		FD_ZERO(&rd);
		FD_SET(sock_recv, &rd);

		
		if(flags == 0)
		{	
			system("killall  acs_mgt");
			close(sock_recv);
			return  NULL;
	    }

        ret = select(sock_recv + 1, &rd, NULL, NULL, &tv);
         if(ret > 0)
         {
            if(FD_ISSET(sock_recv, &rd)) 
			{
			    memset(buf,0,sizeof(buf));	
		 		bytes=recvfrom(sock_recv, buf, sizeof(buf), 0, (struct sockaddr*)&srv_addr, (void *)&socklen);

				memcpy(&val,buf,4);
				acs_seqnum= val;
				cnt=0;
                cluster_log(LOG_DEBUG,"acs_mgt:%d   acs_seqnum:%d   \n", bytes, acs_seqnum);
            }        
		 }
		 else if(ret==0)
		 {
			printf("acs_mgt alive timeout\n");
			if(cnt==3)
			{
				system("killall acs_mgt &");
				// start acs_mgt again 
				sprintf(cmd,"/sbin/acs_mgt -d -s %d  & ",acs_seqnum);
                cluster_log(LOG_DEBUG,"start  acs_mgt  again\n");
				ret=system(cmd);
				cnt=0;
			}
			cnt++;	 
		 }
	}
}



static void cluster_cor_get_options(int argc, char * argv[])
{
	int opt = 0;
	
	while ((opt = getopt(argc, argv, "hp:I:V:")) > 1)
	{
		switch (opt)
		{
			case 'p':
				
				memcpy(g_mac_str,optarg,strlen(optarg));
				

            cluster_log(LOG_DEBUG,"%s-%d opt p: %d,%s\n", __func__, __LINE__, g_priority,g_mac_str);
				break;
				
			case 'I':
				g_clusterId = atoi(optarg);
            cluster_log(LOG_DEBUG,"%s-%d opt i: %d\n",  __func__, __LINE__, g_clusterId);
				break;	

    		case 'V':
				g_vipaddr = inet_addr(optarg);
            cluster_log(LOG_DEBUG,"%s-%d opt v:%d:%s\n", __func__, __LINE__, g_vipaddr, optarg);
				break;
			default:
            cluster_log(LOG_DEBUG,"\nUsage: %s  [-I clusterID] [-p priority]\n");
				break;	
		}
	}
}


uint32_t  get_svc_ipaddr(void)
{
		return entry[svc_num].ip;
}


uint32_t  get_ipaddr(void )
{
    char if_name[16] = "br-wan";
    int fd;
    struct sockaddr_in  sin;
//	struct sockaddr_in  *net_mask;
    struct ifreq        ifr;
//	uint8_t addr_p[20]={0};
//	struct in_addr  addr_n;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        cluster_log(LOG_ERR,"socket error");
		return pvc_brast;
    }

    strncpy(ifr.ifr_name, if_name, 10);
#if 0	
	// get netmask
	 if (!(ioctl(fd, SIOCGIFNETMASK, &ifr)))
	 {
		   net_mask =(struct sockaddr_in *)&(ifr.ifr_netmask); 
		   printf("netmask:%s\n",inet_ntoa(net_mask->sin_addr));
	 
	 }
#endif 
	//get brast
	if (! (ioctl(fd, SIOCGIFBRDADDR, &ifr)))
	{	
		memcpy(&sin, &ifr.ifr_addr, sizeof(ifr.ifr_addr));
        //cluster_log(LOG_DEBUG,"brast:  %s\n", inet_ntop(AF_INET,&sin.sin_addr,addr_p,16));
		pvc_brast = sin.sin_addr.s_addr;
	}


	//get ip
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0)      //SIOCGIFADDR ??ии?interface address
    {
        memcpy(&sin, &ifr.ifr_addr, sizeof(ifr.ifr_addr));
       // cluster_log(LOG_DEBUG,"self ip:  %s\n", inet_ntop(AF_INET,&sin.sin_addr,addr_p,16));
		self_ap.ip = sin.sin_addr.s_addr;
		entry[0].ip =  self_ap.ip;

    }
    else
        cluster_log(LOG_WARNING,"get ip failed\n");

    close(fd);

	return pvc_brast;

}



int check_big()
{
    u_int16_t tmp = 1;
    u_int8_t *p;

    p = (u_int8_t *)&tmp;
    if(p[1] == 1)
        return 1;
    else
        return 0;




}

void parse_mac(u_int8_t *str,uint8_t  *g_mac)
{
    u_int16_t mac[6];
    u_int8_t  *p;
    int i = 0;

    if(check_big()) {

        sscanf((void *)str, "%2hx:%2hx:%2hx:%2hx:%2hx:%2hx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

        for(i = 0; i < 6; i++) {
            p = (u_int8_t *)&mac[i];
            memcpy(&g_mac[i], &p[1], 1);
        }

    } else {

        sscanf((void *)str, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &g_mac[0], &g_mac[1], &g_mac[2], &g_mac[3], &g_mac[4], &g_mac[5]);

    }


}


void get_mac()
{
    FILE *fp = NULL;
    char str[256];
    char *tmp = NULL;
    char *end = NULL;
    memset(str, 0, 256);

    sprintf(str, "showsysinfo  | grep MAC | awk -F':' '{print $2,$3,$4,$5,$6,$7 }'");
    fp = popen(str, "r");
    if(fp)
    {
        memset(str, 0, 256);
        fgets(str, sizeof(str), fp);

        tmp = strtok(str, " ");
        int i = 0;
        while(tmp)
        {
            self_ap.mac[i++] = strtol(tmp, &end, 16);
            printf("%02x\n", self_ap.mac[i - 1]);
            tmp = strtok(NULL, " ");
        }

        pclose(fp);
    }
    else
    {
        printf("get ap base mac error\n");
        exit(-1);
    }

    return;

}

unsigned char get_product_type_code()
{
	char temp_str[100] = {0};
	char str_tmp[64];
	unsigned char str[64];
	unsigned char product_type = 0, i = 0;
	
	memset(temp_str, 0, 100);
	memset(str_tmp, 0 ,64);
	memset(str, 0, 64);
	
	sprintf(temp_str, "partool -part mtd5 -show model");	
	PopenFile(temp_str, str_tmp, sizeof(str_tmp));
	strcpy((void *)&str, trim(str_tmp));
	
	cluster_log(LOG_DEBUG,"%s-%d ProductType= %s len= %d\n", __func__, __LINE__,  str, strlen((void *)&str));

	for(i = 0;i < product_type_cnt;i++)
	{
		if(0 == strcmp((void *)&str, (void *)&product_type_table[i].product_type))
		{
			product_type = product_type_table[i].type_code;
			break;
		}
	}

	return product_type;
}



unsigned char Get_Config_Version()
{
	char temp_str[100] = {0};
	char str_tmp[64];
	unsigned char str[64];
	unsigned char software_version = 0;
	unsigned char *p = NULL;
	int config_ver=0;
	unsigned  char mod=0;
	
	memset(temp_str, 0, 100);
	memset(str_tmp, 0 ,64);
	memset(str, 0, 64);
	
	sprintf(temp_str, "getrevnumber");	
	PopenFile(temp_str, str_tmp, sizeof(str_tmp));
	strcpy((void *)&str, trim(str_tmp));
	
	cluster_log(LOG_DEBUG,"%s-%d Config_Version= %s len= %d\n", __func__, __LINE__,  str, strlen((void *)&str));

	p = str;
	config_ver=atoi(p);
	if(config_ver!=0)
		mod= (config_ver % 0xff) +1;
	else
		mod =0;

	cluster_log(LOG_DEBUG,"%s-%d Config_Version= %d,mod:%d\n", __func__, __LINE__,  config_ver,mod);
	
	return mod;
}
void Get_Ap_Version(unsigned char *ap_version)
{
	char temp_str[100] = {0};
	char str_tmp[64];
	unsigned char str[64];
	
	memset(temp_str, 0, 100);
	memset(str_tmp, 0 ,64);
	memset(str, 0, 64);
	
	sprintf(temp_str, "showver");	
	PopenFile(temp_str, str_tmp, sizeof(str_tmp));
	strcpy(str, trim(str_tmp));
	
	cluster_log(LOG_DEBUG,"%s-%d Software_Version= %s len= %d\n", __func__, __LINE__,  str, strlen(str));

	memcpy(ap_version, str, VERSION_MAX_LEN);
	
	cluster_log(LOG_DEBUG,"%s-%d Ap_Version= %s len= %d\n", __func__, __LINE__,  ap_version, strlen(ap_version));
}

unsigned char Get_Software_Version()
{
	char temp_str[100] = {0};
	char str_tmp[64];
	unsigned char str[64];
	unsigned char software_version = 0;
	unsigned char *p = NULL;
	
	memset(temp_str, 0, 100);
	memset(str_tmp, 0 ,64);
	memset(str, 0, 64);
	
	sprintf(temp_str, "showver");	
	PopenFile(temp_str, str_tmp, sizeof(str_tmp));
	strcpy((void *)&str, trim(str_tmp));
	
	cluster_log(LOG_DEBUG,"%s-%d Software_Version= %s len= %d\n", __func__, __LINE__,  str, strlen((void *)&str));

	p = str;
	
	software_version = *p - '0';
	
	cluster_log(LOG_DEBUG,"%s-%d Software_Version= %d\n", __func__, __LINE__,  software_version);
	
	return software_version;
}

void get_priority()
{
    uint8_t set_priority = 0; //get from uci
   // int conf_seq = 0;     // get from config file module
   // int product_type = 0; //default 0

    self_ap.prio.prio.priority = set_priority;
    self_ap.prio.prio.config_seq = Get_Config_Version();
    self_ap.prio.prio.product_type = get_product_type_code() + Get_Software_Version();
    memcpy(self_ap.prio.prio.mac_tail, &self_ap.mac[3], 3);
}

void get_cluster_id()
{
    
    self_ap.cluster_id = g_clusterId;
}

void get_state()
{

    get_mac();

   // get_priority();

   // get_cluster_id();

    get_ipaddr();

    self_ap.role = VC;
    self_ap.state = DISCOVERY;
    self_ap.auth = 0;
	
	Get_Ap_Version(self_ap.ap_version);

}




void load_config()
{
    //uint32_t ip;
    //uint8_t mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	int ret,i=0,find = 0;
	char cmd[128] = {0};
	struct in_addr addr_n;
	uint8_t addr_p[20]={0};
	
    /*  clean env */
    memset(entry, 0, sizeof(struct cluster_member) * 128);
    memset(&table, 0, sizeof(struct table_entry));
    memset(auth, 0, sizeof(struct  table_auth) * 16);

	
	system("killall  acs_mgt  &");   

	get_state();


	 //add pvc
     insert_auth_entry(self_ap.mac);
     entry[0].role = PVC;
     entry[0].state = RUN;
	 entry[0].ip =  self_ap.ip;

	
	ret=load_config_file();
	if(ret<0)
	{
   	 	get_priority();
		//get_cluster_id();
		system("ifconfig  br-wan:0  10.0.0.1  up");
	}
	else
	{

		// init config 
		//self_ap.cluster_id = config_file_data.cluster_id;
		//self_ap.prio.prio.priority = config_file_data.cluster_priority;

		
		self_ap.prio.prio.config_seq = Get_Config_Version();
   	    self_ap.prio.prio.product_type = get_product_type_code() + Get_Software_Version();
    	memcpy(self_ap.prio.prio.mac_tail, &self_ap.mac[3], 3);

		addr_n.s_addr = config_file_data.cluster_vip_netmask;
		inet_ntop(AF_INET,&addr_n,(void *)&addr_p,16);
		config_pvc_vipaddr(config_file_data.cluster_vip,addr_p);
		

		// load auth ap list 
		for(i=0;i< config_file_data.cluster_member_count;i++)
		{
			if(!memcmp(config_file_data.mac[i],self_ap.mac,6))
			{
				find=1;
				continue;
			}
	
			insert_blacklist_entry(config_file_data.mac[i]);
	
		}

		if(find)
		{
				
				sprintf(cmd, "uci -c %s del_list cluster.cluster.cluster_member='%02x:%02x:%02x:%02x:%02x:%02x' ", CLUSTER_CONFIG_PATH, self_ap.mac[0],self_ap.mac[1],self_ap.mac[2],self_ap.mac[3],self_ap.mac[4],self_ap.mac[5]);
				system(cmd);
				sprintf(cmd, "uci -c %s commit cluster", CLUSTER_CONFIG_PATH);
				system(cmd);
				sprintf(cmd, "cd /etc/cfm/config/config-pub/;rm -f pub-cfg-md5;md5sum * > pub-cfg-md5");
				system(cmd);
		}

	}



	get_cluster_id();
	self_is_svc_blacklist();
	elect_svc();
}

void cluster_cor_init(void)
{
		int ret;
		int so_reuse =1;
		struct sockaddr_in send_addr;
		
		umask(0);
		
		/* init */
		table.entry_cnt = 0;
		table.free_cnt = 0;
		table.new_free = 0;
		table.auth_cnt = 0;
		memset(entry, 0, sizeof(struct cluster_member) * 128);
		memset(auth, 0, sizeof(struct table_auth) * 16);
		self_ap.cluster_id = g_clusterId;
		get_state();

		parse_mac(g_mac_str,g_mac);
		if(!memcmp(g_mac,self_ap.mac,MAC_LEN))
		{
			g_priority=1;
			dump_mac(LOG_DEBUG,g_mac);
		}
		else
		{
			cluster_log(LOG_DEBUG,"g_mac is:\n");
			dump_mac(LOG_DEBUG,g_mac);
			cluster_log(LOG_DEBUG,"self mac is:\n");
			dump_mac(LOG_DEBUG,self_ap.mac);
		}
		self_ap.prio.prio.priority = g_priority;
		flags =  g_priority;
		pthread_mutex_init(&table.table_mutex, NULL);

		memset(blacklist_entry,0,sizeof(blacklist_entry[ENTRY_SIZE]));
		system("killall acs_mgt  &");

		/* init rsrp recv */
	if((sock_recv_rsrp = (socket(AF_INET, SOCK_DGRAM, 0))) < 0)
    {
        cluster_log(LOG_ERR,"create rsrp recv socket failed\n");
        exit(1);
		
    }
	
    send_addr.sin_family = AF_INET;
    send_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    send_addr.sin_port = htons(CLUSTER_PORT_RECV);
	setsockopt(sock_recv_rsrp, SOL_SOCKET, SO_REUSEADDR, &so_reuse, sizeof(so_reuse));
	//setsockopt(sock_recv_rsrp, SOL_SOCKET, SO_REUSEPORT, &so_reuse, sizeof(so_reuse));

	ret = bind(sock_recv_rsrp, (struct sockaddr *)&send_addr, sizeof(send_addr));
   if(ret <0)
   	{
		cluster_log(LOG_ERR,"recv rsrp socket bind error\n");
		exit(1);
   	}


}
int self_is_svc(void)
{
	unsigned char i = 0, j = 0, k = 0, l = 0, m = 0,  flag = 0, find = 0, find_result = 0;
	uint8_t addr_p[20]={0};
	struct in_addr addr_n;
	
	for(i = 0; i < risp_pkt_recv.Mem_num && i < MAX_CLUSTER_AP; i++)
	{
		if(memcmp(self_ap.mac, risp_pkt_recv.WTP_RF[i].ap_base_mac, 6) == 0)
		{
			if(risp_pkt_recv.WTP_RF[i].role != SVC)
			{
				cluster_log(LOG_DEBUG,"%s-%d self is not svc\n", __func__, __LINE__);
				return 0;
			}				
			else
			{
			
				find = 1;
				cluster_log(LOG_DEBUG,"%s-%d self is svc\n", __func__, __LINE__);
				break;
			}
				
		}
	}

	if(find)
	{
		for(i = 0; i < risp_pkt_recv.Mem_num && i < MAX_CLUSTER_AP; i++)
		{
			for(j = 0; j < table.entry_cnt; j++) 
			{
				if(entry[j].on == 0 || entry[j].auth == 0)
		            continue;
				
		        if(memcmp(entry[j].mac, risp_pkt_recv.WTP_RF[i].ap_base_mac, 6) != 0)
		        {
		            continue;
				}
		        else 
				{
					flag = j;
		            find_result = 1;
					cluster_log(LOG_DEBUG,"%s-%d self_mac:%x:%x:%x:%x:%x:%x\n", __func__, __LINE__,entry[j].mac[0],entry[j].mac[1],entry[j].mac[2],entry[j].mac[3],entry[j].mac[4],entry[j].mac[5]);
		            break;
		        }
		    }

			if(find_result == 1)
			{
				cluster_log(LOG_DEBUG,"%s-%d ---------------------%d-----------------------\n", __func__, __LINE__, flag);
				
				entry[flag].ip = risp_pkt_recv.WTP_RF[i].ipaddr;
				entry[flag].neighbor_cnt = risp_pkt_recv.WTP_RF[i].neighbor_cnt;
				entry[flag].prio.prio.priority = (u_int8_t)risp_pkt_recv.WTP_RF[i].priority;
				entry[flag].radiocnt = risp_pkt_recv.WTP_RF[i].radiocnt;
				//entry[flag].role = risp_pkt_recv.WTP_RF[i].role;

				addr_n.s_addr = entry[flag].ip;
				inet_ntop(AF_INET,&addr_n,(void *)&addr_p,16);
				cluster_log(LOG_DEBUG,"ip:%s neighbor_cnt:%d priority:%d radiocnt:%d\n", addr_p, entry[flag].neighbor_cnt, entry[flag].prio.prio.priority, entry[flag].radiocnt);

				for(k = 0;k < entry[flag].radiocnt && k < L_RADIO_NUM; k++)
				{
					entry[flag].WTP_Radio[k].radioid = risp_pkt_recv.WTP_RF[i].WTP_Radio[k].radioid;
					entry[flag].WTP_Radio[k].channel = risp_pkt_recv.WTP_RF[i].WTP_Radio[k].channel;
					entry[flag].WTP_Radio[k].txpower = risp_pkt_recv.WTP_RF[i].WTP_Radio[k].txpower;

					cluster_log(LOG_DEBUG,"\tradio[%d]--radioid:%d--channel:%d--txpower:%d\n", k, entry[flag].WTP_Radio[k].radioid,entry[flag].WTP_Radio[k].channel,entry[flag].WTP_Radio[k].txpower);
				}

				for(l = 0;l < entry[flag].neighbor_cnt && l < MAX_CLUSTER_AP; l++)
				{
					memcpy(entry[flag].rssi_of_others[l].ap_base_mac, risp_pkt_recv.WTP_RF[i].rssi_of_others[l].ap_base_mac, MAC_LEN);
					entry[flag].rssi_of_others[l].radiocnt = risp_pkt_recv.WTP_RF[i].rssi_of_others[l].radiocnt;
					
					cluster_log(LOG_DEBUG,"neighbor[%d]:mac:%x:%x:%x:%x:%x:%x--radiocnt:%d\n", l, \
						entry[flag].rssi_of_others[l].ap_base_mac[0], \
						entry[flag].rssi_of_others[l].ap_base_mac[1], \
						entry[flag].rssi_of_others[l].ap_base_mac[2], \
						entry[flag].rssi_of_others[l].ap_base_mac[3], \
						entry[flag].rssi_of_others[l].ap_base_mac[4], \
						entry[flag].rssi_of_others[l].ap_base_mac[5], \
						entry[flag].rssi_of_others[l].radiocnt);
					
					for(m = 0; m < entry[flag].rssi_of_others[l].radiocnt && m < L_RADIO_NUM; m++)
					{
						entry[flag].rssi_of_others[l].ap_radio[m].radioid = risp_pkt_recv.WTP_RF[i].rssi_of_others[l].ap_radio[m].radioid;
						entry[flag].rssi_of_others[l].ap_radio[m].channel = risp_pkt_recv.WTP_RF[i].rssi_of_others[l].ap_radio[m].channel;
						entry[flag].rssi_of_others[l].ap_radio[m].rssi = risp_pkt_recv.WTP_RF[i].rssi_of_others[l].ap_radio[m].rssi;
						entry[flag].rssi_of_others[l].ap_radio[m].txpower = risp_pkt_recv.WTP_RF[i].rssi_of_others[l].ap_radio[m].txpower;

						cluster_log(LOG_DEBUG,"\tradio[%d]:radioid:%d--channel:%d--rssi:%d--txpower:%d\n", m, \
							entry[flag].rssi_of_others[l].ap_radio[m].radioid, \
							entry[flag].rssi_of_others[l].ap_radio[m].channel, \
							entry[flag].rssi_of_others[l].ap_radio[m].rssi, \
							entry[flag].rssi_of_others[l].ap_radio[m].txpower);
					}

				}
			}
			else
			{
				cluster_log(LOG_DEBUG,"%s-%d entry has no this mac\n", __func__, __LINE__);
			}
		}		
	}
	else
	{
		cluster_log(LOG_DEBUG,"%s-%d has no self\n", __func__, __LINE__);
		return 0;
	}

	return 0;
}


int self_is_svc_blacklist(void)
{
	unsigned char i = 0, j = 0, k = 0, l = 0, m = 0,  flag = 0, find = 0;
	uint8_t addr_p[20]={0};
	int  cnt = 1, tag = 0;
	struct in_addr addr_n;
	
	for(i = 0; i < risp_pkt_recv.Mem_num && i < MAX_CLUSTER_AP; i++)
	{
		if(memcmp(self_ap.mac, risp_pkt_recv.WTP_RF[i].ap_base_mac, 6) == 0)
		{
			if(risp_pkt_recv.WTP_RF[i].role != SVC)
			{
				cluster_log(LOG_DEBUG,"%s-%d self is not svc\n", __func__, __LINE__);
				return 0;
			}				
			else
			{
			
				find = 1;
				tag = i;
				cluster_log(LOG_DEBUG,"%s-%d self is svc\n", __func__, __LINE__);
				break;
			}
				
		}
	}

	if(find)
	{
		for(i = 0; i < risp_pkt_recv.Mem_num && i < MAX_CLUSTER_AP; i++)
		{
			if(i == tag)
	        {
	           flag = 0;
				cnt=0;
			}
	        else
	        {
	         	flag = i + cnt;				
			}
			
			cluster_log(LOG_DEBUG,"%s-%d ---------------------%d-----------------------\n", __func__, __LINE__, flag);
			
			insert_auth_entry(risp_pkt_recv.WTP_RF[i].ap_base_mac);
			entry[flag].neighbor_cnt = risp_pkt_recv.WTP_RF[i].neighbor_cnt;
			entry[flag].prio.prio.priority = (u_int8_t)risp_pkt_recv.WTP_RF[i].priority;
			entry[flag].radiocnt = risp_pkt_recv.WTP_RF[i].radiocnt;
			
			if(flag != 0)
			{
				
				entry[flag].ip = risp_pkt_recv.WTP_RF[i].ipaddr;
				
			}
			addr_n.s_addr = entry[flag].ip;
			inet_ntop(AF_INET,&addr_n,(void *)&addr_p,16);
			cluster_log(LOG_DEBUG,"ip:%s neighbor_cnt:%d priority:%d radiocnt:%d\n", addr_p, entry[flag].neighbor_cnt, entry[flag].prio.prio.priority, entry[flag].radiocnt);

			for(k = 0;k < entry[flag].radiocnt && k < L_RADIO_NUM; k++)
			{
				entry[flag].WTP_Radio[k].radioid = risp_pkt_recv.WTP_RF[i].WTP_Radio[k].radioid;
				entry[flag].WTP_Radio[k].channel = risp_pkt_recv.WTP_RF[i].WTP_Radio[k].channel;
				entry[flag].WTP_Radio[k].txpower = risp_pkt_recv.WTP_RF[i].WTP_Radio[k].txpower;

				cluster_log(LOG_DEBUG,"\tradio[%d]--radioid:%d--channel:%d--txpower:%d\n", k, entry[flag].WTP_Radio[k].radioid,entry[flag].WTP_Radio[k].channel,entry[flag].WTP_Radio[k].txpower);
			}

			for(l = 0;l < entry[flag].neighbor_cnt && l < MAX_CLUSTER_AP; l++)
			{
				memcpy(entry[flag].rssi_of_others[l].ap_base_mac, risp_pkt_recv.WTP_RF[i].rssi_of_others[l].ap_base_mac, MAC_LEN);
				entry[flag].rssi_of_others[l].radiocnt = risp_pkt_recv.WTP_RF[i].rssi_of_others[l].radiocnt;
				
				cluster_log(LOG_DEBUG,"neighbor[%d]:mac:%x:%x:%x:%x:%x:%x--radiocnt:%d\n", l, \
					entry[flag].rssi_of_others[l].ap_base_mac[0], \
					entry[flag].rssi_of_others[l].ap_base_mac[1], \
					entry[flag].rssi_of_others[l].ap_base_mac[2], \
					entry[flag].rssi_of_others[l].ap_base_mac[3], \
					entry[flag].rssi_of_others[l].ap_base_mac[4], \
					entry[flag].rssi_of_others[l].ap_base_mac[5], \
					entry[flag].rssi_of_others[l].radiocnt);
				
				for(m = 0; m < entry[flag].rssi_of_others[l].radiocnt && m < L_RADIO_NUM; m++)
				{
					entry[flag].rssi_of_others[l].ap_radio[m].radioid = risp_pkt_recv.WTP_RF[i].rssi_of_others[l].ap_radio[m].radioid;
					entry[flag].rssi_of_others[l].ap_radio[m].channel = risp_pkt_recv.WTP_RF[i].rssi_of_others[l].ap_radio[m].channel;
					entry[flag].rssi_of_others[l].ap_radio[m].rssi = risp_pkt_recv.WTP_RF[i].rssi_of_others[l].ap_radio[m].rssi;
					entry[flag].rssi_of_others[l].ap_radio[m].txpower = risp_pkt_recv.WTP_RF[i].rssi_of_others[l].ap_radio[m].txpower;

					cluster_log(LOG_DEBUG,"\tradio[%d]:radioid:%d--channel:%d--rssi:%d--txpower:%d\n", m, \
						entry[flag].rssi_of_others[l].ap_radio[m].radioid, \
						entry[flag].rssi_of_others[l].ap_radio[m].channel, \
						entry[flag].rssi_of_others[l].ap_radio[m].rssi, \
						entry[flag].rssi_of_others[l].ap_radio[m].txpower);
				}

			}
			
			
		}		
	}
	else
	{
		cluster_log(LOG_DEBUG,"%s-%d has no self\n", __func__, __LINE__);
		return 0;
	}

	return 0;
}
int main(int argc, char *argv[])
{


    int ret;

    pthread_t  thread_check_pvc;
    pthread_t  thread_show_members;
	pthread_t thread_config_sync;

    //UCHAR mac4[8]={0x00,0x00,0xB5,0xE5,0x00,0x00};

	cluster_cor_get_options(argc,argv);

	cluster_cor_init();



    ret = pthread_create(&thread_check_pvc, NULL, (void *)create_check_pvc_thread, NULL);
    if(0 != ret)
    {
        cluster_log(LOG_ERR,"create check pvc  fail.\n");
        pthread_join(thread_check_pvc, NULL);
        return  FALSE;

    }

    // show  members thread
    ret = pthread_create(&thread_show_members, NULL, (void *)create_show_members_thread, NULL);
    if(0 != ret)
    {
        cluster_log(LOG_ERR,"create show members fail.\n");
        pthread_join(thread_show_members, NULL);
        return  FALSE;

    }

	
	ret = pthread_create(&thread_config_sync, NULL, (void *)create_config_sync_thread, NULL);
    if(0 != ret)
    {
        cluster_log(LOG_ERR,"create config sync thread fail.\n");
        pthread_join(thread_config_sync, NULL);
        return  FALSE;

    }


    while(1)
    {

        cluster_log(LOG_DEBUG,"flags is %d, into svc/vc <--->pvc state\n", flags);

        if(flags == 1)   // svc --->pvc
        {

            load_config();
			
            cluster_log(LOG_DEBUG,"pvc mode!!!\n");

			
            //  update  ap members info
            ret = pthread_create(&thread_rsrp_recv, NULL, (void *)create_rsrp_recv_thread, NULL);
            if( 0 != ret )
            {
                cluster_log(LOG_ERR,"create_rsrp_recv_thread fail.\n");
                pthread_join(thread_rsrp_recv, NULL);
                return FALSE;
            }


            // sync pvc info to svc
            ret = pthread_create(&thread_risp_send, NULL, (void *)create_risp_send_thread, NULL);
            if( 0 != ret )
            {
                cluster_log(LOG_ERR,"create_risp_send_thread fail.\n");
                pthread_join(thread_risp_send, NULL);
                return FALSE;
            }


            //keep alive  -> send rscp
            ret = pthread_create(&thread_rscp_send, NULL, (void *)create_rscp_send_thread, NULL);
            if( 0 != ret )
            {
                cluster_log(LOG_ERR,"create_rscp_send_thread fail.\n");
                pthread_join(thread_rscp_send, NULL);
                return FALSE;
            }



            //cluster members ageing
            ret = pthread_create(&thread_ageing, NULL, (void *)create_cluster_ageing_thread, NULL);
            if( 0 != ret )
            {
                cluster_log(LOG_ERR,"create cluster ageing thread fail.\n");
                pthread_join(thread_ageing, NULL);
                return FALSE;
            }

            //ACS 
            ret = pthread_create(&thread_acs, NULL, (void *)create_cluster_acs_thread, NULL);
            if( 0 != ret )
            {
                cluster_log(LOG_ERR,"create cluster acs thread fail.\n");
                pthread_join(thread_acs, NULL);
                return FALSE;
            }

			pvc_switch = 1;      

            pthread_join(thread_rsrp_recv, NULL);
            pthread_join(thread_rscp_send, NULL);
            pthread_join(thread_risp_send, NULL);
            //ageing
            pthread_join(thread_ageing, NULL);
            //acs
            pthread_join(thread_acs, NULL);


        }
        else if(flags == 0)     // pvc--> svc
        {

            printf("svc/vc mode!\n");
            /*  clean env */
            memset(entry, 0, sizeof(struct cluster_member) * 128);
            memset(&table, 0, sizeof(struct table_entry));
            memset(auth, 0, sizeof(struct  table_auth) * 16);
			
			system("killall acs_mgt &");
			 
            system("ifconfig  br-wan:0  down & ");
            ret = pthread_create(&thread_check_vc, NULL, (void *)create_check_vc_thread, NULL);
            if( 0 != ret )
            {
                cluster_log(LOG_ERR,"Create check vc thread fail.\n");
                pthread_join(thread_check_vc, NULL);
                return FALSE;
            }
			
			pvc_switch = 0;

            pthread_join(thread_check_vc, NULL);

        }


    }




    pthread_join(thread_show_members, NULL);
    pthread_join(thread_check_pvc, NULL);
	pthread_join(thread_config_sync,NULL);


	close(sock_recv_rsrp);

    return TRUE;

}









































