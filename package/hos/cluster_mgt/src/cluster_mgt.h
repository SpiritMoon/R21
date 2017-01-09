#ifndef CLUSTER_MGT_H
#define CLUSTER_MGT_H


#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "hccpprotocol.h"
#include "Log.h"

#define cluster_send_vc_port 32767
#define cluster_send_pvc_port 32768
#define cluster_send_acs_port 32769
#define cluster_recv_port 32767

#define cluster_dbcp_interval 2
#define cluster_discovry_limit 10
#define cluster_rsrp_interval 10
#define cluster_rirp_interval 60
#define cluster_rscp_interval 10
#define cluster_join_ageing_interval 60
#define cluster_pvc_aging_interval 10
#define cluster_svc_aging_interval  5


#define PIPE_NAME  "/tmp/cluster_mgt_pipe"
#define PIPE_CMD  "/tmp/cluster_cmd_pipe"
#define CLUSTER_FIFO "/tmp/cluster_fifo"
#define DOMAIN_NAME "/tmp/cluster_mgt_socket"
#define DOMAIN2_NAME "/tmp/cluster_socket"
#define BGSCAN_PATH "/tmp/unix-bgscan"

extern P_ELECT_MB_LIST elect_member_list;

#define PRODUCT_TYPE_LEN 32
#define CONFIGURATION_STATE_LEN 16
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

inline int mac_is_equal( u_int8_t *mac_l, u_int8_t *mac_r)
{
	return !memcmp( mac_l, mac_r, MAC_LEN);
}


P_ELECT_MB elect_mb_search(P_ELECT_MB_LIST ptr_mb_list, u_int8_t *mac_addr)
{
	P_ELECT_MB ptr_mb = NULL;
	
	if (ptr_mb_list == NULL)
	{
		return NULL;
	}

	ptr_mb = ptr_mb_list->ptr_elect_mb;	
	while (ptr_mb != NULL)
	{
		if (mac_is_equal(ptr_mb->mac_addr, mac_addr))
		{
			return ptr_mb;
		}
		
		ptr_mb = ptr_mb->next;
	}
	
	return NULL;
}


CWBool elect_mb_remove(P_ELECT_MB_LIST ptr_mb_list, u_int8_t *mac_addr)
{
	P_ELECT_MB ptr_pre = NULL;
	P_ELECT_MB ptr_mb = NULL;
	P_ELECT_MB ptr_iter = NULL;
	
	if (NULL == ptr_mb_list || NULL == ptr_mb_list->ptr_elect_mb)
	{
		return CW_FALSE;
	}

	ptr_pre = ptr_mb_list->ptr_elect_mb;
	if (mac_is_equal(ptr_pre->mac_addr, mac_addr))
	{
		ptr_mb_list->ptr_elect_mb = ptr_pre->next;
		FREE_OBJECT(ptr_pre);
		ptr_mb_list->elect_mb_count--;
		
		return CW_TRUE;
	}
	
	ptr_pre = ptr_mb_list->ptr_elect_mb;
	ptr_mb = ptr_pre->next;
	while (ptr_mb != NULL)
	{
		if (mac_is_equal(ptr_mb->mac_addr, mac_addr))
		{
			ptr_iter = ptr_mb->next;
			FREE_OBJECT(ptr_mb);
			ptr_pre->next = ptr_iter;
            
			ptr_mb_list->elect_mb_count--;
			return CW_TRUE;
		}
		
		ptr_pre = ptr_mb;
		ptr_mb = ptr_mb->next;
	}
	
	return CW_FALSE;
}



//add node to elect list , this list is order by pri, there is  three situation
// 1. there is already a node with the same mac and pri, update aging time and break;
// 2. there is already a node with the same mac , but not the same pri, delete old one add insert new one in the correct positon.
// 3. there is not node with the same mac, insert this node into list order by pri
int elect_mb_add(P_ELECT_MB_LIST ptr_mb_list, u_int8_t *mac_addr, CLUSTER_PRI pri)
{
	P_ELECT_MB ptr_mb = NULL;
	P_ELECT_MB ptr_pre = NULL;
	P_ELECT_MB ptr_cur = NULL;
	
	if (ptr_mb_list == NULL)
	{
		return -1;
	}
	
    ptr_cur = elect_mb_search(elect_member_list, mac_addr);
	if (ptr_cur)
	{
		if (ptr_cur->cluster_pri.hap_priority == pri.hap_priority)
		{
			ptr_cur->timeout_flag = 0;
			return ptr_mb_list->elect_mb_count;
		}
		else
		{
			syslog_debug("%s-%d "MACSTR" original-pri %llx now %llx\n",
						__func__, __LINE__, MAC2STR(mac_addr), ptr_cur->cluster_pri.hap_priority, pri.hap_priority);
			
			elect_mb_remove(elect_member_list, mac_addr);
			
			syslog_debug("%s-%d elect_member_list count %d\n", __func__, __LINE__, ptr_mb_list->elect_mb_count);
			
			return elect_mb_add(elect_member_list, mac_addr, pri);
		}
	}
	
	ptr_mb = ptr_mb_list->ptr_elect_mb;
	while (ptr_mb != NULL)
	{
		if (ptr_mb->cluster_pri.hap_priority < pri.hap_priority)
		{
			ptr_cur = (P_ELECT_MB)malloc(sizeof(ELECT_MB));
			if (ptr_cur)
			{
				syslog_debug("%s-%d "MACSTR" pri %llx > "MACSTR" pri %llx\n",
							__func__, __LINE__, MAC2STR(mac_addr), pri.hap_priority,
							MAC2STR(ptr_mb->mac_addr), ptr_mb->cluster_pri.hap_priority);
				
				memset(ptr_cur, 0, sizeof(ELECT_MB));
				memcpy(ptr_cur->mac_addr, mac_addr, MAC_LEN);
				memcpy(&ptr_cur->cluster_pri, &pri, sizeof(CLUSTER_PRI));
				ptr_cur->timeout_flag = 0;
				if (ptr_pre == NULL)
				{
					ptr_cur->next = ptr_mb_list->ptr_elect_mb;
					ptr_mb_list->ptr_elect_mb = ptr_cur;
				}
				else
				{
					ptr_cur->next = ptr_mb;
					ptr_pre->next = ptr_cur;
				}
				
				ptr_mb_list->elect_mb_count++;
				syslog_debug("%s-%d elect_member_list count %d\n", __func__, __LINE__, ptr_mb_list->elect_mb_count);
				
				return ptr_mb_list->elect_mb_count;
			}
		}
		
		ptr_pre = ptr_mb;
		ptr_mb = ptr_mb->next;
	}

	ptr_cur = (P_ELECT_MB)malloc(sizeof(ELECT_MB));
	if (ptr_cur)
	{
		memset(ptr_cur, 0, sizeof(ELECT_MB));
		memcpy(ptr_cur->mac_addr, mac_addr, MAC_LEN);
		memcpy(&ptr_cur->cluster_pri, &pri, sizeof(CLUSTER_PRI));
		ptr_cur->next = NULL;
		ptr_cur->timeout_flag = 0;
		if (NULL == ptr_pre)
		{
			ptr_mb_list->ptr_elect_mb = ptr_cur;
			syslog_debug("%s-%d "MACSTR" pri %llx insert to head\n",
						__func__, __LINE__, MAC2STR(mac_addr), pri.hap_priority);
		}
		else
		{
			ptr_pre->next = ptr_cur;
			syslog_debug("%s-%d "MACSTR" pri %llx insert to tail\n",
						__func__, __LINE__, MAC2STR(mac_addr), pri.hap_priority);
		}
		
		ptr_mb_list->elect_mb_count++;
		syslog_debug("%s-%d elect_member_list count %d\n", __func__, __LINE__, ptr_mb_list->elect_mb_count);
	}
	
	return ptr_mb_list->elect_mb_count;
}


//remove node which is aging
int elect_mb_aging(P_ELECT_MB_LIST ptr_mb_list)
{
	P_ELECT_MB ptr_pre = NULL;
	P_ELECT_MB ptr_head = NULL;
	P_ELECT_MB ptr_iter = NULL;
	
	if (ptr_mb_list->ptr_elect_mb == NULL)
	{
		return 0;
	}
	
	ptr_head = (P_ELECT_MB)malloc(sizeof(ELECT_MB)); 
	ptr_head->next = ptr_mb_list->ptr_elect_mb;

	ptr_pre = ptr_head;
	ptr_iter = ptr_head->next;

	while (ptr_iter != NULL)
	{
		if (ptr_iter->timeout_flag > 3)
		{
			ptr_pre->next = ptr_iter->next;
			FREE_OBJECT(ptr_iter);
			ptr_iter = ptr_pre->next;
			ptr_mb_list->elect_mb_count--;
		}
		else
		{
			ptr_iter->timeout_flag++;
			ptr_pre = ptr_iter;
			ptr_iter = ptr_iter->next;
		}
	}

	ptr_mb_list->ptr_elect_mb = ptr_head->next;
	FREE_OBJECT(ptr_head);
	
	return ptr_mb_list->elect_mb_count;
}

//clean the elect list 
int elect_mb_clean(P_ELECT_MB_LIST ptr_mb_list)
{
	if (ptr_mb_list == NULL)
	{
		return -1;
	}

	P_ELECT_MB ptr_cur = NULL;
	P_ELECT_MB ptr_iter = ptr_mb_list->ptr_elect_mb;

	while (ptr_iter != NULL)
	{
		ptr_cur = ptr_iter;
		ptr_iter = ptr_iter->next;
		FREE_OBJECT(ptr_cur);
	}

	ptr_mb_list->ptr_elect_mb = NULL;
	ptr_mb_list->elect_mb_count = 0;
	
	return 0;
}

inline int max( int a, int b)
{
	return a >= b ? a : b;
}

int control_init_pipe(void);
int sock_scan_request(void);
int recv_scan_response(void);
void GetRadioInfo(void);

CLUSTER_MB *Search_list_by_mac(unsigned char *mac);
CLUSTER_MB *self_add_cluster(void);
int add_member_list(Hccp_Protocol_Struct *dbcp);

CWBool Fill_Inf_Data(struct CLUSTER_INF *cluster_inf);
CWBool Fill_RIRP_Data(RF_environment *RFInfo);
CWBool Fill_RISP_Data(CLUSTER_RF_environment *EnvInfo);
int handle_recvcmd(unsigned char *buf, unsigned int buflen, struct sockaddr_un *model_addr);

CWBool ParseHCCPProtocol(char *buf, int readBytes, ProtocolMessage **messages);


#endif
