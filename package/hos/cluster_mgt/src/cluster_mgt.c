#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>


#include <netinet/if_ether.h>
#include <net/if_arp.h>



#include "timerlib.h"
#include "sock_domain.h"
#include "hccpprotocol.h"
#include "cluster_mgt.h"
#include "libhccp.h"
#include "Log.h"

CLUSTER_MEMBER_LIST cluster_member_list;
unsigned char cluster_mgt_dbg_level = 0;

unsigned char product_type_cnt = 2;
char *wan="br-wan";

//int cluster_state = DISCOVERY;
int cluster_socket_send = 0;
int cluster_socket_recv = 0;
int arp_sock=-1;
P_AP_STAT self_state = NULL;
P_PVC_STAT pvc_state = NULL;
P_CLUSTER_MB_LIST cluster_mem_list = NULL;
P_ELECT_MB_LIST elect_member_list = NULL;
int if_pipe = -1;
int cmd_pipe = -1;
int if_local_socket = -1;
int local_sock = -1;
int g_priority = 0;
int g_clusterId = 100;
int dbcp_timer_id = TIMER_DEFAULT;
int times_up_id = TIMER_DEFAULT;
int pvc_aging_id = TIMER_DEFAULT;
int svc_aging_id = TIMER_DEFAULT;
int rsrp_timer_id = TIMER_DEFAULT;
int rsrp_timer_run_id = TIMER_DEFAULT;
int join_ageing_id = TIMER_DEFAULT;
int svc_timer = 0;
int ScanRetransmit = 0;
struct timeval timeout;
uint8_t  g_mac_str[64]={0};
uint8_t  g_mac[6]={0};

static fd_set read_fs;
static fd_set read_fds;
//static fd_set write_fds;
//static fd_set excpt_fds;
uint32_t brast_ipaddr = 0;
unixAddr toBGSC;
static volatile unsigned char g_syncflag = 0;
void being_pvc();
void Insert_list_from_head(CLUSTER_MB *new);
void send_rsrp(void);
int update_member_list(Hccp_Protocol_Struct *rscp);
void cleanup_member_list(void);


Product_Type product_type_table[] = 
{
	{"model not exist", MODEL_NOT_EXIST},
	{"AP101", AP101}	
};


void cluster_mgt_log(const char * fmt, ...)
{
    char buf[256];
    va_list ap;
    if(!cluster_mgt_dbg_level)
        return;
    va_start(ap,fmt);
    vsnprintf(buf,256,fmt,ap);
    va_end(ap);
	syslog(LOG_DEBUG,"%s" ,buf);
    printf("%s\n",buf);
}

char *trim(char *str_org)
{
	if (NULL == str_org)
	{
		syslog_debug("%s-%d str_org= NULL\n", __func__, __LINE__);
		return NULL;
	}

	if (0 == strlen(str_org))
	{
		syslog_debug("%s-%d Empty String\n", __func__, __LINE__);
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


char *dump_state(char *str, int state)
{
	memset(str, 0, strlen(str));
	switch(state)
	{
		case DISCOVERY:
			sprintf(str, "DISCOVERY");
			break;
		case JOIN:
			sprintf(str, "JOIN");
			break;
		case CHECK:
			sprintf(str, "CHECK");
			break;
		case RUN:
			sprintf(str, "RUN");
			break;	
		case LOST:
			sprintf(str, "LOST");
			break;		
		default:
			sprintf(str, "UNKNOW");
			break;	
	}
	return str;
}

char *dump_role(char *str, int role)
{
	memset(str, 0, strlen(str));
	switch(role)
	{
		case PVC:
			sprintf(str, "PVC");
			break;
		case SVC:
			sprintf(str, "SVC");
			break;
		case VC:
			sprintf(str, "VC");
			break;
		default:
			sprintf(str, "UNKNOW");
			break;	
	}
	return str;
}

char *dump_mac(char *str, u_int8_t *mac)
{
	if( str == NULL || mac == NULL )
	{
		return NULL;
	}
	memset(str, 0, strlen(str));
	sprintf(str, "%02x:%02x:%02x:%02x:%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return str;
}


inline int show_mb_mac(P_ELECT_MB_LIST ptr_mb_list)
{
	P_ELECT_MB p = NULL;
	
	if (!ptr_mb_list)
	{
		return -1;
	}
	
	syslog_debug("list count: %d\n", ptr_mb_list->elect_mb_count);
	p = ptr_mb_list->ptr_elect_mb;
	
	while (p != NULL)
	{
		syslog_debug("mb mac: %2x:%2x:%2x:%2x:%2x:%2x\n", MAC2STR(p->mac_addr));
		
		p = p->next;
	}
	
	return 0;
}



int check_big()
{
    u_int16_t tmp = 1;
    u_int8_t *p;

    p =(u_int8_t *) &tmp;
    if(p[1] == 1)
        return 1;
    else
        return 0;




}

void parse_mac(uint8_t *str,uint8_t  *g_mac)
{
    u_int16_t mac[6];
    u_int8_t  *p;
    int i = 0;

    if(check_big()) {

        sscanf((void *)str,"%2hx:%2hx:%2hx:%2hx:%2hx:%2hx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

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
	char str[256] = {0};
	char *tmp = NULL;
	char *end = NULL;
	memset(str, 0, 256);

	sprintf(str, "showsysinfo  | grep MAC | awk -F':' '{print $2,$3,$4,$5,$6,$7 }'");
	fp = popen(str, "r");
	if (fp)
	{
		memset(str, 0, 256);
		fgets(str, sizeof(str), fp);

		tmp = strtok(str, " ");
		int i = 0;
		while (tmp)
		{
			self_state->ap_mac[i++] = strtol(tmp, &end, 16); 
			//printf("%02x\n", self_state->ap_mac[i-1]);
			tmp = strtok(NULL, " ");
		}

		pclose(fp);
	}
	else
	{
		syslog_err("%s-%d get ap base mac error\n", __func__, __LINE__);
		exit(-1);
	}
	
	return;
	
}

unsigned char get_product_type_code()
{
	char temp_str[100] = {0};
	char str_tmp[PATH_LEN];
	unsigned char str[PATH_LEN];
	unsigned char product_type = 0, i = 0;
	
	memset(temp_str, 0, 100);
	memset(str_tmp, 0 ,PATH_LEN);
	memset(str, 0, PATH_LEN);
	
	sprintf(temp_str, "partool -part mtd5 -show model");	
	PopenFile(temp_str, str_tmp, sizeof(str_tmp));
	strcpy((void *)&str, trim(str_tmp));
	
	syslog_debug("%s-%d ProductType= %s len= %d\n", __func__, __LINE__,  str, strlen((void *)&str));

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
	char str_tmp[PATH_LEN];
	unsigned char str[PATH_LEN];
	unsigned char software_version = 0;
	unsigned char *p = NULL;
	int config_ver=0;
	unsigned  char mod=0;
	
	memset(temp_str, 0, 100);
	memset(str_tmp, 0 ,PATH_LEN);
	memset(str, 0, PATH_LEN);
	
	sprintf(temp_str, "getrevnumber");	
	PopenFile(temp_str, str_tmp, sizeof(str_tmp));
	strcpy((void *)&str, trim(str_tmp));
	
	syslog_debug("%s-%d Config_Version= %s len= %d\n", __func__, __LINE__,  str, strlen((void *)&str));

	p = str;
	config_ver=atoi(p);
	if(config_ver!=0)
		mod= (config_ver % 0xff) +1;
	else
	   mod=0;
	syslog_debug("%s-%d Config_Version= %d,mod:%d\n", __func__, __LINE__,  config_ver,mod);
	
	return mod;
}

unsigned char Get_Software_Version()
{
	char temp_str[100] = {0};
	char str_tmp[PATH_LEN];
	unsigned char str[PATH_LEN];
	unsigned char software_version = 0;
	unsigned char *p = NULL;
	
	memset(temp_str, 0, 100);
	memset(str_tmp, 0 ,PATH_LEN);
	memset(str, 0, PATH_LEN);
	
	sprintf(temp_str, "showver");	
	PopenFile(temp_str, str_tmp, sizeof(str_tmp));
	strcpy((void *)&str, trim(str_tmp));
	
	syslog_debug("%s-%d Software_Version= %s len= %d\n", __func__, __LINE__,  str, strlen((void *)&str));

	p = str;
	
	software_version = *p - '0';
	
	syslog_debug("%s-%d Software_Version= %d\n", __func__, __LINE__,  software_version);
	
	return software_version;
}
void Get_Ap_Version(unsigned char *ap_version)
{
	char temp_str[100] = {0};
	char str_tmp[PATH_LEN];
	unsigned char str[PATH_LEN];
	
	memset(temp_str, 0, 100);
	memset(str_tmp, 0 ,PATH_LEN);
	memset(str, 0, PATH_LEN);
	
	sprintf(temp_str, "showver");	
	PopenFile(temp_str, str_tmp, sizeof(str_tmp));
	strcpy(str, trim(str_tmp));
	
	syslog_debug("%s-%d Software_Version= %s len= %d\n", __func__, __LINE__,  str, strlen(str));

	memcpy(ap_version, str, VERSION_MAX_LEN);
	
	syslog_debug("%s-%d Ap_Version= %s len= %d\n", __func__, __LINE__,  ap_version, strlen(ap_version));
}
void Get_Ap_Name(unsigned char *ap_name)
{
	char temp_str[100] = {0};
	char str_tmp[PATH_LEN];
	unsigned char str[PATH_LEN];
	
	memset(temp_str, 0, 100);
	memset(str_tmp, 0 ,PATH_LEN);
	memset(str, 0, PATH_LEN);
	
	sprintf(temp_str, "uci get system.sysinfo.hostname");	
	PopenFile(temp_str, str_tmp, sizeof(str_tmp));
	strcpy(str, trim(str_tmp));
	
	syslog_debug("%s-%d Ap_Name= %s len= %d\n", __func__, __LINE__,  str, strlen(str));

	memcpy(ap_name, str, AP_NAME_MAX_LEN);
	
	syslog_debug("%s-%d Ap_Name= %s len= %d\n", __func__, __LINE__,  ap_name, strlen(ap_name));
}

void Get_Configuration_State(unsigned char *state)
{
	char temp_str[100] = {0};
	char str_tmp[PATH_LEN];
	unsigned char str[PATH_LEN];
	
	memset(temp_str, 0, 100);
	memset(str_tmp, 0 ,PATH_LEN);
	memset(str, 0, PATH_LEN);
	
	sprintf(temp_str, "cat /tmp/configuration_state");	
	PopenFile(temp_str, str_tmp, sizeof(str_tmp));
	strcpy(str, trim(str_tmp));
	
	syslog_debug("%s-%d Configuration_State= %s len= %d\n", __func__, __LINE__,  str, strlen(str));

	memcpy(state, str, CONFIGURATION_STATE_LEN);
	
	syslog_debug("%s-%d Configuration_State= %s len= %d\n", __func__, __LINE__,  state, strlen(state));
}

void get_priority()
{
	//int set_priority = 0; //get from uci 
	//int conf_seq = 0;     // get from config file module 
	unsigned char product_type = 0; //default 0

	product_type = get_product_type_code();

	parse_mac(g_mac_str,g_mac);
	if(!memcmp(g_mac,self_state->ap_mac,MAC_LEN))
	{
		g_priority=1;
	}
	
	self_state->ap_priority.priority.priority = g_priority;
	self_state->ap_priority.priority.config_seq = Get_Config_Version();; 
	self_state->ap_priority.priority.product_type = product_type + Get_Software_Version();
	memcpy(self_state->ap_priority.priority.mac_tail, &self_state->ap_mac[3], 3);
	
	COPY_MEMORY(&(self_state->ap_priority.hap_priority), &(self_state->ap_priority.priority), sizeof(PRI));
}

void get_cluster_id()
{
	//int cluster_id = 0; // get from uci
	self_state->cluster_id = g_clusterId;
}


uint32_t get_ipaddr()
{
	char if_name[16] = "br-wan";
	int fd;
	struct sockaddr_in  sin;
	struct sockaddr_in  *net_mask;
	struct ifreq ifr;
	//uint8_t *ip = NULL;	
	 
	fd = socket(AF_INET, SOCK_DGRAM, 0);  
	if (fd == -1)
	{  
		syslog_debug("%s-%d socket error\n", __func__, __LINE__);  
		return  brast_ipaddr; 
	} 
	
	strncpy(ifr.ifr_name, if_name, 10);

	#if 0	
	// get netmask
	if (!(ioctl(fd, SIOCGIFNETMASK, &ifr)))
	{
		net_mask =(struct sockaddr_in *)&(ifr.ifr_netmask); 
		syslog_debug("netmask:%s\n",inet_ntoa(net_mask->sin_addr));
	}
	#endif

	//get brast
	if (!(ioctl(fd, SIOCGIFBRDADDR, &ifr)))
	{
		memcpy(&sin, &ifr.ifr_addr, sizeof(ifr.ifr_addr));
		syslog_debug("%s-%d brast:  %s\n", __func__, __LINE__, inet_ntoa(sin.sin_addr));
		brast_ipaddr = sin.sin_addr.s_addr;
	}
	
	if (ioctl(fd, SIOCGIFADDR, &ifr) == 0)    //SIOCGIFADDR 获取interface address  
	{
		memcpy(&sin, &ifr.ifr_addr, sizeof(ifr.ifr_addr));  
		syslog_debug("%s-%d self ip:  %s\n", __func__, __LINE__, inet_ntoa(sin.sin_addr));
		self_state->ap_ipaddr = sin.sin_addr.s_addr;
	} 
	else
	{
		syslog_err("%s-%d get ip failed\n", __func__, __LINE__);
	}
	
	close(fd);
	
	return brast_ipaddr;
}

inline int wlread_radio_count(void)
{
	char cmdbuf[128] = {0};
	char str_tmp[16] = {0};
	
	sprintf(cmdbuf, "uci get spec.wifi.count -c /etc/.system/");
	
	if (CW_FALSE == PopenFile(cmdbuf, str_tmp, sizeof(str_tmp)))
	{
		return CW_FALSE;
	}
	
	return atoi(str_tmp);
}

inline int devread_radio_count(void)
{
	char cmdbuf[128];
	char str_tmp[16];
	
	memset(cmdbuf, 0, sizeof(cmdbuf));
	sprintf(cmdbuf, "cat /proc/net/dev | grep wifi | wc -l");
	
	memset(str_tmp, 0, sizeof(str_tmp));
	if (CW_FALSE == PopenFile(cmdbuf, str_tmp, sizeof(str_tmp)))
	{
		return CW_FALSE;
	}
	
	return atoi(str_tmp);
}


int GetRadioMaxCount(void)
{
	int radio_count = 0;
	
	if (0 == (radio_count = wlread_radio_count()))
	{
		if (0 == (radio_count = devread_radio_count()))
		{
			radio_count = 2;
		}
	}

	if(radio_count > L_RADIO_NUM)
	{
		radio_count = L_RADIO_NUM;
	}
	
	return radio_count;
}


int get_channel(char *if_name)
{
	int channel;
	char cmd_str[128];
	char str_tmp[24];
	
	memset(cmd_str, 0, 128);
	sprintf(cmd_str, "iwlist %s channel | awk -F \" \" '/Current/ {print $5}' | awk -F \")\" '{print $1}'", if_name);
	PopenFile(cmd_str, str_tmp, sizeof(str_tmp));
	
	channel = atoi(str_tmp);
	
	return channel;
}


int get_txpower(char *if_name)
{
	int txpower;
	char cmd_str[128];
	char str_tmp[24];
	
	memset(cmd_str, 0, 128);
	sprintf(cmd_str, "iwlist %s txpower | awk -F \" \" '/Current/ {print $2 }' | awk -F \"=\" '{print $2}'", if_name);
	PopenFile(cmd_str, str_tmp, sizeof(str_tmp));
	
	txpower = atoi(str_tmp);
	
	return txpower;
}


void GetRadioInfo(void)
{
	int j = 0;
	char cmd_str[128] = {0};
	char str_tmp[24] = {0};
	
	if (!self_state)
	{
		syslog_err("%s-%d self_state= NULL\n", __func__, __LINE__);
		return;
	}
	
	self_state->radiocnt = GetRadioMaxCount();
	for (j = 0; j < self_state->radiocnt && j < L_RADIO_NUM; j++)
	{
		char if_name[16] = "athscan";
		sprintf(if_name+strlen(if_name), "%d", j);
		char if_name_ath[16] = "ath";
		sprintf(if_name_ath+strlen(if_name_ath), "%d", j);

	
		memset(cmd_str, 0, 128);
		memset(str_tmp, 0, 24);
		sprintf(cmd_str, "cat /proc/net/dev | grep %s | awk -F \":\" '{print $1}'", if_name);
		PopenFile(cmd_str, str_tmp, sizeof(str_tmp));

		if(0 == strcmp(str_tmp, if_name))
		{
			syslog_debug("%s-%d  athscan\n", __func__, __LINE__);
		}
		else
		{
			memset(cmd_str, 0, 128);
			memset(str_tmp, 0, 24);
			sprintf(cmd_str, "cat /proc/net/dev | grep %s | awk -F \":\" '{print $1}' | head -n 1", if_name_ath);
			PopenFile(cmd_str, str_tmp, sizeof(str_tmp));
			memset(if_name, 0, 16);
			memcpy(if_name, str_tmp, 16);

			syslog_debug("%s-%d  ath\n", __func__, __LINE__);
		}

		syslog_debug("%s-%d  if_name:%s\n", __func__, __LINE__, if_name);
		self_state->WTP_Radio[j].radioid = j;
		self_state->WTP_Radio[j].channel = get_channel(if_name);
		self_state->WTP_Radio[j].txpower = get_txpower(if_name);
		syslog_debug("%s-%d radio %d channel %d txpower %d\n",
					__func__, __LINE__, self_state->WTP_Radio[j].radioid,
					self_state->WTP_Radio[j].channel, self_state->WTP_Radio[j].txpower);
	}
}


inline int get_real_product_name(char *pd_name, unsigned int len)
{
	if ((NULL == pd_name) || (len < PATH_LEN))
	{
		return CW_FALSE;
	}
	
	char temp_str[100] = {0};
	char str_tmp[PATH_LEN];
	unsigned char str[PATH_LEN];
	memset(temp_str, 0, 100);
	
	sprintf(temp_str, "/usr/sbin/showsysinfo | awk -F \":\" '/Device Model/ {print $2}'");
	
	memset(str_tmp, 0 ,PATH_LEN);
	PopenFile(temp_str, str_tmp, sizeof(str_tmp));
	memset(str, 0, PATH_LEN);
	strcpy((void *)&str, trim(str_tmp));
	syslog_debug("%s-%d RealModel= %s len= %d\n", __func__, __LINE__,  str, strlen((void *)&str));
	memcpy(pd_name, str, strlen((void *)&str));
	
	return CW_TRUE;
}


inline int get_board_id(char *board_id, unsigned int len)
{
	if ((NULL == board_id) || (len < BOARD_ID_LEN))
	{
		return CW_FALSE;
	}
	
	char cmd_str[128];
	char res_str[PATH_LEN];
	unsigned char str[PATH_LEN];
	memset(cmd_str, 0, sizeof(cmd_str));
	
	sprintf(cmd_str, "/usr/sbin/showsysinfo | awk -F \":\" '/SN/ {print $2}'");
	
	memset(res_str, 0 , PATH_LEN);
	PopenFile(cmd_str, res_str, sizeof(res_str));
	memset(str, 0, PATH_LEN);
	strcpy((char *)str, trim(res_str));
	syslog_debug("%s-%d WTPBoardID= %s len= %d\n", __func__, __LINE__, str, strlen((void *)&str));
	memcpy(board_id, str, BOARD_ID_LEN);
	
	return CW_TRUE;
}


void get_state()
{
	self_state->ap_role = VC;
	self_state->ap_state = DISCOVERY;
	
	get_mac();
	get_ipaddr();
	get_cluster_id();
	get_priority();

	if (g_priority)
	{
		being_pvc();
	}
	
	GetRadioInfo();
	
	get_real_product_name(self_state->model, sizeof(self_state->model));
	get_board_id(self_state->SN, sizeof(self_state->SN));
}



int control_init_pipe( void )
{
	int fp = 0;
	mkfifo(PIPE_NAME, 0666);
	fp = open(PIPE_NAME, O_RDWR|O_NONBLOCK);
	return fp;
}

void cluster_init_pipe(void)
{
	int ret = 0;

	
	

	unlink(PIPE_NAME);
	
	if (!access(PIPE_NAME, F_OK))
	{
		syslog_warning("%s-%d access file exited! \n", __func__, __LINE__);
		system("rm -f  /tmp/cluster_mgt_pipe ");		
	}
	
	

	ret = mkfifo(PIPE_NAME, 0666);
	if(ret < 0)
	{
		syslog_err("%s-%d mkfifo PIPE_NAME errno:%d\n", __func__, __LINE__, errno);
		exit(1);
	}

	if_pipe = open(PIPE_NAME, O_RDWR);

	unlink(PIPE_CMD);
	if (!access(PIPE_CMD, F_OK))
	{
		syslog_warning("%s-%d access file exited! \n", __func__, __LINE__);
		system("rm -f  /tmp/cluster_cmd_pipe ");		
	}
	

	ret = mkfifo(PIPE_CMD, 0666);
	if(ret < 0)
	{
		syslog_err("%s-%d mkfifo PIPE_CMD errno:%d\n", __func__, __LINE__, errno);
		exit(1);
	}
}


void sig_handler(int sig)
{
     if (sig == SIGUSR1) {   // successed
        
         g_syncflag = 1;
        
         syslog_debug("%s-%d %s\n", __func__, __LINE__, "get USR1 from configd");
     }
	 else if(sig == SIGUSR2)  // failed  
	 {
		g_syncflag=2;
		 syslog_debug("%s-%d %s\n", __func__, __LINE__, "get USR2 from configd");
	 }
}

void sig_pipe_handler(int sig)
{

	cluster_init_pipe();
	syslog_warning("%s init  pipe again\n",__func__);
	
}


void  cluster_signal_init(void)
{

	 if ( signal(SIGUSR1, sig_handler) == SIG_ERR) {
			 syslog_debug("%s-%d %s\n", __func__, __LINE__, strerror(errno));
		 }

	 if ( signal(SIGUSR2, sig_handler) == SIG_ERR) {
			 syslog_debug("%s-%d %s\n", __func__, __LINE__, strerror(errno));
		 }

	 if ( signal(SIGPIPE, sig_pipe_handler) == SIG_ERR) {
			 syslog_debug("%s-%d %s\n", __func__, __LINE__, strerror(errno));
		 }
}

void cluster_init()
{
	pthread_mutex_init(&cluster_member_list_mutex, NULL);
	cluster_member_list.member_count = 0;
	cluster_member_list.cluster_member_list_head = NULL;
	int so_reuse = 1;
	int so_broadcast = 1;

	umask(0);

	cluster_socket_send = socket(PF_INET, SOCK_DGRAM, 0);
	if (cluster_socket_send < 0)
	{
		syslog_err("%s-%d create send socket error\n", __func__, __LINE__);
		exit(1);
	}
	
	setsockopt(cluster_socket_send, SOL_SOCKET, SO_BROADCAST, &so_broadcast, sizeof(so_broadcast));
	
	cluster_socket_recv = socket(AF_INET, SOCK_DGRAM, 0);
	if (cluster_socket_recv < 0)
	{
		syslog_err("%s-%d create recv socket error\n", __func__, __LINE__);
		exit(1);
	}

	struct sockaddr_in server_sockaddr;
 	server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_port = htons(cluster_recv_port);
    server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	setsockopt(cluster_socket_recv, SOL_SOCKET, SO_REUSEADDR, &so_reuse, sizeof(so_reuse));
//	setsockopt(cluster_socket_recv, SOL_SOCKET, SO_REUSEPORT, &so_reuse, sizeof(so_reuse));

	if (bind(cluster_socket_recv, (struct sockaddr *)&server_sockaddr, sizeof(server_sockaddr)) == -1)
    {
		syslog_err("%s-%d receive socket bind error\n", __func__, __LINE__);
		exit(1);
    }

    toBGSC.addr.sun_family = PF_UNIX;
    strcpy(toBGSC.addr.sun_path, BGSCAN_PATH); 
    toBGSC.addrlen = strlen(toBGSC.addr.sun_path) + sizeof(toBGSC.addr.sun_family);
	
	self_state = NULL;
	self_state = (P_AP_STAT)malloc(sizeof(AP_STAT));
	if (self_state != NULL)
	{
		memset(self_state, 0, sizeof(AP_STAT));
	}
	else
	{
		syslog_err("%s-%d malloc self_state error\n", __func__, __LINE__);
		exit(1);
	}
	
	pvc_state = NULL;
	pvc_state = (P_PVC_STAT)malloc(sizeof(PVC_STAT));
	if (pvc_state != NULL)
	{
		memset(pvc_state, 0, sizeof(PVC_STAT));
	}
	else
	{
		syslog_err("%s-%d malloc pvc_state error\n", __func__, __LINE__);
		exit(1);
	}
	
	get_state();
	
	cluster_mem_list = NULL;
	cluster_mem_list = (P_CLUSTER_MB_LIST)malloc(sizeof(CLUSTER_MB_LIST));
	if (cluster_mem_list != NULL)
	{
		memset(cluster_mem_list, 0, sizeof(CLUSTER_MB_LIST));
	}
	else
	{
		syslog_err("%s-%d malloc cluster_mem_list error\n", __func__, __LINE__);
		exit(1);
	}
	
	CLUSTER_MB *self = NULL;
	if ((self = self_add_cluster())!=NULL)
	{
		pthread_mutex_lock(&cluster_member_list_mutex);
		Insert_list_from_head(self);
		pthread_mutex_unlock(&cluster_member_list_mutex);
		
		syslog_debug("%s-%d self["MACSTR"] insert to member list\n", __func__, __LINE__, MAC2STR(self_state->ap_mac));
	}
	
	pthread_mutex_init(&elect_member_list_mutex, NULL);
	elect_member_list = NULL;
	elect_member_list = (P_ELECT_MB_LIST)malloc(sizeof(ELECT_MB_LIST));
	if (elect_member_list != NULL)
	{
		memset(elect_member_list, 0, sizeof(ELECT_MB_LIST));
	}
	else
	{
		syslog_err("%s-%d malloc elect_member_list error\n", __func__, __LINE__);
		exit(1);
	}
	
	pthread_mutex_lock(&elect_member_list_mutex);
	elect_mb_add(elect_member_list, self_state->ap_mac, self_state->ap_priority);
	pthread_mutex_unlock(&elect_member_list_mutex);

	cluster_init_pipe();
	if (if_pipe <= 0)
	{
		syslog_err("%s-%d open if_pipe error\n", __func__, __LINE__);
		exit(1);
	}


	cluster_signal_init();

	if ((!(InitSocket(&if_local_socket, DOMAIN_NAME)))
        || (!(InitSocket(&local_sock, DOMAIN2_NAME))))
    {
        syslog_err("%s-%d create local socket error\n", __func__, __LINE__);
        exit(1);
    }

	
	/* test code , for response member list 
	cluster_member_list->member_count = 2;
	char mac[6] = {0x01,0x02,0x03,0x04,0x05,0x06};
	memcpy(cluster_member_list->cluster_member[0].mac_addr, mac,6);
	cluster_member_list->cluster_member[0].cluster_state = RUN;
	cluster_member_list->cluster_member[0].cluster_role = PVC;

	mac[0] = 0x00;
	memcpy(cluster_member_list->cluster_member[1].mac_addr, mac,6);
	cluster_member_list->cluster_member[1].cluster_state = JOIN;
	cluster_member_list->cluster_member[1].cluster_role = VC;
	*/
}


void load_config()
{
	return;
}

#if 1  // open by cxq

static int arp_set(int ipaddr, uint8_t *mac)
 {
     struct arpreq arpreq;
     struct sockaddr_in *sin;
	 struct sockaddr_in ip;
     struct in_addr ina;
     int flags;
     int rc;

 	ip.sin_addr.s_addr= ipaddr;
     syslog_debug("set arp entry for IP:%s\tMAC:%02x:%02x:%02x:%02x:%02x:%02x\n", inet_ntoa(ip.sin_addr), mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
 
     /*you must add this becasue some system will return "Invlid argument"
        because some argument isn't zero */
     memset(&arpreq, 0, sizeof(struct arpreq));
     sin = (struct sockaddr_in *) &arpreq.arp_pa;
     memset(sin, 0, sizeof(struct sockaddr_in));
     sin->sin_family = AF_INET;
     ina.s_addr = ipaddr;
     memcpy(&sin->sin_addr, (char *) &ina, sizeof(struct in_addr));
     memcpy((unsigned char *) arpreq.arp_ha.sa_data,mac,MAC_LEN);
     strcpy(arpreq.arp_dev, "br-wan");
 
     flags = ATF_PERM | ATF_COM; //note, must set flag, if not,you will get error
 
     arpreq.arp_flags = flags;
 
     rc = ioctl(arp_sock, SIOCSARP, &arpreq);
     if (rc < 0)
     {
         syslog_err("%s\n", "set arp error...");
         return -1;
     } else
        syslog_debug("%s\n", "set arp successfully");

    return 0;
 }


static int arp_del(int ipaddr)
 {
     struct arpreq arpreq;
     struct sockaddr_in *sin;
	  struct sockaddr_in ip;
     struct in_addr ina;
     //int flags;
     int rc;
 	ip.sin_addr.s_addr = ipaddr;
     syslog_debug("del arp entry for IP:%s\n", inet_ntoa(ip.sin_addr));
 
     /*you must add this becasue some system will return "Invlid argument"
        because some argument isn't zero */
     memset(&arpreq, 0, sizeof(struct arpreq));
     sin = (struct sockaddr_in *) &arpreq.arp_pa;
     memset(sin, 0, sizeof(struct sockaddr_in));
     sin->sin_family = AF_INET;
     ina.s_addr = ipaddr;
     memcpy(&sin->sin_addr, (char *) &ina, sizeof(struct in_addr));
     strcpy(arpreq.arp_dev, "br-wan");
 

     rc = ioctl(arp_sock, SIOCDARP, &arpreq);
     if (rc < 0)
     {
         syslog_warning("%s\n", "del arp error...");
         return -1;
     } else
        syslog_debug("%s\n", "del arp successfully");

    return 0;
 }



void  save_pvc_ip(void)
{
	char cmd[256]={0};
	char addr_p[16] = {0};
	struct in_addr addr_n;
	
	addr_n.s_addr = pvc_state->pvc_ipaddr;
	
	if (inet_ntop(AF_INET, &addr_n, addr_p, (socklen_t )sizeof(addr_p)) == NULL)
	{
		memcpy(addr_p, "0.0.0.0", 7);
	}

	//  pvc :1 vc:3 svc:2
	sprintf(cmd, "echo %d:%s:%d  > /tmp/pvc-info ",self_state->ap_role,addr_p,self_state->ap_state);
	system(cmd);
	
}




void update_pvc_state(RSCP_format *packet, int ipaddr)
{
	int count = 0, i = 0;
	// set static  arp  
	arp_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(arp_sock < 0)
		syslog_err("create arp socket error  \n");
	else
	{
		if(pvc_state->pvc_ipaddr != ipaddr)
		{
			arp_del(pvc_state->pvc_ipaddr);
			arp_set(ipaddr,packet->mac);
			pvc_state->pvc_ipaddr = ipaddr;
			save_pvc_ip();
		}

		close(arp_sock);
	}
	
	pvc_state->pvc_ipaddr = ipaddr;
	pvc_state->pvc_priority.priority.priority = packet->priority;
	pvc_state->pvc_priority.priority.config_seq = packet->config_sequence;
	pvc_state->pvc_priority.priority.product_type = packet->product_type;
	memcpy(pvc_state->pvc_priority.priority.mac_tail, &packet->mac[3], 3);
	
	pvc_state->pvc_state = RUN;
	memcpy(pvc_state->pvc_mac, packet->mac, MAC_LEN);
	
	count= packet->count;
	for (i = 0; i < count; i++)
	{
		if (packet->cluster_member[i].role == SVC)
		{
			memcpy(pvc_state->svc_mac, packet->cluster_member[i].mac, MAC_LEN);
			break;
		}
	} 	
	
	svc_timer = 0;
	pvc_state->timer = 0;
	send_rsrp();

	
}


void send_dbcp(void)
{
	int j = 0;
	int ret = 0;
	u_int8_t buffer[1048] = {0};
	struct sockaddr_in recv_addr;
	DBCP_format dbcp;
	
	recv_addr.sin_family = AF_INET;
	recv_addr.sin_addr.s_addr = get_ipaddr();//inet_addr("192.168.100.255");
	recv_addr.sin_port = htons(cluster_send_vc_port);

	memset(&dbcp, 0, sizeof(DBCP_format));
	dbcp.head.protocolType = DBCP;
	dbcp.head.clusterID = self_state->cluster_id;
	dbcp.priority = self_state->ap_priority.priority.priority;
	dbcp.config_sequence = self_state->ap_priority.priority.config_seq;
	dbcp.product_type = self_state->ap_priority.priority.product_type;
	memcpy(dbcp.mac, self_state->ap_mac, MAC_LEN);
	dbcp.state = self_state->ap_state;
	dbcp.radiocnt = self_state->radiocnt;
	
	for (j = 0; j < dbcp.radiocnt && j < L_RADIO_NUM; j++)
	{		
		dbcp.WTP_Radio[j].radioid = self_state->WTP_Radio[j].radioid;
		dbcp.WTP_Radio[j].channel = self_state->WTP_Radio[j].channel;
		dbcp.WTP_Radio[j].txpower = self_state->WTP_Radio[j].txpower;
	}
	
	Assemble_DBCP((char *)buffer, &dbcp);

	ret = sendto(cluster_socket_send, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr*)&recv_addr, sizeof(recv_addr));
	syslog_debug("%s ret= %d errno:%d\n",__func__, ret, errno);
}



void send_rsrp(void)
{
	u_int8_t buffer[1048] = {0};
	struct sockaddr_in recv_addr;
	RSRP_format rsrp;
	int i = 0;
	
	memset(&rsrp,0,sizeof(RSRP_format));
	GetRadioInfo();
	recv_addr.sin_family = AF_INET;
	recv_addr.sin_addr.s_addr = pvc_state->pvc_ipaddr;  
	recv_addr.sin_port = htons(cluster_send_pvc_port);

	/* init  rsrp proto node  */
	rsrp.head.protocolType = RSRP;
	rsrp.head.clusterID = self_state->cluster_id;
	rsrp.priority = self_state->ap_priority.priority.priority;
	rsrp.config_sequence = self_state->ap_priority.priority.config_seq = Get_Config_Version();
	rsrp.product_type = self_state->ap_priority.priority.product_type;
	rsrp.state =  self_state->ap_state;
	get_ipaddr();
	rsrp.ip  =  self_state->ap_ipaddr;
	// txpower info
	rsrp.radiocnt  = self_state->radiocnt;
	for (i = 0; i < rsrp.radiocnt && i < L_RADIO_NUM; i++)
	{
		rsrp.WTP_Radio[i].channel = self_state->WTP_Radio[i].channel;
		rsrp.WTP_Radio[i].radioid = self_state->WTP_Radio[i].radioid;
		rsrp.WTP_Radio[i].txpower = self_state->WTP_Radio[i].txpower;
	}
	#if 0
	int count =  rsrp.radiocnt;
	for (i = 0; i < count ; i++)
	{
		printf("mgt rsrp recv radio:  %d(channel),%d(rid),%d(txpower)-------------\n",rsrp.WTP_Radio[i].channel,rsrp.WTP_Radio[i].radioid,rsrp.WTP_Radio[i].txpower);
	}
#endif  
	memcpy(rsrp.mac, self_state->ap_mac, MAC_LEN);

	Get_Ap_Version(rsrp.ap_version);
	Get_Ap_Name(rsrp.ap_name);

	Assemble_RSRP((char *)buffer, &rsrp);

	int val = sendto(cluster_socket_send, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr*)&recv_addr, sizeof(recv_addr));
	
	syslog_debug("%s-%d send rsrp :%d, errno:%d\n", __func__, __LINE__, val, errno);
}


void rsrp_send( void)
{
	send_rsrp();
    
	rsrp_timer_id =	timer_add(cluster_rsrp_interval, 0, (void *)&rsrp_send, NULL);
}

void rsrp_run_send( void)
{
	send_rsrp();
    
	rsrp_timer_run_id =	timer_add(cluster_rsrp_interval, 0, (void *)&rsrp_run_send, NULL);
}

void discovery_send(void)
{
	send_dbcp();
	
	pthread_mutex_lock(&elect_member_list_mutex);
	elect_mb_aging(elect_member_list);
	pthread_mutex_unlock(&elect_member_list_mutex);

	//show_mb_mac(elect_member_list);

	dbcp_timer_id = timer_add(cluster_dbcp_interval, 0, (void *)&discovery_send, NULL);
}


CWBool bigest_priority(void)
{
	pthread_mutex_lock(&elect_member_list_mutex);
	
	if (self_state == NULL
		|| elect_member_list == NULL
		|| elect_member_list->ptr_elect_mb == NULL)
	{
		pthread_mutex_unlock(&elect_member_list_mutex);
		
		syslog_debug("%s-%d param= NULL\n", __func__, __LINE__);
		
		return CW_FALSE;
	}
	
	syslog_debug("%s-%d self mac= "MACSTR"\n", __func__, __LINE__, MAC2STR(self_state->ap_mac));
	
	syslog_debug("%s-%d elect mac= "MACSTR"\n", __func__, __LINE__, MAC2STR(elect_member_list->ptr_elect_mb->mac_addr));
	
	if (mac_is_equal(elect_member_list->ptr_elect_mb->mac_addr, self_state->ap_mac))
	{
		pthread_mutex_unlock(&elect_member_list_mutex);
		
		return CW_TRUE;
	}
	
	pthread_mutex_unlock(&elect_member_list_mutex);
	
	return CW_FALSE;
}


void report_to_PVC_mode(void)
{
	int fd = -1;

	save_pvc_ip();
	
	if ((fd = open(CLUSTER_FIFO, O_WRONLY | O_NONBLOCK)) < 0)
	{
		syslog_err("%s-%d open fifo fail\n", __func__, __LINE__);
		return;
	}
	
	syslog_warning("vc/svc  to being pvc!\n");
	write(fd, "pvc", 3);
	
	close(fd);
}


void clean_pvc_prio(void)
{
	//int prio=0;
	char cmd[256]={0};
	sprintf(cmd, "cluster-cfg   set cluster.cluster.cluster_priority='ff:ff:ff:ff:ff:ff' ");
	system(cmd);
	self_state->ap_priority.priority.priority = g_priority = 0;
}


void report_to_VC_mode(void)
{
	int fd = -1;

	save_pvc_ip();
	
	if ((fd = open(CLUSTER_FIFO, O_WRONLY)) < 0)
	{
		syslog_err("%s-%d open fifo fail\n", __func__, __LINE__);
		return;
	}

	syslog_warning("pvc  to being  vc!\n");
	write(fd, "vc", 3);
	
	close(fd);
}


void being_pvc()
{
	self_state->ap_role = PVC;
	memcpy(pvc_state->pvc_mac, self_state->ap_mac, MAC_LEN);
	pvc_state->pvc_ipaddr = self_state->ap_ipaddr;
	pvc_state->pvc_priority.priority.priority = self_state->ap_priority.priority.priority;
	pvc_state->pvc_priority.priority.config_seq = self_state->ap_priority.priority.config_seq;
	pvc_state->pvc_priority.priority.product_type  = self_state->ap_priority.priority.product_type;
	memcpy(pvc_state->pvc_priority.priority.mac_tail, &self_state->ap_mac[3], 3);
	pvc_state->pvc_priority.hap_priority = self_state->ap_priority.hap_priority;
	pvc_state->pvc_state = CHECK;
	pvc_state->timer = 0;
	self_state->ap_state = CHECK;
	report_to_PVC_mode();
}

void svc_being_pvc()
{
	self_state->ap_role = PVC;
	memcpy(pvc_state->pvc_mac, self_state->ap_mac, MAC_LEN);
	pvc_state->pvc_ipaddr = self_state->ap_ipaddr;
	pvc_state->pvc_priority.priority.priority = self_state->ap_priority.priority.priority;
	pvc_state->pvc_priority.priority.config_seq = self_state->ap_priority.priority.config_seq;
	pvc_state->pvc_priority.priority.product_type  = self_state->ap_priority.priority.product_type;
	memcpy(pvc_state->pvc_priority.priority.mac_tail, &self_state->ap_mac[3], 3);
	
	self_state->ap_state = RUN; 
	report_to_PVC_mode();
}

void discovery_time_up(void)
{
	if (bigest_priority())
	{
		syslog_warning("%s....being pvc! self has bigest prority!\n",__func__);
		being_pvc();
	}
	else
	{
		times_up_id = timer_add(cluster_discovry_limit, 0, (void *)&discovery_time_up, NULL);
	}

	syslog_debug("%s-%d self state= %d(%s)\n", __func__, __LINE__, self_state->ap_state, STATE_STR(self_state->ap_state));
}


void join_ageing_timer(void)
{
	if (pvc_state->timer > 2)
	{
		self_state->ap_state = DISCOVERY;
		TimerCancel(&rsrp_timer_id, 1);
		syslog_warning("%s-%d vc/svc join timeout to discovery\n", __func__, __LINE__);
	}
	else
	{
		pvc_state->timer++;
		join_ageing_id = timer_add(cluster_join_ageing_interval, 0, (void *)&join_ageing_timer, NULL);
	}
}
//discovery state: elect PVC
CLUSTER_STATE Enter_Discovery()
{
	int ret = 0;
	fd_set rd;
	u_int8_t buffer[1048] = {0};
	struct sockaddr_in addr;
	struct timeval tv;
	Hccp_Protocol_Struct packet;
	CLUSTER_PRI prio;
	prio.hap_priority = 0;
	int addr_len = sizeof(struct sockaddr_in);
	
	dbcp_timer_id = timer_add(cluster_dbcp_interval, 0, (void *)&discovery_send, NULL);
	if(dbcp_timer_id <0)
	{
		syslog_err("timer_add  dbcp_timer  failed!\n");
		dbcp_timer_id = timer_add(cluster_dbcp_interval, 0, (void *)&discovery_send, NULL);
	}
	times_up_id = timer_add(cluster_discovry_limit, 0, (void *)&discovery_time_up, NULL);
	if(times_up_id < 0)
	{
		syslog_err("timer_add  up_timer  failed!\n");	
		times_up_id = timer_add(cluster_discovry_limit, 0, (void *)&discovery_time_up, NULL);
	}

	while (1)
	{
		FD_ZERO(&rd);
		FD_SET(cluster_socket_recv, &rd);
		
		memset(buffer, 0, sizeof(buffer));
		tv.tv_sec = 2;
		tv.tv_usec =  0;

		ret = select(cluster_socket_recv + 1, &rd, NULL, NULL, &tv);
		if (ret > 0)
		{
			if (FD_ISSET(cluster_socket_recv, &rd))
			{
				//syslog_debug("discovery  recv packet\n");

				//必须用非阻塞，否则无法跳出discovery 状态
				recvfrom(cluster_socket_recv, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&addr, (void *)&addr_len);

				Parse_HCCPProtocol((void *)&buffer, &packet);
				int type = packet.type;

				//syslog_debug("discovery ready type:%d\n", type);
				if (packet.u.dbcp.head.clusterID != self_state->cluster_id)
				{
					syslog_debug("cluster_id: discovery recv cluster_id:%d, self cluster_id :%d\n",packet.u.dbcp.head.clusterID,self_state->cluster_id);
					continue;
				}

				switch(type)
				{
					case DBCP:
					{
						syslog_debug("%s-%d recv dbcp "MACSTR"\n", __func__, __LINE__, MAC2STR(packet.u.dbcp.mac));
						//show_mb_mac(elect_member_list);
						memset(&prio, 0, sizeof(CLUSTER_PRI));
						prio.priority.priority = packet.u.dbcp.priority;
						prio.priority.config_seq = packet.u.dbcp.config_sequence;
						prio.priority.product_type = packet.u.dbcp.product_type;
						memcpy(prio.priority.mac_tail, &packet.u.dbcp.mac[3], 3);
						COPY_MEMORY(&prio.hap_priority, &prio.priority, sizeof(PRI));
						
						pthread_mutex_lock(&elect_member_list_mutex);
						elect_mb_add(elect_member_list, packet.u.dbcp.mac, prio);
						pthread_mutex_unlock(&elect_member_list_mutex);
						
						pthread_mutex_lock(&cluster_member_list_mutex);
						add_member_list(&packet);
						pthread_mutex_unlock(&cluster_member_list_mutex);

						syslog_debug("%s-%d add/update "MACSTR"\n", __func__, __LINE__, MAC2STR(packet.u.dbcp.mac));

						break;
					}
					case RSCP:
					{
						if (self_state->ap_role !=PVC)
						{
							self_state->ap_state = JOIN;
						}
						syslog_warning("%s-%d recv rscp goto join & update pvc state\n", __func__, __LINE__);
						update_pvc_state(&packet.u.rscp,addr.sin_addr.s_addr); // ip?
                       
						break;
					}
					default:
					{
						break;
					}
				}
			}
		}
		if (self_state->ap_state != DISCOVERY)
		{
			char str[BUF_SIZE] = {0};
			syslog_warning("%s-%d state= %s\n", __func__, __LINE__, dump_state(str, self_state->ap_state));
			TimerCancel(&dbcp_timer_id, 1);
			TimerCancel(&times_up_id, 1);
			
			pthread_mutex_lock(&elect_member_list_mutex);
			elect_mb_clean(elect_member_list);
			pthread_mutex_unlock(&elect_member_list_mutex);
			
			syslog_warning("%s-%d remove timer & clean member list\n", __func__, __LINE__);
			break;
		}
	}
	
	return self_state->ap_state;
}


CWBool has_self_mac(RSCP_format *rscp)
{
	int conut = 0, i = 0;
	RSCP_cluster_member *tmp = NULL;

	if (!rscp)
	{
		return CW_FALSE;
	}
	
	tmp = (rscp->cluster_member);
	conut = rscp->count;
	
	for (i = 0; i < conut; i++)
	{
		if (!memcmp(tmp[i].mac, self_state->ap_mac, MAC_LEN))
		{
			return CW_TRUE;
		}
	}
	
	return CW_FALSE;
}


//join state: waiting for rscp, if it is include mac address itself, go into run state;else still waiting
CLUSTER_STATE Enter_Join()
{
	int ret = 0;
	fd_set rd;
	u_int8_t buffer[1048] = {0};
	struct sockaddr_in addr;
	struct timeval tv;
	Hccp_Protocol_Struct packet;
	int addr_len = sizeof(struct sockaddr_in);

	save_pvc_ip();
	
	rsrp_timer_id = timer_add(cluster_rsrp_interval, 0, (void *)&rsrp_send, NULL);
	if(rsrp_timer_id < 0)
	{
		syslog_err("timer_add  rsrp_timer  failed!\n");
		rsrp_timer_id = timer_add(cluster_rsrp_interval, 0, (void *)&rsrp_send, NULL);

	}
	
	//  add timer  if  timeout 120s  join  -->discovery 
	join_ageing_id = timer_add(cluster_join_ageing_interval, 0, (void *)&join_ageing_timer, NULL);
    if(join_ageing_id < 0)
	{
		syslog_err("timer_add  join_ageing_timer  failed!\n");
		join_ageing_id = timer_add(cluster_join_ageing_interval, 0, (void *)&join_ageing_timer, NULL);
	}

	syslog_warning("%s-%d\n", __func__, __LINE__);
	
	while (1)
	{
		FD_ZERO(&rd);
		FD_SET(cluster_socket_recv, &rd);
		
		memset(buffer, 0, sizeof(buffer));
		tv.tv_sec = 10;
		tv.tv_usec =  0;
		
		ret = select(cluster_socket_recv + 1, &rd, NULL, NULL, &tv);
		if (ret > 0)
		{
			if (FD_ISSET(cluster_socket_recv, &rd))
			{
				//必须用非阻塞，否则无法立即跳出Join 状态
				recvfrom(cluster_socket_recv, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&addr, (void *)&addr_len);

				Parse_HCCPProtocol((void *)&buffer, &packet);
				int type = packet.type;

				if (packet.u.dbcp.head.clusterID != self_state->cluster_id)
				{
					syslog_debug("cluster_id: join recv cluster_id:%d, self cluster_id :%d\n",packet.u.dbcp.head.clusterID,self_state->cluster_id);
					continue;
				}

				switch(type)
				{
					case RSCP:
					{
						syslog_debug("%s-%d recv rscp update pvc state\n", __func__, __LINE__);
						update_pvc_state(&packet.u.rscp,addr.sin_addr.s_addr);

						if (has_self_mac(&packet.u.rscp))
						{
							self_state->ap_state = CHECK;
							
							pthread_mutex_lock(&cluster_member_list_mutex);
							update_member_list(&packet);
							pthread_mutex_unlock(&cluster_member_list_mutex);
							
							syslog_warning("%s-%d state check update member list\n", __func__, __LINE__);
						}
						
						break;
					}
					default:
					{
						break;
					}
				}
			}
		}
		
		if (self_state->ap_state != JOIN)
		{
			syslog_warning("%s-%d remove timer join ageing timer\n", __func__, __LINE__);
			TimerCancel(&join_ageing_id, 1);
			return self_state->ap_state;
		}
	}
}




CLUSTER_STATE Enter_check()
{
	char str[256] = {0};
	int sync_ok=0;

	syslog_debug("%s-%d\n", __func__, __LINE__);

	memset(str, 0, 256);
	
	unsigned char state[CONFIGURATION_STATE_LEN];
	memset(state, 0, CONFIGURATION_STATE_LEN);
	Get_Configuration_State(state);
	
	if(strcmp(state, "NONE") == 0)
	{
		syslog_warning("%s-%d NONE\n", __func__, __LINE__);
	}
	else if(strcmp(state, "ZTP") == 0)
	{
		system("bg-s -x single=1 &");
		syslog_warning("%s-%d enter run ztp \n", __func__, __LINE__);
		TimerCancel(&rsrp_timer_id,1);
		send_rsrp();
		return RUN;
	}

	save_pvc_ip();

	if(self_state->ap_role !=PVC)
	{

		 syslog_debug("%s-%d send usr1  signal\n", __func__, __LINE__);
		 if (system("kill -USR1 `pidof configd`") < 0) {
			 syslog_warning("%s-%d %s\n", __func__, __LINE__, strerror(errno));
			 TimerCancel(&rsrp_timer_id,1);
			 sleep(1);
			 return JOIN;
		 }

		 while (1) {
			 pause();

			 if (g_syncflag == 1) {
				 g_syncflag = 0;
				 sync_ok=1;		
			 }
			 else if(g_syncflag == 2)
			 {
				 g_syncflag = 0;
				 sync_ok=0;		
			 }
			 break;
		 }
	}
	else
	{
		sync_ok=1;
	}


	if (sync_ok==1)
	{
        system("bg-s -x single=1 &");
		syslog_debug("%s-%d enter run\n", __func__, __LINE__);
		TimerCancel(&rsrp_timer_id,1);
		send_rsrp();
		return RUN;
	}
	else
	{
		pthread_mutex_lock(&cluster_member_list_mutex);
		cleanup_member_list();
		pthread_mutex_unlock(&cluster_member_list_mutex);
		syslog_warning("%s-%d config sync error & cleanup member list\n", __func__, __LINE__);
		//system("reboot");
		
		{
			TimerCancel(&rsrp_timer_id,1);
			sleep(1);
			return JOIN;
		}
	}
}



void send_rirp(void)
{
	int i = 0, j = 0, ret = 0;
	u_int8_t buffer[1048]= {0};
	struct sockaddr_in recv_addr;
	RIRP_format rirp;
	RF_environment RFInfo;

	memset(&rirp,0,sizeof(RIRP_format));

	pthread_mutex_lock(&cluster_member_list_mutex);
	Fill_RIRP_Data(&RFInfo);
	pthread_mutex_unlock(&cluster_member_list_mutex);
	
	recv_addr.sin_family = AF_INET;
	recv_addr.sin_addr.s_addr = pvc_state->pvc_ipaddr;
	recv_addr.sin_port = htons(cluster_send_pvc_port);
	
	/* init  rsrp proto node  */
	rirp.head.protocolType = RIRP;
	rirp.head.clusterID = self_state->cluster_id;
	rirp.head.protocolType =  RIRP;
	memcpy(rirp.mac, self_state->ap_mac, MAC_LEN);

	/* neighbor_count */
	rirp.neighbor_count = RFInfo.neighbor_cnt;
	for (i = 0; i < rirp.neighbor_count; i++)
	{
		memcpy(rirp.cluster_neighbor[i].mac, RFInfo.rssi_of_others[i].ap_base_mac, MAC_LEN);
		rirp.cluster_neighbor[i].radiocnt = RFInfo.rssi_of_others[i].radiocnt;
		
		for (j = 0; j < rirp.cluster_neighbor[i].radiocnt; j++)
		{
			rirp.cluster_neighbor[i].WTP_Radio[j].radioid = RFInfo.rssi_of_others[i].ap_radio[j].radioid;
			rirp.cluster_neighbor[i].WTP_Radio[j].channel = RFInfo.rssi_of_others[i].ap_radio[j].channel;
			rirp.cluster_neighbor[i].WTP_Radio[j].txpower = (unsigned char)RFInfo.rssi_of_others[i].ap_radio[j].txpower;
			rirp.cluster_neighbor[i].WTP_Radio[j].rssi = RFInfo.rssi_of_others[i].ap_radio[j].rssi;
		}
	}
	
	Assemble_RIRP((void *)&buffer, &rirp);
	
	ret = sendto(cluster_socket_send, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr*)&recv_addr, sizeof(recv_addr));
	syslog_debug("%s ret= %d errno:%d\n", __func__, ret, errno);
}


void rirp_send( void )
{
	send_rirp();
	
	times_up_id = timer_add(cluster_rirp_interval, 0, (void *)&rirp_send, NULL);
}

void  send_rscp(void)
{
	int i = 0;
	u_int8_t buffer[1048] = {0};
	struct sockaddr_in recv_addr;
	RSCP_format rscp;

	memset(&rscp,0,sizeof(RSCP_format));
	recv_addr.sin_family = AF_INET;
	recv_addr.sin_addr.s_addr = htonl(INADDR_ANY);  //
	recv_addr.sin_port = htons(cluster_recv_port);
	
	/* init  rscp proto node  */
	rscp.head.clusterID = self_state->cluster_id;
	rscp.priority = self_state->ap_priority.priority.priority;
	rscp.config_sequence = self_state->ap_priority.priority.config_seq;
	rscp.product_type = self_state->ap_priority.priority.product_type;
	memcpy(rscp.mac, self_state->ap_mac, MAC_LEN);
	
	/* count */
	rscp.count = cluster_mem_list->member_count;
	for (i = 0; i < rscp.count; i++)
	{
		rscp.cluster_member[i].role = cluster_mem_list->cluster_member[i].role;
		rscp.cluster_member[i].state = cluster_mem_list->cluster_member[i].status;
		memcpy(rscp.cluster_member[i].mac, cluster_mem_list->cluster_member[i].mac_addr, MAC_LEN);
	}
	
	Assemble_RSCP((void *)&buffer, &rscp);
	
	sendto(cluster_socket_send, buffer, sizeof(buffer), 0, (struct sockaddr*)&recv_addr, sizeof(recv_addr));
}


void rscp_send( void)
{
	send_rscp();
	
	timer_add(cluster_rscp_interval, 0, (void *)&rscp_send, NULL);
}


CWBool the_same_cluster_id(RSCP_format *rscp)
{
	if (rscp->head.clusterID != self_state->cluster_id)
	{
		syslog_debug("cluster_id:  run recv cluster_id:%d, self cluster_id :%d\n",rscp->head.clusterID,self_state->cluster_id);
		return CW_FALSE;
	}
	
	return CW_TRUE;
}

//**********************************
CLUSTER_MB *Search_list_by_mac(unsigned char *mac)
{
	CLUSTER_MB *p = cluster_member_list.cluster_member_list_head;
	while (p != NULL)
	{
		if (mac_is_equal(p->mac_addr, mac))
		{
			return p;
		}
		p = p->next;
	}
	return NULL;
}

void Insert_list_from_head(CLUSTER_MB *new)
{
	if (NULL == new)
	{
		return ;
	}
	
	new->next = cluster_member_list.cluster_member_list_head;
	cluster_member_list.cluster_member_list_head = new;
	cluster_member_list.member_count++;
}

void Delete_list(CLUSTER_MB *del)
{
	CLUSTER_MB *p = cluster_member_list.cluster_member_list_head;
	CLUSTER_MB *q = p;

	while (p != NULL)
	{
		if (p == del)
		{
			if (p == cluster_member_list.cluster_member_list_head)
			{
				cluster_member_list.cluster_member_list_head = p->next;
			}
			else
			{
				q->next = p->next;
			}
			FREE_OBJECT(p);
			
			break;
		}
		q = p;
		p = p->next;
	}
	cluster_member_list.member_count--;
}


CLUSTER_MB *self_add_cluster(void)
{
	int j = 0;
	CLUSTER_MB *self = NULL;
	
	self = (CLUSTER_MB*)malloc(sizeof(CLUSTER_MB));
	if (self == NULL)
	{
		syslog_debug("%s-%d malloc failed\n", __func__, __LINE__);
	}
	else
	{
		memset(self, 0, sizeof(CLUSTER_MB));
		self->next = NULL;
		self->clusterID = g_clusterId;
		self->role = VC;
		self->status = DISCOVERY;
		self->ipaddr = self_state->ap_ipaddr;
		memcpy(self->mac_addr, self_state->ap_mac, MAC_LEN);
		memcpy(&(self->priority), &(self_state->ap_priority), sizeof(CLUSTER_PRI));
		self->radiocnt = self_state->radiocnt;
		syslog_debug("%s-%d add "MACSTR" %d radio(s)\n",
					__func__, __LINE__, MAC2STR(self->mac_addr), self->radiocnt);
		
		for (j = 0; j < self->radiocnt && j < L_RADIO_NUM; j++)
		{
			self->WTP_Radio[j].radioid = self_state->WTP_Radio[j].radioid;
			self->WTP_Radio[j].channel = self_state->WTP_Radio[j].channel;
			self->WTP_Radio[j].txpower = self_state->WTP_Radio[j].txpower;
			memcpy(self->WTP_Radio[j].radio_mac, self->mac_addr, MAC_LEN);
			if (1 == j)
			{
				self->WTP_Radio[j].radio_mac[5] += 0x08;
			}
		}
	}
	return self;
}

int add_member_list(Hccp_Protocol_Struct *dbcp)
{
	unsigned char j = 0;
	CLUSTER_MB *p = NULL;
	
	p = Search_list_by_mac(dbcp->u.dbcp.mac);
	if (p == NULL)
	{
		CLUSTER_MB *new = (CLUSTER_MB*)malloc(sizeof(CLUSTER_MB));
		if (new == NULL)
		{
			syslog_debug("%s-%d new malloc failed\n", __func__, __LINE__);
		}
		else
		{
			memset(new, 0, sizeof(CLUSTER_MB));
			new->next = NULL;
			new->role = VC;
			new->clusterID = dbcp->u.dbcp.head.clusterID;
			new->status = dbcp->u.dbcp.state;
			new->priority.priority.priority = dbcp->u.dbcp.priority;
			new->priority.priority.config_seq = dbcp->u.dbcp.config_sequence;
			new->priority.priority.product_type = dbcp->u.dbcp.product_type;
			memcpy(new->priority.priority.mac_tail, &dbcp->u.dbcp.mac[3], 3);
			
			COPY_MEMORY(&(new->priority.hap_priority), &(new->priority.priority), sizeof(PRI));
			
			memcpy(new->mac_addr, dbcp->u.dbcp.mac, MAC_LEN);
			new->radiocnt = dbcp->u.dbcp.radiocnt;
			syslog_debug("%s-%d add "MACSTR" %d radio(s)\n",
						__func__, __LINE__, MAC2STR(new->mac_addr), new->radiocnt);
			
			for (j = 0; j < new->radiocnt && j < L_RADIO_NUM; j++)
			{
				new->WTP_Radio[j].radioid = dbcp->u.dbcp.WTP_Radio[j].radioid;
				new->WTP_Radio[j].channel = dbcp->u.dbcp.WTP_Radio[j].channel;
				new->WTP_Radio[j].txpower = dbcp->u.dbcp.WTP_Radio[j].txpower;
				memcpy(new->WTP_Radio[j].radio_mac, new->mac_addr, MAC_LEN);
				if (1 == j)
				{
					new->WTP_Radio[j].radio_mac[5] += 0x08;
				}
				syslog_debug("%s-%d radio %d channel %d txpower %d\n",
							__func__, __LINE__, new->WTP_Radio[j].radioid,
							new->WTP_Radio[j].channel, new->WTP_Radio[j].txpower);
			}
			
			Insert_list_from_head(new);
		}
	}
	else
	{
		p->status = dbcp->u.dbcp.state;
		p->priority.priority.priority = dbcp->u.dbcp.priority;
		p->priority.priority.config_seq = dbcp->u.dbcp.config_sequence;
		p->priority.priority.product_type = dbcp->u.dbcp.product_type;
		memcpy(p->priority.priority.mac_tail, &dbcp->u.dbcp.mac[3], 3);
		
		COPY_MEMORY(&(p->priority.hap_priority), &(p->priority.priority), sizeof(PRI));
		
		p->radiocnt = dbcp->u.dbcp.radiocnt;
		/*syslog_debug("%s-%d update "MACSTR" %d radio(s)\n",
					__func__, __LINE__, MAC2STR(p->mac_addr), p->radiocnt);*/
		
		for (j = 0; j < p->radiocnt; j++)
		{
			p->WTP_Radio[j].radioid = dbcp->u.dbcp.WTP_Radio[j].radioid;
			p->WTP_Radio[j].channel = dbcp->u.dbcp.WTP_Radio[j].channel;
			p->WTP_Radio[j].txpower = dbcp->u.dbcp.WTP_Radio[j].txpower;
			memcpy(p->WTP_Radio[j].radio_mac, p->mac_addr, MAC_LEN);
			if (1 == j)
			{
				p->WTP_Radio[j].radio_mac[5] += 0x08;
			}
			
			/*syslog_debug("%s-%d update radio %d channel %d txpower %d\n",
						__func__, __LINE__, p->WTP_Radio[j].radioid,
						p->WTP_Radio[j].channel, p->WTP_Radio[j].txpower);*/
		}
	}
	
	return 0;
}


int update_member_list(Hccp_Protocol_Struct *rscp)
{
	unsigned char i = 0, j = 0, flag_delete = 1;
	int tag = -1;
	CLUSTER_MB *ret = NULL, *p = NULL;
	
	p = cluster_member_list.cluster_member_list_head;

	for (i = 0; i < rscp->u.rscp.count && i < MAX_CLUSTER_AP; i++)
	{
		if (mac_is_equal(self_state->ap_mac, rscp->u.rscp.cluster_member[i].mac))
		{
			self_state->ap_role = rscp->u.rscp.cluster_member[i].role;
			tag = i;
		//	if(rscp->u.rscp.cluster_member[i].state == LOST)
		//		return -1;
			//self_state->ap_state = rscp->u.rscp.cluster_member[i].state;
			break;
		}
		if (i == rscp->u.rscp.count - 1)
		{
			return -1;
		}
	}
	
	for (i = 0; i < rscp->u.rscp.count && i < MAX_CLUSTER_AP; i++)
	{
		ret = Search_list_by_mac(rscp->u.rscp.cluster_member[i].mac);
		if (ret == NULL)
		{
			CLUSTER_MB *new = (CLUSTER_MB*)malloc(sizeof(CLUSTER_MB));
			if (new == NULL)
			{
				syslog_debug("%s-%d new malloc failed\n", __func__, __LINE__);
			}
			else
			{
				memset(new, 0, sizeof(CLUSTER_MB));
				new->next = NULL;
				new->clusterID = rscp->u.rscp.head.clusterID;
				new->role = rscp->u.rscp.cluster_member[i].role;
				new->status = rscp->u.rscp.cluster_member[i].state;
				new->ipaddr = rscp->u.rscp.cluster_member[i].ip;
				memcpy(new->mac_addr, rscp->u.rscp.cluster_member[i].mac, MAC_LEN);
				new->radiocnt = rscp->u.rscp.cluster_member[i].radiocnt;
				syslog_debug("%s-%d add "MACSTR" %d radio(s)\n",
							__func__, __LINE__, MAC2STR(new->mac_addr), new->radiocnt);
				
				for (j = 0; j < new->radiocnt && j < L_RADIO_NUM; j++)
				{
					new->WTP_Radio[j].radioid = rscp->u.rscp.cluster_member[i].WTP_Radio[j].radioid;
					new->WTP_Radio[j].channel = rscp->u.rscp.cluster_member[i].WTP_Radio[j].channel;
					new->WTP_Radio[j].txpower = rscp->u.rscp.cluster_member[i].WTP_Radio[j].txpower;
					memcpy(new->WTP_Radio[j].radio_mac, new->mac_addr, MAC_LEN);
					if (1 == j)
					{
						new->WTP_Radio[j].radio_mac[5] += 0x08;
					}
					cluster_mgt_log("%s-%d radio %d channel %d txpower %d\n",
								__func__, __LINE__, new->WTP_Radio[j].radioid,
								new->WTP_Radio[j].channel, new->WTP_Radio[j].txpower);
				}
				
				Insert_list_from_head(new);
			}
		}
		else
		{
			ret->role = rscp->u.rscp.cluster_member[i].role;
			ret->status = rscp->u.rscp.cluster_member[i].state;
			ret->ipaddr = rscp->u.rscp.cluster_member[i].ip;
			ret->radiocnt = rscp->u.rscp.cluster_member[i].radiocnt;
			cluster_mgt_log("%s-%d update "MACSTR" %d radio(s)\n",
						__func__, __LINE__, MAC2STR(ret->mac_addr), ret->radiocnt);
			
			for (j = 0; j < ret->radiocnt && j < L_RADIO_NUM; j++)
			{
				ret->WTP_Radio[j].radioid = rscp->u.rscp.cluster_member[i].WTP_Radio[j].radioid;
				ret->WTP_Radio[j].channel = rscp->u.rscp.cluster_member[i].WTP_Radio[j].channel;
				ret->WTP_Radio[j].txpower = rscp->u.rscp.cluster_member[i].WTP_Radio[j].txpower;
				memcpy(ret->WTP_Radio[j].radio_mac, ret->mac_addr, MAC_LEN);
				if (1 == j)
				{
					ret->WTP_Radio[j].radio_mac[5] += 0x08;
				}
				
				cluster_mgt_log("%s-%d update radio %d channel %d txpower %d\n",
							__func__, __LINE__, ret->WTP_Radio[j].radioid,
							ret->WTP_Radio[j].channel, ret->WTP_Radio[j].txpower);
			}
			if (i == tag)
			{
				ret->radiocnt = self_state->radiocnt;
				for (j = 0; j < ret->radiocnt && j < L_RADIO_NUM; j++)
				{        
					ret->WTP_Radio[j].radioid = self_state->WTP_Radio[j].radioid;
					ret->WTP_Radio[j].channel = self_state->WTP_Radio[j].channel;
					ret->WTP_Radio[j].txpower = self_state->WTP_Radio[j].txpower;
					memcpy(ret->WTP_Radio[j].radio_mac, ret->mac_addr, MAC_LEN);
					if (1 == j)
					{
						ret->WTP_Radio[j].radio_mac[5] += 0x08;
					}
					
					cluster_mgt_log("%s-%d update self radio %d channel %d txpower %d\n",
								__func__, __LINE__, ret->WTP_Radio[j].radioid,
								ret->WTP_Radio[j].channel, ret->WTP_Radio[j].txpower);
				}
			}
		}
	}

	while (p != NULL)
	{
		flag_delete = 1;
		for (i = 0; i < rscp->u.rscp.count && i < MAX_CLUSTER_AP; i++)
		{
			if (mac_is_equal(p->mac_addr, rscp->u.rscp.cluster_member[i].mac))
			{
				flag_delete = 0;
				break;
			}
		}
		if (flag_delete == 1)
		{
			Delete_list(p);
		}
		
		p = p->next;
	}

	return 0;
}


void cleanup_member_list(void)
{
	CLUSTER_MB *p = cluster_member_list.cluster_member_list_head;
	CLUSTER_MB *q = p;
	cluster_member_list.cluster_member_list_head = NULL;

	while (p != NULL)
	{
		q = p->next;
		FREE_OBJECT(p);
		p = q;
	}
}


//************************************


int the_same_pvc_mac(RSCP_format *rscp)
{
  //printf("   mac: %2x:%2x:%2x:%2x:%2x:%2x   \n", pvc_state->pvc_mac[0],pvc_state->pvc_mac[1], pvc_state->pvc_mac[2],
//               pvc_state->pvc_mac[3], pvc_state->pvc_mac[4], pvc_state->pvc_mac[5]);
	
	if (!memcmp(pvc_state->pvc_mac,rscp->mac, MAC_LEN)	|| !memcmp(pvc_state->svc_mac,rscp->mac, MAC_LEN))
	{
		return 1;
	}
	
	return 0;
}

int cmp_prio_pvc(RSCP_format *rscp)
{
	CLUSTER_PRI prio;
	prio.priority.priority = rscp->priority;
	prio.priority.config_seq = rscp->config_sequence;
	prio.priority.product_type = rscp->product_type;
	memcpy(prio.priority.mac_tail, &rscp->mac[3], 3);
	
	if (pvc_state->pvc_priority.hap_priority < prio.hap_priority)
	{
		return 1;
	}
	
	return 0;
}


void cluster_svc_aging(void)
{
	if (svc_timer > 5)
	{
		if (self_state->ap_role == SVC)
		{
			syslog_err("pvc offline,svc  to being pvc!\n");
			svc_being_pvc(); 
		}
	}
	else
	{
		svc_timer++;
		svc_aging_id = timer_add(cluster_svc_aging_interval, 0, (void *)&cluster_svc_aging, NULL);
	}
}

void cluster_pvc_aging(void)
{
	if (pvc_state->timer > 30)
	{
		if (self_state->ap_role == PVC)
		{
			report_to_VC_mode();
			self_state->ap_state =  DISCOVERY;
			self_state->ap_role =VC;
			syslog_err("%s-%d pvc timeout to vc\n", __func__, __LINE__);
			//system("reboot ");
		}
		else if (self_state->ap_role != PVC)
		{
			syslog_err("%s-%d vc timeout to discovery\n", __func__, __LINE__);
			self_state->ap_state =  DISCOVERY;
		}
		
	}
	else
	{
		pvc_state->timer++;
		pvc_aging_id = timer_add(cluster_pvc_aging_interval, 0, (void *)&cluster_pvc_aging, NULL);
	}
}

/*run state: 1. send RSRP every 10 secs
			 2. send RIRP every 60 secs
			 3. update PVC state
			 4. maintain cluster state
*/
CLUSTER_STATE Enter_run()
{
	int ret = 0;
	fd_set fds;
	u_int8_t buffer[1048] = {0};
	//  int rsrp_timer_id = timer_add( cluster_rsrp_interval, 0, rsrp_send, NULL );
	times_up_id = timer_add( cluster_rirp_interval, 0, (void *)&rirp_send, NULL );
	if(times_up_id < 0)
	{
		syslog_err("timer_add  rirp_timer  failed!\n");
		times_up_id = timer_add( cluster_rirp_interval, 0, (void *)&rirp_send, NULL );
	}


	svc_aging_id = timer_add(cluster_svc_aging_interval, 0, (void *)&cluster_svc_aging, NULL);
	if(svc_aging_id < 0)
	{
		syslog_err("timer_add  svc_aging_timer  failed!\n");
		svc_aging_id = timer_add(cluster_svc_aging_interval, 0, (void *)&cluster_svc_aging, NULL);

	}
	pvc_aging_id = timer_add(cluster_pvc_aging_interval, 0, (void *)&cluster_pvc_aging, NULL);
	if(pvc_aging_id < 0)
	{
		syslog_err("timer_add  pvc_aging_timer  failed!\n");
		pvc_aging_id = timer_add(cluster_pvc_aging_interval, 0, (void *)&cluster_pvc_aging, NULL);
	}
	struct sockaddr_in addr;
	struct timeval tv;
	Hccp_Protocol_Struct packet;
	
	int addr_len = sizeof(struct sockaddr_in);
	syslog_warning("%s-%d\n", __func__, __LINE__);
	
	
	while(1)
	{
		FD_ZERO(&fds);
		FD_SET(cluster_socket_recv, &fds);
		memset(buffer, 0, sizeof(buffer));
		tv.tv_sec = 10;
		tv.tv_usec =  0;

		ret = select(cluster_socket_recv + 1, &fds, NULL, NULL, &tv);
		if (ret > 0)
		{
			if (FD_ISSET(cluster_socket_recv, &fds))
			{
				//必须用非阻塞
				recvfrom( cluster_socket_recv, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&addr , (void *)&addr_len );

				Parse_HCCPProtocol((void *)&buffer, &packet);
				int type = packet.type;
				
				switch(type)
				{
					case RSCP:
					{

						if (the_same_cluster_id(&packet.u.rscp))
						{ 
							if (the_same_pvc_mac(&packet.u.rscp) && self_state->ap_role != PVC)
							{
								pthread_mutex_lock(&cluster_member_list_mutex);
								if (update_member_list(&packet) < 0)
								{
							  		 // --> JOIN
									self_state->ap_state = JOIN;
									self_state->ap_role = VC;
									cleanup_member_list();
									syslog_warning("%s-%d update_member_list abort\n", __func__, __LINE__);
								}
								
								pthread_mutex_unlock(&cluster_member_list_mutex);
								
								update_pvc_state(&packet.u.rscp,addr.sin_addr.s_addr);
								syslog_debug("%s-%d vc/svc update member list\n", __func__, __LINE__);
							}
							else if (self_state->ap_role == PVC)
							{
								if (!memcmp(pvc_state->pvc_mac,packet.u.rscp.mac, MAC_LEN))
								{
									pthread_mutex_lock(&cluster_member_list_mutex);
									if (update_member_list(&packet) < 0)
									{
										syslog_warning("%s-%d pvc self update member list abort\n", __func__, __LINE__);
									}
									pthread_mutex_unlock(&cluster_member_list_mutex);
									
									update_pvc_state(&packet.u.rscp,addr.sin_addr.s_addr);							
									syslog_debug("%s-%d pvc self update member list\n", __func__, __LINE__);
								}
								/*  
								else if (!memcmp(pvc_state->svc_mac,packet.u.rscp.mac, MAC_LEN))
								{
									update_pvc_state(&packet.u.rscp,addr.sin_addr.s_addr);							
									
									pthread_mutex_lock(&cluster_member_list_mutex);
									cleanup_member_list();
									pthread_mutex_unlock(&cluster_member_list_mutex);
									
									self_state->ap_role = VC;
									self_state->ap_state = JOIN;
									report_to_VC_mode();
									clean_pvc_prio();
									syslog_debug("pvc svc merge :svc win!\n");
								}
								*/
								else
								{
									if (cmp_prio_pvc(&packet.u.rscp))
									{
										update_pvc_state(&packet.u.rscp,addr.sin_addr.s_addr);
										
										pthread_mutex_lock(&cluster_member_list_mutex);
										cleanup_member_list();
										pthread_mutex_unlock(&cluster_member_list_mutex);
										
										self_state->ap_role = VC;
										self_state->ap_state = JOIN;
										report_to_VC_mode();
										clean_pvc_prio();
										syslog_warning("pvc merge now  into  vc mode\n");
									}								
								}
								
								/*
									//pvc -->vc 
									if (self_state->ap_role == PVC)
									{
										self_state->ap_role = VC;
										report_to_VC_mode();
									}
								*/
									

							}
							else
							{
								if (cmp_prio_pvc(&packet.u.rscp))
								{
									update_pvc_state(&packet.u.rscp,addr.sin_addr.s_addr);
									
									pthread_mutex_lock(&cluster_member_list_mutex);
									cleanup_member_list();		
									pthread_mutex_unlock(&cluster_member_list_mutex);
									self_state->ap_role = VC;
									self_state->ap_state = JOIN;
									report_to_VC_mode();
									syslog_warning("%s-%d vc/svc join again\n", __func__, __LINE__);
								}
							}
						}

						break;
					}
					default:
					{
						break;
					}
				}

			}
		}
				
		if (self_state->ap_state != RUN)
		{
			TimerCancel(&times_up_id, 1);
			TimerCancel(&pvc_aging_id, 1);
			TimerCancel(&svc_aging_id,1);
			syslog_warning("%s-%d leave run to %s !!!\n", __func__, __LINE__, STATE_STR(self_state->ap_state));
			return self_state->ap_state;
		}
	}
}
#endif


CWBool show_auth_list(unsigned char *buffer, unsigned char *bufPtr)
{
	unsigned int curLen = 0;
	
	if (cluster_member_list.cluster_member_list_head == NULL)
	{
		return CW_FALSE;
	}
	
	curLen += sprintf((char*)bufPtr, "%-20s  %-20s  %-10s  ", "mac", "ip", "prio");
	bufPtr = buffer + curLen;
	curLen += sprintf((char*)bufPtr, "%-10s  %-10s  %-10s\n", "state", "role", "auth");
	bufPtr = buffer + curLen;
	
	CLUSTER_MB *p = cluster_member_list.cluster_member_list_head;
	while (p != NULL)
	{
		char addr_p[16] = {0};
		int priority = 0;
		struct in_addr addr_n;
		
		addr_n.s_addr = p->ipaddr;
		
		if (inet_ntop(AF_INET, &addr_n, addr_p, (socklen_t )sizeof(addr_p)) == NULL)
		{
			memcpy(addr_p, "0.0.0.0", 7) ;
		}
		
		curLen += sprintf((char*)bufPtr, ""MACSTR"     %-20s  ", MAC2STR(p->mac_addr), addr_p);
		bufPtr = buffer + curLen;

		priority = p->priority.priority.priority;
		if (!(MACCMP(self_state->ap_mac, p->mac_addr)))
		{
			priority = g_priority;
		}
		
		curLen += sprintf((char*)bufPtr, "%-10d  %-10d  ", priority, p->status);
		bufPtr = buffer + curLen;
		
		curLen += sprintf((char*)bufPtr, "%-10d  %-10d\n", p->role, 1);
		
		bufPtr = buffer + curLen;
				
		p = p->next;
	}
	
	return CW_TRUE;
}


CWBool show_member_list(unsigned char *buffer, unsigned char *bufPtr)
{
	int j = 0;
	char str[BUF_SIZE] = {0};
	unsigned int curLen = 0;
	
	if (cluster_member_list.cluster_member_list_head == NULL)
	{
		return CW_FALSE;
	}
		  
	curLen += sprintf((char*)bufPtr, "%-15s  %-20s  %-20s  %-10s  ", "ClusterID", "IP", "MAC", "role");
	bufPtr = buffer + curLen;
	//curLen += sprintf((char*)bufPtr, "%-20s  %-15s  %-15s  ", "priority", "status", "radio_num");
	curLen += sprintf((char*)bufPtr, "%-15s  %-15s  ", "status", "radio_num");
	bufPtr = buffer + curLen;
	curLen += sprintf((char*)bufPtr, "%-10s  %-10s  %-10s  %-10s\n", "radioid", "channel", "txpower", "rssi");
	bufPtr = buffer + curLen;
	
	CLUSTER_MB *p = cluster_member_list.cluster_member_list_head;
	while (p != NULL)
	{
		char addr_p[16] = {0};
		struct in_addr addr_n;
		
		addr_n.s_addr = p->ipaddr;
		
		if (inet_ntop(AF_INET, &addr_n, addr_p, (socklen_t )sizeof(addr_p)) == NULL)
		{
			memcpy(addr_p, "0.0.0.0", 7) ;
		}
		
		curLen += sprintf((char*)bufPtr, "%-15d  %-20s  ", p->clusterID, addr_p);
		bufPtr = buffer + curLen;
		
		curLen += sprintf((char*)bufPtr, ""MACSTR"     %-10s  ",
							MAC2STR(p->mac_addr), dump_role(str, p->role));
		bufPtr = buffer + curLen;
		
		//curLen += sprintf((char*)bufPtr, "%-20lld  %-15s  %-15d  %s",
		curLen += sprintf((char*)bufPtr, "%-15s  %-15d  %s",
		//					p->priority.hap_priority, dump_state(str, p->status),
							dump_state(str, p->status),
							p->radiocnt, (p->radiocnt) ? "" : "\n");
		
		bufPtr = buffer + curLen;
		
		for (j = 0; j < p->radiocnt && j < L_RADIO_NUM; j++)
		{
			if (j)
			{
				curLen += sprintf((char*)bufPtr, "%-15s  %-20s  %-20s  %-10s  ", "", "", "", "");
				bufPtr = buffer + curLen;
				
				//curLen += sprintf((char*)bufPtr, "%-20s  %-15s  %-15s  ", "", "", "");
				curLen += sprintf((char*)bufPtr, "%-15s  %-15s  ", "", "");
				bufPtr = buffer + curLen;
			}
			
			curLen += sprintf((char*)bufPtr, "%-10d  %-10d  %-10d  %-10d\n", p->WTP_Radio[j].radioid,
								p->WTP_Radio[j].channel, p->WTP_Radio[j].txpower, p->WTP_Radio[j].rssi);
			bufPtr = buffer + curLen;
		}
		p = p->next;
	}
	
	return CW_TRUE;
}


CWBool show_self_state(unsigned char *buffer, unsigned char *bufPtr)
{
	char str[BUF_SIZE] = {0};
	unsigned int curLen = 0;
	
	if (!self_state)
	{
		return CW_FALSE;
	}
	
	curLen += sprintf((char*)bufPtr, "%-10s  %-20s  %-10s  ", "ClusterID", "MAC", "role");
	bufPtr = buffer + curLen;
	
	curLen += sprintf((char*)bufPtr, "%-10s  %-15s\n", "priority", "status");
	bufPtr = buffer + curLen;
	
	curLen += sprintf((char*)bufPtr, "%-10d  "MACSTR"     %-10s  ",
					self_state->cluster_id, MAC2STR(self_state->ap_mac), dump_role(str, self_state->ap_role));
	bufPtr = buffer + curLen;
    
	curLen += sprintf((char*)bufPtr, "%-10llx  %-15s\n",
					self_state->ap_priority.hap_priority, dump_state(str, self_state->ap_state));
	bufPtr = buffer + curLen;
	
	return CW_TRUE;
}


CWBool show_pvc_state(unsigned char *buffer, unsigned char *bufPtr)
{
	char addr_p[16] = {0};
	struct in_addr addr_n;
	char str[BUF_SIZE] = {0};
	unsigned int curLen = 0;
	
	if (!pvc_state)
	{
		return CW_FALSE;
	}
	
	addr_n.s_addr = pvc_state->pvc_ipaddr;
	
	if (inet_ntop(AF_INET, &addr_n, addr_p, (socklen_t )sizeof(addr_p)) == NULL)
	{
		memcpy(addr_p, "0.0.0.0", 7);
	}
	
	curLen += sprintf((char*)bufPtr, "%-20s  %-20s  ", "IP", "MAC");
	bufPtr = buffer + curLen;
	
	curLen += sprintf((char*)bufPtr, "%-20s  %-15s\n", "priority", "status");
	bufPtr = buffer + curLen;
	
	curLen += sprintf((char*)bufPtr, "%-20s  "MACSTR"     ", addr_p, MAC2STR(pvc_state->pvc_mac));
	bufPtr = buffer + curLen;
	
	curLen += sprintf((char*)bufPtr, "%-20llx  %-15s\n",
				pvc_state->pvc_priority.hap_priority, dump_state(str, pvc_state->pvc_state));
	bufPtr = buffer + curLen;
	
	return CW_TRUE;
}


void cluster_mgt_display(char *cmd)
{
	int len = strlen(cmd);
	char command[MAX_CMD] = {0};
	int ret, v = 0;

	if (access(PIPE_CMD, F_OK) < 0)
	{
		syslog_info("%s-%d access cluster cmd pipe failed\n", __func__, __LINE__);
	}
	
	cmd_pipe = open(PIPE_CMD, O_WRONLY);
	if (cmd_pipe < 0)
	{
		err(1, "Could not open cluster cmd socket '%s'", PIPE_CMD);
    }

	v = fcntl(cmd_pipe, F_GETFL, 0);
	if (v | O_NONBLOCK)
	{
		v |= O_NONBLOCK;
		fcntl(cmd_pipe, F_SETFL, v);
	}
	
	/* always terminate command with newline */
	strncpy(command, cmd, len);
//	command[len] = '\n';
	command[len+1] = '\0';
	
	ret=write(cmd_pipe, command, len+1);
	syslog_debug("%s  write:%d\n",__func__,ret);
    close(cmd_pipe);  
}

void parse_command(char *in)
{
	char *cmd = NULL;	
	unsigned char *bufPtr = NULL;
	unsigned char buffer[MAX_CMD] = {0};
	
	if (in == NULL)
	{
		return;
	}
	
	bufPtr = buffer;
		
	cmd = strsep(&in, "=");
	
	if (cmd && (strcmp(cmd, "show") == 0))
	{
		syslog_debug("%s cmd:%s\n",__func__,cmd);
		if (in && strcmp(in, "mb_list") == 0)
		{
			pthread_mutex_lock(&cluster_member_list_mutex);
			show_auth_list(buffer, bufPtr);
			pthread_mutex_unlock(&cluster_member_list_mutex);
			syslog_debug("%s  cmd:%s\n",__func__,in);
		}
		else if (in && strcmp(in, "member") == 0) //show member list
		{
			pthread_mutex_lock(&cluster_member_list_mutex);
			show_member_list(buffer, bufPtr);
			pthread_mutex_unlock(&cluster_member_list_mutex);
			syslog_debug("%s cmd:%s\n",__func__,in);
		}
		else if (in && strcmp(in, "pvc") == 0) //show PVC state
		{
			show_pvc_state(buffer, bufPtr);
			syslog_debug("%s cmd:%s\n",__func__,in);
		}
		else if (in && strcmp(in, "self") == 0) //show state it self
		{
			show_self_state(buffer, bufPtr);
			syslog_debug("%s cmd:%s\n",__func__,in);
		}
	}
	
	cluster_mgt_display((char *)buffer);
	
	return;
}


void pipe_receive_command(void)
{
	int len = 0;
	char *end = NULL;
	char buf[MAX_CMD] = {0};
	char *pos = buf;

	len = read(if_pipe, buf, MAX_CMD);
	if (len > 0)
	{
		buf[len] = '\0';
		/* we can receive multiple \n separated commands */
		while ((end = strchr(pos, '\n')) != NULL)
		{
			*end = '\0';
			parse_command(pos);
			pos = end + 1;
		}
	
	}
}


int Get_Rssi_Stat(CLUSTER_RSSI *Rssi_Stat, unsigned char *mac)
{
	int i = 0;
    int index = -1;
    int free_index = -1;
    
	if (!Rssi_Stat || !mac) 
	{
		return CW_FALSE;
	} 
	
    for (i = 0; i < MAX_CLUSTER_AP; i++)
    {
        if (0 == Rssi_Stat[i].use)
        {
            if (free_index == -1)
            {
                free_index = i;
            }
            continue;
        }

        if (!(MACCMP(Rssi_Stat[i].ap_mac, mac)))
        {
            index = i;

            break;
        }
    }
    if (index == -1)
    {
        if (free_index == -1)
        {
            syslog_debug("%s-%d Rssi_Stat table full!\n", __func__, __LINE__);
        }
        else
        {
            index = free_index;
            Rssi_Stat[index].use = 1;
            memcpy(Rssi_Stat[index].ap_mac, mac, MAC_LEN);
        }
    }

    return index;
}


CWBool calculate_Cluster_Member_Rssi(Msg_Scan *vap_info, int vap_num)
{
	int i = 0, j = 0, k = 0;
	int index = 0;
	int radioid = 0;
	unsigned char mac[MAC_LEN] = {0};
	unsigned char mac1[MAC_LEN] = {0};
	CLUSTER_RSSI Rssi_Stat[MAX_CLUSTER_AP];
	CLUSTER_MB *mem = NULL;
	
	if (!vap_info) 
	{
		return CW_FALSE;
	}
	memset(Rssi_Stat, 0, (MAX_CLUSTER_AP)*sizeof(CLUSTER_RSSI));
	
	for (k = 0; k < vap_num; k++)
	{
		memset(mac, 0, MAC_LEN);
		memcpy(mac, vap_info[k].vap_mac, MAC_LEN);
		mac[5] &= 0xf0;
		memset(mac1, 0, MAC_LEN);
		memcpy(mac1, vap_info[k].vap_mac, MAC_LEN);
		mac1[5] &= 0xf8;
        
		int flag = 0;
		mem = Search_list_by_mac(mac);
		if (mem)
		{
			if (!(MACCMP(mac1, mem->WTP_Radio[1].radio_mac)))
			{
				flag = 1;
				radioid = 1;
			}
			else if (!(MACCMP(mac, mem->WTP_Radio[0].radio_mac)))
			{
				flag = 1;
				radioid = 0;
			}
		}
		
		if (flag)
		{
			mem->scan_tag = 1;
			
			index = Get_Rssi_Stat(Rssi_Stat, mac);
			if (-1 != index)
			{
				Rssi_Stat[index].radio_rssi[radioid].rssi_total += vap_info[k].rssi;
				Rssi_Stat[index].radio_rssi[radioid].signum++;
				//syslog_debug("%s-%d match ["MACSTR"] radio %d\n", __func__, __LINE__, MAC2STR(mem->mac_addr), radioid);
			}
		}
	}
	
	for (i = 0; i < MAX_CLUSTER_AP; i++)
	{
		for (j = 0; j < L_RADIO_NUM; j++)
		{
			if (Rssi_Stat[i].radio_rssi[j].signum)
			{
				int rssi_cnt = Rssi_Stat[i].radio_rssi[j].signum;
				int avg_rssi = Rssi_Stat[i].radio_rssi[j].rssi_total/rssi_cnt;

                mem = Search_list_by_mac(Rssi_Stat[i].ap_mac);
                if (mem)
                {
                    struct tm *p = NULL; 
                    mem->WTP_Radio[j].rssi = avg_rssi;
                    time(&(mem->WTP_Radio[j].rssi_stamp));
                    p = localtime(&(mem->WTP_Radio[j].rssi_stamp));
                    
                    syslog_debug("%s-%d time %d:%d:%d ["MACSTR"] radio%d rssi %d\n",
                            __func__, __LINE__, p->tm_hour, p->tm_min, p->tm_sec, MAC2STR(Rssi_Stat[i].ap_mac), j, avg_rssi);
                }
                
			}
		}
	}
	
	return CW_TRUE;
}


CWBool SCAN_OP(ProtocolMessage *msgPtr, int len)
{
	int i = -1;
	int offsetTillMessages = 0;
	unsigned char *vap_mac = NULL;
	unsigned char *vap_chan = NULL;
	unsigned char *vap_rssi = NULL;
	TLVHeader tlvVal;
	Msg_Scan vap_info[1024];
	
	offsetTillMessages = msgPtr->offset;
	memset(vap_info, 0 , sizeof(Msg_Scan) * 1024);
	
	while ((msgPtr->offset - offsetTillMessages) < len)
	{
		memset(&tlvVal, 0, sizeof(TLVHeader));
		
		ParseTLVHeader(msgPtr, &tlvVal);
		
		if ((msgPtr->offset - offsetTillMessages + tlvVal.length) > len)
		{
			syslog_debug("%s-%d Message Element elemType= %d(%s) elemLen=%d offset=%d MsgLen= %d\n",
					__func__, __LINE__, tlvVal.type, MSG_ELEM_TYPE_STR(tlvVal.type), tlvVal.length, msgPtr->offset, len);
			
			return CW_FALSE;
		}
		
		switch (tlvVal.type)
		{     
			case MSG_ELEMENT_TYPE_VAP_MAC:
			{
				vap_mac = (unsigned char *)ProtocolRetrieveRawBytes(msgPtr, tlvVal.length);
				COPY_MEMORY(vap_info[++i].vap_mac, vap_mac, tlvVal.length);
				
				//syslog_debug("%s i= %d mac= "MACSTR" ", __func__, i, MAC2STR(vap_mac));
				FREE_OBJECT(vap_mac);
				
				break;
            }
			
			case MSG_ELEMENT_TYPE_VAP_CHAN:
			{
				vap_chan = (unsigned char *)ProtocolRetrieveRawBytes(msgPtr, tlvVal.length);
				COPY_MEMORY(&(vap_info[i].channel), vap_chan, tlvVal.length);
				
				//syslog_debug(" chan= %d\n", *vap_chan);
				FREE_OBJECT(vap_chan);
				
				break;
			}
			
			case MSG_ELEMENT_TYPE_VAP_RSSI:
			{
				vap_rssi = (unsigned char *)ProtocolRetrieveRawBytes(msgPtr, tlvVal.length);
				COPY_MEMORY(&(vap_info[i].rssi), vap_rssi, tlvVal.length);
				
				//syslog_debug(" rssi= %d ", *vap_rssi);
				FREE_OBJECT(vap_rssi);
				
				break;
			}
			
			default:
			{
				msgPtr->offset += tlvVal.length;
				
				break;
			}
		}
	}
	
	/*syslog_debug("%s-%d MsgLen= %d offset=%d vapnum= %d\n",
			__func__, __LINE__, len, (msgPtr->offset-offsetTillMessages), i+1);*/
	
	pthread_mutex_lock(&cluster_member_list_mutex);
	calculate_Cluster_Member_Rssi(vap_info, i+1);
	pthread_mutex_unlock(&cluster_member_list_mutex);
	
	if (msgPtr->offset-offsetTillMessages != len)
	{
		syslog_debug("%s-%d MsgLen= %d offset=%d Garbage at the End of the Message\n",
				__func__, __LINE__, len, (msgPtr->offset-offsetTillMessages));
		
		return CW_FALSE;
	}
	
	return CW_TRUE;
}

CWBool Fill_Inf_Data(struct CLUSTER_INF *cluster_inf)
{
	int j = 0;
	int k = 0;
	
	if (!cluster_inf)
	{
		return CW_FALSE;
	}

	CLUSTER_MB *p = cluster_member_list.cluster_member_list_head;
	while (p != NULL)
	{
		cluster_inf->cluster_MB[k].clusterID = p->clusterID;
		cluster_inf->cluster_MB[k].ipaddr = p->ipaddr;
		cluster_inf->cluster_MB[k].status = p->status;
		cluster_inf->cluster_MB[k].role = p->role;
		memcpy(cluster_inf->cluster_MB[k].ap_base_mac, p->mac_addr, MAC_LEN);
		
		cluster_inf->cluster_MB[k].radiocnt = p->radiocnt;
		
		for (j = 0; j < p->radiocnt && j < L_RADIO_NUM; j++)
		{
			memcpy(&(cluster_inf->cluster_MB[k].WTP_Radio[j]), &(p->WTP_Radio[j]), sizeof(WTP_RADIO));
		}
		
		k++;
		if (MAX_CLUSTER_AP == k)
		{
			break;
		}
		
		p = p->next;
	}
	
	cluster_inf->mem_num = k;
	syslog_debug("%s-%d cluster memnum %d\n", __func__, __LINE__, k);
	
	return CW_TRUE;
}


CWBool Fill_RIRP_Data(RF_environment *RFInfo)
{
    int m = 0;
	
	if (!RFInfo)
	{
		return CW_FALSE;
	}
	
    if (self_state)
    {
        memcpy(RFInfo->ap_base_mac, self_state->ap_mac, MAC_LEN);
        
        CLUSTER_MB *p = cluster_member_list.cluster_member_list_head;
        while (p != NULL)
        {
            if (!(MACCMP(p->mac_addr, self_state->ap_mac)))
            {
                p = p->next;
                continue;
            }
            if (p->scan_tag)
            {
                RFInfo->rssi_of_others[m].radiocnt = p->radiocnt;
                memcpy(RFInfo->rssi_of_others[m].ap_base_mac, p->mac_addr, MAC_LEN);
                memcpy(RFInfo->rssi_of_others[m].ap_radio, p->WTP_Radio, (L_RADIO_NUM*sizeof(WTP_RADIO)));
                m++;
				if (MAX_CLUSTER_AP == m)
				{
					break;
				}
            }
            
            p = p->next;
        }
        RFInfo->neighbor_cnt = m;
        syslog_debug("%s-%d neighbor_cnt = %d\n", __func__, __LINE__, m);

	    return CW_FALSE;
    }
    
	return CW_TRUE;
}


CWBool Fill_RISP_Data(CLUSTER_RF_environment *EnvInfo)
{
    int m = 0;

	if (!EnvInfo)
	{
		return CW_FALSE;
	}
    
    EnvInfo->ACS_sequence = 80;
	
    CLUSTER_MB *mem = cluster_member_list.cluster_member_list_head;
    CLUSTER_MB *p = cluster_member_list.cluster_member_list_head;
    
    while (mem != NULL)
    {
        int n = 0;
        while (p != NULL)
        {
            if (!(MACCMP(p->mac_addr, mem->mac_addr)))
            {
                p = p->next;
                continue;
            }
            
            if (p->scan_tag)
            {
				EnvInfo->WTP_RF[m].rssi_of_others[n].radiocnt = p->radiocnt;
				memcpy(EnvInfo->WTP_RF[m].rssi_of_others[n].ap_base_mac, p->mac_addr, MAC_LEN);
				memcpy(EnvInfo->WTP_RF[m].rssi_of_others[n].ap_radio, p->WTP_Radio, (L_RADIO_NUM*sizeof(WTP_RADIO)));
				n++;
				if (MAX_CLUSTER_AP == n)
				{
					break;
				}
			}
			
			p = p->next;
		}
		
		EnvInfo->WTP_RF[m].role = mem->role;
		EnvInfo->WTP_RF[m].priority = mem->priority.priority.priority;
		EnvInfo->WTP_RF[m].ipaddr = mem->ipaddr;
		EnvInfo->WTP_RF[m].radiocnt = mem->radiocnt;   
		memcpy(EnvInfo->WTP_RF[m].ap_base_mac, mem->mac_addr, MAC_LEN);
		EnvInfo->WTP_RF[m].neighbor_cnt = n;
		m++;
		
		syslog_debug("%s-%d wtp%d["MACSTR"] neighbor_cnt= %d\n",
					__func__, __LINE__, m, MAC2STR(EnvInfo->WTP_RF[m].ap_base_mac), n);
		
		if (MAX_CLUSTER_AP == m)
		{
			break;
		}
		
		mem = mem->next;
	}
	
	EnvInfo->Mem_num = m;
	syslog_debug("%s-%d cluster member num %d\n", __func__, __LINE__, m);
	
	return CW_TRUE;
}


int handle_recvcmd(unsigned char *buf, unsigned int buflen, struct sockaddr_un *model_addr)
{
	int ret = 0;
	MessageHeader msgheader; 
	ProtocolMessage completeMsg;	
	ProtocolMessage *messages = NULL;
	struct CLUSTER_INF cluster_inf;
	
	if (buf == NULL)
	{
		return CW_FALSE;
	}
	
	memset(&cluster_inf, 0, sizeof(struct CLUSTER_INF));
	memset(&completeMsg, 0, sizeof(ProtocolMessage));
	
	completeMsg.msg = (char *)buf;
	completeMsg.offset = 0;
	
	if (!(ParseMessageHeader(&completeMsg, &msgheader)))
	{
		syslog_debug("%s-%d parsing message header error!\n", __func__, __LINE__);
		return CW_FALSE;
	}
	
	syslog_debug("%s-%d msgop %d(%s) msgtype= %d msgLen= %d \n",
			__func__, __LINE__, msgheader.operation, MSG_OP_TYPE_STR(msgheader.operation), msgheader.messageType, msgheader.msgElemsLen);
	
	if ((msgheader.operation == MSG_REQUEST) && (msgheader.msgElemsLen < buflen))
	{
		pthread_mutex_lock(&cluster_member_list_mutex);
		Fill_Inf_Data(&cluster_inf);
		pthread_mutex_unlock(&cluster_member_list_mutex);

		switch (msgheader.messageType)
		{
			case PVC_STATE_INFO:
				ret = AssemblePVCInfo(&messages, &cluster_inf);
				
				break;
			case CLUSTER_MEMBER_INFO:
				ret = AssembleClusterMemberInfo(&messages, &cluster_inf);
				
				break;
			case CLUSTER_ENV_INFO:
				ret = AssembleEnvInfo(&messages, &cluster_inf);
				
				break;
            default:
				syslog_debug("%s-%d Unrecognized Element Type\n", __func__, __LINE__);
				return CW_FALSE;
        }
		if (CW_FALSE != ret && messages && messages->msg)
		{
			if (!SendMsg(if_local_socket, model_addr, (unsigned char *)messages->msg, messages->offset))
			{
				syslog_debug("%s-%d sendto if_local_socket error\n", __func__, __LINE__);
				ret = CW_FALSE;
			}
		}
		if (messages && messages->msg)
		{
			//wid_hex_dump((unsigned char *)messages->msg, messages->offset);//log is too many,so delete
			cluster_mgt_log("free start:%s-%d\n",__func__,__LINE__);	
			FREE_PROTOCOL_MESSAGE(*messages);
			cluster_mgt_log("%s-%d\n",__func__,__LINE__);
			FREE_OBJECT(messages);
			cluster_mgt_log("free end:%s-%d\n",__func__,__LINE__);
		}
		
        return ret;
    }
	else if ((msgheader.operation == MSG_RESPONSE) && (msgheader.msgElemsLen < buflen))
	{
		switch (msgheader.messageType)
		{
			case SCAN_AP_INFO:
					
				if (!(SCAN_OP(&completeMsg, msgheader.msgElemsLen)))
				{
					return CW_FALSE;
				}
				
				break;
				
			default:
                    
				return CW_FALSE;
		}
		return CW_TRUE;
	}
	
	return CW_FALSE;
}

int sock_scan_request()
{
    unsigned char sendbuf[SOCK_BUFSIZE];
    MessageHeader msg;
    int buflen = 0;
    
    buflen = sizeof(MessageHeader);

    msg.apver = 0;
    msg.operation = MSG_REQUEST;
    msg.reserved = 0;
    msg.messageType = SCAN_AP_INFO;
    msg.msgElemsLen = 0;

    memset(sendbuf, 0, SOCK_BUFSIZE);
    memcpy(sendbuf, &msg, sizeof(MessageHeader));
	
    if (SendMsg(local_sock, &toBGSC.addr, sendbuf, buflen))
    {
        ScanRetransmit = 0;
        TimerRequest(RECV_SCAN_INTERVAL_TIMER, &scan_timer, SIGSCAN);
    }
    else
    {
		ScanRetransmit++;
		syslog_debug("%s-%d msg retransmission %d times!\n", __func__, __LINE__, ScanRetransmit);
		
		if (ScanRetransmit < SCAN_MAX_RETRANSMIT)
		{
			sock_scan_request();
		}
		else
		{
            ScanRetransmit = 0;
            TimerRequest(RECV_SCAN_INTERVAL_TIMER, &scan_timer, SIGSCAN);
		}
    }
	
	return CW_TRUE;
}


int recv_scan_response()
{
	int readBytes = 0;
	unsigned char buf[SOCK_BUFSIZE] = {0};
	struct sockaddr_un src_addr;
	
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	
	FD_ZERO(&read_fs);
	FD_SET(local_sock, &read_fs);
	
	while (select(local_sock+1, &read_fs, NULL, NULL, &timeout) < 0)
	{
		syslog_debug("%s-%d select %s\n", __func__, __LINE__, strerror(errno));
		if (errno != EINTR)
		{
			return CW_FALSE;
		}
	}

	if (FD_ISSET(local_sock, &read_fs))
	{
		ZERO_MEMORY(buf, SOCK_BUFSIZE);
		
		if (RecvMsg(local_sock, buf, SOCK_BUFSIZE, &src_addr, &readBytes))
		{
			syslog_debug("%s-%d recv msglen= %d\n", __func__, __LINE__, readBytes);

			return handle_recvcmd(buf, readBytes, NULL);
		}
	}
	
	return CW_TRUE;
}


THREAD_RETURN_TYPE cluster_get_scan(void * arg)
{
	if (!(TimerRequest(RECV_SCAN_INTERVAL_TIMER, &scan_timer, SIGSCAN)))
	{
		syslog_debug("%s-%d scan timer request failed\n", __func__, __LINE__);
	}
	
	REPEAT_FOREVER
	{
		recv_scan_response();
	}
	return NULL;
}


void local_receive()
{
	int len = 0;
	unsigned char buffer[SOCK_BUFSIZE];
	struct sockaddr_un model_addr;  
	
	memset(buffer, 0, SOCK_BUFSIZE);
	
	if (RecvMsg(if_local_socket, buffer, SOCK_BUFSIZE, &model_addr, &len))
	{
		handle_recvcmd(buffer, len, &model_addr);
	}
	
	return;
}

THREAD_RETURN_TYPE recv_thread(void *ptr)
{
	REPEAT_FOREVER
	{
		int ret = -1, mfd = -1;
		
		FD_ZERO(&read_fds); 
		FD_SET(if_pipe, &read_fds);
		FD_SET(if_local_socket, &read_fds);
		
		mfd = max(if_pipe, if_local_socket)+1;
		
		ret = select(mfd, &read_fds, NULL, NULL, NULL);
		if (ret > 0)
		{
			if (FD_ISSET(if_pipe, &read_fds)) 
			{
				pipe_receive_command();
			}
			else if(FD_ISSET(if_local_socket, &read_fds))
			{
				local_receive();
			}
			else
			{
				continue;
			}
		}
	}
	
	return NULL;
}


void cluster_mgt_cmd(char *cmd)
{
	int v = 0,ret;
	int len = strlen(cmd);
	char command[MAX_CMD] = {0};
	char buf[MAX_CMD] = {0};
	fd_set rd;
	struct timeval tv;

	while (access(PIPE_NAME, F_OK) < 0)
	{
		err(1, "pipe '%s' inaccessible...\n", PIPE_NAME);
	}
	
	if_pipe = open(PIPE_NAME, O_WRONLY|O_NONBLOCK);
	if (if_pipe < 0)
	{
		system("kill -PIPE  `pgrep   /sbin/cluster_mgt` ");
		err(1, "Could not open cluster pipe '%s'\n", PIPE_NAME);
	
	}
	
	v = fcntl(if_pipe, F_GETFL, 0);
	if (v | O_NONBLOCK)
	{
		v |= O_NONBLOCK;
		fcntl(if_pipe, F_SETFL, v);
	}
	
	/* always terminate command with newline */
	strncpy(command, cmd, len);
	command[len] = '\n';
	command[len+1] = '\0';
	
	ret=write(if_pipe, command, len+1);
	syslog_debug("%s  write:%d\n",__func__,ret);

	cmd_pipe = open(PIPE_CMD, O_RDONLY | O_NONBLOCK);
	if (cmd_pipe < 0)
	{
		err(1, "Could not open command fifo '%s'\n", PIPE_CMD);
	}
	
	//select 
	FD_ZERO(&rd);
    FD_SET(cmd_pipe, &rd);
	tv.tv_sec = 3;
	tv.tv_usec =  0;
	ret = select(cmd_pipe + 1, &rd, NULL, NULL, &tv);
	if(ret > 0)
	{
		if(FD_ISSET(cmd_pipe, &rd))
		{

			len = read(cmd_pipe, buf, MAX_CMD);
			if (len > 0)
			{
				buf[len] = '\0';
				printf("%s", buf);
			}
			else
			{
				printf("error\n");
			}
	
		}
	}else if(ret == 0)
	{
	
	   printf("cluster mgt  get info  timeout  \n");
	}

	close(if_pipe);
	close(cmd_pipe);
}


static void cluster_mgt_get_options(int argc, char * argv[])
{
	int opt = 0;
	
	while ((opt = getopt(argc, argv, "hp:I:x:")) > 1)
	{
		switch (opt)
		{
			case 'p':
			
				memcpy(g_mac_str,optarg,strlen(optarg));
				syslog_debug("%s-%d opt p: %s\n", __func__, __LINE__, g_mac_str);
				break;
				
			case 'I':
				g_clusterId = atoi(optarg);
				syslog_debug("%s-%d opt i: %d\n",  __func__, __LINE__, g_clusterId);
				break;
			
    		case 'x':
    			cluster_mgt_cmd(optarg);
    			exit(0);

    		case 'h':
			default:
				syslog_debug("\nUsage: %s [-h] [-I clusterID] [-p priority]\n"
					"\t\t[-x command]\n"

					"General Options: Description (default value)\n"
					"  -h\t\tHelp\n"

					"  -I <clusterID>\tNode timeout in seconds (60)\n"
					"  -p <priority>\tDisplay update interval in ms (100)\n"

					"\nFeature Options:\n"

					"  -x <command>\tSend control command\n",
					argv[0]);
				exit(0);
		}
	}
}



int handle_rscp(struct CLUSTER_INF *cluster_mb)
{
	int k = 0;
	CLUSTER_MB *mem = NULL;
    
	if (NULL == cluster_mb)
	{
		return CW_FALSE;
	}
	
	for (k = 0; k < cluster_mb->mem_num; k++)
	{
		pthread_mutex_lock(&cluster_member_list_mutex);
		mem = Search_list_by_mac(cluster_mb->cluster_MB[k].ap_base_mac);
		if (mem)
		{
			mem->role = cluster_mb->cluster_MB[k].role;
			mem->status = cluster_mb->cluster_MB[k].status;
			syslog_debug("%s-%d ap["MACSTR"] %s %s\n",
					__func__, __LINE__, MAC2STR(cluster_mb->cluster_MB[k].ap_base_mac),
					(mem->role == 1) ? "PVC" :(mem->role == 2) ? "SVC" : "VC",
					(mem->status == 1) ? "discovery" :(mem->status == 2) ? "run" : "offline");
		}
		else
		{
			syslog_debug("%s-%d mac["MACSTR"] no match\n", __func__, __LINE__, MAC2STR(cluster_mb->cluster_MB[k].ap_base_mac));
		}
		
		pthread_mutex_unlock(&cluster_member_list_mutex);
    }

    return CW_TRUE;
}


CWBool ParseHCCPProtocol(char *buf, int readBytes, ProtocolMessage **messages) 
{
	ProtocolMessage msg;
	HCCPHeader HccpHeadval;
	WTPDescriptor wtpdesc;
	struct CLUSTER_INF cluster_mb;
	HCCPRSCP RSCPRequest;
	memset(&wtpdesc, 0, sizeof(WTPDescriptor));
	memset(&cluster_mb, 0, sizeof(struct CLUSTER_INF));
	memset(&RSCPRequest, 0, sizeof(HCCPRSCP));
	
	msg.msg = NULL;
	msg.offset = 0;
	
	if (!ProtocolParseFragment(buf, readBytes, &HccpHeadval, &msg)) 
	{
		return CW_FALSE;
	}
	
	switch (HccpHeadval.protocolType) 
	{
		case DBCP:
		{                   
			syslog_debug("%s-%d protocolType:DBCP\n", __func__, __LINE__);
			
			if (!ParseDBCP(&msg, &wtpdesc))
			{
				return CW_FALSE;
			}
			
			break;
		}
		
		case RSCP:
		{
			syslog_debug("%s-%d protocolType:RSCP\n", __func__, __LINE__);
			
			if (!ParseRSCP(&msg, &RSCPRequest))
			{
				return CW_FALSE;
			}
			handle_rscp(&(RSCPRequest.cluster_mb));
			
			break;
		}
		
		case RSRP:
		{
			syslog_debug("%s-%d protocolType:RSRP\n", __func__, __LINE__);
			
			if (!ParseRSRP(&msg, &wtpdesc))
			{
				return CW_FALSE;
			}
			
			break;
		}
		
		case RIRP:
		{
			syslog_debug("%s-%d protocolType:RIRP\n", __func__, __LINE__);
			RF_environment RIRPRequest;
			memset(&RIRPRequest, 0, sizeof(RF_environment));
			
			if (!ParseRIRP(&msg, &RIRPRequest))
			{
				return CW_FALSE;
			}
			break;
		}
		
		case RISP:
		{
			syslog_debug("%s-%d protocolType:RISP\n", __func__, __LINE__);
			CLUSTER_RF_environment RISPRequest;
			memset(&RISPRequest, 0, sizeof(CLUSTER_RF_environment));
			
			if (!ParseRISP(&msg, &RISPRequest))
			{
				return CW_FALSE;
			}
			break;
		}
		
		case ACS:
		{
			syslog_debug("%s-%d protocolType:ACS\n", __func__, __LINE__);
			
			/*if (!ParseACS(&msg, messages))
			{
				return CW_FALSE;
			}*/
			break;
		}
		
		default:
		{
			syslog_debug("%s-%d protocolType %d\n", __func__, __LINE__, HccpHeadval.protocolType);
			break;
		}
	}
	
	FREE_PROTOCOL_MESSAGE(msg);
	
	return CW_TRUE;
}



int main (int argc, char * argv[])
{
#if SERVER_SYSLOG
#else
	LogInitFile(gLogFileName);
#endif
	cluster_mgt_get_options(argc, argv);
	
//load config option,calculate priority itself
//	load_config();

	cluster_init();
	
	if (timer_init() == 0)
	{
		syslog_err("%s-%d Can't init timer module\n", __func__, __LINE__);
		exit(1);
	}
	
	CWThread thread_bgs;
	if (!CreateThread(&thread_bgs, cluster_get_scan, NULL, 0))
	{
		syslog_err("%s-%d Error Create background scanning Thread", __func__, __LINE__);
		exit(1);
	}
	
	CWThread thread_Recv;
	if (!CreateThread(&thread_Recv, recv_thread, NULL, 0))
	{
		syslog_err("%s-%d Error Create Recv Thread\n", __func__, __LINE__);
		exit(1);
	}
/*	
	if (!(TimerRequest(GET_RADIO_INFO_TIMER, &uprf_timer, SIGUPRF)))
	{
		syslog_warning("%s-%d update rf timer request failed\n", __func__, __LINE__);
	}
*/	
	if (!(TimerRequest(RSSI_AGING_TIMER, &rfag_timer, SIGRFAG)))
	{
		syslog_warning("%s-%d rssi aging timer request failed\n", __func__, __LINE__);
	}
	
	while (1)
	{
		syslog_debug("%s-%d cluster management runing  ...\n", __func__, __LINE__);
		sleep(1);
		

		switch(self_state->ap_state)
		{
			case DISCOVERY:
			{
				self_state->ap_state = Enter_Discovery();
				break;
			}
			case JOIN:
			{
				self_state->ap_state = Enter_Join();
				break;
			}
			case CHECK:
			{
				self_state->ap_state = Enter_check();
				break;
			}
			case RUN:
			{
				self_state->ap_state = Enter_run();
				break;
			}
			default:
			{
				syslog_err("%s-%d error state %d\n", __func__, __LINE__, self_state->ap_state);
				break;
			}
		}

	}
}
