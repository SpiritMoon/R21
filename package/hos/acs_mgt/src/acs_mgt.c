#include<libhccp/libhccp.h>
#include<stdio.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/ipc.h>
#include<sys/socket.h>
#include<string.h>
#include<sys/msg.h>
#include<netinet/in.h> 
#include<arpa/inet.h> 
#include<stdlib.h> 
#include<errno.h> 
#include<netdb.h> 
#include<stdarg.h> 
#include<sys/un.h>
#include<fcntl.h>
#include<syslog.h>
#include <inttypes.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>


#include "timerlib.h"

int keep_alive_timer_id = -1;
int local_sockfd, sockfd;
struct sockaddr_in my_addr;
int err_log;
struct sockaddr_un local_addr;
unsigned int gSeqnum = 1;
unsigned char acs_dbg_level = 0;
unsigned int clusterID = 100;
uint32_t broadcast_addr = 0;
unsigned char mac[MAC_LEN] = {0};

#define ERROR -1
#define CLIENT_PORT 4568
#define LOCAL_PORT 4567
#define keep_alive_interval 10
#define ACS_PATH "/tmp/socket_path"
#define PIPE_ACS_MGT  "/tmp/acs_mgt_pipe"

void acs_log(const char * fmt, ...)
{
    char buf[256];
    va_list ap;
    if(!acs_dbg_level)
        return;
    va_start(ap,fmt);
    vsnprintf(buf,256,fmt,ap);
    va_end(ap);
	syslog(LOG_DEBUG, buf);
    printf("%s\n",buf);
}
char *trim(char *str_org)
{
	if (NULL == str_org)
	{
		acs_log("%s-%d str_org= NULL\n", __func__, __LINE__);
		return NULL;
	}

	if (0 == strlen(str_org))
	{
		acs_log("%s-%d Empty String\n", __func__, __LINE__);
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
		acs_log("%s-%d cmd:%s error[%s]\n", __func__, __LINE__, cmd_str, strerror(errno));
		
		return HAN_FALSE;
	}
}
unsigned int Get_ClusterId()
{
	char temp_str[100] = {0};
	char str_tmp[64];
	unsigned char str[64];
	unsigned int clusterid = 0;
	
	memset(temp_str, 0, 100);
	memset(str_tmp, 0 ,64);
	memset(str, 0, 64);
	
	sprintf(temp_str, "uci get cluster.cluster.cluster_id");	
	PopenFile(temp_str, str_tmp, sizeof(str_tmp));
	strcpy(str, trim(str_tmp));
	
	acs_log("%s-%d ClusterId= %s \n", __func__, __LINE__,  str);

	clusterid = atoi(str);

	acs_log("%s-%d ClusterId= %d \n", __func__, __LINE__,  clusterid);
	
	return clusterid;
}
uint32_t get_broadcast_addr()
{
	char if_name[16] = "br-wan";
	int fd;
	struct sockaddr_in  sin;
	struct ifreq ifr;
	 
	fd = socket(AF_INET, SOCK_DGRAM, 0);  
	if (fd == -1)
	{  
		acs_log("%s-%d socket error\n", __func__, __LINE__);  
		return  broadcast_addr; 
	} 
	
	strncpy(ifr.ifr_name, if_name, 10);


	//get brast
	if (!(ioctl(fd, SIOCGIFBRDADDR, &ifr)))
	{
		memcpy(&sin, &ifr.ifr_addr, sizeof(ifr.ifr_addr));
		acs_log("%s-%d broadcast_addr:  %s\n", __func__, __LINE__, inet_ntoa(sin.sin_addr));
		broadcast_addr = sin.sin_addr.s_addr;
	}	
	
	close(fd);
	
	return broadcast_addr;
}
void acs_mgt_cmd(void)
{
	int fd_pipe;
	char buf[128] = "show seq_num";	
	
	fd_pipe = open(PIPE_ACS_MGT, O_WRONLY|O_NONBLOCK);
	if(fd_pipe < 0)
	{
		err(1, "Could not open acs_mgt pipe '%s'\n", PIPE_ACS_MGT);
		exit(0);
	}	
	
	write(fd_pipe, buf, strlen(buf));
}
void acs_mgt_get_options(int argc, char *argv[])
{
	int ch;
	while(-1 != (ch = getopt(argc, argv, "vds:c:")))
	{
		switch(ch)
		{
			case 'v':
			{
				acs_mgt_cmd();
				exit(0);	
			}
			case 'd':
			{
				acs_dbg_level = 1;
				acs_log("open debug!\n");
				break;	
			}
			case 's':
			{
				gSeqnum = atoi(optarg);
				acs_log("seqnum: %d\n", atoi(optarg));
				break;
			}
			case 'c':
			{
				clusterID = atoi(optarg);
				acs_log("clusterID: %d\n", atoi(optarg));
				break;
			}
			case '?':
			{
				if(optopt == 's' || optopt == 'c')
				{
					fprintf(stderr, "option -%c requires argument!\n", optopt);					
				}
				else
				{
					fprintf(stderr, "unknown option '-%c'!\n", optopt);					
				}
				exit(0);
			}
			default:
			{
				fprintf(stderr, "unknown option '-%c'!\n", optopt);
				exit(0);
			}
			
		}
		
	}
}
void seq_num_send(void)
{
	char buf_send[32];
	memset(buf_send, 0, sizeof(buf_send));
	memcpy(buf_send, &gSeqnum, sizeof(unsigned int));
	
	acs_log("seq_num_send!\n\n");
	
	if(ERROR == sendto(local_sockfd, buf_send, sizeof(buf_send), 0, (struct sockaddr*)&local_addr, sizeof(local_addr)))
	{
		perror("sendto");
		acs_log("sendto fail!\n\n");
	}
	else
	{
		acs_log("sendto succeed!  gSeqnum:%d\n\n", gSeqnum);
	}	
}
void keep_alive_send(void)
{
	acs_log("==================================keep_alive_send\n\n");
	seq_num_send();	
	keep_alive_timer_id = timer_add(keep_alive_interval, 0, &keep_alive_send, NULL);
}
void *acs_mgt_function(void)
{
	Hccp_Protocol_Struct acs_packet;
	ACS_format acs_packet_Sequence_resp, acs_packet_token_resp;
	char buf_Sequence_resp[512], buf_Token_resp[512], recv_buf[512] = "", cli_ip[INET_ADDRSTRLEN] = "";	
	int recv_len;
	int so_broadcast = 1;
	struct sockaddr_in client_addr;
	struct sockaddr_in brast_addr;
	socklen_t cliaddr_len = sizeof(client_addr);
	
	setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &so_broadcast, sizeof(so_broadcast));
	brast_addr.sin_family = AF_INET;
	
	acs_log("acs_mgt_function--receive data...\n");
	
	while(1)
	{		
		memset(recv_buf, 0, sizeof(recv_buf));
		recv_len = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&client_addr, &cliaddr_len);
		if(recv_len < 0)
		{
			perror("recvfrom");
			close(sockfd);
			exit(-1);
		}
		
		acs_log("---------------------------------------------------------------\n");
		inet_ntop(AF_INET, &client_addr.sin_addr, cli_ip, INET_ADDRSTRLEN);
		acs_log("receive data from ip:%s,port:%d\n", cli_ip, ntohs(client_addr.sin_port));
		acs_log("data_len:%d\n", recv_len);

		memset(&acs_packet, 0, sizeof(acs_packet));
		if(HAN_FALSE == Parse_HCCPProtocol(recv_buf,  &acs_packet))
		{
			acs_log("Parse_HCCPProtocol error!\n");
			continue;
		}
		
		acs_log("acs_packet_type:%d\n", acs_packet.u.acs.msgtype);
		
		switch(acs_packet.u.acs.msgtype)
		{
			case Sequence_req:
			{
				acs_log("receive pkt: Sequence_req\n");
				
				memset(&acs_packet_Sequence_resp, 0, sizeof(acs_packet_Sequence_resp));
				memset(buf_Sequence_resp, 0, sizeof(buf_Sequence_resp));
				acs_packet_Sequence_resp.head.clusterID = Get_ClusterId();
				acs_packet_Sequence_resp.head.protocolLen = 12;
				acs_packet_Sequence_resp.head.protocolType = ACS;
				acs_packet_Sequence_resp.head.protocolver = 1;
				acs_packet_Sequence_resp.head.seqnum = 0;
				acs_packet_Sequence_resp.msgtype = Sequence_resp;
				acs_packet_Sequence_resp.seq_num = gSeqnum;
				memcpy(acs_packet_Sequence_resp.mac, mac, MAC_LEN);
				//memset(mac, 0, MAC_LEN);
				acs_log("be going to call Assemble_ACS_SequenceResponse.\n");
				
				if(HAN_FALSE == Assemble_ACS_SequenceResponse(buf_Sequence_resp, &acs_packet_Sequence_resp))
				{
					acs_log("Assemble_ACS_SequenceResponse error!\n");
					break;
				}
				
				acs_log("Assemble_ACS_SequenceResponse finish.\n");
				
				brast_addr.sin_addr.s_addr = get_broadcast_addr();
				brast_addr.sin_port = htons(CLIENT_PORT);
				if(ERROR == sendto(sockfd, buf_Sequence_resp, sizeof(buf_Sequence_resp), 0, (struct sockaddr*)&brast_addr, sizeof(brast_addr)))
				{
					perror("sendto");
					break;
				}
				
				acs_log("Seqnum:%d\n", gSeqnum);
				acs_log("send Sequence_resp over!\n");
				
				break;
			}
			case Sequence_resp:
			{
				break;
			}
			case Token_req:
			{
				acs_log("receive pkt: Token_req\n");
				
				if(acs_packet.u.acs.seq_num == gSeqnum)
				{
					acs_log("gSeqnum = seq_num_recv.\n");
					
					memset(&acs_packet_token_resp, 0, sizeof(acs_packet_token_resp));
					memset(buf_Token_resp, 0, sizeof(buf_Token_resp));
					acs_packet_token_resp.head.clusterID = Get_ClusterId();
					acs_packet_token_resp.head.protocolLen = 12;
					acs_packet_token_resp.head.protocolType = ACS;
					acs_packet_token_resp.head.protocolver = 0;
					acs_packet_token_resp.head.seqnum = 0;
					acs_packet_token_resp.msgtype = Token_resp;
					acs_packet_token_resp.seq_num = ++gSeqnum;
					memcpy(acs_packet_token_resp.mac, acs_packet.u.acs.mac, MAC_LEN);
					memcpy(mac, acs_packet.u.acs.mac, MAC_LEN);
					acs_log("be going to call Assemble_ACS_TokenResponse.\n");
					
					if(HAN_FALSE == Assemble_ACS_TokenResponse(buf_Token_resp, &acs_packet_token_resp))
					{
						acs_log("Assemble_ACS_TokenResponse error!\n");
						break;
					}
					
					acs_log("Assemble_ACS_TokenResponse finish.\n");
					
					brast_addr.sin_addr.s_addr = get_broadcast_addr();
					brast_addr.sin_port = htons(CLIENT_PORT);
					if(ERROR == sendto(sockfd, buf_Token_resp, sizeof(buf_Token_resp), 0, (struct sockaddr*)&brast_addr, sizeof(brast_addr)))
					{
						perror("sendto");
						break;
					}
					
					acs_log("Seqnum:%d\n", gSeqnum);
					acs_log("send Token_resp over!\n");
					

				}
				else
				{
					acs_log("gSeqnum != seq_num_recv.\n");					
				}
				
				break;
			}
			case Token_resp:
			{
				break;
			}
			default:
			{
				break;
			}
		}

	}
	close(sockfd);
	
}
 
void *recv_pipe_function(void)
{
	int fd_pipe, len_recv;
	char buf_recv[128] = "";	
	
	fd_pipe = open(PIPE_ACS_MGT, O_RDWR);
	if (fd_pipe < 0)
	{
		err(1, "Could not open acs_mgt fifo '%s'\n", PIPE_ACS_MGT);
	}
	
	while(1)
	{
		memset(buf_recv, 0, sizeof(buf_recv));		
		
		len_recv = read(fd_pipe, buf_recv, sizeof(buf_recv));
		if(len_recv > 0)
		{			
			acs_log("seq_num: %d\n\n", gSeqnum);
			printf("seq_num: %d\n\n", gSeqnum);
		}		
	}	
}
void acs_pipe_init(void)
{
	int ret;
	
	unlink(PIPE_ACS_MGT);
	ret = mkfifo(PIPE_ACS_MGT, 0666);
	if(ret < 0)
	{
		acs_log("mkfifo fail!\n\n");
	}
	
	acs_log("mkfifo finish!\n\n");
}
void acs_mgt_init(void)
{
	acs_log("acs_mgt_init...\n\n");
	
	if (timer_init() == 0)
	{
		acs_log("%s-%d Can't init timer module\n", __func__, __LINE__);
		exit(1);
	}
	
	acs_log("timer_init finished!\n\n");	
	
	local_sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(local_sockfd < 0)
	{
		perror("socket");
		exit(-1);
	}
	
	acs_log("socket local_sockfd finished!\n\n");
	
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0)
	{
		perror("socket");
		exit(-1);
	}
	
	acs_log("socket sockfd finished!\n\n");
	
	local_addr.sun_family = AF_UNIX;
	strcpy(local_addr.sun_path, ACS_PATH);		
	
	acs_log("local_addr.sun_path:%s\n\n", ACS_PATH);
	
	bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(LOCAL_PORT);
	my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	
	err_log = bind(sockfd, (struct sockaddr*)&my_addr, sizeof(my_addr));
	if(err_log != 0)
	{
		perror("bind");
		close(sockfd);
		exit(-1);
	}
	
	acs_log("binding server to port %d\n", LOCAL_PORT);	
	
	acs_log("keep_alive_send timer add finish!\n\n");
	
	acs_pipe_init();
	
	acs_log("acs_mgt_init finish!\n\n");
}
int main(int argc, char *argv[])
{
	int i = 0;
    for (i = 0; i < sysconf(_SC_OPEN_MAX); i++) {
         if (i != STDIN_FILENO && i != STDOUT_FILENO
             && i != STDERR_FILENO)
             close(i);
    }

	pthread_t thread_recv_pipe;	
	const char *ident = "acs_mgt:";
	openlog(ident, 0, LOG_SYSLOG);
	
	acs_mgt_get_options(argc, argv);		
	
	acs_log("acs module start!\n");	
	
	acs_mgt_init();
	
	keep_alive_timer_id = timer_add(keep_alive_interval, 0, &keep_alive_send, NULL);
	
	if(0 != pthread_create(&thread_recv_pipe, NULL, (void *)recv_pipe_function, NULL)) 
	{
        acs_log("create thread_recv_pipe fail.\n");        
    }

    acs_mgt_function();
	
	pthread_join(thread_recv_pipe, NULL);
	
	closelog();
	return 0;
}
































