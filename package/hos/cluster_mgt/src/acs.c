#include"libhccp.h"
#include<stdio.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/ipc.h>
#include<sys/socket.h>
#include<string.h>
#include<time.h>
#include <sys/msg.h>
#include<pthread.h>

#include<netinet/in.h> 
#include<arpa/inet.h> 
#include<stdlib.h> 
#include<errno.h> 
#include<netdb.h> 
#include<stdarg.h> 

int gSeqnum = 1;
#define CLIENT_PORT 4567
#define DEBUG_SWITCH 1
int main(int argc, char *argv[])
{
	unsigned short port = 4567;

	Hccp_Protocol_Struct acs_packet;
	ACS_format acs_packet_Sequence_resp, acs_packet_token_resp;
	char buf_Sequence_resp[16], buf_Token_resp[22];
	
	int sockfd;
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0)
	{
		perror("socket");
		exit(-1);
	}
	
	struct sockaddr_in my_addr;
	bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(port);
	my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if(DEBUG_SWITCH)
	{
		printf("binding server to port %d\n", port);
	}

	int err_log;
	err_log = bind(sockfd, (struct sockaddr*)&my_addr, sizeof(my_addr));
	if(err_log != 0)
	{
		perror("bind");
		close(sockfd);
		exit(-1);
	}

	if(DEBUG_SWITCH)
	{
		printf("receive data...\n");
	}
	
	while(1)
	{
		int recv_len;
		char recv_buf[512] = "";
		struct sockaddr_in client_addr;
		char cli_ip[INET_ADDRSTRLEN] = "";
		socklen_t cliaddr_len = sizeof(client_addr);
		
		recv_len = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&client_addr, &cliaddr_len);

		if(DEBUG_SWITCH)
		{
			printf("---------------------------------------------------------------\n");
			inet_ntop(AF_INET, &client_addr.sin_addr, cli_ip, INET_ADDRSTRLEN);
			printf("receive data from ip:%s,port:%d\n", cli_ip, ntohs(client_addr.sin_port));
			printf("data_len:%d\n", recv_len);
		}

		memset(&acs_packet, 0, sizeof(acs_packet));
		Parse_HCCPProtocol(recv_buf,  &acs_packet);
		
		if(DEBUG_SWITCH)
		{			
			printf("acs_packet_type:%d\n", acs_packet.u.acs.msgtype);
		}
		
		switch(acs_packet.u.acs.msgtype)
		{
			case Sequence_req:
			{
				memset(&acs_packet_Sequence_resp, 0, sizeof(acs_packet_Sequence_resp));
				memset(buf_Sequence_resp, 0, sizeof(buf_Sequence_resp));
				acs_packet_Sequence_resp.clusterID = 100;
				acs_packet_Sequence_resp.msgtype = Sequence_resp;
				acs_packet_Sequence_resp.seq_num = gSeqnum;

				
				Assemble_ACS_SequenceResponse(buf_Sequence_resp, &acs_packet_Sequence_resp) ;
				
				client_addr.sin_port = htons(CLIENT_PORT);
				sendto(sockfd, buf_Sequence_resp, sizeof(buf_Sequence_resp), 0, (struct sockaddr*)&client_addr, sizeof(client_addr));

				if(DEBUG_SWITCH)
				{
					printf("Seqnum:%d\n", gSeqnum);
					printf("send Sequence_resp over!\n");
				}
				
				break;
			}
			case Sequence_resp:
			{
				break;
			}
			case Token_req:
			{
				
				if(acs_packet.u.acs.seq_num == gSeqnum)
				{
					memset(&acs_packet_token_resp, 0, sizeof(acs_packet_token_resp));
					memset(buf_Token_resp, 0, sizeof(buf_Token_resp));
					acs_packet_token_resp.clusterID = 100;
					acs_packet_token_resp.msgtype = Token_resp;
					acs_packet_token_resp.seq_num = ++gSeqnum;
					memcpy(acs_packet_token_resp.mac, acs_packet.u.acs.mac, MAC_LEN);

					Assemble_ACS_TokenResponse(buf_Token_resp, &acs_packet_token_resp) ;
					
					client_addr.sin_port = htons(CLIENT_PORT);
					sendto(sockfd, buf_Token_resp, sizeof(buf_Token_resp), 0, (struct sockaddr*)&client_addr, sizeof(client_addr));

					if(DEBUG_SWITCH)
					{
						printf("Seqnum:%d\n", gSeqnum);
						printf("send Token_resp over!\n");
					}
					

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
	return 0;
}
































