#include <sys/types.h>      
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include "sock_domain.h"
#include "Log.h"

//init local socket 
int InitSocket(int *sock, char *path_name)
{
	int sndbuf = SOCK_BUFSIZE*2;
	struct sockaddr_un addr;
	
	*sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (*sock < 0)
	{
		syslog_debug("%s-%d socket init error %s\n", __func__, __LINE__, strerror(errno));
		return CW_FALSE; 
	}
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path_name, sizeof(addr.sun_path)-1);
	unlink(addr.sun_path);
	
	//bind socket
	if (bind(*sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		syslog_debug("%s-%d socket bind error %s\n", __func__, __LINE__, strerror(errno));
		close(*sock);
		unlink(path_name);
		return CW_FALSE; 
	}
    
    if ((setsockopt(*sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf))) < 0)
    {   
        printf("%s setsockopt %s",__func__,strerror(errno));
        return CW_FALSE;
    }
	return CW_TRUE;
}

// send buf on an unconnected UDP socket.
int SendMsg(CWSocket sock, struct sockaddr_un *addrPtr, unsigned char *buf, int len)
{
	int addr_len = sizeof(struct sockaddr_un);
	
	if (buf == NULL || addrPtr == NULL)
	{
		syslog_debug("%s-%d pointer= NULL\n", __func__, __LINE__);
		return CW_FALSE;
	}
	
	if (sendto(sock, buf, len, 0, (struct sockaddr *)addrPtr, addr_len) < 0)
	{
		syslog_info("<sendto error>%s-%d buf=%x len= %d\n", __func__,__LINE__, buf, len);
		return CW_FALSE;
	}
	return CW_TRUE;
}

int RecvMsg(int socket, unsigned char *buf, int len, struct sockaddr_un *desaddr, int *readBytes)
{
	//check legal sendbuf, desaddr
	socklen_t addrlen;
	
	if (NULL == buf || NULL == desaddr || NULL == readBytes)
	{
		syslog_debug("%s-%d local socket receive message buf is NULL\n", __func__, __LINE__);
		return CW_FALSE;
	}
	
	addrlen = sizeof(struct sockaddr_un);
	
	while ((*readBytes = recvfrom(socket, buf, len, 0, (struct sockaddr *)desaddr, &addrlen)) < 0)
	{
		syslog_debug("%s-%d socket recv message error\n", __func__, __LINE__);
		if (errno == EINTR)
		{
			continue;
		}
		return CW_FALSE;
	}
	
	return CW_TRUE;
}


