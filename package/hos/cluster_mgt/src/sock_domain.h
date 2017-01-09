#ifndef SOCK_DOMAIN_H
#define SOCK_DOMAIN_H

#include <sys/types.h>
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

#include "common.h"

int InitSocket(int *sock, char *path_name);
int SendMsg(CWSocket sock, struct sockaddr_un *addrPtr, unsigned char *buf, int len);
int RecvMsg(int socket, unsigned char *buf, int len, struct sockaddr_un *desaddr, int *readBytes);

#endif
