#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <dirent.h>
#include <sched.h>
#include <errno.h>
#include <assert.h>
#include <syslog.h>
#include <pthread.h>
#include <unistd.h>
#include <getopt.h>
#include <err.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>

#include <sys/un.h>
#include <sys/ipc.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/msg.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <linux/if_ether.h>

#include "timerlib.h"

#define	IFI_NAME	16			/* same as IFNAMSIZ in <net/if.h> */
#define	IFI_HADDR	 8			/* allow for 64-bit EUI-64 in future */
#define	IFI_ADDR_NUM	8
#define	IFI_IF_NUM	8
#define MAX_CLUSTER_AP 16
#define MAC_LEN  6       /* size of 802.11 address */
#define L_RADIO_NUM		4
#define MAX_CMD		65535
#define CLUSTER_PRI_MAX 0x0FFF000000000000
#define CLUSTER_PRI_MIN 0

#define BUF_SIZE 1024
#define PATH_LEN (64)
#define BOARD_ID_LEN 64

#define BUF_MAX_LEN 8192

#define SOCK_BUFSIZE 8192

#define TIMER_DEFAULT -1
#define	SCAN_MAX_RETRANSMIT		3

/*---for rssi cache time---*/
#define MAX_SURVIVAL_TIME  60*5

pthread_mutex_t  cluster_member_list_mutex;
pthread_mutex_t  elect_member_list_mutex;

typedef int CWSocket;
typedef struct sockaddr_storage CWNetworkLev4Address;

typedef pthread_t CWThread;
typedef pthread_mutex_t ThreadMutex;
typedef pthread_cond_t ThreadCondition;
typedef pthread_key_t ThreadSpecific;
typedef pthread_once_t ThreadOnce;

#define	THREAD_RETURN_TYPE						void*
#define	ThreadSigMask(how, set, old_set)		pthread_sigmask(how, set, old_set)
#define	ThreadIsEqual(t1, t2)					pthread_equal(t1,t2)
#define	ThreadSelf()							pthread_self()
#define	ThreadKill(t1, signal)					pthread_kil(t1,signal)
#define	ThreadSendSignal						ThreadKill
#define	THREAD_ONCE_INIT						PTHREAD_ONCE_INIT
#define	ThreadCallOnce							pthread_once

#define	REPEAT_FOREVER				while(1)
typedef void* (*THREAD_FUNCTION)(void*);
typedef int ThreadId;

#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define MACCMP(a, b)    \
        (a)[0] != (b)[0] || (a)[1] != (b)[1] || (a)[2] != (b)[2]   \
        || (a)[3] != (b)[3] || (a)[4] != (b)[4] || (a)[5] != (b)[5]
#endif

#define DEBUG_ENABLE	1 	/* should be off in release version */
#if DEBUG_ENABLE
#define FUNC_LINE_FMT		"%s-%d "
#define FUNC_LINE_LITERAL	__func__,__LINE__
#else
#define FUNC_LINE_FMT		"%s "
#define FUNC_LINE_LITERAL 	""
#endif

#define		ZERO_MEMORY					bzero
#define		COPY_MEMORY(dst, src, len)			bcopy(src, dst, len)

#define		BUFFER_SIZE					65536
#define		CREATE_OBJECT_ERR(obj_name, obj_type, on_err)	{obj_name = (obj_type*) (malloc(sizeof(obj_type))); if (!(obj_name)) {on_err}}
#define		FREE_OBJECT(obj_name)				{if (obj_name){free((obj_name)); (obj_name) = NULL;}}


#define		CREATE_OBJECT_SIZE_ERR(obj_name, obj_size,on_err)	{obj_name = (malloc(obj_size)); if (!(obj_name)) {on_err}}
#define		CREATE_ARRAY_ERR(ar_name, ar_size, ar_type, on_err)	{ar_name = (ar_type*) (malloc(sizeof(ar_type) * (ar_size))); if(!(ar_name)) {on_err}}
#define		CREATE_STRING_ERR(str_name, str_length, on_err)	{str_name = (char*) (malloc(sizeof(char) * ((str_length)+1) ) ); if(!(str_name)) {on_err}}
#define		CREATE_STRING_FROM_STRING_ERR(str_name, str, on_err)	{CREATE_STRING_ERR(str_name, strlen(str), on_err); strcpy((str_name), str);}


#define	CREATE_PROTOCOL_MESSAGE(mess, size, err)		CREATE_OBJECT_SIZE_ERR(((mess).msg), (size), err);		\
									ZERO_MEMORY(((mess).msg), (size));						\
									(mess).offset = 0;

#define CREATE_PROTOCOL_MSG_ARRAY_ERR(ar_name, ar_size, on_err) 	{\
											CREATE_ARRAY_ERR(ar_name, ar_size, ProtocolMessage, on_err)\
											int i = 0;\
											for (i = 0; i < (ar_size); i++) {\
												(ar_name)[i].msg = NULL;\
												(ar_name)[i].offset = 0; \
											}\
										}


#define COPY_MH_INTERFACE_PTR(int1, int2)		COPY_NET_ADDR_PTR( &((int1)->addr), &((int2)->addr));	\
							COPY_NET_ADDR_PTR( &((int1)->addrIPv4), &((int2)->addrIPv4));\
							(int1)->sock = (int2)->sock;					\
							(int1)->kind = (int2)->kind;	\
							(int1)->systemIndex = (int2)->systemIndex;\
							(int1)->systemIndexbinding = (int2)->systemIndexbinding;\
							memcpy((int1)->ifname,(int2)->ifname,IFI_NAME);



#define	FREE_PROTOCOL_MESSAGE(mess)		FREE_OBJECT(((mess).msg));								\
									(mess).offset = 0;


#define	COPY_NET_ADDR_PTR(addr1, addr2)  	sock_cpy_addr_port(((struct sockaddr*)(addr1)), ((struct sockaddr*)(addr2)))
#define	COPY_NET_ADDR(addr1, addr2)		COPY_NET_ADDR_PTR(&(addr1), &(addr2))
#define UseSockNtop(sa, block) 		{ 						\
							char __str[128] = {0};			\
							char *str; str = sock_ntop_r(((struct sockaddr*)(sa)), __str);\
							{block}					\
						}

typedef enum {
	CW_FALSE = 0,
	CW_TRUE = 1
} CWBool;

typedef struct{
	struct sockaddr_un addr;
	int 	addrlen;
}unixAddr;

extern int ScanRetransmit;
extern unixAddr toBGSC;
extern struct timeval timeout;
extern char gLogFileName[];

void wid_hex_dump(unsigned char *buffer, int buffLen);

__inline__ int NetworkGetAddressSize(CWNetworkLev4Address *addrPtr);
char *sock_ntop_r(const struct sockaddr *sa, char *str);
int sock_cpy_addr_port(struct sockaddr *sa1, const struct sockaddr *sa2);

CWBool PopenFile(char *cmd_str, char *str, int len);

CWBool CreateThread(CWThread *newThread, THREAD_FUNCTION threadFunc, void *arg, int less);
CWBool CreateThreadMutex(ThreadMutex *theMutex);
void DestroyThreadMutex(ThreadMutex *theMutex);
CWBool ThreadMutexLock(ThreadMutex *theMutex);
CWBool ThreadMutexTryLock(ThreadMutex *theMutex);
void ThreadMutexUnlock(ThreadMutex *theMutex);

void HandleTimer(TimerArg arg);
CWBool TimerRequest(int sec, TimerID *idPtr, int signalToRaise);
CWBool TimerCancel(TimerID *idPtr, int isFree);

#endif

