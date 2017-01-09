#include "common.h"
#include "timerlib.h"
#include "Log.h"
#include "hccpprotocol.h"

extern int sock_scan_request(void);
extern void GetRadioInfo(void);



// timers
typedef struct {
 	CWThread *requestedThreadPtr;
 	int signalToRaise;
} ThreadTimerArg;

TimerID scan_timer = 0;  //the timer's name
TimerID uprf_timer = 0;
TimerID rfag_timer = 0;

void wid_hex_dump(unsigned char *buffer, int buffLen)
{
	unsigned int i = 0, j = 0;
	unsigned int num = 0;
	unsigned int curLen = 0;
	unsigned char lineBuffer[255] = {0}, *bufPtr = NULL;
	
	if (!buffer)
	{
		return;
	}
	syslog_debug(".......................RX.......................%d\n", buffLen);
	
	bufPtr = lineBuffer;
	num = buffLen / 16;
	for (i = 0; i < num; i++)
	{
		syslog_debug("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
					buffer[i * 16 + 0], buffer[i * 16 + 1], buffer[i * 16 + 2], buffer[i * 16 + 3],
					buffer[i * 16 + 4], buffer[i * 16 + 5], buffer[i * 16 + 6], buffer[i * 16 + 7],
					buffer[i * 16 + 8], buffer[i * 16 + 9], buffer[i * 16 + 10], buffer[i * 16 + 11],
					buffer[i * 16 + 12], buffer[i * 16 + 13], buffer[i * 16 + 14], buffer[i * 16 + 15]);
	}
	if ((buffLen%16) != 0)
	{
		j = num * 16;
		for (i = j; i < buffLen; i++)
		{
			curLen += sprintf((char*)bufPtr, "%02x ", buffer[i]);
			bufPtr = lineBuffer + curLen;
		}
		syslog_debug("%s\n", lineBuffer);
	}
	
	syslog_debug(".......................RX.......................\n");
}

__inline__ int NetworkGetAddressSize(CWNetworkLev4Address *addrPtr)
{
	// assume address is valid
	
	switch ( ((struct sockaddr*)(addrPtr))->sa_family )
	{		
    	#ifdef	IPV6
    	// IPv6 is defined in Stevens' library
    		case AF_INET6:
    			return sizeof(struct sockaddr_in6);
    			break;
    	#endif
    		case AF_INET:
    		default:
    			return sizeof(struct sockaddr_in);
	}
}


/* include sock_ntop */
char *sock_ntop_r(const struct sockaddr *sa, char *str)
{
	char portstr[8] = {0};
	
	switch (sa->sa_family)
	{
		case AF_INET:
		{
			struct sockaddr_in	*sin = (struct sockaddr_in *) sa;
			
			if (inet_ntop(AF_INET, &sin->sin_addr, str, 128) == 0)
			{
				return(NULL);
			}	
			if (ntohs(sin->sin_port) != 0)
			{
				snprintf(portstr, sizeof(portstr), ":%d", ntohs(sin->sin_port));
				strcat(str, portstr);
			}
			return(str);
	    }
/* end sock_ntop */

#ifdef	IPV6
		case AF_INET6:
		{
			struct sockaddr_in6	*sin6 = (struct sockaddr_in6 *) sa;
			
			str[0] = '[';
			if (inet_ntop(AF_INET6, &sin6->sin6_addr, str + 1, 128 - 1) == NULL)
			{
				return(NULL);
			}	
			if (ntohs(sin6->sin6_port) != 0)
			{
				snprintf(portstr, sizeof(portstr), "]:%d", ntohs(sin6->sin6_port));
				strcat(str, portstr);
				return(str);
			}
			return (str + 1);
		}
#endif

#ifdef	AF_UNIX
		case AF_UNIX:
		{
			struct sockaddr_un	*unp = (struct sockaddr_un *) sa;
			
			/* OK to have no pathname bound to the socket: happens on
			every connect() unless client calls bind() first. */
			if (unp->sun_path[0] == 0)
			{
				strcpy(str, "(no pathname bound)");
			}	
			else
			{
				snprintf(str, 128, "%s", unp->sun_path);
			}	
			return(str);
		}
#endif

#ifdef	HAVE_SOCKADDR_DL_STRUCT
		case AF_LINK:
		{
			struct sockaddr_dl	*sdl = (struct sockaddr_dl *) sa;
			
			if (sdl->sdl_nlen > 0)
			{
				snprintf(str, 128, "%*s (index %d)", sdl->sdl_nlen, &sdl->sdl_data[0], sdl->sdl_index);
			}	
			else
			{
				snprintf(str, 128, "AF_LINK, index=%d", sdl->sdl_index);
			}	
			return(str);
		}
#endif
	default:
		snprintf(str, 128, "sock_ntop: unknown AF_xxx: %d", sa->sa_family);
		return(str);
	}
    return (NULL);
}

int sock_cpy_addr_port(struct sockaddr *sa1, const struct sockaddr *sa2)
{
	sa1->sa_family = sa2->sa_family;
	
	switch (sa1->sa_family)
	{
		case AF_INET:
		{
			(memcpy( &((struct sockaddr_in *) sa1)->sin_addr,
						&((struct sockaddr_in *) sa2)->sin_addr,
						sizeof(struct in_addr)));
			((struct sockaddr_in *) sa1)->sin_port = ((struct sockaddr_in *) sa2)->sin_port;
			return 0;
		}

#ifdef	IPV6
		case AF_INET6:
		{
			(memcpy( &((struct sockaddr_in6 *) sa1)->sin6_addr,
						&((struct sockaddr_in6 *) sa2)->sin6_addr,
						sizeof(struct in6_addr)));
		
			(((struct sockaddr_in6 *) sa1)->sin6_port =	((struct sockaddr_in6 *) sa2)->sin6_port);
			return 0;
		}
#endif

#ifdef	AF_UNIX
		case AF_UNIX:
		{
			(strcpy(((struct sockaddr_un *) sa1)->sun_path, ((struct sockaddr_un *) sa2)->sun_path));
			return 0;
		}
#endif

#ifdef	HAVE_SOCKADDR_DL_STRUCT
		case AF_LINK:
		{
			return(-1);		/* no idea what to copy here ? */
		}
#endif
	}
    return (-1);
}

CWBool PopenFile(char *cmd_str, char *str, int len)
{
	FILE *fp = NULL;
	
	if (cmd_str == NULL ||str == NULL)
	{
		return CW_FALSE;
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
		
		return CW_TRUE;
	}
	else
	{
		syslog_debug("%s-%d cmd:%s error[%s]\n", __func__, __LINE__, cmd_str, strerror(errno));
		
		return CW_FALSE;
	}
}


CWBool CreateThread(CWThread *newThread, THREAD_FUNCTION threadFunc, void *arg, int less)
{
	pthread_attr_t attr;
	size_t ss;	
	int s = PTHREAD_CREATE_DETACHED;
	
	if (newThread == NULL)
	{
	    return CW_FALSE;
	}
	
	pthread_attr_init(&attr);
	if (less)
	{
		pthread_attr_getstacksize(&attr,&ss);	
		ss = (ss*3)/4;
		pthread_attr_setstacksize(&attr,ss);
	}
	pthread_attr_setdetachstate(&attr,s);
		
	if (pthread_create(newThread, &attr, threadFunc, arg) != 0)
	{
		return CW_FALSE;
	}

	return CW_TRUE;
}

// Creates a thread mutex (wrapper for pthread_mutex_init)
CWBool CreateThreadMutex(ThreadMutex *theMutex)
{
	if (theMutex == NULL)
	{
	    return CW_FALSE;
	}
	
	switch (pthread_mutex_init(theMutex, NULL))
	{
		case 0: // success
			break;
		case ENOMEM:
			return CW_FALSE;
		default:
			return CW_FALSE;
	}
	return CW_TRUE;
}

// Free a thread mutex (wrapper for pthread_mutex_destroy)
void DestroyThreadMutex(ThreadMutex *theMutex)
{
	if (theMutex == NULL)
	    return;
	pthread_mutex_destroy(theMutex);
}

// locks a mutex among threads at the specified address (blocking)
CWBool ThreadMutexLock(ThreadMutex *theMutex)
{
	if (theMutex == NULL)
	    return CW_FALSE;
	
	if (pthread_mutex_lock( theMutex ) != 0)
	{
		return CW_FALSE;
	}
/*
	fprintf(stdout, "Mutex %p locked by %p.\n", theMutex, pthread_self());
	fflush(stdout);
*/
	return CW_TRUE;
}

// locks a mutex among threads at the specified address (non-blocking).
// CW_TRUE if lock was acquired, CW_FALSE otherwise
CWBool ThreadMutexTryLock(ThreadMutex *theMutex)
{
	if (theMutex == NULL)
	{
		return CW_FALSE;
	}
	
	if (pthread_mutex_trylock( theMutex ) == EBUSY)
	{
	    return CW_FALSE;
	}
	
	return CW_TRUE;
}

// unlocks a mutex among threads at the specified address
void ThreadMutexUnlock(ThreadMutex *theMutex)
{
	if (theMutex == NULL)
	{
	    return;
	}
	pthread_mutex_unlock( theMutex );
/*
	fprintf(stdout, "Mutex %p UNlocked by %p.\n", theMutex, pthread_self());
	fflush(stdout);
*/
}


void HandleTimer(TimerArg arg)
{
    int j = 0;
	time_t timep;  
	struct tm *p = NULL; 
	ThreadTimerArg *a = (ThreadTimerArg*)arg;
	int signalToRaise = a->signalToRaise;
	
	if (signalToRaise == SIGSCAN)
	{
		time(&timep);
		p = localtime(&timep);
		syslog_debug("%s-%d %02d:%02d:%02d send scan request\n",__func__, __LINE__, p->tm_hour, p->tm_min, p->tm_sec);
		
		sock_scan_request();
	}
	else if (signalToRaise == SIGRFAG)
	{
		pthread_mutex_lock(&cluster_member_list_mutex);
		
		CLUSTER_MB *mem = cluster_member_list.cluster_member_list_head;
		while (mem != NULL)
		{
			int count = 0;
			for (j = 0; j < mem->radiocnt && j < L_RADIO_NUM; j++)
			{
				if (mem->WTP_Radio[j].rssi)
				{
					time(&timep);
					p = localtime(&timep);
					
					if (timep - mem->WTP_Radio[j].rssi_stamp > MAX_SURVIVAL_TIME)
					{
						syslog_debug("%s-%d %02d:%02d:%02d "MACSTR" radio%d rssi %d aging\n",
									__func__, __LINE__, p->tm_hour, p->tm_min, p->tm_sec,
									MAC2STR(mem->mac_addr), j, mem->WTP_Radio[j].rssi);
						
						mem->WTP_Radio[j].rssi = 0;
						count++;
					}
				}
			}
			if (count == mem->radiocnt)
			{
				mem->scan_tag = 0;
			}
			
			mem = mem->next;
		}
		
		pthread_mutex_unlock(&cluster_member_list_mutex);
		
		if (!(TimerRequest(RSSI_AGING_TIMER, &rfag_timer, SIGRFAG)))
		{
			syslog_debug("%s-%d rssi aging timer request failed\n", __func__, __LINE__);
		}
	}
	else if (signalToRaise == SIGUPRF)
	{
		time(&timep);
		p = localtime(&timep);
		syslog_debug("%s-%d %02d:%02d:%02d update radio info\n",__func__, __LINE__, p->tm_hour, p->tm_min, p->tm_sec);
		
		GetRadioInfo();
		
		if (!(TimerRequest(GET_RADIO_INFO_TIMER, &uprf_timer, SIGUPRF)))
		{
			syslog_debug("%s-%d uprf timer request failed\n", __func__, __LINE__);
		}
	}

	FREE_OBJECT(a);

	return;
}

CWBool TimerRequest(int sec, TimerID *idPtr, int signalToRaise)
{
	ThreadTimerArg *arg = NULL;
	
	if (sec < 0 || idPtr == NULL)
	{
		return CW_FALSE;
	}
	CREATE_OBJECT_ERR(arg, ThreadTimerArg, return CW_FALSE;);
	
	memset(arg, 0 ,sizeof(ThreadTimerArg));
	arg->signalToRaise = signalToRaise;
		
	if ((*idPtr = timer_add(sec, 0, &HandleTimer, arg)) == -1)
	{
		syslog_debug("%s-%d timer_add failed\n", __func__, __LINE__);
		return CW_FALSE;
	}
	syslog_debug("%s-%d signal %s TimerID= %d\n", __func__, __LINE__, SIGNAL_STR(signalToRaise), *idPtr);

	return CW_TRUE;
}

CWBool TimerCancel(TimerID *idPtr, int isFree)
{
	timer_rem(*idPtr, isFree);
	*idPtr = TIMER_DEFAULT;
	return CW_TRUE;
}


