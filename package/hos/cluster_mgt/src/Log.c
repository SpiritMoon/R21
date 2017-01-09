#include "common.h"
#include <syslog.h>
#include <assert.h>
#include "Log.h"


//#define WRITE_STD_OUTPUT 1 

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

static FILE *gLogFile = NULL;

#ifndef SINGLE_THREAD
ThreadMutex gFileMutex;
#endif


int gEnabledLog = 1;
int gMaxLogFileSize = (1024*1024*1024);

int gLogdebugLevel = SYSLOG_DEBUG_DEFAULT;
int gLOGLEVEL = SYSLOG_DEBUG_ALL;
char gLogFileName[] = LOG_FILE_NAME;


void LogInitFile(char *fileName)
{
	if (fileName == NULL)
	{
		printf("%s-%d Wrong File Name for Log File\n", __func__, __LINE__);
	}

	if ((gLogFile = fopen(fileName, "a+")) == NULL)
	{
		printf("%s-%d Can't open log file: %s\n", __func__, __LINE__, strerror(errno));
		exit(1);
	}

#ifndef SINGLE_THREAD
	if (!CreateThreadMutex(&gFileMutex))
	{
		syslog_crit("%s-%d Can't Init File Mutex for Log\n", __func__, __LINE__);
		fclose(gLogFile);
		exit(1);
	}
#endif
}


CWBool checkResetFile()
{
	long fileSize = 0;

	if ((fileSize = ftell(gLogFile)) == -1)
	{
		syslog_crit("%s-%d An error with log file occurred: %s\n", __func__, __LINE__, strerror(errno));
		return CW_FALSE;
	}
	
	if (fileSize >= gMaxLogFileSize)
	{
		fclose(gLogFile);
		if ((gLogFile = fopen(gLogFileName, "w")) == NULL) 
		{
			syslog_crit("%s-%d Can't open log file: %s\n", __func__, __LINE__, strerror(errno));
			return CW_FALSE;
		}
	}
	return CW_TRUE;
}


void LogCloseFile()
{
#ifndef SINGLE_THREAD
	DestroyThreadMutex(&gFileMutex);
#endif

	fclose(gLogFile);
}

void syslog_emerg(char *format,...)
{
	char buf[2048] = {0};
	
	sprintf(buf, "%s ", "<emerg>");
	
	va_list ptr;
	va_start(ptr,format);
	vsprintf(buf+strlen(buf),format,ptr);
	va_end(ptr);
	
#if SERVER_SYSLOG
	openlog(LOG_MODULE, 0, LOG_DAEMON);
	syslog(LOG_EMERG,"%s",buf);
	closelog();	
#else
	fprintf(gLogFile, "%s\n", buf);
#endif
}


void syslog_alert(char *format,...)
{
	char buf[2048] = {0};

	sprintf(buf, "%s ", "<alert>");
	
	va_list ptr;
	va_start(ptr,format);
	vsprintf(buf+strlen(buf),format,ptr);
	va_end(ptr);
	
#if SERVER_SYSLOG
	openlog(LOG_MODULE, 0, LOG_DAEMON);
	syslog(LOG_ALERT,"%s",buf);
	closelog();	
#else
	fprintf(gLogFile, "%s\n", buf);	
#endif
}


void syslog_crit(char *format,...)
{
	char buf[2048] = {0};
	
	sprintf(buf,"%s ", "<crit>");

	va_list ptr;
	va_start(ptr,format);
	vsprintf(buf+strlen(buf),format,ptr);

	va_end(ptr);
#if SERVER_SYSLOG
	openlog(LOG_MODULE, 0, LOG_DAEMON);
	syslog(LOG_CRIT, "%s", buf);
	closelog();	
#else
	fprintf(gLogFile, "%s\n", buf);
#endif	
}


void syslog_err(char *format,...)
{
	char buf[2048] = {0};

	sprintf(buf,"%s ", "<err>");
	
	va_list ptr;
	va_start(ptr,format);
	vsprintf(buf+strlen(buf),format,ptr);
	va_end(ptr);
	
#if SERVER_SYSLOG
	openlog(LOG_MODULE, 0, LOG_DAEMON);
	syslog(LOG_ERR,"%s", buf);
	closelog();	
#else
	fprintf(gLogFile, "%s\n", buf);
#endif
}


void syslog_warning(char *format,...)
{
	char buf[2048] = {0};
	
	sprintf(buf,"%s ", "<warn>");
	
	va_list ptr;
	va_start(ptr,format);
	vsprintf(buf+strlen(buf),format,ptr);
	va_end(ptr);
	
#if SERVER_SYSLOG
	openlog(LOG_MODULE, 0, LOG_DAEMON);
	syslog(LOG_WARNING,"%s",buf);
	closelog();	
#else
	fprintf(gLogFile, "%s\n", buf);
#endif
}


void syslog_notice(char *format,...)
{
	char buf[2048] = {0};
	
	sprintf(buf,"%s ", "<notice>");
	
	va_list ptr;
	va_start(ptr,format);
	vsprintf(buf+strlen(buf),format,ptr);
	va_end(ptr);

#if SERVER_SYSLOG
	openlog(LOG_MODULE, 0, LOG_DAEMON);
	syslog(LOG_NOTICE,"%s",buf);
	closelog(); 
#else
	fprintf(gLogFile, "%s\n", buf);
#endif
}


void syslog_info(char *format,...)
{
	char buf[2048] = {0};
	
	sprintf(buf,"%s ", "<info>");
	
	va_list ptr;
	va_start(ptr,format);
	vsprintf(buf+strlen(buf),format,ptr);
	va_end(ptr);

#if SERVER_SYSLOG
	openlog(LOG_MODULE, 0, LOG_DAEMON);
	syslog(LOG_INFO,"%s",buf);
	closelog(); 
#else
	fprintf(gLogFile, "%s\n", buf);
#endif
}


void syslog_debug_debug(int type, char *format,...)
{
	char buf[2048] = {0};

	if (gLOGLEVEL & type)
	{
		va_list ptr;
		va_start(ptr, format);
		vsprintf(buf+strlen(buf), format, ptr);
		va_end(ptr);
		
#if SERVER_SYSLOG
		openlog(LOG_MODULE, 0, LOG_DAEMON);
		syslog(LOG_DEBUG, "%s", buf);
		closelog();
#else
		fprintf(gLogFile, "%s\n", buf);
#endif
	}
}


void syslog_debug_info(char *format,...)
{
	int log_level = SYSLOG_DEBUG_INFO;
	char buf[2048] = {0};

	if (gLOGLEVEL & log_level)
	{
		va_list ptr;
		va_start(ptr,format);
		vsprintf(buf+strlen(buf),format,ptr);
		va_end(ptr);
		
#if SERVER_SYSLOG
		openlog(LOG_MODULE, 0, LOG_DAEMON);
		syslog(LOG_DEBUG,"%s",buf);
		closelog();
#else
		fprintf(gLogFile, "%s\n", buf);
#endif
	}
}

void syslog_debug(char *format,...)
{
	int log_level = SYSLOG_DEBUG;
	char buf[2048] = {0};

	if (gLOGLEVEL & log_level)
	{
		sprintf(buf, "%s ", "<dbg>");
		
		va_list ptr;
		va_start(ptr, format);
		vsprintf(buf+strlen(buf), format, ptr);
		va_end(ptr);
		
#if SERVER_SYSLOG
		openlog(LOG_MODULE, 0, LOG_DAEMON);
		syslog(LOG_DEBUG, "%s", buf);
		closelog();
#else
		fprintf(gLogFile, "%s\n", buf);
#endif
	}
}


/*****************************************************************************
 *	mac2str
 * 
 *	mac to strig
 *
 *  INPUT:
 *		haddr - mac address 
 *  
 *  OUTPUT:
 * 	 NULL
 *
 *  RETURN:
 * 	 static_buferr - mac string
 * 	 NULL
 *
 ****************************************************************************/

char *mac2str(unsigned char *haddr)
{
	static int count = 0;
	static unsigned char buf[STATIC_BUFFER_SIZE][MAX_MAC_STRING_LEN];
	int len = MAX_MAC_STRING_LEN;	
	unsigned char *tmp = NULL;

	count++;
	if (count >= STATIC_BUFFER_SIZE)
	{
		count = 0;
	}
	
	tmp = (unsigned char *)&(buf[count][0]);
	
	memset(tmp, 0, len);
	if (NULL != haddr)
	{
		snprintf((char *)tmp, MAX_MAC_STRING_LEN, "%02X:%02X:%02X:%02X:%02X:%02X", MAC2STR(haddr));
	}
	
	return (char *)tmp;
}

/**********************************************************************
 *	u32ip2str
 * 
 *	IPv4 address to string (EXP: 0x0a01010a -> 10.1.1.10)
 *
 *  INPUT:
 *		u32_ipaddr - IPv4 address 
 *  
 *  OUTPUT:
 * 	 NULL
 *
 *  RETURN:
 * 	 char * - ipv4 address string
 * 	 NULL - failed
 *
 **********************************************************************/
char *u32ip2str(unsigned int u32_ipaddr)
{	
	struct in_addr inaddr;

	memset(&inaddr, 0, sizeof(struct in_addr));

	inaddr.s_addr = u32_ipaddr;

	return inet_ntoa(inaddr);
}


