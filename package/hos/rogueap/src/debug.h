/******************************************************************************
  File Name    : rogue_debug.h
  Author       : zhaoenjuan
  Date         : 20160227
  Description  : debug
******************************************************************************/

#include <stdio.h>
#include <syslog.h>
#ifndef _ROGUEAP_DEBUG_H_
#define _ROGUEAP_DEBUG_H_

/* Debug module ID*/
#define MODULE_DRIVER			0
#define MODULE_BACKGROUND		1
#define MODULE_CLUSTER			2
#define MODULE_WEB				3
#define MODULE_ROGUE			4

/*Debug level*/
#define ROGUEAP_LOG_LEVEL_EMERG		0  /*Affect the system running or other components*/
#define ROGUEAP_LOG_LEVEL_ERR		1  /*Report system err information*/
#define ROGUEAP_LOG_LEVEL_WARNING	2  /*Suggest a potential problem*/
#define ROGUEAP_LOG_LEVEL_INFO		3  /*Prompt information*/
#define ROGUEAP_LOG_LEVEL_DEBUG		4  /*Debug information*/


extern unsigned char rogue_debug_level;

#define rogue_debug_waring(fmt, args...)  do{     \
        if (rogue_debug_level > 1)                \
        {                                       \
            printf(fmt, ##args);                \
            printf("\r\n");                     \
   	        openlog("rogueap", 0, LOG_DAEMON);      \
            syslog(LOG_WARNING, fmt, ##args);   \
            closelog();                         \
        }                                       \
}while(0)

#define rogue_debug_error(fmt, args...)   do{ \
        if (rogue_debug_level > 0)            \
        {                                   \
            printf(fmt, ##args);            \
            printf("\r\n");                 \
            openlog("rogueap", 0, LOG_DAEMON);  \
            syslog(LOG_ERR, fmt, ##args);   \
            closelog();                     \
        }                                   \
}while(0)

#define rogue_debug_trace(fmt, args...)   do{ \
        if (rogue_debug_level > 2)            \
        {                                   \
            printf(fmt, ##args);            \
            printf("\r\n");                 \
   	        openlog("rogueap", 0, LOG_DAEMON);  \
            syslog(LOG_DEBUG, fmt, ##args); \
            closelog();                     \
        }                                   \
}while(0)


void rogue_debug(int module_id,int log_level,char *msg);	
void packet_dump(char *pos,int len);
void dump_file_open(char *mode);
void dump_file_close(void);

#endif