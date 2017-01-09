/******************************************************************************
  File Name    : dnsrd_debug.h
  Author       : lhc
  Date         : 20160302
  Description  : debug
******************************************************************************/

#ifndef _DNSRD_DEBUG_H_
#define _DNSRD_DEBUG_H_

#include <syslog.h>

extern unsigned char dnsrd_debug_level;

#define dnsrd_debug_waring(fmt, args...)  do{     \
        if (dnsrd_debug_level > 1)                \
        {                                       \
            printf(fmt, ##args);                \
            printf("\r\n");                     \
   	        openlog("dnsrd", 0, LOG_DAEMON);      \
            syslog(LOG_WARNING, fmt, ##args);   \
            closelog();                         \
        }                                       \
}while(0)

#define dnsrd_debug_error(fmt, args...)   do{ \
        if (dnsrd_debug_level > 0)            \
        {                                   \
            printf(fmt, ##args);            \
            printf("\r\n");                 \
            openlog("dnsrd", 0, LOG_DAEMON);  \
            syslog(LOG_ERR, fmt, ##args);   \
            closelog();                     \
        }                                   \
}while(0)

#define dnsrd_debug_trace(fmt, args...)   do{ \
        if (dnsrd_debug_level > 2)            \
        {                                   \
            printf(fmt, ##args);            \
            printf("\r\n");                 \
   	        openlog("dnsrd", 0, LOG_DAEMON);  \
            syslog(LOG_DEBUG, fmt, ##args); \
            closelog();                     \
        }                                   \
}while(0)

#endif
