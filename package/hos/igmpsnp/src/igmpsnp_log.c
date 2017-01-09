/*******************************************************************************
Copyright (C) Autelan Technology


This software file is owned and distributed by Autelan Technology 
********************************************************************************


THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR 
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
********************************************************************************
* igmp_snp_log.c
*
*
* CREATOR:
* 		jinpc@autelan.com
*
* DESCRIPTION:
* 		igmp inter source, handle igmp log infomation.
*
* DATE:
*		10/14/2008
*
* FILE REVISION NUMBER:
*  		$Revision: 1.10 $
*
*******************************************************************************/
#ifdef __cplusplus
extern "C"
{
#endif
#include <syslog.h>
#include <stdarg.h>
#include "igmpsnp_log.h"
#include "igmpsnp_com.h"


char *ident = "igmpsnp";

extern igmp_snoop_debug;



/**********************************************************************************
 *  igmp_snoop_log_set_debug_value
 * 
 *  DESCRIPTION:
 *		This function set up one igmp snoop debug level
 *
 *  INPUT:
 * 	 	val_mask - debug level value stands for one level 
 *  
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 	 	IGMPSNP_RETURN_CODE_ALREADY_SET - if debug level has already been set before.
 *	 	IGMPSNP_RETURN_CODE_OK - debug level setup successfully.
 *
 **********************************************************************************/


void igmp_debug_log(const char * fmt, ...)
{
    char buf[256];
    va_list ap;
    if(!igmp_snoop_debug)
        return;
    va_start(ap,fmt);
    vsnprintf(buf,256,fmt,ap);
    va_end(ap);
    printf("%s\n",buf);
}

/**********************************************************************************
 *igmp_snp_syslog_emerg
 *
 *  DESCRIPTION:
 *		output the daemon debug info to   /proc/kes_syslog
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_emerg
(
	char *format,...
)
{

	va_list ptr;
	char buf[IGMP_SNP_SYSLOG_LINE_BUFFER_SIZE] = {0};

	// ident null or format message null
	if(!ident || !format) {
		return;
	}

	openlog(ident, 0, LOG_DAEMON);

	// put log
	va_start(ptr, format);
	vsprintf(buf,format,ptr);
	va_end(ptr);
	syslog(LOG_EMERG,buf);

	return; 
}

 

/**********************************************************************************
 *igmp_snp_syslog_alert
 *
 *  DESCRIPTION:
 *		output the daemon debug info to   /proc/kes_syslog
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_alert
(
	char *format,...
)
{

	va_list ptr;
	char buf[IGMP_SNP_SYSLOG_LINE_BUFFER_SIZE] = {0};


	// ident null or format message null
	if(!ident || !format) {
		return;
	}

	openlog(ident, 0, LOG_DAEMON);

	// put log
	va_start(ptr, format);
	vsprintf(buf,format,ptr);
	va_end(ptr);
	syslog(LOG_ALERT,buf);


	return; 
}


/**********************************************************************************
 *igmp_snp_syslog_crit
 *
 *  DESCRIPTION:
 *		output the daemon debug info to   /proc/kes_syslog
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_crit
(
	char *format,...
)
{

	va_list ptr;
	char buf[IGMP_SNP_SYSLOG_LINE_BUFFER_SIZE] = {0};


	// ident null or format message null
	if(!ident || !format) {
		return;
	}

	openlog(ident, 0, LOG_DAEMON);

	// put log
	va_start(ptr, format);
	vsprintf(buf,format,ptr);
	va_end(ptr);
	syslog(LOG_CRIT,buf);


	return; 
}


/**********************************************************************************
 * igmp_snp_syslog_err
 *
 *  DESCRIPTION:
 *		output the daemon debug info to   /proc/kes_syslog
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_err
(
	char *format,...
)
{

	va_list ptr;
	char buf[IGMP_SNP_SYSLOG_LINE_BUFFER_SIZE] = {0};


	// ident null or format message null
	if(!ident || !format) {
		return;
	}

	openlog(ident, 0, LOG_DAEMON);

	// put log
	va_start(ptr, format);
	vsprintf(buf,format,ptr);
	va_end(ptr);
	syslog(LOG_ERR,buf);


	return; 
}

/**********************************************************************************
 * igmp_snp_syslog_warn
 *
 *  DESCRIPTION:
 *		output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_warn
(
	char *format,...
)
{
	va_list ptr;
	char buf[IGMP_SNP_SYSLOG_LINE_BUFFER_SIZE] = {0};
 
 
	// ident null or format message null
	if(!ident || !format) {
		return;
	}

	openlog(ident, 0, LOG_DAEMON);

	// put log
	va_start(ptr, format);
	vsprintf(buf,format,ptr);
	va_end(ptr);
	syslog(LOG_WARNING,buf);

	return;
}

/**********************************************************************************
 *  igmp_snp_syslog_notice
 *
 *  DESCRIPTION:
 *		output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_notice
(
	char *format,...
)
{
	va_list ptr;
	char buf[IGMP_SNP_SYSLOG_LINE_BUFFER_SIZE] = {0};
  
	// ident null or format message null
	if(!ident || !format) {
		return;
	}

	openlog(ident, 0, LOG_DAEMON);
 
	// put log
	va_start(ptr, format);
	vsprintf(buf,format,ptr);
	va_end(ptr);
	syslog(LOG_NOTICE,buf);

	return;
}


/**********************************************************************************
 *  igmp_snp_syslog_notice
 *
 *  DESCRIPTION:
 *		output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_info
(
	char *format,...
)
{
	va_list ptr;
	char buf[IGMP_SNP_SYSLOG_LINE_BUFFER_SIZE] = {0};
  
	// ident null or format message null
	if(!ident || !format) {
		return;
	}

	openlog(ident, 0, LOG_DAEMON);
 
	// put log
	va_start(ptr, format);
	vsprintf(buf,format,ptr);
	va_end(ptr);
	syslog(LOG_INFO,buf);

	return;
}


/**********************************************************************************
 * igmp_snp_syslog_dbg
 *
 *  DESCRIPTION:
 *		output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_dbg
(
	char *format,...
)
{
	va_list ptr;
	char buf[IGMP_SNP_SYSLOG_LINE_BUFFER_SIZE] = {0}; 

	// ident null or format message null
	if(!ident || !format) {
		return;
	} 
	openlog(ident, 0, LOG_DAEMON); 
 

	// put log
	va_start(ptr, format);
	vsprintf(buf,format,ptr);
	va_end(ptr);
	syslog(LOG_DEBUG,buf);


	return;
}


 
#ifdef __cplusplus
}
#endif

