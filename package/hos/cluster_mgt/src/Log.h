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
* CWLog.h
*
*
* CREATOR:
* autelan.software.wireless-control. team
*
* DESCRIPTION:
* wid module
*
*
*******************************************************************************/


#ifndef __HCCP_Log_HEADER__
#define __HCCP_Log_HEADER__

extern char gLogFileName[];

#define LOG_FILE_NAME				"/tmp/cluster_mgt.txt"
#define LOG_MODULE					"cluster_mgt"
#define SERVER_SYSLOG	1
#define LOG_INDENT_LEN	(16)


#define SYSLOG_EMERG	0
#define SYSLOG_ALERT	1
#define SYSLOG_CRIT		2
#define SYSLOG_ERR		3
#define SYSLOG_WARNING	4
#define SYSLOG_NOTICE	5
#define SYSLOG_INFO		6
#define SYSLOG_DEBUG	7
#define SYSLOG_DEFAULT	0


#define SYSLOG_DEBUG_NONE		0
#define SYSLOG_DEBUG_INFO		1
#define SYSLOG_DEBUG_DEBUG		8
#define SYSLOG_DEBUG_ALL		15
#define SYSLOG_DEBUG_DEFAULT	15
//if the syslog system forbidden showing the debug_info,we should change the default value to 0
extern int gLogdebugLevel;

extern int gLOGLEVEL;

enum debug_level
{
	LOG_DEFAULT = 0x1,
	LOG_ALL = 0xf,
};



#define STATIC_BUFFER_SIZE			(16)
#define MAX_MAC_STRING_LEN			(32)
extern char gLogFileName[];
void LogInitFile(char *fileName);
void syslog_emerg(char *format,...);
void syslog_alert(char *format,...);
void syslog_crit(char *format,...);
void syslog_err(char *format,...);
void syslog_warning(char *format,...);
void syslog_notice(char *format,...);
void syslog_info(char *format,...);
void syslog_debug(char *format,...);
void syslog_debug_info(char *format,...);
void syslog_debug_debug(int type, char *format,...);


char *mac2str(unsigned char *haddr);
char *u32ip2str(unsigned int u32_ipaddr);
void LogCloseFile();

#endif
