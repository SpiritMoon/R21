/*****************************************************
 *	auth_local /Accout and Access Code Addtion and Delete
 *	Copyright (c) 2016-2017, Nie Hongyan
 *
 *****************************************************/
#ifndef AUTH_LOCAL_H
#define AUTH_LOCAL_H

char *ident = "auth_local";

#ifndef os_malloc
#define os_malloc(s) malloc((s))
#endif
#ifndef os_free
#define os_free(p) free((p))
#endif

#ifndef os_memset
#define os_memset(s, c, n) memset(s, c, n)
#endif
#ifndef os_memcmp
#define os_memcmp(s1, s2, n) memcmp((s1), (s2), (n))
#endif

#ifndef os_strlen
#define os_strlen(s) strlen(s)
#endif
#ifndef os_strchr
#define os_strchr(s, c) strchr((s), (c))
#endif

#ifndef os_strcat
#define os_strcat(s, c) strcat((s), (c))
#endif
#ifndef os_strcpy
#define os_strcpy(s1, s2) strcpy((s1), (s2))
#endif
#ifndef os_strstr
#define os_strstr(s1, s2) strstr((s1), (s2))
#endif
#ifndef os_strcmp
#define os_strcmp(s1, s2) strcmp((s1), (s2))
#endif
#ifndef os_strcmp
#define os_strcmp(_a, _b)           strcmp(_a, _b)
#endif
#ifndef os_strncmp
#define os_strncmp(s1, s2, _n)      strncmp(s1, s2, _n)
#endif

#define USER_DATABASE_PATH	"/var/run/userdb/" 
#define ACCOUT_DATABASE_PATH	"/var/run/userdb/accout" 
#define ACCOUT_DATABASE_TMP_PATH	"/var/run/userdb/accout.tmp" 
#define ACCESS_CODE_DATABASE_PATH	"/var/run/userdb/accesscode" 
#define ACCESS_CODE_DATABASE_TMP_PATH	"/var/run/userdb/accesscode.tmp" 

#define WELCOME_TEXT_STORE_PATH	"/www/internal_portal/welcome.txt" 

#define TMP_BUF_SIZE 512
#define PASSWD_BUF_SIZE 256
#define HTTP_URL_BUF_SIZE 256
#define ACCESSCODE_TMP_BUF_SIZE 32
#define USER_ADD_PARAMETER_NUM 11
#define USER_HTTP_DOWNLOAD_PARAMETER_NUM 3
#define USER_DEL_PARAMETER_NUM 3
#define USER_SHOW_PARAMETER_NUM 2
#define USER_GROUP_SHOW_PARAMETER_NUM 3
#define USER_ACCESSCODE_PARAMETER_NUM 3


/* syslog line buffer size used in auth_local  */
#define AUTH_LOCAL_SYSLOG_LINE_BUFFER_SIZE	(256)	

#define AUTH_LOCAL_OUT_FILE "/var/log/auth_local.log"

/**********************************************************************************
 *  auth_local_syslog_info
 *
 *  DESCRIPTION:
 *		output the daemon syslog info to /proc/kes_syslog
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
void auth_local_syslog_info
(
	char *format,...
);

#endif

