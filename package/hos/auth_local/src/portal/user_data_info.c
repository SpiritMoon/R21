#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include "user_data_info.h"

char *user_optarg;
int user_optind = 1;
int user_optopt;
static FILE *tftp_upload_file = NULL;
static int user_cli_cmd_http_download_logo(char *httpurl)
{
	char cmd[HTTP_URL_BUF_SIZE];
	int ret;

	if((os_strstr(user_optarg,"http:")) != NULL){
        memset(cmd,0,HTTP_URL_BUF_SIZE);
		sprintf(cmd,"wget %s -O /www/internal_portal/logo.jpg\n",user_optarg);

		ret = system(cmd);
	}
	else{
		printf("ERROR: This command support HTTP download logo file!\n");
	    return -1;
	}
}
static int user_cli_cmd_http_download_policy(char *httpurl)
{
	char cmd[HTTP_URL_BUF_SIZE];
	int ret;

	if((os_strstr(user_optarg,"http:")) != NULL){
        memset(cmd,0,HTTP_URL_BUF_SIZE);
		sprintf(cmd,"wget %s -O /www/internal_portal/policy.txt\n",user_optarg);

		ret = system(cmd);
	}
	else{
		printf("ERROR: This command support HTTP download policy text!\n");
	    return -1;
	}
}
static int user_cli_cmd_http_download_welcome(char *httpurl)
{
	char cmd[HTTP_URL_BUF_SIZE];
	int ret;

	if((os_strstr(user_optarg,"http:")) != NULL){
        memset(cmd,0,HTTP_URL_BUF_SIZE);
		sprintf(cmd,"wget %s -O /www/internal_portal/welcome.txt\n",user_optarg);

		ret = system(cmd);
	}
	else{
		printf("ERROR: This command support HTTP download welcome text!\n");
	    return -1;
	}
}

static int user_cli_cmd_add_accesscode(char *accesscode)
{
	char buf[ACCESSCODE_TMP_BUF_SIZE];
	FILE *userdb;
	char accesscode_tmp[ACCESSCODE_TMP_BUF_SIZE];
	time_t	time_tmp;
	struct tm *auth_local_time;
	
	char *wday[]={"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
	
	time(&time_tmp);
	auth_local_time=localtime(&time_tmp); 

	auth_local_syslog_info("Add AccessCode: %s\n",accesscode );
	if(tftp_upload_file != NULL){
		fprintf(tftp_upload_file,"%d-%02d-%02d %s %02d:%02d:%02d Add AccessCode: %s\n", 
								 (1900+auth_local_time->tm_year), ( 1+auth_local_time->tm_mon), auth_local_time->tm_mday,  wday[auth_local_time->tm_wday],
								 auth_local_time->tm_hour, auth_local_time->tm_min, auth_local_time->tm_sec, accesscode);
	}
	userdb= fopen(ACCESS_CODE_DATABASE_PATH, "a+");

	if(userdb){
		os_memset(buf,0,sizeof(buf));
    	while(fgets(buf,ACCESSCODE_TMP_BUF_SIZE,userdb) != NULL){
		sscanf(buf,"%s",accesscode_tmp);
		//auth_local_syslog_info("accesscode: %s, add_accesscode: %s\n",accesscode_tmp,accesscode);
   		if( 0 == os_strcmp(accesscode_tmp,accesscode) ){
    		auth_local_syslog_info("AccessCode %s has been added, please check !\n",accesscode);
			fclose(userdb);
			return -1;
    	}
    		os_memset(buf,0,sizeof(buf));
    	}
	}
	else
	{
		if( access(USER_DATABASE_PATH, 0 )){
    		if (mkdir(USER_DATABASE_PATH, 666) < 0) {
    	        auth_local_syslog_info("Build file path: %s fail. %s\n", USER_DATABASE_PATH,strerror(errno));
    	        return -1;
            }
		}
		userdb= fopen(ACCESS_CODE_DATABASE_PATH, "a+");
		if (!userdb){			
			auth_local_syslog_info("File %s not writeable.\n",ACCESS_CODE_DATABASE_PATH);
			return -1;		
		}		
	}
	snprintf(buf, sizeof(buf), "%s",accesscode);
	fprintf( userdb, "%s\n", buf );	    
	auth_local_syslog_info("AccessCode(%s) Addition Success!\n",accesscode);
	
	if(tftp_upload_file != NULL){
		fprintf(tftp_upload_file,"%d-%02d-%02d %s %02d:%02d:%02d AccessCode(%s) Addition Success!\n", 
								 (1900+auth_local_time->tm_year), ( 1+auth_local_time->tm_mon), auth_local_time->tm_mday,  wday[auth_local_time->tm_wday],
								 auth_local_time->tm_hour, auth_local_time->tm_min, auth_local_time->tm_sec, accesscode);
	}
	fclose(userdb);	
	return 0;
}

static int user_cli_cmd_del_accesscode(char *accesscode)
{
	char buf[ACCESSCODE_TMP_BUF_SIZE];
	char tmp[ACCESSCODE_TMP_BUF_SIZE]; 
	FILE *userdb;
	FILE *userdb_tmp;
	char accesscode_tmp[ACCESSCODE_TMP_BUF_SIZE];
	time_t	time_tmp;
	struct tm *auth_local_time;
	
	char *wday[]={"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
	
	time(&time_tmp);
	auth_local_time=localtime(&time_tmp); 
	
	userdb= fopen(ACCESS_CODE_DATABASE_PATH, "a+");
	if (!userdb){
		auth_local_syslog_info("open %s failed.\n",ACCESS_CODE_DATABASE_PATH);
		return -1;
	}
	userdb_tmp= fopen(ACCESS_CODE_DATABASE_TMP_PATH, "a+");
	if (!userdb_tmp){
		auth_local_syslog_info("open %s failed.\n",ACCESS_CODE_DATABASE_TMP_PATH);
		return -1;
	}
	os_memset(buf,0,sizeof(buf));
	os_memset(tmp,0,sizeof(tmp));
	while(fgets(buf,ACCESSCODE_TMP_BUF_SIZE,userdb) != NULL){
		sscanf(buf,"%s",accesscode_tmp);
        	//printf("accesscode: %s, delete_accesscode: %s\n",accesscode_tmp,accesscode);

		if( 0 == os_strcmp(accesscode_tmp,accesscode) ){
			auth_local_syslog_info("Delete AccessCode(%s) successfully !\r\n",accesscode);
			if(tftp_upload_file != NULL){
				fprintf(tftp_upload_file,"%d-%02d-%02d %s %02d:%02d:%02d Delete AccessCode(%s) successfully !\n", 
										 (1900+auth_local_time->tm_year), ( 1+auth_local_time->tm_mon), auth_local_time->tm_mday,  wday[auth_local_time->tm_wday],
										 auth_local_time->tm_hour, auth_local_time->tm_min, auth_local_time->tm_sec);
			}
			continue;
		}
		fputs(buf,userdb_tmp);
		os_memset(buf,0,sizeof(buf));
		os_memset(tmp,0,sizeof(tmp));
	}
	fclose(userdb);
    fclose(userdb_tmp);
	if( unlink(ACCESS_CODE_DATABASE_PATH) != 0 ){
		auth_local_syslog_info("delete %s failed.\n",ACCESS_CODE_DATABASE_PATH);
		return -1;
	}
	
	if( rename(ACCESS_CODE_DATABASE_TMP_PATH, ACCESS_CODE_DATABASE_PATH) != 0 ){
		auth_local_syslog_info("rename %s failed.\n",ACCESS_CODE_DATABASE_TMP_PATH);
		return -1;
	}
	return 0;
}

static int user_cli_cmd_show_accesscode()
{
	FILE *userdb;
	char buf[ACCESSCODE_TMP_BUF_SIZE];
	int flag = 1;
	
	userdb = fopen(ACCESS_CODE_DATABASE_PATH, "r" );
	
	if (!userdb){
		printf("No access code information in the file !\n");
	    flag = 0;
		return -1;
	}
	printf("==============================================================\n");
    if(flag){
    	os_memset(buf,0,sizeof(buf));
    	while(fgets(buf,ACCESSCODE_TMP_BUF_SIZE,userdb) != NULL){
    		printf("  %s",buf);
    		os_memset(buf,0,sizeof(buf));
    	}
    	fclose(userdb);
    }
	printf("==============================================================\n");
	return 0;
}

static int user_cli_cmd_add(int argc, char *argv[])
{
	char buf[TMP_BUF_SIZE];
	char username[64];
	FILE *userdb;
	time_t	time_tmp;
	struct tm *auth_local_time;
	
	char *wday[]={"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
	
	time(&time_tmp);
	auth_local_time=localtime(&time_tmp); 

	userdb= fopen(ACCOUT_DATABASE_PATH, "a+");
	if(userdb){
		os_memset(buf,0,sizeof(buf));
		while(fgets(buf,TMP_BUF_SIZE,userdb) != NULL){
			sscanf(buf,"%s",username);
    		//auth_local_syslog_info("The Datebase user: %s, new add user: %s\n",username,user_optarg);
    		if( 0 == os_strcmp(username,user_optarg) ){
    			auth_local_syslog_info("The user(%s) has been added, please check !\n",user_optarg);
				fclose(userdb);
                return -1;
    		}
    		os_memset(buf,0,sizeof(buf));
    	}
	}
	else
		{
			if( access(USER_DATABASE_PATH, 0 ))
			{
				if (mkdir(USER_DATABASE_PATH, 666) < 0) {
			        auth_local_syslog_info("Build file path: %s fail. %s\n", USER_DATABASE_PATH,strerror(errno));
			        return -1;
		        }
			}	
			userdb= fopen(ACCOUT_DATABASE_PATH, "a+");
			if (!userdb){			
				auth_local_syslog_info("File %s not writeable.\n",ACCOUT_DATABASE_PATH);
				return -1;		
			}		
	}
	snprintf(buf, sizeof(buf), "%s %s %s %s %s %s %s %s %s",user_optarg,argv[0],argv[1],argv[2],argv[3],argv[4],argv[5],argv[6],argv[7]);
	fprintf( userdb, "%s\n", buf ); 
	
	auth_local_syslog_info("Accout Add User: Username(%s) Password(%s) Firstname(%s) Lastname(%s) Mail(%s) Phone(%s) Company(%s) Startdate(%s) Enddate(%s)\r\n",
											 user_optarg,argv[0],argv[1],argv[2],argv[3],argv[4],argv[5],argv[6],argv[7]);
	auth_local_syslog_info("User(%s) Addition Success!\n",user_optarg);
	if(tftp_upload_file != NULL){
	fprintf(tftp_upload_file,"%d-%02d-%02d %s %02d:%02d:%02d Accout Add User: Username(%s) Password(%s) Firstname(%s) Lastname(%s) Mail(%s) Phone(%s) Company(%s) Startdate(%s) Enddate(%s)\r\n", 
								 (1900+auth_local_time->tm_year), ( 1+auth_local_time->tm_mon), auth_local_time->tm_mday,  wday[auth_local_time->tm_wday],
							 auth_local_time->tm_hour, auth_local_time->tm_min, auth_local_time->tm_sec,user_optarg,argv[0],argv[1],argv[2],argv[3],argv[4],argv[5],argv[6],argv[7]);
		fprintf(tftp_upload_file,"%d-%02d-%02d %s %02d:%02d:%02d User(%s) Addition Success!\n", 
								 (1900+auth_local_time->tm_year), ( 1+auth_local_time->tm_mon), auth_local_time->tm_mday,  wday[auth_local_time->tm_wday],
								 auth_local_time->tm_hour, auth_local_time->tm_min, auth_local_time->tm_sec, user_optarg);
	}
	fclose(userdb); 
	return 0;
}

static char *format_str(char *dst, char *src)
{
	int i=0,j=0;
	if(!dst || !src)
		return NULL;
	while(src[i] != '\0' ){
		if( src[i] != ' ' )
			dst[j] = src[i];
		else{
			dst[j++] = '\t';
			dst[j++]= '\t';
			dst[j++] = '\t';
			dst[j] = '\t';
		}
		i++;
		j++;
	}
	return dst;
}

static int user_cli_cmd_del(char *username)
{
	char buf[TMP_BUF_SIZE];
	char tmp[TMP_BUF_SIZE + 6];  /*add six \t*/
	FILE *userdb;
	FILE *userdb_tmp;
	char username_tmp[64];
	time_t	time_tmp;
	struct tm *auth_local_time;
	
	char *wday[]={"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
	
	time(&time_tmp);
	auth_local_time=localtime(&time_tmp); 

	userdb= fopen(ACCOUT_DATABASE_PATH, "a+");
	if (!userdb){
		auth_local_syslog_info("open %s failed.\n",ACCOUT_DATABASE_PATH);
		return -1;
	}
	userdb_tmp= fopen(ACCOUT_DATABASE_TMP_PATH, "a+");
	if (!userdb_tmp){
		auth_local_syslog_info("open %s failed.\n",ACCOUT_DATABASE_TMP_PATH);
		return -1;
	}
	os_memset(buf,0,sizeof(buf));
	os_memset(tmp,0,sizeof(tmp));
	while(fgets(buf,TMP_BUF_SIZE,userdb) != NULL){
		sscanf(buf,"%s",username_tmp);
        //printf("username: %s, delete_user: %s\n",username_tmp,username);

		if( 0 == os_strcmp(username_tmp,username)){
			auth_local_syslog_info("Delete the user(%s) successfully !\r\n" ,username);
			if(tftp_upload_file != NULL){
				fprintf(tftp_upload_file,"%d-%02d-%02d %s %02d:%02d:%02d Delete the user(%s) successfully !\r\n", 
										 (1900+auth_local_time->tm_year), ( 1+auth_local_time->tm_mon), auth_local_time->tm_mday,  wday[auth_local_time->tm_wday],
										 auth_local_time->tm_hour, auth_local_time->tm_min, auth_local_time->tm_sec, username);
			}
			continue;
		}
		fputs(buf,userdb_tmp);
		os_memset(buf,0,sizeof(buf));
		os_memset(tmp,0,sizeof(tmp));
	}
	fclose(userdb);
    fclose(userdb_tmp);
	if( unlink(ACCOUT_DATABASE_PATH) != 0 ){
		auth_local_syslog_info("delete %s failed.\n",ACCOUT_DATABASE_PATH);
		return -1;
	}
	
	if( rename(ACCOUT_DATABASE_TMP_PATH, ACCOUT_DATABASE_PATH) != 0 ){
		auth_local_syslog_info("rename %s failed.\n",ACCOUT_DATABASE_PATH);
		return -1;
	}
	return 0;

}

static int user_cli_cmd_show()
{
	FILE *userdb;
	char buf[TMP_BUF_SIZE];
	//char tmp[TMP_BUF_SIZE + 6];  /*add six \t*/
	int accout_flag = 1;
	char username[20];
	char passwd[PASSWD_BUF_SIZE],first_n[32],last_n[32],mail[32],phone[32],company[128];	
	char data_s[16] = { 0 };
	char data_e[16] = { 0 };
	userdb = fopen(ACCOUT_DATABASE_PATH, "r" );
	
	if (!userdb){
		printf("No user information in the file !\n");
		accout_flag = 0;
		return -1;
	}
	printf("\nUsername\tPassword\tFirstname\tLastname\tMail    \tPhone   \tCompany \tStartdate\tEnddate\n");
	printf("=====================================================================================================================================\n");
	if(accout_flag){
    	os_memset(buf,0,sizeof(buf));
    	//os_memset(tmp,0,sizeof(tmp));
    	while(fgets(buf,TMP_BUF_SIZE,userdb) != NULL){
    		//printf("%s",format_str(tmp, buf));
			sscanf(buf,"%s %s %s %s %s %s %s %s %s",username,passwd,first_n,last_n,mail,phone,company,data_s,data_e);
    		printf("%-16s %-16s %-16s %-16s %-16s %-16s %-16s %-16s %-16s\n",username,passwd,first_n,last_n,mail,phone,company,data_s,data_e);
			os_memset(buf,0,sizeof(buf));
    		//os_memset(tmp,0,sizeof(tmp));
    	}
    	fclose(userdb);
	}
	printf("=====================================================================================================================================\n");
	return 0;
}

#if 0
static int user_group_cli_cmd_show(char *groupname)
{
	FILE *userdb;
	char guest_buf[TMP_BUF_SIZE] = "guest";
	char employee_buf[TMP_BUF_SIZE] = "employee";
	char tmp[TMP_BUF_SIZE + 6];  /*add six \t*/

    if( 0 == os_strncmp(guest_buf,groupname,os_strlen(groupname)) ){
    	userdb = fopen(GUEST_DATABASE_PATH, "r" );
    	if (!userdb){
    		printf("open %s failed.\n",GUEST_DATABASE_PATH);
    		return -1;
    	}
    	printf("=========================================================================================\n");
    	printf("user name\t\t\tpassword\t\t\tgroup name\n");
    	os_memset(guest_buf,0,sizeof(guest_buf));
    	os_memset(tmp,0,sizeof(tmp));
    	while(fgets(guest_buf,TMP_BUF_SIZE,userdb) != NULL){
    		printf("%s",format_str(tmp, guest_buf));
    		os_memset(guest_buf,0,sizeof(guest_buf));
    		os_memset(tmp,0,sizeof(tmp));
    	}
    	fclose(userdb);
    	printf("=========================================================================================\n");

	}
	else if(0 == os_strncmp(employee_buf,groupname,os_strlen(groupname))){
    	userdb = fopen(EMPLOYEE_DATABASE_PATH, "r" );
    	if (!userdb){
    		printf("open %s failed.\n",EMPLOYEE_DATABASE_PATH);
    		return -1;
    	}
    	printf("=========================================================================================\n");
    	printf("user name\t\t\tpassword\t\t\tgroup name\n");
    	os_memset(employee_buf,0,sizeof(employee_buf));
    	os_memset(tmp,0,sizeof(tmp));
    	while(fgets(employee_buf,TMP_BUF_SIZE,userdb) != NULL){
    		printf("%s\r\n",format_str(tmp, employee_buf));
    		os_memset(employee_buf,0,sizeof(employee_buf));
    		os_memset(tmp,0,sizeof(tmp));
    	}
    	fclose(userdb);
    	printf("=========================================================================================\n");
	} 
	return 0;
}
#endif

int user_info_getopt(int argc, char *const argv[], const char *optstring)
{
	static int optchr = 1;
	char *cp;

	if (optchr == 1) {
		if (user_optind >= argc) {
			/* all arguments processed */
			return EOF;
		}

		if (argv[user_optind][0] != '-' || argv[user_optind][1] == '\0') {
			/* no option characters */
			return EOF;
		}
	}

	if (os_strcmp(argv[user_optind], "--") == 0) {
		/* no more options */
		user_optind++;
		return EOF;
	}

	user_optopt = argv[user_optind][optchr];
	cp = os_strchr(optstring, user_optopt);
	if (cp == NULL || user_optopt == ':') {
		if (argv[user_optind][++optchr] == '\0') {
			optchr = 1;
			user_optind++;
		}
		return '?';
	}

	if (cp[1] == ':') {
		/* Argument required */
		optchr = 1;
		if (argv[user_optind][optchr + 1]) {
			/* No space between option and argument */
			user_optarg = &argv[user_optind++][optchr + 1];
		} else if (++user_optind >= argc) {
			/* option requires an argument */
			return '?';
		} else {
			/* Argument in the next argv */
			user_optarg = argv[user_optind++];
		}
	} else {
		/* No argument */
		if (argv[user_optind][++optchr] == '\0') {
			optchr = 1;
			user_optind++;
		}
		user_optarg = NULL;
	}
	return *cp;
}
static void usage(void)
{
	printf(
		"\n"
		"usage: userm_cli [-a <user passwd firstname lastname mail phone company startdate enddate>]\n" 
        "\t\t [-A <accesscode>] [-d <user>] [-D <accesscode>] [-s] [-S] [-h] \n\n"
		"-a <user passwd firstname lastname mail phone company startdate enddate>\t\tadd new user to database\n"
		"-A <accesscode>\t\t\tadd new access code to database\n"
		"-d <user>\t\t\tdelete user from database\n"
		"-D <accesscode>\t\t\tdelete access code from database\n"
		"-s\t\t\t\tshow user information\n"
		"-S\t\t\t\tshow access code\n"
		"-h \t\t\t\thelp(show this usage text)\n");
}

void auth_local_syslog_info
(
	char *format,...
)
{
	va_list ptr;
	char buf[AUTH_LOCAL_SYSLOG_LINE_BUFFER_SIZE] = {0};
  
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

int main(int argc, char *argv[])
{
	char ch;
	int ret = 0;
	
	time_t	time_tmp;
	struct tm *auth_local_time;
	
	char *wday[]={"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
	
	time(&time_tmp);
	auth_local_time=localtime(&time_tmp); 
	tftp_upload_file = fopen(AUTH_LOCAL_OUT_FILE, "a");
	if (tftp_upload_file == NULL){
		auth_local_syslog_info("%d-%02d-%02d %s %02d:%02d:%02d auth_local_debug_open_file: Failed to open "
			   "output file, using standard output\n", 
								 (1900+auth_local_time->tm_year), ( 1+auth_local_time->tm_mon), auth_local_time->tm_mday,  wday[auth_local_time->tm_wday],
								 auth_local_time->tm_hour, auth_local_time->tm_min, auth_local_time->tm_sec);
		//return -1;
	}
	while((ch = user_info_getopt(argc, argv, "a:d:shg:A:D:SH:W:P:")) != -1){
		switch(ch){
			case 'a':
				if(USER_ADD_PARAMETER_NUM == argc){
    				user_cli_cmd_add(argc-user_optind, &argv[user_optind]);
				}
				else
    				usage();
				break;
			case 'd':
				if(USER_DEL_PARAMETER_NUM == argc){
    				user_cli_cmd_del(user_optarg);
				}
				else
					usage();
				break;
			case 's':
				if(USER_SHOW_PARAMETER_NUM == argc){
    				user_cli_cmd_show();
		        }
				else
					usage();
				break;
#if 0
			case 'g':
				if(USER_GROUP_SHOW_PARAMETER_NUM == argc){
				    user_group_cli_cmd_show(user_optarg);
				}
				else
					usage();
				break;
#endif
			case 'A':
				if(USER_ACCESSCODE_PARAMETER_NUM == argc){
    				user_cli_cmd_add_accesscode(user_optarg);
				}
				else
    				usage();
				break;
			case 'D':
				if(USER_ACCESSCODE_PARAMETER_NUM == argc){
    				user_cli_cmd_del_accesscode(user_optarg);
				}
				else
					usage();
				break;
			case 'S':
				if(USER_SHOW_PARAMETER_NUM == argc){
    				user_cli_cmd_show_accesscode();
		        }
				else
					usage();
				break;
			case 'H':
				if(USER_HTTP_DOWNLOAD_PARAMETER_NUM == argc){
    				user_cli_cmd_http_download_logo(user_optarg);
				}
				else
    				usage();
				break;
			case 'W':
				if(USER_HTTP_DOWNLOAD_PARAMETER_NUM == argc){
    				user_cli_cmd_http_download_welcome(user_optarg);
				}
				else
    				usage();
				break;
			case 'P':
				if(USER_HTTP_DOWNLOAD_PARAMETER_NUM == argc){
    				user_cli_cmd_http_download_policy(user_optarg);
				}
				else
    				usage();
				break;

			default:
				usage();
				return -1;
		}	
	}
    return 0;
}



