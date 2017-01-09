/******************************************************************************
  ÎÄ ¼þ Ãû   : tech support command
******************************************************************************/
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>


#define SYSLOG_FILE     "/tmp/kes_history_syslog.log"
#define TRAPS_FILE      "/tmp/kes_history_traps.log"
#define REBOOT_FILE     "/.tmpinfo/.resetinfo"
#define KES_FILE        "/proc/kes_flag"
#define TAR_SYSLOG      "syslog.tar.gz"

#define MEM_COMMAND     "free"
#define CPU_COMMAND     "sar 1 1"
#define FLS_COMMAND     "df -h"
#define DEVMEM_COMMAND  "devmem"
#define REG_WATCHDOG    0x18060008


#define MIN_INTERFACES  1
#define MAX_INTERFACES  254
#define IF_NAMESIZE     16
#define ATH_NAME        "ath"
#define RESET_DISPLAY   "[1] "


static int
usage(void)
{
	fprintf(stderr, "usage:\n");
	fprintf(stderr, "1          show system info\n");
	fprintf(stderr, "2          show WIFI info\n");
	fprintf(stderr, "3          show traps info\n");
	fprintf(stderr, "4          show syslog info\n");
	fprintf(stderr, "5          show cpu utilization\n");
	fprintf(stderr, "6          show mem utilization\n");
	fprintf(stderr, "7          tcpdump command\n");
	fprintf(stderr, "8 [HOST]   traceroute [HOST] command\n");
	fprintf(stderr, "9 [HOST]   ping command\n");
	fprintf(stderr, "10         check reboot reason\n");
	fprintf(stderr, "11         tar syslog\n");
    
	return 1;
}

int show_system_log(char *file)
{
    FILE *fp;
    char StrLine[1024];

    fp = fopen(file,"r");
    if(fp == NULL)
    {
        printf("No Log information found\n");
        return 0;
    }
    
    fseek( fp, -5000L, SEEK_END );

    while (!feof(fp)) 
    { 
        fgets(StrLine,1024,fp);
        printf("%s", StrLine);
    }
    fclose(fp);

    return 0;
}


int exec_system_cmd(char *cmd)
{

    FILE *fp;
    char StrLine[1024] = {0};

    //printf("%s\n",cmd);
    fp = popen(cmd,"r");

    if(fp == NULL)
        return -1;

    while (!feof(fp)) 
    { 
        memset(StrLine,0,sizeof(StrLine));
        fgets(StrLine,1024,fp);
        printf("%s", StrLine);
    }
    pclose(fp);

    return 0;
}

int exec_mem_utilization()
{
    FILE *fp;
    char cmd[64] = {0};
    int mem_total = 0;
    int mem_used = 0;
    char StrLine[1024] = {0};

    sprintf(cmd,"%s %s",MEM_COMMAND,"|grep Mem| awk '{print $2}'");
    fp = popen(cmd,"r");
    fgets(StrLine,1024,fp);
    mem_total = atoi(StrLine);
    pclose(fp);

    memset(cmd,0,sizeof(cmd));
    memset(StrLine,0,sizeof(StrLine));
    
    sprintf(cmd,"%s %s",MEM_COMMAND,"|grep Mem| awk '{print $3}'");
    fp = popen(cmd,"r");
    fgets(StrLine,1024,fp);
    mem_used = atoi(StrLine);
    pclose(fp);

    printf("%d\n",((mem_used * 100) / mem_total));

    return 0;
}

int exec_cpu_utilization()
{
    FILE *fp;
    char cmd[64] = {0};
    int cpu_idle = 0;
    char StrLine[1024] = {0};

    sprintf(cmd,"%s %s",CPU_COMMAND,"|grep Average|awk '{print $8}'");
    //sprintf(cmd,"%s","cat /tmp/cpu_utilization");
    fp = popen(cmd,"r");
    fgets(StrLine,1024,fp);
    cpu_idle = atoi(StrLine);
    pclose(fp);

    printf("%d\n",(100 - cpu_idle));
    
    return 0;
}

int reboot_judgment(char *file)
{
    FILE *fp;
    char StrLine[1024];

    fp = fopen(file,"r");
    if(fp == NULL)
    {
        printf("No reboot information found\n");
        return 0;
    }
    
    while (!feof(fp)) 
    { 
        memset(StrLine,0,sizeof(StrLine));
        fgets(StrLine,1024,fp);
        if(strncmp(StrLine,RESET_DISPLAY,strlen(RESET_DISPLAY)-1) == 0)
        {
            printf("%s", StrLine + strlen(RESET_DISPLAY));
        }
    }
    fclose(fp);

    return 0;
}

void tar_syslog_file(char *msg,...)
{
	char cmd[512] = {0};
	char dest[512] = {0};
	
	char blank[512] = " ";
	int ret = 0;
	
	chdir("/tmp");
	char *arg;
	va_list ap;
	va_start(ap,msg);
	
	while((arg = va_arg(ap,char*)) != NULL)
	{	
		ret = access(arg ,F_OK);
		if(ret != 0)
			continue;
		strcat(blank,arg);
		strcat(dest,blank); 
		memcpy(blank," ",10);		
	}
	va_end(ap);
	sprintf(cmd,"tar czvf %s %s",TAR_SYSLOG,dest);
    exec_system_cmd(cmd);
    return 0;
}

int main(int argc, char **argv)
{
	int if_index = 0;
	char if_name[IF_NAMESIZE] = {0};
    char buf[64] = {0};;
    if(argc == 2)
    {
        // system info
        if (!strcmp(argv[1], "1"))
        {
            exec_system_cmd(MEM_COMMAND);
            //exec_system_cmd(CPU_COMMAND);
            exec_system_cmd(FLS_COMMAND);
        }
        // wifi info
        else if (!strcmp(argv[1], "2"))
        {

        	for (if_index = MIN_INTERFACES; if_index < MAX_INTERFACES; if_index++)
        	{
        		if(if_indextoname(if_index, if_name) == NULL)
        			continue;
                
        		if(strncmp(if_name, ATH_NAME, 3) != 0)
                {
        			continue;
        		}
                memset(buf,0,sizeof(buf));
                sprintf(buf,"%s %s","iwconfig",if_name);
                exec_system_cmd(buf);
                memset(buf,0,sizeof(buf));
                sprintf(buf,"%s %s list","wlanconfig",if_name);
                exec_system_cmd(buf);
            }

        }
        // kes traps info
        else if (!strcmp(argv[1], "3"))
        {
            //show_system_log(TRAPS_FILE);
            if (!access(TRAPS_FILE,0))
            {
                sprintf(buf,"%s %s","tail -n 50 ",TRAPS_FILE);
                exec_system_cmd(buf);
            }
            else
                printf("No Log information found\n");
        }
        // kes syslog info
        else if (!strcmp(argv[1], "4"))
        {
            //show_system_log(SYSLOG_FILE);
            if (!access(SYSLOG_FILE,0))
            {
                sprintf(buf,"%s %s","tail -n 50 ",SYSLOG_FILE);
                exec_system_cmd(buf);
            }
            else
                printf("No Log information found\n");
        }
        // CPU utilization
        else if (!strcmp(argv[1], "5"))
        {
            exec_cpu_utilization();
        }
        // mem utilization
        else if (!strcmp(argv[1], "6"))
        {
            exec_mem_utilization();
        }
        // tcpdump -c 10 -q
        else if (!strcmp(argv[1], "7"))
        {
            sprintf(buf,"%s %s","tcpdump","-c 20 -q");
            exec_system_cmd(buf);
        }
    	else if(!strcmp(argv[1], "10"))
    	{
    		reboot_judgment(REBOOT_FILE);
    	}
        else if (!strcmp(argv[1], "11"))
        {		
            sprintf(buf,"cat /proc/kes_syslog > /tmp/kes_syslog");
            exec_system_cmd(buf);
			
			tar_syslog_file(3,"kes_syslog","kes_history_syslog.log","kes_history_traps.log");

			memset(buf,0,64);
            sprintf(buf,"rm /tmp/kes_syslog");
            exec_system_cmd(buf);

        }
        else if (!strcmp(argv[1], "-h"))
        {
            usage();
        }
        else
        {
            exec_system_cmd(argv[1]);
			
        }

    }
    else if(argc == 3)
    {
        if(strlen(argv[2]) > 20)
        {
            printf("Error: Input argument too long (longer than 20 chars).\n");
            return 0;
        }
    
        // traceroute  -w 1 -m 10 -q 1 -v
        if (!strcmp(argv[1], "8"))
        {
            sprintf(buf,"%s %s %s","traceroute",argv[2],"-w 1 -m 16 -q 1");
            exec_system_cmd(buf);
        }
        // ping 
        else if (!strcmp(argv[1], "9"))
        {
            sprintf(buf,"%s %s %s","ping",argv[2],"-c 5 -w 5 -v");
            exec_system_cmd(buf);
        }
        else
        {
            usage();
        }

    }
    else
    {
        usage();
    }
    
    return 0;
}


