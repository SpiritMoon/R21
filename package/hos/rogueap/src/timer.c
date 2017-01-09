/******************************************************************************
  File Name    : timer.c
  Author       : zhaoej
  Date         : 20160216
  Description  : Timer trigger
******************************************************************************/
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "timer.h"
#include "rogue_utils.h"

#define TIMER_INVAL 30
int aging_time = 0;
/*Init timer*/
void init_timer(void){
	struct itimerval time_val;
	time_val.it_value.tv_sec = 0;
	time_val.it_value.tv_usec = 100;

	time_val.it_interval.tv_sec = TIMER_INVAL;
	time_val.it_interval.tv_usec = 0;
	if(setitimer(TIMER_INTERVAL,&time_val, (struct itimerval *)0)==-1){
		perror("start_timer: setitimer error!"); 
		rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_ERR,"Timer:setitimer error!");
		rogue_debug_error("[ROGUEAP]: start_timer=>setitimer error");
		exit(-1); 
	}
}

/*
**trigger signal--execute function 
**[call recv data from background scanning and cluster management information]
*/
void get_info(int signo){
	
	time_t rawtime;
	struct tm *timeinfo;
	char str[64]={0};
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	dump_file_open("w+");
	fprintf(DUMP_FILE,"Enter the lastest of timer!\tData\tTime is:%s",asctime(timeinfo));
	dump_file_close();
	printf("***************************\tData\tTime is:%s",asctime(timeinfo));
	if(signo == SIG_HANDLE){
		rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_DEBUG,"The latest of the timer running successful!");
		rogue_debug_trace("[ROGUEAP]: The latest timer running success,Time:%s",asctime(timeinfo));
		rg_get_info();
	}
	else{
		rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_WARNING,"signo is not SIGALRM!");
		rogue_debug_trace("[ROGUEAP]: signo is not SIGALRM!");
	}
	
	aging_time ++;
	
	if(aging_time*TIMER_INVAL == MAX_AGING_TIME){
		//aging mechanism  handle aging ap and sta
		time_t c_time;
		c_time=time(&c_time);
		sprintf(str,"The latest aging time is:%s",asctime(localtime(&c_time)));
		rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_DEBUG,str);
		rogue_debug_trace("[ROGUEAP]: The latest aging time is:%s",asctime(localtime(&c_time)));
		rg_find_aging_member(SCAN_AP_SIGN);
		rg_find_aging_member(SCAN_STA_SIGN);
		rg_find_aging_member(CLUSTER_MEMBER_SIGN);
		aging_time = 0;
	}
}


/*Init signal */
void init_sigaction(void){
	struct sigaction sig_act;
	sig_act.sa_handler = get_info;
	sig_act.sa_flags = 0;
	sigemptyset(&sig_act.sa_mask);
	sigaction(SIG_HANDLE,&sig_act,NULL);
}



