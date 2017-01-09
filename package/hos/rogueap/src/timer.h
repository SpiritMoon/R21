/******************************************************************************
  File Name    : timer.c
  Author       : zhaoej
  Date         : 20160216
  Description  : timer.c
******************************************************************************/
#ifndef __ROGUEAP_TIMER_H__
#define __ROGUEAP_TIMER_H__

#define SIG_HANDLE SIGALRM
#define TIMER_INTERVAL ITIMER_REAL


void init_timer();
void init_sigaction();
void get_info(int signo);


#endif