/******************************************************************************
  File Name    : control.h
  Author       : zhaoej
  Date         : 20160309
  Description  : control.c
******************************************************************************/
#ifndef _CONTROL_H_
#define _CONTROL_H_

extern int ctlpipe;


void control_init_pipe();
void master_init_pipe();

void control_send_command(char* cmd);

void control_receive_command();

void control_finish(int fd, char* pipe);


#endif
