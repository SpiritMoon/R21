/******************************************************************************
  File Name    : dnsrd_parse.h
  Author       : lhc
  Date         : 20160302
  Description  : dnsrd_parse.c
******************************************************************************/

#ifndef _DNSRD_PARSE_H_
#define _DNSRD_PARSE_H_

struct dnsmsghead {
    unsigned short transid;
    unsigned short flag;
    unsigned short questcont;
    unsigned short answercont;
    unsigned short authorcont;
    unsigned short addcont;
};

struct dnsmsganswear {
    unsigned short name;
    unsigned short type;
    unsigned short Class;
    unsigned short time1;//for pad
    unsigned short time2;
    unsigned short datelen;
    unsigned int   addr;
};

void Dnsrd_recvmsg_form_kernel(int socketfd);
int Dnsrd_sendmsg_to_kernel(int socketfd, void *data, int data_len);

#endif
