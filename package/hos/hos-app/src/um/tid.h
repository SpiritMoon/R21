/******************************************************************************
  文 件 名   : tid.h
  作    者   : wenjue
  生成日期   : 2014年11月19日
  功能描述   : tid.c的头文件
******************************************************************************/
#ifndef _UM_TID_H_
#define _UM_TID_H_

#define TID_MAC_MAXLEN       20
#define TID_HOSTNAME_MAXLEN  128
#define TID_OSTYPE_MAXLEN    32
#define TID_CPUTYPE_MAXLEN   32
#define TID_DEVTYPE_MAXLEN   8
#define TID_DEVMODEL_MAXLEN   16
#define TID_IPADDR_MAXLEN   16

struct devinfo{
    char hostname[TID_HOSTNAME_MAXLEN];
    char mac[TID_MAC_MAXLEN];
    char ostype[TID_OSTYPE_MAXLEN];
    char cputype[TID_CPUTYPE_MAXLEN];
    char devmodel[TID_DEVMODEL_MAXLEN];
    char devtype[TID_DEVTYPE_MAXLEN];
    char ipaddr[TID_IPADDR_MAXLEN];
};

struct devinfonode{
    int aging;
    struct devinfo stdevinfo;
    struct devinfonode *prev;
    struct devinfonode *next;
};

struct devinfohead{
    struct devinfonode *next;
    pthread_rwlock_t rw_lock;
};


void um_connect_statics_del(uint32_t ip);
void um_connect_statics_set(uint32_t ip, int count);

void *tid_pthreadhandle(void *data);


#endif
