/*
 * arp-proxy / hash_table 
 * Copyright (c) 2016-2017, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef ARPP_TBL_H
#define ARPP_TBL_H

#define ARPP_ITEM_HASH_TABLE_SIZE 1024

typedef struct arpp_item_s
{
	struct arpp_item_s *next;
	unsigned int  bind_type;
	unsigned char state;
	unsigned char haddr_len;
	unsigned char chaddr[ETH_ALEN];
	unsigned short vlanId;
	unsigned int ip_addr;
	unsigned int lease_time;
	unsigned int sys_escape; /*��Ӱ󶨱���ʱϵͳ��������������ʱ�� */
	unsigned int cur_expire;	   /* ��ǰʹ�õ���Ч��IP��ַ״̬��ʱʱ��,����ʾʱʹ��*/
	unsigned int ifindex;
	unsigned int flags;
}arpp_item_t;

arpp_item_t *arpp_item_hash_table[ARPP_ITEM_HASH_TABLE_SIZE];
void *arpp_tbl_item_new_from_msg(WAM_MSG *msg);
int arpp_tbl_item_debug_show(void);
unsigned int arpp_tbl_item_remove(arpp_item_t *item);
#endif
