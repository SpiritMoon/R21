/*
 * arp-proxy / hash_table function
 * Copyright (c) 2016-2017, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stddef.h>

#include "common.h"
#include "os.h"
#include "eloop.h"
#include "debug.h"
#include "arp_proxy.h"
#include "arpp_tbl.h"

arpp_item_t *arpp_item_hash_table[ARPP_ITEM_HASH_TABLE_SIZE] = {0};

unsigned int arpp_tbl_ip_hash(unsigned int ipaddr)
{
    return ipaddr % ARPP_ITEM_HASH_TABLE_SIZE;
}

int arpp_tbl_item_debug_show(void)
{
	unsigned int key = 0;
	arpp_item_t *temp_item = NULL;
	for (key = 0; key < ARPP_ITEM_HASH_TABLE_SIZE; key++) {
		temp_item = arpp_item_hash_table[key];
		while(temp_item) {
			arpp_printf(ARPP_DEBUG, "%-7s:%02x:%02x:%02x:%02x:%02x:%02x ", 
				"mac", temp_item->chaddr[0], temp_item->chaddr[1],
				temp_item->chaddr[2], temp_item->chaddr[3],
				temp_item->chaddr[4], temp_item->chaddr[5]);
			arpp_printf(ARPP_DEBUG, "%-7s:%s\n", "ip", u32ip2str(temp_item->ip_addr));
			arpp_printf(ARPP_DEBUG, "%-7s:%d\n","lease", temp_item->lease_time);
			temp_item = temp_item->next;
		}
	}

	return 0;
}

void *arpp_tbl_item_new_from_msg(WAM_MSG *msg)
{
	arpp_item_t *item = NULL;
	int i;

	item = malloc(sizeof(arpp_item_t));
	if (!item) {
		arpp_printf(ARPP_ERROR, "%s: can not malloc the memory\n", __func__);			
		return NULL;
	}
	memset(item, 0, sizeof(arpp_item_t));
	
	item->ip_addr = msg->ip_addr;
	for (i = 0; i < ETH_ALEN; i++) {
		item->chaddr[i] = msg->addr[i];
	}
	item->lease_time = msg->lease_time;

	return item;
}

void *arpp_tbl_item_find_by_ip(unsigned int ipaddr)
{
	unsigned int key = 0;
	arpp_item_t *temp_item = NULL;
	
	if (ipaddr == 0) {
		arpp_printf(ARPP_DEBUG, "%s: error, parameter is null\n", __func__);
		return NULL;
	}
	
	key = arpp_tbl_ip_hash(ipaddr);
	if (key >= ARPP_ITEM_HASH_TABLE_SIZE) {
		arpp_printf(ARPP_DEBUG, "%s: error in calculate the hash value %d, ip %#x\n", __func__, key, ipaddr);
		return NULL;
	}

	temp_item = arpp_item_hash_table[key];
	while (temp_item) {
		if (temp_item->ip_addr == ipaddr) {
			arpp_printf(ARPP_DEBUG, "found item by ip " MACSTR " %s\n", 
					MAC2STR(temp_item->chaddr), u32ip2str(temp_item->ip_addr));
			
			break;
		}
		temp_item = temp_item->next;
	}
	
	return temp_item;
}

unsigned int arpp_tbl_item_remove(arpp_item_t *item)
{
    unsigned int key = 0;
	arpp_item_t *temp_item = NULL;

	if ((NULL == item) || (!item->ip_addr)) {
		arpp_printf(ARPP_DEBUG, "%s: error, parameter is null\n", __func__);
		return 1;
	}

	key = arpp_tbl_ip_hash(item->ip_addr);
	if (key >= ARPP_ITEM_HASH_TABLE_SIZE)	{
		arpp_printf(ARPP_DEBUG, "error in calculate the ip hash value\n");
		return 1;
	}

	if (arpp_item_hash_table[key] == item) {	
		arpp_item_hash_table[key] = item->next;
		item->next = NULL;
		arpp_printf(ARPP_DEBUG, "delete table from ip hash " MACSTR " %s\n", 
				MAC2STR(item->chaddr), u32ip2str(item->ip_addr));
		
		return 0;
	}

	temp_item = arpp_item_hash_table[key];
	while(temp_item && temp_item->next) {
		if (temp_item->next == item) {
			temp_item->next = item->next;
			item->next = NULL;

			arpp_printf(ARPP_DEBUG, "delete table from ip hash " MACSTR " %s\n", 
				MAC2STR(item->chaddr), u32ip2str(item->ip_addr));

			return 0;
		}
		temp_item = temp_item->next;
	}
	return 1;
}

int *arpp_tbl_item_insert(arpp_item_t *item)
{
	unsigned int key = 0;
	arpp_item_t *tmp = NULL;
	
	if ((NULL == item) || (!item->ip_addr)) {
		arpp_printf(ARPP_DEBUG, "%s: error, parameter is null\n", __func__);
		return -1;
	}

	while (tmp = arpp_tbl_item_find_by_ip(item->ip_addr)) {
		arpp_tbl_item_remove(tmp);
		arpp_printf(ARPP_INFO, MACSTR " %s already in ip hash table\n", 
			MAC2STR(tmp->chaddr), u32ip2str(tmp->ip_addr));
	}
	
	key = arpp_tbl_ip_hash(item->ip_addr);
	if (key >= ARPP_ITEM_HASH_TABLE_SIZE)	{
		arpp_printf(ARPP_DEBUG, "error in calculate the ip hash value\n");
		return -1;
	}
	item->next = arpp_item_hash_table[key];
	arpp_item_hash_table[key] = item;

    return 0;
}


