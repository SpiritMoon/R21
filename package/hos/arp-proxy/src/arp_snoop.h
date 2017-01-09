/*
 * ARP Proxy
 * Copyright (c) 2014, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef ARP_SNOOP_H
#define ARP_SNOOP_H

void printPacketBuffer(unsigned char *buffer,unsigned long buffLen);

int arp_snoop_init(struct arpp_iface *arpp_if);
void arp_snoop_deinit(struct arpp_iface *arpp_if);
int handle_nl_arp(struct arpp_interfaces *interfaces, struct arppm_nl_msg *nl_msg);

#endif /* ARP_SNOOP_H */

