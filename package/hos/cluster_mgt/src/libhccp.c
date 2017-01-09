#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include "libhccp.h"

#define HCCP_HEADER_LEN 10

HANBool Assemble_HCCPHeader(char *buf, HCCPHeaderValues *protocolVal)
{
	if (buf == NULL)
	{
	    return HAN_FALSE;
	}

	protocolVal->clusterID = htonl(protocolVal->clusterID);
	protocolVal->seqnum = htons(protocolVal->seqnum);
	protocolVal->protocolLen = htons(protocolVal->protocolLen);
	
	memcpy(buf, &protocolVal->protocolver, sizeof(unsigned char));	
	memcpy(buf + sizeof(unsigned char), &protocolVal->seqnum, sizeof(unsigned short));	
	memcpy(buf + sizeof(unsigned short) + sizeof(unsigned char), &protocolVal->protocolType, sizeof(unsigned char));	
	memcpy(buf + sizeof(unsigned short) + sizeof(unsigned char) * 2, &protocolVal->protocolLen, sizeof(unsigned short));
	memcpy(buf + sizeof(unsigned short) * 2 + sizeof(unsigned char) * 2, &protocolVal->clusterID, sizeof(unsigned int));	
	
	
	return HAN_TRUE;
}

HANBool Parse_HCCPHeader(char *buf,  Hccp_Protocol_Struct *parse_packet) 
{
	parse_packet->type = *((unsigned char*)(buf + sizeof(unsigned char) + sizeof(unsigned short)));
	
	parse_packet->u.dbcp.head.protocolver = *((unsigned char*)buf);
	parse_packet->u.dbcp.head.seqnum = *((unsigned short*)(buf + sizeof(unsigned char)));
	parse_packet->u.dbcp.head.protocolType = parse_packet->type;
	parse_packet->u.dbcp.head.protocolLen = *((unsigned short*)(buf + sizeof(unsigned char) * 2 + sizeof(unsigned short)));
	parse_packet->u.dbcp.head.clusterID = *((unsigned int*)(buf + sizeof(unsigned char) * 2 + sizeof(unsigned short) * 2));


	parse_packet->u.dbcp.head.clusterID = ntohl(parse_packet->u.dbcp.head.clusterID);
	parse_packet->u.dbcp.head.seqnum = ntohs(parse_packet->u.dbcp.head.seqnum);
	parse_packet->u.dbcp.head.protocolLen = ntohs(parse_packet->u.dbcp.head.protocolLen);
	
	return HAN_TRUE;
}

char *Tlv_Assemble_8_Bit(unsigned short type, unsigned char value, char *buf)
{
	unsigned short len = sizeof(unsigned char);
	
	type = htons(type);
	len = htons(len);
	
	memcpy(buf, &type, TYPE_LEN);
	buf+=TYPE_LEN;
	memcpy(buf, &len, LENGTH_LEN);
	buf+=LENGTH_LEN;

	memcpy(buf, &value, sizeof(unsigned char));
	buf+=sizeof(unsigned char);
	
	return buf;
}

char *Tlv_Assemble_16_Bit(unsigned short type, unsigned short value, char *buf)
{
	unsigned short len = sizeof(unsigned short);
	
	type = htons(type);
	len = htons(len);
	value = htons(value);
	
	memcpy(buf, &type, TYPE_LEN);
	buf+=TYPE_LEN;
	memcpy(buf, &len, LENGTH_LEN);
	buf+=LENGTH_LEN;

	memcpy(buf, &value, sizeof(unsigned short));
	buf+=sizeof(unsigned short);
	
	return buf;
}

char *Tlv_Assemble_32_Bit(unsigned short type, unsigned int value, char *buf)
{
	unsigned short len = sizeof(unsigned int);
	
	type = htons(type);
	len = htons(len);
	value = htonl(value);
	
	memcpy(buf, &type, TYPE_LEN);
	buf+=TYPE_LEN;
	memcpy(buf, &len, LENGTH_LEN);
	buf+=LENGTH_LEN;

	memcpy(buf, &value, sizeof(unsigned int));
	buf+=sizeof(unsigned int);
	
	return buf;
}

char *Tlv_Assemble_String(unsigned short type, char *value, char *buf)
{
	unsigned short len = strlen(value);
	
	type = htons(type);
	len = htons(len);
	
	memcpy(buf, &type, TYPE_LEN);
	buf+=TYPE_LEN;
	memcpy(buf, &len, LENGTH_LEN);
	buf+=LENGTH_LEN;

	memcpy(buf, value, strlen(value));
	buf+=strlen(value);
	
	return buf;
}

char *Tlv_Assemble_MAC(unsigned short type, unsigned char *value, char *buf)
{
	unsigned short len = MAC_LEN;
	
	type = htons(type);
	len = htons(len);
	
	memcpy(buf, &type, TYPE_LEN);
	buf+=TYPE_LEN;
	memcpy(buf, &len, LENGTH_LEN);
	buf+=LENGTH_LEN;

	memcpy(buf, value, MAC_LEN);
	buf+=MAC_LEN;
	
	return buf;
}

void Mark_end(char *buf)
{
	unsigned short type = HCCP_ELEM_END;
	type = htons(type);
	memcpy(buf, &type, TYPE_LEN);
}

HANBool Assemble_DBCP_Compact(char *buf, DBCP_format *dbcp)
{
	char *p = NULL;
	unsigned char i =0;
	
	memcpy(buf + HCCP_HEADER_LEN, &dbcp->priority, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char), &dbcp->config_sequence, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 2, &dbcp->product_type, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3, dbcp->mac, MAC_LEN);

	p = buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3 + MAC_LEN;
	memcpy(p, &dbcp->state, sizeof(unsigned char));
	p+=sizeof(unsigned char);
	memcpy(p, &dbcp->radiocnt, sizeof(unsigned char));
	p+=sizeof(unsigned char);

	for(i = 0; i < dbcp->radiocnt && i < L_RADIO_NUM; i++)
	{
		memcpy(p, &dbcp->WTP_Radio[i].radioid, sizeof(unsigned char));
		p+=sizeof(unsigned char);
		memcpy(p, &dbcp->WTP_Radio[i].channel, sizeof(unsigned char));
		p+=sizeof(unsigned char);
		memcpy(p, &dbcp->WTP_Radio[i].txpower, sizeof(unsigned char));
		p+=sizeof(unsigned char);
	}
	
	return HAN_TRUE;
}

HANBool Assemble_DBCP_Tlv(char *buf, DBCP_format *dbcp)
{
	unsigned char i =0;
	
	buf += HCCP_HEADER_LEN;
	
	buf = Tlv_Assemble_8_Bit(DBCP_PKT_PRIORITY, dbcp->priority, buf);
	buf = Tlv_Assemble_8_Bit(DBCP_PKT_CONFIG_SEQUENCE, dbcp->config_sequence, buf);
	buf = Tlv_Assemble_8_Bit(DBCP_PKT_PRODUCT_TYPE, dbcp->product_type, buf);
	buf = Tlv_Assemble_MAC(DBCP_PKT_MAC, dbcp->mac, buf);
	buf = Tlv_Assemble_8_Bit(DBCP_PKT_STATE, dbcp->state, buf);
	buf = Tlv_Assemble_8_Bit(DBCP_PKT_RADIOCNT, dbcp->radiocnt, buf);	

	for(i = 0; i < dbcp->radiocnt && i < L_RADIO_NUM; i++)
	{
		buf = Tlv_Assemble_8_Bit(DBCP_PKT_WTP_RADIO_RADIOID, dbcp->WTP_Radio[i].radioid, buf);
		buf = Tlv_Assemble_8_Bit(DBCP_PKT_WTP_RADIO_CHANNEL, dbcp->WTP_Radio[i].channel, buf);
		buf = Tlv_Assemble_8_Bit(DBCP_PKT_WTP_RADIO_TXPOWER, dbcp->WTP_Radio[i].txpower, buf);

		buf = Tlv_Assemble_8_Bit(DBCP_PKT_RADIOCNT_END, 0, buf);
	}
	
	Mark_end(buf);
	
	return HAN_TRUE;
}

HANBool Assemble_DBCP(char *buf, DBCP_format *dbcp) 
{
	if (buf == NULL || dbcp == NULL)
	{
	    return HAN_FALSE;
	}
	
	dbcp->head.protocolType = DBCP;
	Assemble_HCCPHeader(buf, &dbcp->head);

	if(TLV_SWITCH)
	{
		Assemble_DBCP_Tlv(buf, dbcp);
	}
	else
	{		
		Assemble_DBCP_Compact(buf, dbcp);
	}
	
    return HAN_TRUE;
	
}

HANBool Assemble_RSRP_Compact(char *buf, RSRP_format *rsrp)
{
	unsigned char i =0;
	char *p = NULL;
	
	memcpy(buf + HCCP_HEADER_LEN, &rsrp->priority, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char), &rsrp->config_sequence, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 2, &rsrp->product_type, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3, rsrp->mac, MAC_LEN);
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3 + MAC_LEN, &rsrp->state, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 4 + MAC_LEN, &rsrp->radiocnt, sizeof(unsigned char));
	
	p = buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 5 + MAC_LEN;
	
	for(i = 0; i < rsrp->radiocnt && i < L_RADIO_NUM;i++)
	{
		memcpy(p, &rsrp->WTP_Radio[i].radioid, sizeof(unsigned char));
		p+=sizeof(unsigned char);
		memcpy(p, &rsrp->WTP_Radio[i].channel, sizeof(unsigned char));
		p+=sizeof(unsigned char);
		memcpy(p, &rsrp->WTP_Radio[i].txpower, sizeof(unsigned char));
		p+=sizeof(unsigned char);
	}

	rsrp->ip = htonl(rsrp->ip);
	memcpy(p, &rsrp->ip, sizeof(unsigned int));
	p+=sizeof(unsigned int);

	memcpy(p, rsrp->ap_version, VERSION_MAX_LEN);
	p+=VERSION_MAX_LEN;
	memcpy(p, rsrp->ap_name, AP_NAME_MAX_LEN);
	p+=AP_NAME_MAX_LEN;

	return HAN_TRUE;
}

HANBool Assemble_RSRP_Tlv(char *buf, RSRP_format *rsrp)
{
	unsigned char i =0;
	
	buf += HCCP_HEADER_LEN;
	
	buf = Tlv_Assemble_8_Bit(RSRP_PKT_PRIORITY, rsrp->priority, buf);
	buf = Tlv_Assemble_8_Bit(RSRP_PKT_CONFIG_SEQUENCE, rsrp->config_sequence, buf);
	buf = Tlv_Assemble_8_Bit(RSRP_PKT_PRODUCT_TYPE, rsrp->product_type, buf);
	buf = Tlv_Assemble_MAC(RSRP_PKT_MAC, rsrp->mac, buf);
	buf = Tlv_Assemble_8_Bit(RSRP_PKT_STATE, rsrp->state, buf);
	buf = Tlv_Assemble_8_Bit(RSRP_PKT_RADIOCNT, rsrp->radiocnt, buf);
	
	for(i = 0; i < rsrp->radiocnt && i < L_RADIO_NUM; i++)
	{
		buf = Tlv_Assemble_8_Bit(RSRP_PKT_WTP_RADIO_RADIOID, rsrp->WTP_Radio[i].radioid, buf);
		buf = Tlv_Assemble_8_Bit(RSRP_PKT_WTP_RADIO_CHANNEL, rsrp->WTP_Radio[i].channel, buf);
		buf = Tlv_Assemble_8_Bit(RSRP_PKT_WTP_RADIO_TXPOWER, rsrp->WTP_Radio[i].txpower, buf);

		buf = Tlv_Assemble_8_Bit(RSRP_PKT_RADIOCNT_END, 0, buf);		
	}
	
	buf = Tlv_Assemble_32_Bit(RSRP_PKT_IP, rsrp->ip, buf);	
	buf = Tlv_Assemble_String(RSRP_PKT_AP_VERSION, rsrp->ap_version, buf);
	buf = Tlv_Assemble_String(RSRP_PKT_AP_NAME, rsrp->ap_name, buf);
	
	Mark_end(buf);

	return HAN_TRUE;
}

HANBool Assemble_RSRP(char *buf, RSRP_format *rsrp) 
{
	if (buf == NULL || rsrp == NULL)
	{
	    return HAN_FALSE;
	}
	
	rsrp->head.protocolType = RSRP;
	rsrp->head.protocolLen = RSRP_PKT_LEN;
	Assemble_HCCPHeader(buf, &rsrp->head);
	
	if(TLV_SWITCH)
	{
		Assemble_RSRP_Tlv(buf, rsrp);
	}
	else
	{		
		Assemble_RSRP_Compact(buf, rsrp);
	}
	
    return HAN_TRUE;
	
}

HANBool Assemble_RSCP_Compact(char *buf, RSCP_format *rscp)
{
	char *p = NULL;
	unsigned char i =0, j = 0;
	
	memcpy(buf + HCCP_HEADER_LEN, &rscp->priority, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char), &rscp->config_sequence, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 2, &rscp->product_type, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3, rscp->mac, MAC_LEN);

	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3 + MAC_LEN, &rscp->count, sizeof(unsigned char));
	
	p = buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 4 + MAC_LEN;
	
	for(i = 0; i < rscp->count && i < MAX_CLUSTER_AP; i++)
	{
		memcpy(p, rscp->cluster_member[i].mac, MAC_LEN);
		p+=MAC_LEN;
		memcpy(p, &rscp->cluster_member[i].role, sizeof(unsigned char));
		p+=sizeof(unsigned char);
		memcpy(p, &rscp->cluster_member[i].state, sizeof(unsigned char));
		p+=sizeof(unsigned char);
		rscp->cluster_member[i].ip = htonl(rscp->cluster_member[i].ip);
		memcpy(p, &rscp->cluster_member[i].ip, sizeof(unsigned int));
		p+=sizeof(unsigned int);
		memcpy(p, &rscp->cluster_member[i].radiocnt, sizeof(unsigned char));
		p+=sizeof(unsigned char);
		
		for(j = 0; j < rscp->cluster_member[i].radiocnt && j < L_RADIO_NUM; j++)
		{
			memcpy(p, &rscp->cluster_member[i].WTP_Radio[j].radioid, sizeof(unsigned char));
			p+=sizeof(unsigned char);
			memcpy(p, &rscp->cluster_member[i].WTP_Radio[j].channel, sizeof(unsigned char));
			p+=sizeof(unsigned char);
			memcpy(p, &rscp->cluster_member[i].WTP_Radio[j].txpower, sizeof(unsigned char));
			p+=sizeof(unsigned char);
		}
	}
	
    return HAN_TRUE;
}

HANBool Assemble_RSCP_Tlv(char *buf, RSCP_format *rscp)
{
	unsigned char i =0, j = 0;
	
	buf += HCCP_HEADER_LEN;
	
	buf = Tlv_Assemble_8_Bit(RSCP_PKT_PRIORITY, rscp->priority, buf);
	buf = Tlv_Assemble_8_Bit(RSCP_PKT_CONFIG_SEQUENCE, rscp->config_sequence, buf);
	buf = Tlv_Assemble_8_Bit(RSCP_PKT_PRODUCT_TYPE, rscp->product_type, buf);
	buf = Tlv_Assemble_MAC(RSCP_PKT_MAC, rscp->mac, buf);
	buf = Tlv_Assemble_8_Bit(RSCP_PKT_COUNT, rscp->count, buf);
	
	for(i = 0; i < rscp->count && i < MAX_CLUSTER_AP; i++)
	{
		buf = Tlv_Assemble_MAC(RSCP_PKT_CLUSTER_MEMBER_MAC, rscp->cluster_member[i].mac, buf);
		buf = Tlv_Assemble_8_Bit(RSCP_PKT_CLUSTER_MEMBER_ROLE, rscp->cluster_member[i].role, buf);
		buf = Tlv_Assemble_8_Bit(RSCP_PKT_CLUSTER_MEMBER_STATE, rscp->cluster_member[i].state, buf);
		buf = Tlv_Assemble_32_Bit(RSCP_PKT_CLUSTER_MEMBER_IP, rscp->cluster_member[i].ip, buf);
		buf = Tlv_Assemble_8_Bit(RSCP_PKT_CLUSTER_MEMBER_RADIOCNT, rscp->cluster_member[i].radiocnt, buf);		
		
		for(j = 0; j < rscp->cluster_member[i].radiocnt && j < L_RADIO_NUM; j++)
		{
			buf = Tlv_Assemble_8_Bit(RSCP_PKT_CLUSTER_MEMBER_WTP_RADIO_RADIOID, rscp->cluster_member[i].WTP_Radio[j].radioid, buf);
			buf = Tlv_Assemble_8_Bit(RSCP_PKT_CLUSTER_MEMBER_WTP_RADIO_CHANNEL, rscp->cluster_member[i].WTP_Radio[j].channel, buf);
			buf = Tlv_Assemble_8_Bit(RSCP_PKT_CLUSTER_MEMBER_WTP_RADIO_TXPOWER, rscp->cluster_member[i].WTP_Radio[j].txpower, buf);

			buf = Tlv_Assemble_8_Bit(RSCP_PKT_CLUSTER_MEMBER_RADIOCNT_END, 0, buf);			
		}
		
		buf = Tlv_Assemble_8_Bit(RSCP_PKT_COUNT_END, 0, buf);
	}

	Mark_end(buf);

	return HAN_TRUE;
}

HANBool Assemble_RSCP(char *buf, RSCP_format *rscp) 
{
	if (buf == NULL || rscp == NULL)
	{
	    return HAN_FALSE;
	}
	
	rscp->head.protocolType = RSCP;
	Assemble_HCCPHeader(buf, &rscp->head);
	
	if(TLV_SWITCH)
	{
		Assemble_RSCP_Tlv(buf, rscp);
	}
	else
	{		
		Assemble_RSCP_Compact(buf, rscp);
	}	
	
    return HAN_TRUE;
}

HANBool Assemble_RIRP_Compact(char *buf, RIRP_format *rirp)
{
	unsigned char i = 0, j = 0;
	char *p = NULL;
	
	memcpy(buf + HCCP_HEADER_LEN, rirp->mac, MAC_LEN);
	memcpy(buf + HCCP_HEADER_LEN + MAC_LEN, &rirp->neighbor_count, sizeof(unsigned char));
	
	p = buf + HCCP_HEADER_LEN + MAC_LEN + sizeof(unsigned char);
	for(i = 0; i < rirp->neighbor_count && i < MAX_CLUSTER_AP;i++)
	{
		memcpy(p, rirp->cluster_neighbor[i].mac, MAC_LEN);
		p+=MAC_LEN;
		memcpy(p, &rirp->cluster_neighbor[i].radiocnt, sizeof(unsigned char));
		p+=sizeof(unsigned char);
		
		for(j = 0; j < rirp->cluster_neighbor[i].radiocnt && j < L_RADIO_NUM; j++)
		{
			memcpy(p, &rirp->cluster_neighbor[i].WTP_Radio[j].radioid, sizeof(unsigned char));
			p+=sizeof(unsigned char);
			memcpy(p, &rirp->cluster_neighbor[i].WTP_Radio[j].channel, sizeof(unsigned char));
			p+=sizeof(unsigned char);
			memcpy(p, &rirp->cluster_neighbor[i].WTP_Radio[j].txpower, sizeof(unsigned char));
			p+=sizeof(unsigned char);
			memcpy(p, &rirp->cluster_neighbor[i].WTP_Radio[j].rssi, sizeof(unsigned char));
			p+=sizeof(unsigned char);
		}		
	}
	
    return HAN_TRUE;
}

HANBool Assemble_RIRP_Tlv(char *buf, RIRP_format *rirp)
{
	unsigned char i = 0, j = 0;
	
	buf += HCCP_HEADER_LEN;
	
	buf = Tlv_Assemble_MAC(RIRP_PKT_MAC, rirp->mac, buf);
	buf = Tlv_Assemble_8_Bit(RIRP_PKT_NEIGHBOR_COUNT, rirp->neighbor_count, buf);
	
	for(i = 0; i < rirp->neighbor_count && i < MAX_CLUSTER_AP; i++)
	{
		buf = Tlv_Assemble_MAC(RIRP_PKT_CLUSTER_NEIGHBOR_MAC, rirp->cluster_neighbor[i].mac, buf);
		buf = Tlv_Assemble_8_Bit(RIRP_PKT_CLUSTER_NEIGHBOR_RADIOCNT, rirp->cluster_neighbor[i].radiocnt, buf);		
		
		for(j = 0; j < rirp->cluster_neighbor[i].radiocnt && j < L_RADIO_NUM;j++)
		{
			buf = Tlv_Assemble_8_Bit(RIRP_PKT_CLUSTER_NEIGHBOR_WTP_RADIO_RADIOID, rirp->cluster_neighbor[i].WTP_Radio[j].radioid, buf);
			buf = Tlv_Assemble_8_Bit(RIRP_PKT_CLUSTER_NEIGHBOR_WTP_RADIO_CHANNEL, rirp->cluster_neighbor[i].WTP_Radio[j].channel, buf);
			buf = Tlv_Assemble_8_Bit(RIRP_PKT_CLUSTER_NEIGHBOR_WTP_RADIO_TXPOWER, rirp->cluster_neighbor[i].WTP_Radio[j].txpower, buf);
			buf = Tlv_Assemble_8_Bit(RIRP_PKT_CLUSTER_NEIGHBOR_WTP_RADIO_RSSI, rirp->cluster_neighbor[i].WTP_Radio[j].rssi, buf);

			buf = Tlv_Assemble_8_Bit(RIRP_PKT_CLUSTER_NEIGHBOR_RADIOCNT_END, 0, buf);
		}
		
		buf = Tlv_Assemble_8_Bit(RIRP_PKT_NEIGHBOR_COUNT_END, 0, buf);
	}

	Mark_end(buf);

	return HAN_TRUE;
}

HANBool Assemble_RIRP(char *buf, RIRP_format *rirp) 
{
	if (buf == NULL || rirp == NULL)
	{
	    return HAN_FALSE;
	}
	
	rirp->head.protocolType = RIRP;
	Assemble_HCCPHeader(buf, &rirp->head);

	if(TLV_SWITCH)
	{
		Assemble_RIRP_Tlv(buf, rirp);
	}
	else
	{		
		Assemble_RIRP_Compact(buf, rirp);
	}	
	
    return HAN_TRUE;
}

HANBool Assemble_RICP_Compact(char *buf, RICP_format *ricp)
{
	unsigned char i = 0;
	char *p = NULL;
	
	ricp->vip = htonl(ricp->vip);
	ricp->vip_netmask = htonl(ricp->vip_netmask);
	memcpy(buf + HCCP_HEADER_LEN, &ricp->op, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char), &ricp->vip, sizeof(unsigned int));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) + sizeof(unsigned int), &ricp->count, sizeof(unsigned char));
	
	p = buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 2 + sizeof(unsigned int);
	for(i = 0; i < ricp->count && i < MAX_CLUSTER_AP; i++)
	{
		memcpy(p, ricp->mac[i], MAC_LEN);
		p+=MAC_LEN;
	}
	
	memcpy(p, &ricp->vip_netmask, sizeof(unsigned int));
	p+=sizeof(unsigned int);
	
    return HAN_TRUE;
}

HANBool Assemble_RICP_Tlv(char *buf, RICP_format *ricp)
{
	unsigned char i = 0;
	
	buf += HCCP_HEADER_LEN;
	
	buf = Tlv_Assemble_8_Bit(RICP_PKT_OP, ricp->op, buf);
	buf = Tlv_Assemble_32_Bit(RICP_PKT_VIP, ricp->vip, buf);
	buf = Tlv_Assemble_32_Bit(RICP_PKT_VIP_NETMASK, ricp->vip_netmask, buf);
	buf = Tlv_Assemble_8_Bit(RICP_PKT_COUNT, ricp->count, buf);
	
	for(i = 0; i < ricp->count && i < MAX_CLUSTER_AP; i++)
	{
		buf = Tlv_Assemble_MAC(RICP_PKT_MAC, ricp->mac[i], buf);

		buf = Tlv_Assemble_8_Bit(RICP_PKT_COUNT_END, 0, buf);
	}
	
	Mark_end(buf);

	return HAN_TRUE;
}

HANBool Assemble_RICP(char *buf, RICP_format *ricp) 
{	
	if (buf == NULL || ricp == NULL)
	{
	    return HAN_FALSE;
	}
	
	ricp->head.protocolType = RICP;
	Assemble_HCCPHeader(buf, &ricp->head);

	if(TLV_SWITCH)
	{
		Assemble_RICP_Tlv(buf, ricp);
	}
	else
	{		
		Assemble_RICP_Compact(buf, ricp);
	}
	
    return HAN_TRUE;
}

HANBool Assemble_RISP_Compact(char *buf, RISP_format *risp)
{
	unsigned char i = 0, j = 0, k = 0, l = 0;
	char *p = NULL;
	unsigned int mem_num = 0;
	
	risp->ACS_sequence = htonl(risp->ACS_sequence);
	mem_num = risp->Mem_num;
	risp->Mem_num = htonl(risp->Mem_num);
	memcpy(buf + HCCP_HEADER_LEN, &risp->ACS_sequence, sizeof(unsigned int));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned int), &risp->Mem_num, sizeof(unsigned int));

	p = buf + HCCP_HEADER_LEN + sizeof(unsigned int) * 2;
	for(i = 0; i < mem_num && i < MAX_CLUSTER_AP; i++)
	{
		risp->WTP_RF[i].ipaddr = htonl(risp->WTP_RF[i].ipaddr);
		risp->WTP_RF[i].priority = htonl(risp->WTP_RF[i].priority);
		
		memcpy(p, &risp->WTP_RF[i].role, sizeof(unsigned char));
		p+=sizeof(unsigned char);
		memcpy(p, &risp->WTP_RF[i].radiocnt, sizeof(unsigned char));
		p+=sizeof(unsigned char);
		memcpy(p, &risp->WTP_RF[i].neighbor_cnt, sizeof(unsigned char));
		p+=sizeof(unsigned char);
		memcpy(p, risp->WTP_RF[i].ap_base_mac, MAC_LEN);
		p+=MAC_LEN;
		memcpy(p, &risp->WTP_RF[i].ipaddr, sizeof(unsigned int));
		p+=sizeof(unsigned int);
		memcpy(p, &risp->WTP_RF[i].priority, sizeof(unsigned int));
		p+=sizeof(unsigned int);

		for(l = 0; l < risp->WTP_RF[i].radiocnt && l < L_RADIO_NUM; l++)
		{
			memcpy(p, &risp->WTP_RF[i].WTP_Radio[l].radioid, sizeof(unsigned char));
			p+=sizeof(unsigned char);
			memcpy(p, &risp->WTP_RF[i].WTP_Radio[l].channel, sizeof(unsigned char));
			p+=sizeof(unsigned char);
			memcpy(p, &risp->WTP_RF[i].WTP_Radio[l].txpower, sizeof(unsigned char));
			p+=sizeof(unsigned char);
		}
		
		for(j = 0; j < risp->WTP_RF[i].neighbor_cnt && j < MAX_CLUSTER_AP; j++)
		{
			memcpy(p, risp->WTP_RF[i].rssi_of_others[j].ap_base_mac, MAC_LEN);
			p+=MAC_LEN;
			memcpy(p, &risp->WTP_RF[i].rssi_of_others[j].radiocnt, sizeof(unsigned char));
			p+=sizeof(unsigned char);
			for(k = 0; k < risp->WTP_RF[i].rssi_of_others[j].radiocnt && k < L_RADIO_NUM; k++)
			{
				memcpy(p, &risp->WTP_RF[i].rssi_of_others[j].ap_radio[k].radioid, sizeof(unsigned char));	
				p+=sizeof(unsigned char);
				memcpy(p, &risp->WTP_RF[i].rssi_of_others[j].ap_radio[k].channel, sizeof(unsigned char));	
				p+=sizeof(unsigned char);
				memcpy(p, &risp->WTP_RF[i].rssi_of_others[j].ap_radio[k].txpower, sizeof(unsigned char));	
				p+=sizeof(unsigned char);
				memcpy(p, &risp->WTP_RF[i].rssi_of_others[j].ap_radio[k].rssi, sizeof(unsigned char));	
				p+=sizeof(unsigned char);
			}			
		}		
	}	
	
    return HAN_TRUE;
}

HANBool Assemble_RISP_Tlv(char *buf, RISP_format *risp)
{
	unsigned char i = 0, j = 0, k = 0, l = 0;
	
	buf += HCCP_HEADER_LEN;	
	
	buf = Tlv_Assemble_32_Bit(RISP_PKT_ACS_SEQUENCE, risp->ACS_sequence, buf);
	buf = Tlv_Assemble_32_Bit(RISP_PKT_MEM_NUM, risp->Mem_num, buf);
	
	for(i = 0; i < risp->Mem_num && i < MAX_CLUSTER_AP; i++)
	{		
		buf = Tlv_Assemble_8_Bit(RISP_PKT_WTP_RF_ROLE, risp->WTP_RF[i].role, buf);
		buf = Tlv_Assemble_MAC(RISP_PKT_WTP_RF_AP_BASE_MAC, risp->WTP_RF[i].ap_base_mac, buf);
		buf = Tlv_Assemble_32_Bit(RISP_PKT_WTP_RF_IPADDR, risp->WTP_RF[i].ipaddr, buf);
		buf = Tlv_Assemble_32_Bit(RISP_PKT_WTP_RF_PRIORITY, risp->WTP_RF[i].priority, buf);
		buf = Tlv_Assemble_8_Bit(RISP_PKT_WTP_RF_RADIOCNT, risp->WTP_RF[i].radiocnt, buf);
		
		for(l = 0; l < risp->WTP_RF[i].radiocnt && l < L_RADIO_NUM; l++)
		{
			buf = Tlv_Assemble_8_Bit(RISP_PKT_WTP_RF_WTP_RADIO_RADIOID, risp->WTP_RF[i].WTP_Radio[l].radioid, buf);
			buf = Tlv_Assemble_8_Bit(RISP_PKT_WTP_RF_WTP_RADIO_CHANNEL, risp->WTP_RF[i].WTP_Radio[l].channel, buf);
			buf = Tlv_Assemble_8_Bit(RISP_PKT_WTP_RF_WTP_RADIO_TXPOWER, risp->WTP_RF[i].WTP_Radio[l].txpower, buf);

			buf = Tlv_Assemble_8_Bit(RISP_PKT_WTP_RF_RADIOCNT_END, 0, buf);
		}
		
		buf = Tlv_Assemble_8_Bit(RISP_PKT_WTP_RF_NEIGHBOR_CNT, risp->WTP_RF[i].neighbor_cnt, buf);
		
		for(j = 0; j < risp->WTP_RF[i].neighbor_cnt && j < MAX_CLUSTER_AP;j++)
		{
			buf = Tlv_Assemble_MAC(RISP_PKT_WTP_RF_RSSI_OF_OTHERS_AP_BASE_MAC, risp->WTP_RF[i].rssi_of_others[j].ap_base_mac, buf);
			buf = Tlv_Assemble_8_Bit(RISP_PKT_WTP_RF_RSSI_OF_OTHERS_RADIOCNT, risp->WTP_RF[i].rssi_of_others[j].radiocnt, buf);
			
			for(k = 0; k < risp->WTP_RF[i].rssi_of_others[j].radiocnt && k < L_RADIO_NUM; k++)
			{
				buf = Tlv_Assemble_8_Bit(RISP_PKT_WTP_RF_RSSI_OF_OTHERS_AP_RADIO_RADIOID, risp->WTP_RF[i].rssi_of_others[j].ap_radio[k].radioid, buf);
				buf = Tlv_Assemble_8_Bit(RISP_PKT_WTP_RF_RSSI_OF_OTHERS_AP_RADIO_CHANNEL, risp->WTP_RF[i].rssi_of_others[j].ap_radio[k].channel, buf);
				buf = Tlv_Assemble_8_Bit(RISP_PKT_WTP_RF_RSSI_OF_OTHERS_AP_RADIO_TXPOWER, risp->WTP_RF[i].rssi_of_others[j].ap_radio[k].txpower, buf);
				buf = Tlv_Assemble_8_Bit(RISP_PKT_WTP_RF_RSSI_OF_OTHERS_AP_RADIO_RSSI, risp->WTP_RF[i].rssi_of_others[j].ap_radio[k].rssi, buf);

				buf = Tlv_Assemble_8_Bit(RISP_PKT_WTP_RF_RSSI_OF_OTHERS_RADIOCNT_END, 0, buf);
			}

			buf = Tlv_Assemble_8_Bit(RISP_PKT_WTP_RF_NEIGHBOR_CNT_END, 0, buf);
		}
		buf = Tlv_Assemble_8_Bit(RISP_PKT_MEM_NUM_END, 0, buf);
	}	

	Mark_end(buf);

	return HAN_TRUE;
}

HANBool Assemble_RISP(char *buf, RISP_format *risp) 
{	
	if (buf == NULL || risp == NULL)
	{
	    return HAN_FALSE;
	}
	risp->head.protocolType = RISP;
	Assemble_HCCPHeader(buf, &risp->head);

	if(TLV_SWITCH)
	{
		Assemble_RISP_Tlv(buf, risp);
	}
	else
	{		
		Assemble_RISP_Compact(buf, risp);
	}
	
    return HAN_TRUE;
}

HANBool Assemble_DCM_Compact(char *buf, DCM_format *dcm)
{
	unsigned char i = 0;
	char *p = NULL;
	
	memcpy(buf + HCCP_HEADER_LEN, &dcm->radionum, sizeof(unsigned char));
	
	p = buf + HCCP_HEADER_LEN + sizeof(unsigned char);
	
	for(i = 0; i < dcm->radionum && i < L_RADIO_NUM; i++)
	{
		memcpy(p, &dcm->radio[i].util, sizeof(unsigned char));	
		p+=sizeof(unsigned char);
		memcpy(p, &dcm->radio[i].stanum, sizeof(unsigned char));
		p+=sizeof(unsigned char);
		memcpy(p, &dcm->radio[i].bandtype, sizeof(unsigned char));
		p+=sizeof(unsigned char);
	}
	
    return HAN_TRUE;
}

HANBool Assemble_DCM_Tlv(char *buf, DCM_format *dcm)
{
	unsigned char i = 0;
	
	buf += HCCP_HEADER_LEN;
	
	buf = Tlv_Assemble_8_Bit(DCM_PKT_RADIONUM, dcm->radionum, buf);
	
	for(i = 0; i < dcm->radionum && i < L_RADIO_NUM; i++)
	{
		buf = Tlv_Assemble_8_Bit(DCM_PKT_RADIO_UTIL, dcm->radio[i].util, buf);
		buf = Tlv_Assemble_8_Bit(DCM_PKT_RADIO_STANUM, dcm->radio[i].stanum, buf);
		buf = Tlv_Assemble_8_Bit(DCM_PKT_RADIO_BANDTYPE, dcm->radio[i].bandtype, buf);

		buf = Tlv_Assemble_8_Bit(DCM_PKT_RADIONUM_END, 0, buf);
	}

	Mark_end(buf);

	return HAN_TRUE;
}

HANBool Assemble_DCM(char *buf, DCM_format *dcm)
{
	if (buf == NULL || dcm == NULL)
	{
	    return HAN_FALSE;
	}
	
	dcm->head.protocolType = DCM;
	Assemble_HCCPHeader(buf, &dcm->head);

	if(TLV_SWITCH)
	{
		Assemble_DCM_Tlv(buf, dcm);
	}
	else
	{		
		Assemble_DCM_Compact(buf, dcm);
	}
	
    return HAN_TRUE;
}
#if 0
HANBool Assemble_ACS_SequenceRequest_Compact(char *buf, ACS_format *acs_packet)
{	
	acs_packet->msgtype = htons(acs_packet->msgtype);
	
	memcpy(buf + HCCP_HEADER_LEN, &acs_packet->msgtype, sizeof(unsigned short));

	return HAN_TRUE;
}

HANBool Assemble_ACS_SequenceRequest_Tlv(char *buf, ACS_format *acs_packet)
{
	
	buf += HCCP_HEADER_LEN;
	
	buf = Tlv_Assemble_16_Bit(ACS_PKT_MSGTYPE, acs_packet->msgtype, buf);
		
	Mark_end(buf);

	return HAN_TRUE;
}

HANBool Assemble_ACS_SequenceRequest(char *buf, ACS_format *acs_packet) 
{
	if (buf == NULL || acs_packet == NULL)
	{
	    return HAN_FALSE;
	}
	
	acs_packet->head.protocolType = ACS;
	Assemble_HCCPHeader(buf, &acs_packet->head);

	if(acs_packet->head.protocolver == 0)
	{
		Assemble_ACS_SequenceRequest_Compact(buf, acs_packet);
	}
	else if(acs_packet->head.protocolver == 1)
	{
		Assemble_ACS_SequenceRequest_Tlv(buf, acs_packet);
	}
	
	return HAN_TRUE;

}

HANBool Assemble_ACS_SequenceResponse_Compact(char *buf, ACS_format *acs_packet)
{	
	acs_packet->msgtype = htons(acs_packet->msgtype);
	acs_packet->seq_num = htonl(acs_packet->seq_num);
	
	memcpy(buf + HCCP_HEADER_LEN, &acs_packet->msgtype, sizeof(unsigned short));	
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned short), &acs_packet->seq_num, sizeof(unsigned int));
	
	return HAN_TRUE;
}

HANBool Assemble_ACS_SequenceResponse_Tlv(char *buf, ACS_format *acs_packet)
{
	
	buf += HCCP_HEADER_LEN;

	buf = Tlv_Assemble_16_Bit(ACS_PKT_MSGTYPE, acs_packet->msgtype, buf);
	buf = Tlv_Assemble_32_Bit(ACS_PKT_SEQ_NUM, acs_packet->seq_num, buf);	

	Mark_end(buf);

	return HAN_TRUE;
	
}

HANBool Assemble_ACS_SequenceResponse(char *buf, ACS_format *acs_packet) 
{
	if (buf == NULL || acs_packet == NULL)
	{
	    return HAN_FALSE;
	}
	
	acs_packet->head.protocolType = ACS;
	Assemble_HCCPHeader(buf, &acs_packet->head);

	if(acs_packet->head.protocolver == 0)
	{
		Assemble_ACS_SequenceResponse_Compact(buf, acs_packet);
	}
	else if(acs_packet->head.protocolver == 1)
	{
		Assemble_ACS_SequenceResponse_Tlv(buf, acs_packet);
	}

	return HAN_TRUE;

}

HANBool Assemble_ACS_TokenRequest_Compact(char *buf, ACS_format *acs_packet)
{	
	acs_packet->msgtype = htons(acs_packet->msgtype);
	acs_packet->seq_num = htonl(acs_packet->seq_num);
	
	
	memcpy(buf + HCCP_HEADER_LEN, &acs_packet->msgtype, sizeof(unsigned short));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned short), &acs_packet->seq_num, sizeof(unsigned int));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned short) + sizeof(unsigned int), acs_packet->mac, MAC_LEN);
	
	return HAN_TRUE;
}

HANBool Assemble_ACS_TokenRequest_Tlv(char *buf, ACS_format *acs_packet)
{
	buf += HCCP_HEADER_LEN;

	buf = Tlv_Assemble_16_Bit(ACS_PKT_MSGTYPE, acs_packet->msgtype, buf);
	buf = Tlv_Assemble_32_Bit(ACS_PKT_SEQ_NUM, acs_packet->seq_num, buf);
	buf = Tlv_Assemble_MAC(ACS_PKT_MAC, acs_packet->mac, buf);
	
	Mark_end(buf);

	return HAN_TRUE;
}

HANBool Assemble_ACS_TokenRequest(char *buf, ACS_format *acs_packet) 
{
	if (buf == NULL || acs_packet == NULL)
	{
	    return HAN_FALSE;
	}	
	
	acs_packet->head.protocolType = ACS;
	Assemble_HCCPHeader(buf, &acs_packet->head);

	if(acs_packet->head.protocolver == 0)
	{
		Assemble_ACS_TokenRequest_Compact(buf, acs_packet);
	}
	else if(acs_packet->head.protocolver == 1)
	{
		Assemble_ACS_TokenRequest_Tlv(buf, acs_packet);
	}
	
	return HAN_TRUE;
}

HANBool Assemble_ACS_TokenResponse_Compact(char *buf, ACS_format *acs_packet)
{
	
	acs_packet->msgtype = htons(acs_packet->msgtype);
	acs_packet->seq_num = htonl(acs_packet->seq_num);
	
	
	memcpy(buf + HCCP_HEADER_LEN, &acs_packet->msgtype, sizeof(unsigned short));	
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned short), &acs_packet->seq_num, sizeof(unsigned int));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned short) + sizeof(unsigned int), acs_packet->mac, MAC_LEN);

	return HAN_TRUE;
}

HANBool Assemble_ACS_TokenResponse_Tlv(char *buf, ACS_format *acs_packet)
{
	
	buf += HCCP_HEADER_LEN;
	
	buf = Tlv_Assemble_16_Bit(ACS_PKT_MSGTYPE, acs_packet->msgtype, buf);
	buf = Tlv_Assemble_32_Bit(ACS_PKT_SEQ_NUM, acs_packet->seq_num, buf);
	buf = Tlv_Assemble_MAC(ACS_PKT_MAC, acs_packet->mac, buf);
	
	Mark_end(buf);

	return HAN_TRUE;
}

HANBool Assemble_ACS_TokenResponse(char *buf, ACS_format *acs_packet) 
{
	if (buf == NULL || acs_packet == NULL)
	{
	    return HAN_FALSE;
	}	
	
	acs_packet->head.protocolType = ACS;
	Assemble_HCCPHeader(buf, &acs_packet->head);

	if(acs_packet->head.protocolver == 0)
	{
		Assemble_ACS_TokenResponse_Compact(buf, acs_packet);
	}
	else if(acs_packet->head.protocolver == 1)
	{
		Assemble_ACS_TokenResponse_Tlv(buf, acs_packet);
	}
	
	return HAN_TRUE;

}
#endif

HANBool Assemble_ACS_SequenceRequest(char *buf, ACS_format *acs_packet) 
{
	if (buf == NULL || acs_packet == NULL)
	{
	    return HAN_FALSE;
	}
	
	acs_packet->msgtype = htons(acs_packet->msgtype);
	acs_packet->head.protocolType = ACS;
	Assemble_HCCPHeader(buf, &acs_packet->head);
	memcpy(buf + HCCP_HEADER_LEN, &acs_packet->msgtype, sizeof(unsigned short));

	return HAN_TRUE;

}
HANBool Assemble_ACS_SequenceResponse(char *buf, ACS_format *acs_packet) 
{
	if (buf == NULL || acs_packet == NULL)
	{
	    return HAN_FALSE;
	}
	
	acs_packet->msgtype = htons(acs_packet->msgtype);
	acs_packet->seq_num = htonl(acs_packet->seq_num);
	acs_packet->head.protocolType = ACS;
	Assemble_HCCPHeader(buf, &acs_packet->head);
	memcpy(buf + HCCP_HEADER_LEN, &acs_packet->msgtype, sizeof(unsigned short));	
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned short), &acs_packet->seq_num, sizeof(unsigned int));
	
	return HAN_TRUE;

}
HANBool Assemble_ACS_TokenRequest(char *buf, ACS_format *acs_packet) 
{
	if (buf == NULL || acs_packet == NULL)
	{
	    return HAN_FALSE;
	}
	
	acs_packet->msgtype = htons(acs_packet->msgtype);
	acs_packet->seq_num = htonl(acs_packet->seq_num);
	
	acs_packet->head.protocolType = ACS;
	Assemble_HCCPHeader(buf, &acs_packet->head);
	memcpy(buf + HCCP_HEADER_LEN, &acs_packet->msgtype, sizeof(unsigned short));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned short), &acs_packet->seq_num, sizeof(unsigned int));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned short) + sizeof(unsigned int), acs_packet->mac, MAC_LEN);
	
	return HAN_TRUE;

}

HANBool Assemble_ACS_TokenResponse(char *buf, ACS_format *acs_packet) 
{
	if (buf == NULL || acs_packet == NULL)
	{
	    return HAN_FALSE;
	}
	
	acs_packet->msgtype = htons(acs_packet->msgtype);
	acs_packet->seq_num = htonl(acs_packet->seq_num);
	
	acs_packet->head.protocolType = ACS;
	Assemble_HCCPHeader(buf, &acs_packet->head);
	memcpy(buf + HCCP_HEADER_LEN, &acs_packet->msgtype, sizeof(unsigned short));	
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned short), &acs_packet->seq_num, sizeof(unsigned int));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned short) + sizeof(unsigned int), acs_packet->mac, MAC_LEN);

	return HAN_TRUE;

}

HANBool Parse_DBCP(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned char i = 0;
	char *p = NULL;
	
	if (buf == NULL || parse_packet == NULL)
	{
	    return HAN_FALSE;
	}
	
	parse_packet->u.dbcp.priority= *((unsigned char*)(buf + HCCP_HEADER_LEN));
	parse_packet->u.dbcp.config_sequence = *((unsigned char*)(buf + HCCP_HEADER_LEN + sizeof(unsigned char)));
	parse_packet->u.dbcp.product_type = *((unsigned char*)(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 2));
	memcpy(parse_packet->u.dbcp.mac, buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3, MAC_LEN);

	p = buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3 + MAC_LEN;
	parse_packet->u.dbcp.state = *((unsigned char*)p);
	p+=sizeof(unsigned char);
	parse_packet->u.dbcp.radiocnt = *((unsigned char*)p);
	p+=sizeof(unsigned char);

	for(i = 0; i < parse_packet->u.dbcp.radiocnt && i < L_RADIO_NUM; i++)
	{
		parse_packet->u.dbcp.WTP_Radio[i].radioid = *((unsigned char*)p);
		p+=sizeof(unsigned char);
		parse_packet->u.dbcp.WTP_Radio[i].channel = *((unsigned char*)p);
		p+=sizeof(unsigned char);
		parse_packet->u.dbcp.WTP_Radio[i].txpower = *((unsigned char*)p);
		p+=sizeof(unsigned char);
	}
	
	return HAN_TRUE;
}

HANBool Parse_RSCP(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned char i = 0, j = 0;
	char *p = NULL;
	
	if (buf == NULL || parse_packet == NULL)
	{
	    return HAN_FALSE;
	}

	parse_packet->u.rscp.priority = *((unsigned char*)(buf + HCCP_HEADER_LEN));
	parse_packet->u.rscp.config_sequence = *((unsigned char*)(buf + HCCP_HEADER_LEN + sizeof(unsigned char)));
	parse_packet->u.rscp.product_type = *((unsigned char*)(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 2));
	memcpy(parse_packet->u.rscp.mac, buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3, MAC_LEN);
	parse_packet->u.rscp.count = *((unsigned char*)(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3 + MAC_LEN));

	p = buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 4 + MAC_LEN;
	for(i = 0; i < parse_packet->u.rscp.count && i < MAX_CLUSTER_AP; i++)
	{
		memcpy(parse_packet->u.rscp.cluster_member[i].mac, p, MAC_LEN);
		p+=MAC_LEN;
		parse_packet->u.rscp.cluster_member[i].role = *((unsigned char*)p);
		p+=1;
		parse_packet->u.rscp.cluster_member[i].state = *((unsigned char*)p);
		p+=1;
		parse_packet->u.rscp.cluster_member[i].ip = *((unsigned int*)p);
		parse_packet->u.rscp.cluster_member[i].ip = ntohl(parse_packet->u.rscp.cluster_member[i].ip);
		p+=sizeof(unsigned int);
		parse_packet->u.rscp.cluster_member[i].radiocnt = *((unsigned char*)p);
		p+=1;

		for(j = 0; j < parse_packet->u.rscp.cluster_member[i].radiocnt && j < L_RADIO_NUM; j++)
		{
			parse_packet->u.rscp.cluster_member[i].WTP_Radio[j].radioid = *((unsigned char*)p);
			p+=1;
			parse_packet->u.rscp.cluster_member[i].WTP_Radio[j].channel = *((unsigned char*)p);
			p+=1;
			parse_packet->u.rscp.cluster_member[i].WTP_Radio[j].txpower = *((unsigned char*)p);
			p+=1;
		}
	}
	return HAN_TRUE;

}

HANBool Parse_RSRP(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned char i = 0;
	char *p = NULL;
	
	if (buf == NULL || parse_packet == NULL)
	{
	    return HAN_FALSE;
	}

	parse_packet->u.rsrp.priority = *((unsigned char*)(buf + HCCP_HEADER_LEN));
	parse_packet->u.rsrp.config_sequence = *((unsigned char*)(buf + HCCP_HEADER_LEN + sizeof(unsigned char)));
	parse_packet->u.rsrp.product_type = *((unsigned char*)(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 2));
	memcpy(parse_packet->u.rsrp.mac, buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3, MAC_LEN);
	parse_packet->u.rsrp.state = *((unsigned char*)(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3 + MAC_LEN));
	parse_packet->u.rsrp.radiocnt = *((unsigned char*)(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 4 + MAC_LEN));
	
	p = buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 5 + MAC_LEN;
	for(i = 0; i < parse_packet->u.rsrp.radiocnt && i < L_RADIO_NUM; i++)
	{
		parse_packet->u.rsrp.WTP_Radio[i].radioid = *((unsigned char*)p);
		p+=sizeof(unsigned char);
		parse_packet->u.rsrp.WTP_Radio[i].channel = *((unsigned char*)p);
		p+=sizeof(unsigned char);
		parse_packet->u.rsrp.WTP_Radio[i].txpower = *((unsigned char*)p);
		p+=sizeof(unsigned char);
	}

	parse_packet->u.rsrp.ip = *((unsigned int*)p);
	parse_packet->u.rsrp.ip = ntohl(parse_packet->u.rsrp.ip);
	p+=sizeof(unsigned int);

	memcpy(parse_packet->u.rsrp.ap_version, p, VERSION_MAX_LEN);
	p+=VERSION_MAX_LEN;
	memcpy(parse_packet->u.rsrp.ap_name, p, AP_NAME_MAX_LEN);
	p+=AP_NAME_MAX_LEN;
	
	
	return HAN_TRUE;
}

HANBool Parse_RIRP(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned char i = 0, j = 0;
	char *p = NULL;

	if (buf == NULL || parse_packet == NULL)
	{
	    return HAN_FALSE;
	}
	
	memcpy(parse_packet->u.rirp.mac, buf + HCCP_HEADER_LEN, MAC_LEN);
	parse_packet->u.rirp.neighbor_count = *((unsigned char *)(buf + HCCP_HEADER_LEN + MAC_LEN));
	
	p = buf + HCCP_HEADER_LEN + MAC_LEN + sizeof(unsigned char);
	for(i = 0; i < parse_packet->u.rirp.neighbor_count && i < MAX_CLUSTER_AP; i++)
	{
		memcpy(parse_packet->u.rirp.cluster_neighbor[i].mac, p, MAC_LEN) ;
		p+=MAC_LEN;
		parse_packet->u.rirp.cluster_neighbor[i].radiocnt = *((unsigned char*)p);
		p+=sizeof(unsigned char);
		
		for(j = 0; j < parse_packet->u.rirp.cluster_neighbor[i].radiocnt && j < L_RADIO_NUM; j++)
		{
			parse_packet->u.rirp.cluster_neighbor[i].WTP_Radio[j].radioid = *((unsigned char*)p);
			p+=sizeof(unsigned char);
			parse_packet->u.rirp.cluster_neighbor[i].WTP_Radio[j].channel = *((unsigned char*)p);
			p+=sizeof(unsigned char);
			parse_packet->u.rirp.cluster_neighbor[i].WTP_Radio[j].txpower = *((unsigned char*)p);
			p+=sizeof(unsigned char);
			parse_packet->u.rirp.cluster_neighbor[i].WTP_Radio[j].rssi = *((unsigned char*)p);
			p+=sizeof(unsigned char);
		}		
	}	
	
	return HAN_TRUE;
}

HANBool Parse_RICP(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned char i = 0;
	char *p = NULL;

	if (buf == NULL || parse_packet == NULL)
	{
		return HAN_FALSE;
	}

	parse_packet->u.ricp.op = *((unsigned char *)(buf + HCCP_HEADER_LEN));
	parse_packet->u.ricp.vip = *((unsigned int *)(buf + HCCP_HEADER_LEN + sizeof(unsigned char)));
	parse_packet->u.ricp.count = *((unsigned char *)(buf + HCCP_HEADER_LEN + sizeof(unsigned char) + sizeof(unsigned int)));

	p = buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 2 + sizeof(unsigned int);
	for(i = 0; i < parse_packet->u.ricp.count && i < MAX_CLUSTER_AP; i++)
	{
		memcpy(parse_packet->u.ricp.mac[i], p, MAC_LEN);
		p+=MAC_LEN;
	}

	parse_packet->u.ricp.vip_netmask = *((unsigned int *)p);
	p+=sizeof(unsigned int);
	
	parse_packet->u.ricp.vip = ntohl(parse_packet->u.ricp.vip);	
	parse_packet->u.ricp.vip_netmask = ntohl(parse_packet->u.ricp.vip_netmask);	
	
	return HAN_TRUE;
}

HANBool Parse_RISP(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned char i = 0, j = 0, k = 0, l = 0;
	char *p = NULL;

	if (buf == NULL || parse_packet == NULL)
	{
		return HAN_FALSE;
	}

	p = buf + HCCP_HEADER_LEN;
	parse_packet->u.risp.ACS_sequence = *((unsigned int *)p);
	p+=sizeof(unsigned int);
	parse_packet->u.risp.Mem_num = *((unsigned int *)p);
	p+=sizeof(unsigned int);
	parse_packet->u.risp.Mem_num = ntohl(parse_packet->u.risp.Mem_num);

	for(i = 0; i < parse_packet->u.risp.Mem_num && i < MAX_CLUSTER_AP; i++)
	{
		parse_packet->u.risp.WTP_RF[i].role = *((unsigned char *)p);
		p+=sizeof(unsigned char);
		parse_packet->u.risp.WTP_RF[i].radiocnt = *((unsigned char *)p);
		p+=sizeof(unsigned char);
		parse_packet->u.risp.WTP_RF[i].neighbor_cnt = *((unsigned char *)p);
		p+=sizeof(unsigned char);
		memcpy(parse_packet->u.risp.WTP_RF[i].ap_base_mac, p, MAC_LEN);
		p+=MAC_LEN;
		parse_packet->u.risp.WTP_RF[i].ipaddr = *((unsigned int *)p);
		parse_packet->u.risp.WTP_RF[i].ipaddr = ntohl(parse_packet->u.risp.WTP_RF[i].ipaddr);
		p+=sizeof(unsigned int);
		parse_packet->u.risp.WTP_RF[i].priority = *((unsigned int *)p);
		parse_packet->u.risp.WTP_RF[i].priority = ntohl(parse_packet->u.risp.WTP_RF[i].priority);
		p+=sizeof(unsigned int);

		for(l = 0; l < parse_packet->u.risp.WTP_RF[i].radiocnt && l < L_RADIO_NUM; l++)
		{
			parse_packet->u.risp.WTP_RF[i].WTP_Radio[l].radioid = *((unsigned char *)p);
			p+=sizeof(unsigned char);
			parse_packet->u.risp.WTP_RF[i].WTP_Radio[l].channel = *((unsigned char *)p);
			p+=sizeof(unsigned char);
			parse_packet->u.risp.WTP_RF[i].WTP_Radio[l].txpower = *((unsigned char *)p);
			p+=sizeof(unsigned char);
		}
		
		for(j = 0; j < parse_packet->u.risp.WTP_RF[i].neighbor_cnt && j < MAX_CLUSTER_AP; j++)
		{
			memcpy(parse_packet->u.risp.WTP_RF[i].rssi_of_others[j].ap_base_mac, p, MAC_LEN);
			p+=MAC_LEN;
			parse_packet->u.risp.WTP_RF[i].rssi_of_others[j].radiocnt = *((unsigned char *)p);
			p+=sizeof(unsigned char);
			for(k = 0; k < parse_packet->u.risp.WTP_RF[i].rssi_of_others[j].radiocnt && k < L_RADIO_NUM; k++)
			{
				parse_packet->u.risp.WTP_RF[i].rssi_of_others[j].ap_radio[k].radioid = *((unsigned char *)p);
				p+=sizeof(unsigned char);
				parse_packet->u.risp.WTP_RF[i].rssi_of_others[j].ap_radio[k].channel = *((unsigned char *)p);
				p+=sizeof(unsigned char);
				parse_packet->u.risp.WTP_RF[i].rssi_of_others[j].ap_radio[k].txpower = *((unsigned char *)p);
				p+=sizeof(unsigned char);
				parse_packet->u.risp.WTP_RF[i].rssi_of_others[j].ap_radio[k].rssi = *((unsigned char *)p);
				p+=sizeof(unsigned char);
			}
		}
	}	
	
	parse_packet->u.risp.ACS_sequence = ntohl(parse_packet->u.risp.ACS_sequence);	
	
	return HAN_TRUE;
}


HANBool Parse_DCM(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned char i = 0;
	char *p = NULL;

	if (buf == NULL || parse_packet == NULL)
	{
	    return HAN_FALSE;
	}
	
	memcpy(&parse_packet->u.dcm.radionum, buf + HCCP_HEADER_LEN, sizeof(unsigned char));
	p = buf + HCCP_HEADER_LEN + sizeof(unsigned char);

	for(i=0;i<parse_packet->u.dcm.radionum;i++)
	{
		parse_packet->u.dcm.radio[i].util = *((unsigned char*)p);
		p+=sizeof(unsigned char);
		parse_packet->u.dcm.radio[i].stanum = *((unsigned char*)p);
		p+=sizeof(unsigned char);
		parse_packet->u.dcm.radio[i].bandtype = *((unsigned char*)p);
		p+=sizeof(unsigned char);
	}
	
	
	return HAN_TRUE;
}


HANBool Parse_ACS(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	if (buf == NULL || parse_packet == NULL)
	{
	    return HAN_FALSE;
	}
	
	parse_packet->u.acs.msgtype = *((unsigned short*)(buf + HCCP_HEADER_LEN));
	parse_packet->u.acs.seq_num = *((unsigned int*)(buf + HCCP_HEADER_LEN + sizeof(unsigned short)));
	parse_packet->u.acs.msgtype = ntohs(parse_packet->u.acs.msgtype);
	switch(parse_packet->u.acs.msgtype)
	{
		case Sequence_req:
		{
			parse_packet->u.acs.msgtype = Sequence_req;
			parse_packet->u.acs.seq_num = 0;
			break;
		}
		case Sequence_resp:
		{
			parse_packet->u.acs.msgtype = Sequence_resp;
			parse_packet->u.acs.seq_num = ntohl(parse_packet->u.acs.seq_num);
			break;
		}
		case Token_req:
		{
			parse_packet->u.acs.msgtype = Token_req;
			parse_packet->u.acs.seq_num = ntohl(parse_packet->u.acs.seq_num);
			memcpy(parse_packet->u.acs.mac, buf + HCCP_HEADER_LEN + sizeof(unsigned short) + sizeof(unsigned int), MAC_LEN);
			break;
		}
		case Token_resp:
		{
			parse_packet->u.acs.msgtype = Token_resp;
			parse_packet->u.acs.seq_num = ntohl(parse_packet->u.acs.seq_num);
			memcpy(parse_packet->u.acs.mac, buf + HCCP_HEADER_LEN + sizeof(unsigned short) + sizeof(unsigned int), MAC_LEN);
			break;
		}
		default :
		{
			break;
		}
	}
	return HAN_TRUE;
}

unsigned short Get_Hccp_Elem_Type(char **buf, unsigned int *length)
{
	unsigned short 	type = 0;
	
	memcpy(&type, *buf, TYPE_LEN);
	
	*buf += TYPE_LEN;
	*length += TYPE_LEN;
	
	return ntohs(type);
}

unsigned short Get_Hccp_Elem_Len(char **buf, unsigned int *length)
{
	unsigned short 	len = 0;
	
	memcpy(&len, *buf, LENGTH_LEN);
	
	*buf += LENGTH_LEN;
	*length += LENGTH_LEN;
	
	return ntohs(len);
}

unsigned char Tlv_Parse_8_Bit(char **buf, unsigned short len, unsigned int *length)
{
	unsigned char value = 0;
	
	memcpy(&value, *buf, 1);

	*buf += 1;
	*length += 1;
	
	return value;
}

unsigned short Tlv_Parse_16_Bit(char **buf,  unsigned short len, unsigned int *length)
{
	unsigned short value = 0;

	memcpy(&value, *buf, 2);

	*buf += 2;
	*length += 2;
	
	return ntohs(value);
}

unsigned int Tlv_Parse_32_Bit(char **buf,  unsigned short len, unsigned int *length)
{
	unsigned int value = 0;

	memcpy(&value, *buf, 4);

	*buf += 4;
	*length += 4;
	
	return ntohl(value);
}

void Tlv_Parse_String(char **buf, char *str, unsigned short len, unsigned int *length)
{
	memcpy(str, *buf, len);

	*buf += len;
	*length += len;
}

void Tlv_Parse_MAC(char **buf, char *str,  unsigned short len, unsigned int *length)
{
	memcpy(str, *buf, MAC_LEN);

	*buf += MAC_LEN;
	*length += MAC_LEN;
}

void Unknown_Type_Handle(char **buf, unsigned short len, unsigned int *length)
{
	*buf += len;
	*length += len;
}

HANBool Parse_DBCP_Tlv(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned char i = 0;
	char *p = NULL;
	unsigned short 	hccp_elem_type = 0;
	unsigned short 	hccp_elem_len = 0;
	unsigned int length = 0;
	
	if (buf == NULL || parse_packet == NULL)
	{
	    return HAN_FALSE;
	}

	buf += HCCP_HEADER_LEN;
	
	while(length < DBCP_BUF_LEN)
	{
		hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
		hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

		if(hccp_elem_type == HCCP_ELEM_END)
		{
			break;
		}
		
		switch(hccp_elem_type)
		{
			case DBCP_PKT_PRIORITY:
			{
				parse_packet->u.dbcp.priority = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
				break;
			}				
			case DBCP_PKT_CONFIG_SEQUENCE:
			{
				parse_packet->u.dbcp.config_sequence = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
				break;
			}
			case DBCP_PKT_PRODUCT_TYPE:
			{
				parse_packet->u.dbcp.product_type = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
				break;
			}
			case DBCP_PKT_MAC:
			{
				Tlv_Parse_MAC(&buf, parse_packet->u.dbcp.mac,  hccp_elem_len, &length);
				break;
			}				
			case DBCP_PKT_STATE:
			{
				parse_packet->u.dbcp.state = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
				break;
			}				
			case DBCP_PKT_RADIOCNT:
			{
				parse_packet->u.dbcp.radiocnt = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);

				for(i = 0; i < parse_packet->u.dbcp.radiocnt && i < L_RADIO_NUM; i++)
				{
					while(length < DBCP_BUF_LEN)
					{
						hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
						hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

						if(hccp_elem_type == DBCP_PKT_RADIOCNT_END)
						{
							Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
							break;
						}
						
						switch(hccp_elem_type)
						{
							case DBCP_PKT_WTP_RADIO_RADIOID:
							{
								parse_packet->u.dbcp.WTP_Radio[i].radioid = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
								break;
							}
							case DBCP_PKT_WTP_RADIO_CHANNEL:
							{
								parse_packet->u.dbcp.WTP_Radio[i].channel = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
								break;
							}
							case DBCP_PKT_WTP_RADIO_TXPOWER:
							{
								parse_packet->u.dbcp.WTP_Radio[i].txpower = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
								break;
							}
							case DBCP_PKT_WTP_RADIO_RSSI:
							{
								parse_packet->u.dbcp.WTP_Radio[i].rssi = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
								break;
							}
							default:
								Unknown_Type_Handle(&buf, hccp_elem_len, &length);
								break;	
						}
					}
				}
				
				break;
			}
			
			
			default:
				Unknown_Type_Handle(&buf, hccp_elem_len, &length);
				break;	
		}
	}	
	
	return HAN_TRUE;
}

HANBool Parse_RSCP_Tlv(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned char i = 0, j = 0;
	char *p = NULL;
	unsigned short 	hccp_elem_type = 0;
	unsigned short 	hccp_elem_len = 0;
	unsigned int length = 0;
	
	if (buf == NULL || parse_packet == NULL)
	{
	    return HAN_FALSE;
	}
	
	buf += HCCP_HEADER_LEN;

	while(length < RSCP_BUF_LEN)
	{
		hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
		hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

		if(hccp_elem_type == HCCP_ELEM_END)
		{
			break;
		}
		
		switch(hccp_elem_type)
		{
			case RSCP_PKT_PRIORITY:
			{
				parse_packet->u.rscp.priority = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
				break;
			}				
			case RSCP_PKT_CONFIG_SEQUENCE:
			{
				parse_packet->u.rscp.config_sequence = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
				break;
			}
			case RSCP_PKT_PRODUCT_TYPE:
			{
				parse_packet->u.rscp.product_type = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
				break;
			}
			case RSCP_PKT_MAC:
			{
				Tlv_Parse_MAC(&buf, parse_packet->u.rscp.mac,  hccp_elem_len, &length);
				break;
			}				
			case RSCP_PKT_COUNT:
			{
				parse_packet->u.rscp.count = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
				
				for(i = 0; i < parse_packet->u.rscp.count && i < MAX_CLUSTER_AP; i++)
				{
					while(length < RSCP_BUF_LEN)
					{
						hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
						hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

						if(hccp_elem_type == RSCP_PKT_COUNT_END)
						{
							Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
							break;
						}
						
						switch(hccp_elem_type)
						{
							case RSCP_PKT_CLUSTER_MEMBER_MAC:
							{
								Tlv_Parse_MAC(&buf, parse_packet->u.rscp.cluster_member[i].mac,  hccp_elem_len, &length);
								break;
							}								
							case RSCP_PKT_CLUSTER_MEMBER_ROLE:
							{
								parse_packet->u.rscp.cluster_member[i].role = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
								break;
							}								
							case RSCP_PKT_CLUSTER_MEMBER_STATE:
							{
								parse_packet->u.rscp.cluster_member[i].state = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
								break;
							}								
							case RSCP_PKT_CLUSTER_MEMBER_IP:
							{
								parse_packet->u.rscp.cluster_member[i].ip = Tlv_Parse_32_Bit(&buf, hccp_elem_len, &length);
								break;
							}								
							case RSCP_PKT_CLUSTER_MEMBER_RADIOCNT:
							{
								parse_packet->u.rscp.cluster_member[i].radiocnt = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);

								for(j = 0; j < parse_packet->u.rscp.cluster_member[i].radiocnt && j < L_RADIO_NUM; j++)
								{
									while(length < RSCP_BUF_LEN)
									{
										hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
										hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

										if(hccp_elem_type == RSCP_PKT_CLUSTER_MEMBER_RADIOCNT_END)
										{
											Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
											break;
										}
										
										switch(hccp_elem_type)
										{
											case RSCP_PKT_CLUSTER_MEMBER_WTP_RADIO_RADIOID:
											{
												parse_packet->u.rscp.cluster_member[i].WTP_Radio[j].radioid = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
												break;
											}
											case RSCP_PKT_CLUSTER_MEMBER_WTP_RADIO_CHANNEL:
											{
												parse_packet->u.rscp.cluster_member[i].WTP_Radio[j].channel = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
												break;
											}
											case RSCP_PKT_CLUSTER_MEMBER_WTP_RADIO_TXPOWER:
											{
												parse_packet->u.rscp.cluster_member[i].WTP_Radio[j].txpower = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
												break;
											}
											case RSCP_PKT_CLUSTER_MEMBER_WTP_RADIO_RSSI:
											{
												parse_packet->u.rscp.cluster_member[i].WTP_Radio[j].rssi = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
												break;
											}
											default:
												Unknown_Type_Handle(&buf, hccp_elem_len, &length);
												break;	
										}
									}
								}
								break;
							}								
							default:
								Unknown_Type_Handle(&buf, hccp_elem_len, &length);
								break;	
						}
					}
					
				}
				break;
			}				
			
			
			default:
				Unknown_Type_Handle(&buf, hccp_elem_len, &length);
				break;	
		}
	}
	
	
	return HAN_TRUE;

}

HANBool Parse_RSRP_Tlv(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned char i = 0;
	char *p = NULL;
	unsigned short 	hccp_elem_type = 0;
	unsigned short 	hccp_elem_len = 0;
	unsigned int length = 0;
	
	if (buf == NULL || parse_packet == NULL)
	{
	    return HAN_FALSE;
	}
	buf += HCCP_HEADER_LEN;

	while(length < RSRP_BUF_LEN)
	{
		hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
		hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

		if(hccp_elem_type == HCCP_ELEM_END)
		{
			break;
		}
		
		switch(hccp_elem_type)
		{
			case RSRP_PKT_PRIORITY:
			{
				parse_packet->u.rsrp.priority = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
				break;
			}
			case RSRP_PKT_CONFIG_SEQUENCE:
			{
				parse_packet->u.rsrp.config_sequence = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
				break;
			}	
			case RSRP_PKT_PRODUCT_TYPE:
			{
				parse_packet->u.rsrp.product_type = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
				break;
			}	
			case RSRP_PKT_MAC:
			{
				Tlv_Parse_MAC(&buf, parse_packet->u.rsrp.mac,  hccp_elem_len, &length);
				break;
			}	
			case RSRP_PKT_STATE:
			{
				parse_packet->u.rsrp.state = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
				break;
			}
			case RSRP_PKT_IP:
			{
				parse_packet->u.rsrp.ip = Tlv_Parse_32_Bit(&buf,  hccp_elem_len, &length);
				break;
			}
			case RSRP_PKT_AP_VERSION:
			{
				Tlv_Parse_String(&buf, parse_packet->u.rsrp.ap_version, hccp_elem_len, &length);
				break;
			}
			case RSRP_PKT_AP_NAME:
			{
				Tlv_Parse_String(&buf, parse_packet->u.rsrp.ap_name, hccp_elem_len, &length);
				break;
			}
			case RSRP_PKT_RADIOCNT:
			{
				parse_packet->u.rsrp.radiocnt = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
				for(i = 0; i < parse_packet->u.rsrp.radiocnt && i < L_RADIO_NUM; i++)
				{
					while(length < RSRP_BUF_LEN)
					{
						hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
						hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

						if(hccp_elem_type == RSRP_PKT_RADIOCNT_END)
						{
							Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
							break;
						}
						
						switch(hccp_elem_type)
						{
							case RSRP_PKT_WTP_RADIO_RADIOID:
							{
								parse_packet->u.rsrp.WTP_Radio[i].radioid = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
								break;
							}
							case RSRP_PKT_WTP_RADIO_CHANNEL:
							{
								parse_packet->u.rsrp.WTP_Radio[i].channel = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
								break;
							}
							case RSRP_PKT_WTP_RADIO_TXPOWER:
							{
								parse_packet->u.rsrp.WTP_Radio[i].txpower = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
								break;
							}
							case RSRP_PKT_WTP_RADIO_RSSI:
							{
								parse_packet->u.rsrp.WTP_Radio[i].rssi = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
								break;
							}
							default:
								Unknown_Type_Handle(&buf, hccp_elem_len, &length);
								break;	
						}
					}
					
				}
				break;
			}			
			
			
			default:
				Unknown_Type_Handle(&buf, hccp_elem_len, &length);
				break;	
		}
	}
	
	return HAN_TRUE;
}

HANBool Parse_RIRP_Tlv(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned char i = 0, j = 0;
	char *p = NULL;
	unsigned short	hccp_elem_type = 0;
	unsigned short	hccp_elem_len = 0;
	unsigned int length = 0;
	
	if (buf == NULL || parse_packet == NULL)
	{
	    return HAN_FALSE;
	}
	
	buf += HCCP_HEADER_LEN;
	
	while(length < RIRP_BUF_LEN)
	{
		hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
		hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

		if(hccp_elem_type == HCCP_ELEM_END)
		{
			break;
		}
		
		switch(hccp_elem_type)
		{
			case RIRP_PKT_MAC:
			{
				Tlv_Parse_MAC(&buf, parse_packet->u.rirp.mac,  hccp_elem_len, &length);
				break;
			}				
			case RIRP_PKT_NEIGHBOR_COUNT:
			{
				parse_packet->u.rirp.neighbor_count = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
				
				for(i = 0; i < parse_packet->u.rirp.neighbor_count && i < MAX_CLUSTER_AP; i++)
				{
					while(length < RIRP_BUF_LEN)
					{
						hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
						hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

						if(hccp_elem_type == RIRP_PKT_NEIGHBOR_COUNT_END)
						{
							Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
							break;
						}
						
						switch(hccp_elem_type)
						{
							case RIRP_PKT_CLUSTER_NEIGHBOR_MAC:
							{
								Tlv_Parse_MAC(&buf, parse_packet->u.rirp.cluster_neighbor[i].mac,  hccp_elem_len, &length);
								break;
							}
							case RIRP_PKT_CLUSTER_NEIGHBOR_RADIOCNT:
							{
								parse_packet->u.rirp.cluster_neighbor[i].radiocnt = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);

								for(j = 0; j < parse_packet->u.rirp.cluster_neighbor[i].radiocnt && j < L_RADIO_NUM; j++)
								{
									while(length < RIRP_BUF_LEN)
									{
										hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
										hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

										if(hccp_elem_type == RIRP_PKT_CLUSTER_NEIGHBOR_RADIOCNT_END)
										{
											Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
											break;
										}
										
										switch(hccp_elem_type)
										{
											case RIRP_PKT_CLUSTER_NEIGHBOR_WTP_RADIO_RADIOID:
											{
												parse_packet->u.rirp.cluster_neighbor[i].WTP_Radio[j].radioid = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
												break;
											}
											case RIRP_PKT_CLUSTER_NEIGHBOR_WTP_RADIO_CHANNEL:
											{
												parse_packet->u.rirp.cluster_neighbor[i].WTP_Radio[j].channel = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
												break;
											}
											case RIRP_PKT_CLUSTER_NEIGHBOR_WTP_RADIO_TXPOWER:
											{
												parse_packet->u.rirp.cluster_neighbor[i].WTP_Radio[j].txpower = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
												break;
											}
											case RIRP_PKT_CLUSTER_NEIGHBOR_WTP_RADIO_RSSI:
											{
												parse_packet->u.rirp.cluster_neighbor[i].WTP_Radio[j].rssi = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
												break;
											}
											default:
												Unknown_Type_Handle(&buf, hccp_elem_len, &length);
												break;	
										}
									}
								}
								break;
							}							
							default:
								Unknown_Type_Handle(&buf, hccp_elem_len, &length);
								break;	
						}
					}
				}
				break;
			}		
			
			default:
				Unknown_Type_Handle(&buf, hccp_elem_len, &length);
				break;	
		}
	}		
	
	return HAN_TRUE;
}

HANBool Parse_RICP_Tlv(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned char i = 0;
	char *p = NULL;
	unsigned short	hccp_elem_type = 0;
	unsigned short	hccp_elem_len = 0;
	unsigned int length = 0;
	
	if (buf == NULL || parse_packet == NULL)
	{
		return HAN_FALSE;
	}
	
	buf += HCCP_HEADER_LEN;
	
	while(length < RICP_BUF_LEN)
	{
		hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
		hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

		if(hccp_elem_type == HCCP_ELEM_END)
		{
			break;
		}
		
		switch(hccp_elem_type)
		{
			case RICP_PKT_OP:
			{
				parse_packet->u.ricp.op = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
				break;
			}				
			case RICP_PKT_VIP:
			{
				parse_packet->u.ricp.vip = Tlv_Parse_32_Bit(&buf, hccp_elem_len, &length);
				break;
			}
			case RICP_PKT_VIP_NETMASK:
			{
				parse_packet->u.ricp.vip_netmask = Tlv_Parse_32_Bit(&buf, hccp_elem_len, &length);
				break;
			}
			case RICP_PKT_COUNT:
			{
				parse_packet->u.ricp.count = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);

				for(i = 0; i < parse_packet->u.ricp.count && i < MAX_CLUSTER_AP; i++)
				{
					while(length < RICP_BUF_LEN)
					{
						hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
						hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

						if(hccp_elem_type == RICP_PKT_COUNT_END)
						{
							Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
							break;
						}
						
						switch(hccp_elem_type)
						{
							case RICP_PKT_MAC:
							{
								Tlv_Parse_MAC(&buf, parse_packet->u.ricp.mac[i],  hccp_elem_len, &length);
								break;
							}							
							default:
								Unknown_Type_Handle(&buf, hccp_elem_len, &length);
								break;	
						}
					}
				}
				break;
			}	
			
			default:
				Unknown_Type_Handle(&buf, hccp_elem_len, &length);
				break;	
		}
	}	
	
	return HAN_TRUE;
}

HANBool Parse_RISP_Tlv(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned char i = 0, j = 0, k = 0, l = 0;
	char *p = NULL;
	unsigned short	hccp_elem_type = 0;
	unsigned short	hccp_elem_len = 0;
	unsigned int length = 0;
	
	if (buf == NULL || parse_packet == NULL)
	{
		return HAN_FALSE;
	}

	buf += HCCP_HEADER_LEN;
	
	while(length < RISP_BUF_LEN)
	{
		hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
		hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

		if(hccp_elem_type == HCCP_ELEM_END)
		{
			break;
		}
		
		switch(hccp_elem_type)
		{
			case RISP_PKT_ACS_SEQUENCE:
			{
				parse_packet->u.risp.ACS_sequence = Tlv_Parse_32_Bit(&buf, hccp_elem_len, &length);
				break;
			}				
			case RISP_PKT_MEM_NUM:
			{
				parse_packet->u.risp.Mem_num = Tlv_Parse_32_Bit(&buf, hccp_elem_len, &length);
				
				for(i = 0; i < parse_packet->u.risp.Mem_num && i < MAX_CLUSTER_AP; i++)
				{
					while(length < RISP_BUF_LEN)
					{
						hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
						hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

						if(hccp_elem_type == RISP_PKT_MEM_NUM_END)
						{
							Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
							break;
						}
						
						switch(hccp_elem_type)
						{
							case RISP_PKT_WTP_RF_ROLE:
							{
								parse_packet->u.risp.WTP_RF[i].role = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
								break;
							}
							case RISP_PKT_WTP_RF_AP_BASE_MAC:
							{
								Tlv_Parse_MAC(&buf, parse_packet->u.risp.WTP_RF[i].ap_base_mac,  hccp_elem_len, &length);
								break;
							}
							case RISP_PKT_WTP_RF_IPADDR:
							{
								parse_packet->u.risp.WTP_RF[i].ipaddr = Tlv_Parse_32_Bit(&buf, hccp_elem_len, &length);
								break;
							}
							case RISP_PKT_WTP_RF_PRIORITY:
							{
								parse_packet->u.risp.WTP_RF[i].priority = Tlv_Parse_32_Bit(&buf, hccp_elem_len, &length);
								break;
							}
							case RISP_PKT_WTP_RF_RADIOCNT:
							{
								parse_packet->u.risp.WTP_RF[i].radiocnt = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);

								for(l = 0; l < parse_packet->u.risp.WTP_RF[i].radiocnt && l < L_RADIO_NUM; l++)
								{
									while(length < RISP_BUF_LEN)
									{
										hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
										hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

										if(hccp_elem_type == RISP_PKT_WTP_RF_RADIOCNT_END)
										{
											Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
											break;
										}
										
										switch(hccp_elem_type)
										{
											case RISP_PKT_WTP_RF_WTP_RADIO_RADIOID:
											{
												parse_packet->u.risp.WTP_RF[i].WTP_Radio[l].radioid = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
												break;
											}
											case RISP_PKT_WTP_RF_WTP_RADIO_CHANNEL:
											{
												parse_packet->u.risp.WTP_RF[i].WTP_Radio[l].channel = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
												break;
											}
											case RISP_PKT_WTP_RF_WTP_RADIO_TXPOWER:
											{
												parse_packet->u.risp.WTP_RF[i].WTP_Radio[l].txpower = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
												break;
											}
											case RISP_PKT_WTP_RF_WTP_RADIO_RSSI:
											{
												parse_packet->u.risp.WTP_RF[i].WTP_Radio[l].rssi = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
												break;
											}
											default:
												Unknown_Type_Handle(&buf, hccp_elem_len, &length);
												break;	
										}
									}
								}
								break;
							}
							case RISP_PKT_WTP_RF_NEIGHBOR_CNT:
							{
								parse_packet->u.risp.WTP_RF[i].neighbor_cnt = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);

								for(j = 0; j < parse_packet->u.risp.WTP_RF[i].neighbor_cnt && j < MAX_CLUSTER_AP; j++)
								{
									while(length < RISP_BUF_LEN)
									{
										hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
										hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

										if(hccp_elem_type == RISP_PKT_WTP_RF_NEIGHBOR_CNT_END)
										{
											Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
											break;
										}
										
										switch(hccp_elem_type)
										{
											case RISP_PKT_WTP_RF_RSSI_OF_OTHERS_AP_BASE_MAC:
											{
												Tlv_Parse_MAC(&buf, parse_packet->u.risp.WTP_RF[i].rssi_of_others[j].ap_base_mac,  hccp_elem_len, &length);
												break;
											}
											case RISP_PKT_WTP_RF_RSSI_OF_OTHERS_RADIOCNT:
											{
												parse_packet->u.risp.WTP_RF[i].rssi_of_others[j].radiocnt = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);

												for(k = 0; k < parse_packet->u.risp.WTP_RF[i].rssi_of_others[j].radiocnt && k < L_RADIO_NUM; k++)
												{
													while(length < RISP_BUF_LEN)
													{
														hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
														hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

														if(hccp_elem_type == RISP_PKT_WTP_RF_RSSI_OF_OTHERS_RADIOCNT_END)
														{
															Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
															break;
														}
														
														switch(hccp_elem_type)
														{
															case RISP_PKT_WTP_RF_RSSI_OF_OTHERS_AP_RADIO_RADIOID:
															{
																parse_packet->u.risp.WTP_RF[i].rssi_of_others[j].ap_radio[k].radioid = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
																break;
															}
															case RISP_PKT_WTP_RF_RSSI_OF_OTHERS_AP_RADIO_CHANNEL:
															{
																parse_packet->u.risp.WTP_RF[i].rssi_of_others[j].ap_radio[k].channel = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
																break;
															}
															case RISP_PKT_WTP_RF_RSSI_OF_OTHERS_AP_RADIO_TXPOWER:
															{
																parse_packet->u.risp.WTP_RF[i].rssi_of_others[j].ap_radio[k].txpower = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
																break;
															}
															case RISP_PKT_WTP_RF_RSSI_OF_OTHERS_AP_RADIO_RSSI:
															{
																parse_packet->u.risp.WTP_RF[i].rssi_of_others[j].ap_radio[k].rssi = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
																break;
															}
															default:
																Unknown_Type_Handle(&buf, hccp_elem_len, &length);
																break;	
														}
													}
												}
												break;
											}											
											default:
												Unknown_Type_Handle(&buf, hccp_elem_len, &length);
												break;	
										}
									}
								}
								break;
							}
							default:
								Unknown_Type_Handle(&buf, hccp_elem_len, &length);
								break;	
						}
					}
				}
				break;
			}			
			
			default:
				Unknown_Type_Handle(&buf, hccp_elem_len, &length);
				break;	
		}
	}
	
	return HAN_TRUE;
}

HANBool Parse_DCM_Tlv(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned char i = 0;
	char *p = NULL;
	unsigned short	hccp_elem_type = 0;
	unsigned short	hccp_elem_len = 0;
	unsigned int length = 0;
	
	if (buf == NULL || parse_packet == NULL)
	{
	    return HAN_FALSE;
	}
	
	buf += HCCP_HEADER_LEN;

	while(1)
	{
		hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
		hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

		if(hccp_elem_type == HCCP_ELEM_END)
		{
			break;
		}
		
		switch(hccp_elem_type)
		{
			case DCM_PKT_RADIONUM:
			{
				parse_packet->u.dcm.radionum = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);

				for(i = 0; i < parse_packet->u.dcm.radionum && i < L_RADIO_NUM; i++)
				{
					while(1)
					{
						hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
						hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

						if(hccp_elem_type == DCM_PKT_RADIONUM_END)
						{
							Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
							break;
						}
						
						switch(hccp_elem_type)
						{
							case DCM_PKT_RADIO_UTIL:
							{
								parse_packet->u.dcm.radio[i].util = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
								break;
							}
							case DCM_PKT_RADIO_STANUM:
							{
								parse_packet->u.dcm.radio[i].stanum = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
								break;
							}
							case DCM_PKT_RADIO_BANDTYPE:
							{
								parse_packet->u.dcm.radio[i].bandtype = Tlv_Parse_8_Bit(&buf, hccp_elem_len, &length);
								break;
							}							
							default:
								Unknown_Type_Handle(&buf, hccp_elem_len, &length);
								break;	
						}
					}
				}
				break;
			}			
			default:
				Unknown_Type_Handle(&buf, hccp_elem_len, &length);
				break;	
		}
	}
	
	return HAN_TRUE;
}

HANBool Parse_ACS_Tlv(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned short 	hccp_elem_type = 0;
	unsigned short 	hccp_elem_len = 0;
	unsigned int length = 0;
	
	if (buf == NULL || parse_packet == NULL)
	{
	    return HAN_FALSE;
	}
	
	buf += HCCP_HEADER_LEN;
	
	while(1)
	{
		hccp_elem_type = Get_Hccp_Elem_Type(&buf, &length);
		hccp_elem_len = Get_Hccp_Elem_Len(&buf, &length);

		if(hccp_elem_type == HCCP_ELEM_END)
		{
			break;
		}
		
		switch(hccp_elem_type)
		{
			case ACS_PKT_MSGTYPE:
			{
				parse_packet->u.acs.msgtype = Tlv_Parse_16_Bit(&buf, hccp_elem_len, &length);
				break;
			}				
			case ACS_PKT_SEQ_NUM:
			{
				parse_packet->u.acs.seq_num = Tlv_Parse_32_Bit(&buf, hccp_elem_len, &length);
				break;
			}
			case ACS_PKT_MAC:
			{
				Tlv_Parse_MAC(&buf, parse_packet->u.acs.mac,  hccp_elem_len, &length);
				break;
			}		
			
			default:
				break;	
		}
	}	
	
	return HAN_TRUE;
}

HANBool Parse_HCCPProtocol(char *buf,  Hccp_Protocol_Struct *parse_packet) 
{
	if (buf == NULL || parse_packet == NULL)
	{
	    return HAN_FALSE;
	}
	
	if(HAN_FALSE == Parse_HCCPHeader(buf, parse_packet))
	{
		return HAN_FALSE;
	}

	switch(parse_packet->type)
	{
		case DBCP:
		{
			Parse_DBCP(buf, parse_packet);
			
			break;
		}
		case RSCP:
		{
			Parse_RSCP(buf, parse_packet);
			break;
		}
		case RSRP:
		{
			Parse_RSRP(buf, parse_packet);
			break;
		}
		case RIRP:
		{
			Parse_RIRP(buf, parse_packet);
			break;
		}
		case RICP:
		{
			Parse_RICP(buf, parse_packet);
			break;
		}
		case DCM:
		{
			Parse_DCM(buf, parse_packet);
			break;
		}
		case RISP:
		{
			Parse_RISP(buf, parse_packet);
			break;
		}
		case ACS:
		{
			Parse_ACS(buf, parse_packet);
			break;
		}
		case DBCP_TLV:
		{
			parse_packet->type = DBCP;
			Parse_DBCP_Tlv(buf, parse_packet);
			
			break;
		}
		case RSCP_TLV:
		{
			parse_packet->type = RSCP;
			Parse_RSCP_Tlv(buf, parse_packet);
			break;
		}
		case RSRP_TLV:
		{
			parse_packet->type = RSRP;
			Parse_RSRP_Tlv(buf, parse_packet);
			break;
		}
		case RIRP_TLV:
		{
			parse_packet->type = RIRP;
			Parse_RIRP_Tlv(buf, parse_packet);
			break;
		}
		case RICP_TLV:
		{
			parse_packet->type = RICP;
			Parse_RICP_Tlv(buf, parse_packet);
			break;
		}			
		case RISP_TLV:
		{
			parse_packet->type = RISP;
			Parse_RISP_Tlv(buf, parse_packet);
			break;
		}
		default:
		{
			printf("hccp protocol do not have this type!\n");
			return HAN_FALSE;
			break;
		}
	}
		
	
	return HAN_TRUE;
}


