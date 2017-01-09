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

HANBool Assemble_DBCP(char *buf, DBCP_format *dbcp) 
{
	if (buf == NULL || dbcp == NULL)
	{
	    return HAN_FALSE;
	}
	dbcp->head.protocolType = DBCP;
	Assemble_HCCPHeader(buf, &dbcp->head);

	memcpy(buf + HCCP_HEADER_LEN, &dbcp->priority, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char), &dbcp->config_sequence, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 2, &dbcp->product_type, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3, dbcp->mac, MAC_LEN);

	
    return HAN_TRUE;
	
}
HANBool Assemble_RSRP(char *buf, RSRP_format *rsrp) 
{
	if (buf == NULL || rsrp == NULL)
	{
	    return HAN_FALSE;
	}
	rsrp->head.protocolType = RSRP;
	Assemble_HCCPHeader(buf, &rsrp->head);

	memcpy(buf + HCCP_HEADER_LEN, &rsrp->priority, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char), &rsrp->config_sequence, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 2, &rsrp->product_type, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3, rsrp->mac, MAC_LEN);
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3 + MAC_LEN, &rsrp->state, sizeof(unsigned char));

	
    return HAN_TRUE;
	
}
HANBool Assemble_RSCP(char *buf, RSCP_format *rscp) 
{
	char *p = NULL;
	unsigned char i =0;
	
	if (buf == NULL || rscp == NULL)
	{
	    return HAN_FALSE;
	}
	rscp->head.protocolType = RSCP;
	Assemble_HCCPHeader(buf, &rscp->head);

	memcpy(buf + HCCP_HEADER_LEN, &rscp->priority, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char), &rscp->config_sequence, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 2, &rscp->product_type, sizeof(unsigned char));
	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3, rscp->mac, MAC_LEN);

	memcpy(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3 + MAC_LEN, &rscp->count, sizeof(unsigned char));
	p = buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 4 + MAC_LEN;
	for(i=0;i<rscp->count;i++)
	{
		memcpy(p, rscp->cluster_member[i].mac, MAC_LEN);
		p+=MAC_LEN;
		memcpy(p, &rscp->cluster_member[i].role, sizeof(unsigned char));
		p+=sizeof(unsigned char);
		memcpy(p, &rscp->cluster_member[i].state, sizeof(unsigned char));
		p+=sizeof(unsigned char);
	}
	
    return HAN_TRUE;
}

HANBool Assemble_RIRP(char *buf, RIRP_format *rirp) 
{
	unsigned char i = 0;
	char *p = NULL;
	
	if (buf == NULL || rirp == NULL)
	{
	    return HAN_FALSE;
	}
	rirp->head.protocolType = RIRP;
	Assemble_HCCPHeader(buf, &rirp->head);
	
	memcpy(buf + HCCP_HEADER_LEN, rirp->mac, MAC_LEN);
	memcpy(buf + HCCP_HEADER_LEN + MAC_LEN, &rirp->neighbor_count, sizeof(unsigned char));
	
	p = buf + HCCP_HEADER_LEN + MAC_LEN + sizeof(unsigned char);
	for(i=0;i < rirp->neighbor_count;i++)
	{
		memcpy(p, rirp->cluster_neighbor[i].mac, MAC_LEN);
		p+=MAC_LEN;
		memcpy(p, &rirp->cluster_neighbor[i]._2g_channel, sizeof(unsigned char));
		p+=sizeof(unsigned char);
		memcpy(p, &rirp->cluster_neighbor[i]._2g_rssi, sizeof(unsigned char));
		p+=sizeof(unsigned char);
		memcpy(p, &rirp->cluster_neighbor[i]._5g_channel, sizeof(unsigned char));
		p+=sizeof(unsigned char);
		memcpy(p, &rirp->cluster_neighbor[i]._5g_rssi, sizeof(unsigned char));
		p+=sizeof(unsigned char);
	}
	
    return HAN_TRUE;
}

HANBool Assemble_DCM(char *buf, DCM_format *dcm)
{
	unsigned char i = 0;
	char *p = NULL;
	
	if (buf == NULL || dcm == NULL)
	{
	    return HAN_FALSE;
	}
	dcm->head.protocolType = DCM;
	Assemble_HCCPHeader(buf, &dcm->head);
	p = buf + HCCP_HEADER_LEN;
	memcpy(p, &dcm->radionum, sizeof(unsigned char));
	p+=sizeof(unsigned char);
	
	memcpy(p, dcm->mac, MAC_LEN);
	p += MAC_LEN;
	for(i=0;i<dcm->radionum;i++)
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
	if (buf == NULL || parse_packet == NULL)
	{
	    return HAN_FALSE;
	}
	
	parse_packet->u.dbcp.priority= *((unsigned char*)(buf + HCCP_HEADER_LEN));
	parse_packet->u.dbcp.config_sequence = *((unsigned char*)(buf + HCCP_HEADER_LEN + sizeof(unsigned char)));
	parse_packet->u.dbcp.product_type = *((unsigned char*)(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 2));
	memcpy(parse_packet->u.dbcp.mac, buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3, MAC_LEN);
	
	return HAN_TRUE;
}

HANBool Parse_RSCP(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned char i = 0;
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
	for(i=0;i < parse_packet->u.rscp.count;i++)
	{
		memcpy(parse_packet->u.rscp.cluster_member[i].mac, p, MAC_LEN);
		p+=MAC_LEN;
		parse_packet->u.rscp.cluster_member[i].role = *((unsigned char*)p);
		p+=1;
		parse_packet->u.rscp.cluster_member[i].state = *((unsigned char*)p);
		p+=1;
	}
	return HAN_TRUE;

}

HANBool Parse_RSRP(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	if (buf == NULL || parse_packet == NULL)
	{
	    return HAN_FALSE;
	}

	parse_packet->u.rsrp.priority = *((unsigned char*)(buf + HCCP_HEADER_LEN));
	parse_packet->u.rsrp.config_sequence = *((unsigned char*)(buf + HCCP_HEADER_LEN + sizeof(unsigned char)));
	parse_packet->u.rsrp.product_type = *((unsigned char*)(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 2));
	memcpy(parse_packet->u.rsrp.mac, buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3, MAC_LEN);
	parse_packet->u.rsrp.state = *((unsigned char*)(buf + HCCP_HEADER_LEN + sizeof(unsigned char) * 3 + MAC_LEN));

	return HAN_TRUE;
}

HANBool Parse_RIRP(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned char i = 0;
	char *p = NULL;

	if (buf == NULL || parse_packet == NULL)
	{
	    return HAN_FALSE;
	}
	
	memcpy(parse_packet->u.rirp.mac, buf + HCCP_HEADER_LEN, MAC_LEN);
	parse_packet->u.rirp.neighbor_count = *((unsigned char *)(buf + HCCP_HEADER_LEN + MAC_LEN));
	
	p = buf + HCCP_HEADER_LEN + MAC_LEN + sizeof(unsigned char);
	for(i=0;i<parse_packet->u.rirp.neighbor_count;i++)
	{
		memcpy(parse_packet->u.rirp.cluster_neighbor[i].mac, p, MAC_LEN) ;
		p+=MAC_LEN;
		parse_packet->u.rirp.cluster_neighbor[i]._2g_channel = *((unsigned char*)p);
		p+=1;
		parse_packet->u.rirp.cluster_neighbor[i]._2g_rssi = *((unsigned char*)p);
		p+=1;
		parse_packet->u.rirp.cluster_neighbor[i]._5g_channel = *((unsigned char*)p);
		p+=1;
		parse_packet->u.rirp.cluster_neighbor[i]._5g_rssi = *((unsigned char*)p);
		p+=1;
	}
	
	
	return HAN_TRUE;
}

HANBool Parse_DCM(char *buf, Hccp_Protocol_Struct *parse_packet)
{
	unsigned char i = 0;
	char *p = NULL;
	DCM_format *info = &parse_packet->u.dcm;

	if (buf == NULL || parse_packet == NULL)
	{
	    return HAN_FALSE;
	}

	memcpy(&parse_packet->u.dcm.radionum, buf + HCCP_HEADER_LEN, sizeof(unsigned char));
	p = buf + HCCP_HEADER_LEN + sizeof(unsigned char);
	memcpy(parse_packet->u.dcm.mac,p, MAC_LEN);
	p += MAC_LEN;
	for(i=0;i<parse_packet->u.dcm.radionum;i++)
	{
		parse_packet->u.dcm.radio[i].util = *((unsigned char*)p);
		p+=sizeof(unsigned char);
		parse_packet->u.dcm.radio[i].stanum = *((unsigned char*)p);
		p+=sizeof(unsigned char);
		parse_packet->u.dcm.radio[i].bandtype = *((unsigned char*)p);
		p+=sizeof(unsigned char);
	}

	printf("recv dcminfo\n");
	
	unsigned char* mac = info->mac;

	printf("radio_num = %d\n",parse_packet->u.dcm.radionum);
	
	printf("eth_mac:%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    for(i = 0; i < info->radionum; i ++){
		printf(" info.radio[%d]utilization= %d\n",i,info->radio[i].util);
		printf(" info.radio[%d]stanum = %d\n",i,info->radio[i].stanum);
		printf(" info.radio[%d]bandtype= %d\n",i,info->radio[i].bandtype);
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
    printf("parse_packet->type = %d \n",parse_packet->type);
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
		case DCM:
		{
			Parse_DCM(buf, parse_packet);
			break;
		}
		case RISP:
		{
			break;
		}
		case ACS:
		{
			Parse_ACS(buf, parse_packet);
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


