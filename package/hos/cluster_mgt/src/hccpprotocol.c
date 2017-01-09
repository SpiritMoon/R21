#include "hccpprotocol.h"
#include "Log.h"

time_t timep;

CWBool ParseTLVHeader(ProtocolMessage *tlvPtr, TLVHeader *valPtr)
{
	if (tlvPtr == NULL || valPtr == NULL)
	{
	    return CW_FALSE;
	}
	
	valPtr->type = ProtocolRetrieve8(tlvPtr);
	valPtr->length = ProtocolRetrieve8(tlvPtr);
	
	return CW_TRUE;
}

// Assembles the TLV Header
CWBool AssembleTLVHeader(ProtocolMessage *tlvPtr, TLVHeader *valPtr)
{
	if (tlvPtr == NULL || valPtr == NULL)
	{
	    return CW_FALSE;
	}
	CREATE_PROTOCOL_MESSAGE(*tlvPtr, 2, return CW_FALSE;);
	
	ProtocolStore8(tlvPtr, valPtr->type);
	ProtocolStore8(tlvPtr, valPtr->length);
	
	return CW_TRUE;
}

// Assemble a TLV Element creating the appropriate header and storing the message.
CWBool AssembleTLVMsgElem(ProtocolMessage *msgPtr, int type)
{
	ProtocolMessage completeMsg;
	
	if (msgPtr == NULL)
	{
	    return CW_FALSE;
	}
	
	CREATE_PROTOCOL_MESSAGE(completeMsg, 4+(msgPtr->offset), return CW_FALSE;);

	// store header
	ProtocolStore8(&completeMsg, type);
	ProtocolStore8(&completeMsg, msgPtr->offset); // size of the body
	
	// store body
	ProtocolStoreMessage(&completeMsg, msgPtr);

	FREE_PROTOCOL_MESSAGE(*msgPtr);

	msgPtr->msg = completeMsg.msg;
	msgPtr->offset = completeMsg.offset;

	return CW_TRUE;
}


CWBool AssembleWTPIP(ProtocolMessage *msgPtr, unsigned int WTPIP)
{
	int size = 4;
	
	if (msgPtr == NULL)
	{
		return CW_FALSE;
	}
	
	CREATE_PROTOCOL_MESSAGE(*msgPtr, size, return CW_FALSE;);

	ProtocolStore32(msgPtr, WTPIP);
	
	//printf("%s-%d assemble wtpIP %X\n", __func__, __LINE__, WTPIP);
	
	return AssembleTLVMsgElem(msgPtr, MSG_ELEMENT_TYPE_WTP_IP);
}

CWBool AssembleWTPMAC(ProtocolMessage *msgPtr, unsigned char *mac)
{	
	if (msgPtr == NULL || mac == NULL)
	{
		return CW_FALSE;
	}
	
	int length = strlen((char *)mac);
	
	CREATE_PROTOCOL_MESSAGE(*msgPtr, length, return CW_FALSE;);

    ProtocolStoreRawBytes(msgPtr, (char *)mac, MAC_LEN);
	
	//printf("%s-%d assemble wtp mac "MACSTR"\n", __func__, __LINE__, MAC2STR(mac));
	
	return AssembleTLVMsgElem(msgPtr, MSG_ELEMENT_TYPE_WTP_MAC);
}
/*
CWBool CWAssembleCLUSTERID(ProtocolMessage *msgPtr, unsigned char *ClusterID)
{	
	if (msgPtr == NULL || ClusterID == NULL)
	{
		return CW_FALSE;
	}
	
	int length = strlen(ClusterID);
	
	CREATE_PROTOCOL_MESSAGE(*msgPtr, length, return CW_FALSE;);

	CWProtocolStoreStr(msgPtr, ClusterID);
	
	printf("%s-%d assemble wtp clusterID %s\n", __func__, __LINE__, ClusterID);
	
	return AssembleTLVMsgElem(msgPtr, MSG_ELEMENT_TYPE_WTP_CLUSTERID);
}*/

CWBool AssembleCLUSTERID(ProtocolMessage *msgPtr, unsigned int ClusterID)
{
    int size = 4;
    
	if (msgPtr == NULL)
	{
		return CW_FALSE;
	}
		
	CREATE_PROTOCOL_MESSAGE(*msgPtr, size, return CW_FALSE;);

	ProtocolStore32(msgPtr, ClusterID);
	
	//printf("%s-%d assemble wtp clusterID %d\n", __func__, __LINE__, ClusterID);
	
	return AssembleTLVMsgElem(msgPtr, MSG_ELEMENT_TYPE_WTP_CLUSTERID);
}


CWBool AssembleWTPSTATUS(ProtocolMessage *msgPtr, unsigned char STATUS)
{
	int size = 1;
	
	if (msgPtr == NULL)
	{
		return CW_FALSE;
	}
	
	CREATE_PROTOCOL_MESSAGE(*msgPtr, size, return CW_FALSE;);

	ProtocolStore8(msgPtr, STATUS);
	
	//printf("%s-%d assemble status %d(%s)\n", __func__, __LINE__, STATUS, (1 == STATUS)? "discovery":(2 == STATUS)? "run":"offline");
	
	return AssembleTLVMsgElem(msgPtr, MSG_ELEMENT_TYPE_WTP_STATUS);
}

CWBool AssembleRadioCnt(ProtocolMessage *msgPtr, unsigned char radiocnt)
{
	int size = 1;
	
	if (msgPtr == NULL)
	{
		return CW_FALSE;
	}
	
	CREATE_PROTOCOL_MESSAGE(*msgPtr, size, return CW_FALSE;);

	ProtocolStore8(msgPtr, radiocnt);
	
	//printf("%s-%d assemble %d radio(s)\n", __func__, __LINE__, radiocnt);
	
	return AssembleTLVMsgElem(msgPtr, MSG_ELEMENT_TYPE_RADIO_CNT);
}

CWBool AssembleRadioID(ProtocolMessage *msgPtr, unsigned char radioid)
{
	int size = 1;
	
	if (msgPtr == NULL)
	{
		return CW_FALSE;
	}
	
	CREATE_PROTOCOL_MESSAGE(*msgPtr, size, return CW_FALSE;);

	ProtocolStore8(msgPtr, radioid);
	
	//printf("%s-%d assemble radio%d\n",__func__, __LINE__, radioid);
	
	return AssembleTLVMsgElem(msgPtr, MSG_ELEMENT_TYPE_RADIO_ID);
}

CWBool AssembleRadioChan(ProtocolMessage *msgPtr, WTP_RADIO *radio)
{
	int size = 1;
	
	if (msgPtr == NULL || radio == NULL)
	{
		return CW_FALSE;
	}
	
	CREATE_PROTOCOL_MESSAGE(*msgPtr, size, return CW_FALSE;);

	ProtocolStore8(msgPtr, radio->channel);
	
	//printf("%s-%d assemble radio%d channel %d\n",__func__, __LINE__, radio->radioid, radio->channel);
	
	return AssembleTLVMsgElem(msgPtr, MSG_ELEMENT_TYPE_RADIO_CHAN);
}

CWBool AssembleRadioTXP(ProtocolMessage *msgPtr, WTP_RADIO *radio)
{
	int size = 1;
	
	if (msgPtr == NULL || radio == NULL)
	{
		return CW_FALSE;
	}
	
	CREATE_PROTOCOL_MESSAGE(*msgPtr, size, return CW_FALSE;);

	ProtocolStore8(msgPtr, radio->txpower);
	
	//printf("%s-%d assemble radio%d txpower %d\n",__func__, __LINE__, radio->radioid, radio->txpower);
	
	return AssembleTLVMsgElem(msgPtr, MSG_ELEMENT_TYPE_RADIO_TXP);
}

CWBool AssembleRadioRssi(ProtocolMessage *msgPtr, WTP_RADIO *radio)
{
	int size = 1;
	
	if (msgPtr == NULL || radio == NULL)
	{
		return CW_FALSE;
	}
	
	CREATE_PROTOCOL_MESSAGE(*msgPtr, size, return CW_FALSE;);

	ProtocolStore8(msgPtr, radio->rssi);
	
	//printf("%s-%d assemble radio%d rssi %d\n",__func__, __LINE__, radio->radioid, radio->rssi);
	
	return AssembleTLVMsgElem(msgPtr, MSG_ELEMENT_TYPE_RADIO_RSSI);
}


CWBool ParseMessageHeader(ProtocolMessage *msgPtr, MessageHeader *valPtr)
{
	if (msgPtr == NULL|| valPtr == NULL)
	{
		return CW_FALSE;
	}
	valPtr->apver = ProtocolRetrieve8(msgPtr);
	valPtr->operation = ProtocolRetrieve8(msgPtr);
	valPtr->reserved = ProtocolRetrieve16(msgPtr);
	valPtr->messageType = ProtocolRetrieve16(msgPtr);
	valPtr->msgElemsLen = ProtocolRetrieve16(msgPtr);
	
	return CW_TRUE;
}

// Assembles the Message Header
CWBool AssembleMessageHeader(ProtocolMessage *msgHdrPtr, MessageHeader *valPtr)
{
	if (msgHdrPtr == NULL || valPtr == NULL)
	{
	    return CW_FALSE;
	}
	CREATE_PROTOCOL_MESSAGE(*msgHdrPtr, 8, return CW_FALSE;);
	
	ProtocolStore8(msgHdrPtr, valPtr->apver);
	ProtocolStore8(msgHdrPtr, valPtr->operation);
	ProtocolStore16(msgHdrPtr, 0);
	ProtocolStore16(msgHdrPtr, valPtr->messageType);
	ProtocolStore16(msgHdrPtr, valPtr->msgElemsLen);
	
	return CW_TRUE;
}

CWBool AssembleMessage
(
	ProtocolMessage **completeMsgPtr, 
	int msgTypeValue,
	int msgoperation,
	ProtocolMessage *msgElems,
	const int msgElemNum, 
	ProtocolMessage *msgElemsBinding,
	const int msgElemBindingNum
)
{
	int i = 0;
	int msgElemsLen = 0;
	ProtocolMessage messageHdr, msg;
	MessageHeader messageVal;
	
	if (completeMsgPtr == NULL || (msgElems == NULL && msgElemNum > 0) || (msgElemsBinding == NULL && msgElemBindingNum > 0))
	{
	    return CW_FALSE;
	}
	
	//Calculate the whole size of the Msg Elements	
	for (i = 0; i < msgElemNum; i++)
	{
		msgElemsLen += msgElems[i].offset;
	}
	for (i = 0; i < msgElemBindingNum; i++)
	{
		msgElemsLen += msgElemsBinding[i].offset;
	}
	//Assemble Message Header
	messageVal.messageType = msgTypeValue;
	messageVal.operation = msgoperation;
	messageVal.msgElemsLen = msgElemsLen;
	
	if (!(AssembleMessageHeader(&messageHdr, &messageVal)))
	{
		FREE_PROTOCOL_MESSAGE(messageHdr);
		for (i = 0; i < msgElemNum; i++)
		{
			FREE_PROTOCOL_MESSAGE(msgElems[i]);
		}
		FREE_OBJECT(msgElems);
		for (i = 0; i < msgElemBindingNum; i++)
		{
    		FREE_PROTOCOL_MESSAGE(msgElemsBinding[i]);
		}
		FREE_OBJECT(msgElemsBinding);
		return CW_FALSE; // will be handled by the caller
	}
	
	// assemble the message putting all the data consecutively
	CREATE_PROTOCOL_MESSAGE(msg, messageHdr.offset + msgElemsLen, return CW_FALSE;);
	
	ProtocolStoreMessage(&msg, &messageHdr);
	for (i = 0; i < msgElemNum; i++)    // store in the request all the Message Elements
	{
		ProtocolStoreMessage(&msg, &(msgElems[i]));
	}
	for (i = 0; i < msgElemBindingNum; i++)    // store in the request all the Message Elements
	{
		ProtocolStoreMessage(&msg, &(msgElemsBinding[i]));
	}

	//Free memory not needed anymore
	FREE_PROTOCOL_MESSAGE(messageHdr);
	for (i = 0; i < msgElemNum; i++)
	{
		FREE_PROTOCOL_MESSAGE(msgElems[i]);
	}
	FREE_OBJECT(msgElems);
	
	for (i = 0; i < msgElemBindingNum; i++)
	{
		FREE_PROTOCOL_MESSAGE(msgElemsBinding[i]);
	}
	FREE_OBJECT(msgElemsBinding);
		
	CREATE_OBJECT_ERR(*completeMsgPtr, ProtocolMessage,  \
						{FREE_PROTOCOL_MESSAGE(msg);return CW_FALSE;});
	
	// assemble the message putting all the data consecutively
	CREATE_PROTOCOL_MESSAGE(((*completeMsgPtr)[0]), msg.offset, \
						{FREE_PROTOCOL_MESSAGE(msg);FREE_OBJECT(*completeMsgPtr);return CW_FALSE;});
	
	ProtocolStoreMessage(&((*completeMsgPtr)[0]), &msg);
	
	FREE_PROTOCOL_MESSAGE(msg);

	return CW_TRUE;
}


CWBool AssemblePVCInfo(ProtocolMessage **messagesPtr, struct CLUSTER_INF *cluster_ap) 
{
	int k = -1;
    //int m = -1;
	int i = 0;
	ProtocolMessage *msgElems = NULL;
	const int MsgElemCount = MAX_CLUSTER_AP*4;
	ProtocolMessage *msgElemsBinding = NULL;
	int msgElemBindingCount = 0;
	
	if (messagesPtr == NULL || cluster_ap == NULL)
	{
		return CW_FALSE;
	}
	
	CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, MsgElemCount, return CW_FALSE;);

	for (i = 0; i < cluster_ap->mem_num; i++)
	{
		if ((!(AssembleCLUSTERID(&(msgElems[++k]), cluster_ap->cluster_MB[i].clusterID)))
			|| (!(AssembleWTPIP(&(msgElems[++k]), cluster_ap->cluster_MB[i].ipaddr)))
			|| (!(AssembleWTPMAC(&(msgElems[++k]), cluster_ap->cluster_MB[i].ap_base_mac)))
			|| (!(AssembleWTPSTATUS(&(msgElems[++k]), cluster_ap->cluster_MB[i].status))))
		{
			int j = 0;
			for (j = 0; j <= k; j++)
			{
				FREE_PROTOCOL_MESSAGE(msgElems[j]);
			}
			FREE_OBJECT(msgElems);
			return CW_FALSE;
		}
	}
	
	/*if (k < MsgElemCount-1)
	{
        for ((m = k+1); m < MsgElemCount; m++)
        {
            CW_FREE_PROTOCOL_MESSAGE(msgElems[m]);
        }
	}*/
	
	if (!(AssembleMessage(messagesPtr, PVC_STATE_INFO, MSG_RESPONSE, msgElems, (k+1), msgElemsBinding, msgElemBindingCount))) 
	{
		return CW_FALSE;
	}
	
	printf("%s-%d assembled message successful\n", __func__, __LINE__);
	
	return CW_TRUE;
}



CWBool AssembleMessageElem
(
	ProtocolMessage *completeMsgPtr, 
	int ElemTypeValue,
	ProtocolMessage *msgElems,
	const int msgElemNum, 
	ProtocolMessage *msgElemsBinding,
	const int msgElemBindingNum
)
{
	int i = 0;
	int msgElemsLen = 0;
	ProtocolMessage tlvHdr, msg;
	TLVHeader tlval;
	
	if (completeMsgPtr == NULL || (msgElems == NULL && msgElemNum > 0) || (msgElemsBinding == NULL && msgElemBindingNum > 0))
	{
	    return CW_FALSE;
	}
	
	//Calculate the whole size of the Sub Elements	
	for (i = 0; i < msgElemNum; i++)
	{
		msgElemsLen += msgElems[i].offset;
	}
	for (i = 0; i < msgElemBindingNum; i++)
	{
		msgElemsLen += msgElemsBinding[i].offset;
	}
	//Assemble TLV Header
	tlval.type = ElemTypeValue;
	tlval.length = msgElemsLen;
	
	if (!(AssembleTLVHeader(&tlvHdr, &tlval)))
	{
		FREE_PROTOCOL_MESSAGE(tlvHdr);
		for (i = 0; i < msgElemNum; i++)
		{
			FREE_PROTOCOL_MESSAGE(msgElems[i]);
		}
		FREE_OBJECT(msgElems);
		for (i = 0; i < msgElemBindingNum; i++)
		{
    		FREE_PROTOCOL_MESSAGE(msgElemsBinding[i]);
		}
		FREE_OBJECT(msgElemsBinding);
		return CW_FALSE; // will be handled by the caller
	}
	
	// assemble the message putting all the data consecutively
	CREATE_PROTOCOL_MESSAGE(msg, tlvHdr.offset + msgElemsLen, return CW_FALSE;);
	
	ProtocolStoreMessage(&msg, &tlvHdr);
	for (i = 0; i < msgElemNum; i++)    // store in the request all the Message Elements
	{
		ProtocolStoreMessage(&msg, &(msgElems[i]));
	}
	for (i = 0; i < msgElemBindingNum; i++)    // store in the request all the Message Elements
	{
		ProtocolStoreMessage(&msg, &(msgElemsBinding[i]));
	}

	//Free memory not needed anymore
	FREE_PROTOCOL_MESSAGE(tlvHdr);
	for (i = 0; i < msgElemNum; i++)
	{
		FREE_PROTOCOL_MESSAGE(msgElems[i]);
	}
	FREE_OBJECT(msgElems);
	
	for (i = 0; i < msgElemBindingNum; i++)
	{
		FREE_PROTOCOL_MESSAGE(msgElemsBinding[i]);
	}
	FREE_OBJECT(msgElemsBinding);
		
	// assemble the message putting all the data consecutively
	CREATE_PROTOCOL_MESSAGE(((completeMsgPtr)[0]), msg.offset, \
						{FREE_PROTOCOL_MESSAGE(msg);return CW_FALSE;});
	
	ProtocolStoreMessage(completeMsgPtr, &msg);
	
	FREE_PROTOCOL_MESSAGE(msg);

	return CW_TRUE;
}

CWBool AssembleRADIOINFO(ProtocolMessage *msgPtr, struct CLUSTER_Mem *cluster_ap)
{
    int i = 0;
    int m = -1;
    
    ProtocolMessage *subElems = NULL;
    const int SubElemCount = (1+L_RADIO_NUM*3);
    
	if (msgPtr == NULL || cluster_ap == NULL)
	{
		return CW_FALSE;
	}
    
    CREATE_PROTOCOL_MSG_ARRAY_ERR(subElems, SubElemCount, return CW_FALSE;);

    if (cluster_ap)
    {
        if (!(AssembleRadioCnt(&(subElems[++m]), cluster_ap->radiocnt)))
        {
            int j = 0;
            for (j = 0; j <= m; j++)
            {
                FREE_PROTOCOL_MESSAGE(subElems[j]);
            }
            FREE_OBJECT(subElems);
            
            return CW_FALSE;
        }
        
        for (i = 0; i < cluster_ap->radiocnt && i < L_RADIO_NUM; i++)
        {
            if ((!(AssembleRadioID(&(subElems[++m]), cluster_ap->WTP_Radio[i].radioid)))
                || (!(AssembleRadioChan(&(subElems[++m]), &(cluster_ap->WTP_Radio[i]))))
                || (!(AssembleRadioTXP(&(subElems[++m]), &(cluster_ap->WTP_Radio[i])))))
            {
                int j = 0;
                for (j = 0; j <= m; j++)
                {
                    FREE_PROTOCOL_MESSAGE(subElems[j]);
                }
                FREE_OBJECT(subElems);
                
                return CW_FALSE;
            }
        }
    }
    
    return AssembleMessageElem(msgPtr, MSG_ELEMENT_TYPE_RADIO_INFO, subElems, (m+1), NULL, 0);
}

CWBool AssembleClusterMemberInfo(ProtocolMessage **messagesPtr, struct CLUSTER_INF *cluster_ap)
{
    int k = -1;
    int i = 0;
    ProtocolMessage *msgElems = NULL;
    const int MsgElemCount = MAX_CLUSTER_AP*5;
    ProtocolMessage *msgElemsBinding = NULL;
    int msgElemBindingCount = 0;
    
    if (messagesPtr == NULL || cluster_ap == NULL)
    {
        return CW_FALSE;
    }
    
    CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, MsgElemCount, return CW_FALSE;);

    for (i = 0; i < cluster_ap->mem_num; i++)
    {
        if ((!(AssembleCLUSTERID(&(msgElems[++k]), cluster_ap->cluster_MB[i].clusterID)))
            || (!(AssembleWTPIP(&(msgElems[++k]), cluster_ap->cluster_MB[i].ipaddr)))
            || (!(AssembleWTPMAC(&(msgElems[++k]), cluster_ap->cluster_MB[i].ap_base_mac)))
            || (!(AssembleWTPSTATUS(&(msgElems[++k]), cluster_ap->cluster_MB[i].status)))
            || (!(AssembleRADIOINFO(&(msgElems[++k]), &(cluster_ap->cluster_MB[i])))))
        {
            int j = 0;
            for (j = 0; j <= k; j++)
            {
                FREE_PROTOCOL_MESSAGE(msgElems[j]);
            }
            FREE_OBJECT(msgElems);

            return CW_FALSE;
        }
    }
    
    if (!(AssembleMessage(messagesPtr, CLUSTER_MEMBER_INFO, MSG_RESPONSE, msgElems, (k+1), msgElemsBinding, msgElemBindingCount))) 
    {
        return CW_FALSE;
    }
    
    syslog_debug("%s-%d assembled message successful\n", __func__, __LINE__);
    
    return CW_TRUE;
}


    
CWBool AssembleRFINFO(ProtocolMessage *msgPtr, WTP_RADIO *Radio)
{
    int m = -1;
    
    ProtocolMessage *subElems = NULL;
    const int SubElemCount = 4;
    
	if (msgPtr == NULL || Radio == NULL)
	{
		return CW_FALSE;
	}
    
    CREATE_PROTOCOL_MSG_ARRAY_ERR(subElems, SubElemCount, return CW_FALSE;);

	if (Radio)
    {
        if ((!(AssembleRadioID(&(subElems[++m]), Radio->radioid)))
            || (!(AssembleRadioChan(&(subElems[++m]), Radio)))
            || (!(AssembleRadioTXP(&(subElems[++m]), Radio)))
            || (!(AssembleRadioRssi(&(subElems[++m]), Radio))))
        {
            int j = 0;
            for (j = 0; j <= m; j++)
            {
                FREE_PROTOCOL_MESSAGE(subElems[j]);
            }
            FREE_OBJECT(subElems);
            
            return CW_FALSE;
        }
    }
    
    return AssembleMessageElem(msgPtr, MSG_ELEMENT_TYPE_RADIO_INFO, subElems, (m+1), NULL, 0);
}




CWBool AssembleAPInfo(ProtocolMessage *msgPtr, struct CLUSTER_Mem *cluster_ap)
{
    int k = -1;
    int j = 0;
    ProtocolMessage *subElems = NULL;
    
	if (msgPtr == NULL || cluster_ap == NULL)
	{
		return CW_FALSE;
	}
	
    const int SubElemCount = 2 + cluster_ap->radiocnt;
    
    CREATE_PROTOCOL_MSG_ARRAY_ERR(subElems, SubElemCount, return CW_FALSE;);

    if (cluster_ap)
    {
        if ((!(AssembleWTPMAC(&(subElems[++k]), cluster_ap->ap_base_mac)))
            || (!(AssembleWTPIP(&(subElems[++k]), cluster_ap->ipaddr))))
        {
            int i = 0;
            for (i = 0; i <= k; i++)
            {
                FREE_PROTOCOL_MESSAGE(subElems[i]);
            }
            FREE_OBJECT(subElems);
        
            return CW_FALSE;
        }
        
        for (j  = 0; j < cluster_ap->radiocnt && j < L_RADIO_NUM; j++)
        {
            if (!(AssembleRFINFO(&(subElems[++k]), &cluster_ap->WTP_Radio[j])))
            {
                int i = 0;
                for (i = 0; i <= k; i++)
                {
                    FREE_PROTOCOL_MESSAGE(subElems[i]);
                }
                FREE_OBJECT(subElems);
            
                return CW_FALSE;
            }
        }
    }
    
    return AssembleMessageElem(msgPtr, MSG_ELEMENT_TYPE_WTP_INFO, subElems, (k+1), NULL, 0);
}

CWBool AssembleEnvInfo(ProtocolMessage **messagesPtr, struct CLUSTER_INF *cluster_inf)
{
	int k = -1;
	int m = 0;
	ProtocolMessage *msgElems = NULL;
	const int MsgElemCount = MAX_CLUSTER_AP;
	ProtocolMessage *msgElemsBinding = NULL;
	int msgElemBindingCount = 0;
	
	if (messagesPtr == NULL || cluster_inf == NULL)
	{
		return CW_FALSE;
	}
	
	CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, MsgElemCount, return CW_FALSE;);
	
	for (m = 0; m < cluster_inf->mem_num; m++)
	{
		if(cluster_inf->cluster_MB[m].status != RUN)
			continue;
		
		if (!(AssembleAPInfo(&(msgElems[++k]), &cluster_inf->cluster_MB[m])))
		{
			int j = 0;
			for (j = 0; j <= k; j++)
			{
				FREE_PROTOCOL_MESSAGE(msgElems[j]);
			}
			FREE_OBJECT(msgElems);
			
			return CW_FALSE;
		}
	}
	
	if (!(AssembleMessage(messagesPtr, CLUSTER_ENV_INFO, MSG_RESPONSE, msgElems, (k+1), msgElemsBinding, msgElemBindingCount))) 
	{
		return CW_FALSE;
	}
    
	//printf("%s-%d assembled message successful\n", __func__, __LINE__);
	
	return CW_TRUE;
}


CWBool AssembleScanResquest(ProtocolMessage **messagesPtr) 
{
	ProtocolMessage *msgElems = NULL;
	const int msgElemCount = 0;
	ProtocolMessage *msgElemsBinding = NULL;
	int msgElemBindingCount = 0;
	
	if (messagesPtr == NULL)
	{
		return CW_FALSE;
	}
	if (!(AssembleMessage(messagesPtr, SCAN_AP_INFO, MSG_REQUEST, msgElems, msgElemCount, msgElemsBinding, msgElemBindingCount))) 
	{
		return CW_FALSE;
	}
		
	return CW_TRUE;
}


// Parse the HCCP Header
CWBool ParseHCCPHeader(ProtocolMessage *protocolPtr, HCCPHeader *valPtr)
{
	if (protocolPtr == NULL || valPtr == NULL)
	{
	    return CW_FALSE;
	}
	
	valPtr->clusterID = ProtocolRetrieve32(protocolPtr);
	valPtr->seqnum = ProtocolRetrieve16(protocolPtr);
	valPtr->protocolver = ProtocolRetrieve8(protocolPtr);
	valPtr->protocolType = ProtocolRetrieve8(protocolPtr);
	valPtr->protocolLen = ProtocolRetrieve16(protocolPtr);

	return CW_TRUE;
}

// Assembles the HCCP Header
CWBool AssembleHCCPHeader(ProtocolMessage *proPtr, HCCPHeader *valPtr)
{
	if (proPtr == NULL || valPtr == NULL)
	{
	    return CW_FALSE;
	}
	CREATE_PROTOCOL_MESSAGE(*proPtr, 10, return CW_FALSE;);
	
	ProtocolStore32(proPtr, valPtr->clusterID);
	ProtocolStore16(proPtr, valPtr->seqnum);
	ProtocolStore8(proPtr, valPtr->protocolver);
	ProtocolStore8(proPtr, valPtr->protocolType);
	ProtocolStore16(proPtr, valPtr->protocolLen);
	
	return CW_TRUE;
}

// Assemble a HCCP Control Packet, with the given Message Elements, Sequence Number and Message Type. Create HCCP Headers.
CWBool AssembleHCCPProtocol
(
	ProtocolMessage **completeMsgPtr, 
	int seqNum, 
	int msgTypeValue, 
	ProtocolMessage *msgElems,
	const int msgElemNum, 
	ProtocolMessage *msgElemsBinding,
	const int msgElemBindingNum
)
{
	int i = 0;
	int msgElemsLen = 0;
	ProtocolMessage protocolHdr;
	HCCPHeader protocolVal;
	
	if (completeMsgPtr == NULL || (msgElems == NULL && msgElemNum > 0) || (msgElemsBinding == NULL && msgElemBindingNum > 0))
	{
	    return CW_FALSE;
	}
	
	//Calculate the whole size of the Msg Elements	
	for (i = 0; i < msgElemNum; i++)
	{
		msgElemsLen += msgElems[i].offset;
	}
	for (i = 0; i < msgElemBindingNum; i++)
	{
		msgElemsLen += msgElemsBinding[i].offset;
	}
	
	CREATE_OBJECT_ERR(*completeMsgPtr, ProtocolMessage, {return CW_FALSE;});

	protocolVal.protocolver = 1;
	protocolVal.clusterID = /*gclusterID*/100;
	protocolVal.seqnum = seqNum;
	protocolVal.protocolType = msgTypeValue;
	protocolVal.protocolLen = msgElemsLen;
	
	if (!(AssembleHCCPHeader(&protocolHdr, &protocolVal)))
	{
		FREE_PROTOCOL_MESSAGE(protocolHdr);
		FREE_OBJECT(*completeMsgPtr);
		return CW_FALSE; // will be handled by the caller
	} 

	// assemble the message putting all the data consecutively
	CREATE_PROTOCOL_MESSAGE(((*completeMsgPtr)[0]), protocolHdr.offset + msgElemsLen, \
						{FREE_PROTOCOL_MESSAGE(protocolHdr);FREE_OBJECT(*completeMsgPtr);return CW_FALSE;});
	
	ProtocolStoreMessage(&((*completeMsgPtr)[0]), &protocolHdr);

	for (i = 0; i < msgElemNum; i++)    // store in the request all the Message Elements
	{
		ProtocolStoreMessage(&((*completeMsgPtr)[0]), &(msgElems[i]));
	}
	for (i = 0; i < msgElemBindingNum; i++)    // store in the request all the Message Elements
	{
		ProtocolStoreMessage(&((*completeMsgPtr)[0]), &(msgElemsBinding[i]));
	}

	for (i = 0; i < msgElemNum; i++)
	{
		FREE_PROTOCOL_MESSAGE(msgElems[i]);
	}
	FREE_OBJECT(msgElems);
	
	for (i = 0; i < msgElemBindingNum; i++)
	{
		FREE_PROTOCOL_MESSAGE(msgElemsBinding[i]);
	}
	FREE_OBJECT(msgElemsBinding);
	
	FREE_PROTOCOL_MESSAGE(protocolHdr);
	
	return CW_TRUE;
}

CWBool AssembleWTPDescriptor(ProtocolMessage *msgPtr, WTPDescriptor *valPtr)
{
	if (msgPtr == NULL || valPtr == NULL)
	{
		return CW_FALSE;
	}

	int length = strlen((char *)valPtr->mac);

	CREATE_PROTOCOL_MESSAGE(*msgPtr, length+3, return CW_FALSE;);

	ProtocolStore8(msgPtr, valPtr->priority);
	ProtocolStore8(msgPtr, valPtr->config_sequence);
	ProtocolStore8(msgPtr, valPtr->product_type);
	ProtocolStoreStr(msgPtr, (char *)valPtr->mac);

	return CW_TRUE;
}


CWBool AssembleDBCP(ProtocolMessage **messagesPtr, WTPDescriptor *protocolVal) 
{
    int k = -1;
    int i = 0;
    ProtocolMessage *msgElems = NULL;
    const int MsgElemCount = 1;
    ProtocolMessage *msgElemsBinding = NULL;
    int msgElemBindingCount = 0;
    
    if (messagesPtr == NULL)
    {
        return CW_FALSE;
    }
    
    CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, MsgElemCount, return CW_FALSE;);
 
    if (!(AssembleWTPDescriptor(&(msgElems[++k]), protocolVal)))
    {
        for (i = 0; i <= k; i++)
        {
            FREE_PROTOCOL_MESSAGE(msgElems[i]);
        }
        FREE_OBJECT(msgElems);

        return CW_FALSE;
    }
   
    wid_hex_dump((unsigned char *)msgElems[k].msg, msgElems[k].offset);
    
    if (!(AssembleHCCPProtocol(messagesPtr, 1, DBCP, msgElems, (k+1), msgElemsBinding, msgElemBindingCount))) 
    {
        return CW_FALSE;
    }
    
    //printf("%s-%d assembled message successful\n", __func__, __LINE__);
    
    return CW_TRUE;
}


CWBool AssembleMemberRoles(ProtocolMessage *msgPtr, struct CLUSTER_INF *cluster_mb)
{
    int i = 0;
	
	if (msgPtr == NULL || cluster_mb == NULL)
	{
		return CW_FALSE;
	}
	
	CREATE_PROTOCOL_MESSAGE(*msgPtr, MAX_CLUSTER_AP*8+1, return CW_FALSE;);
	
	ProtocolStore8(msgPtr, (unsigned char)cluster_mb->mem_num);

	for (i = 0; i < cluster_mb->mem_num; i++)
	{
    	ProtocolStoreRawBytes(msgPtr, (char *)cluster_mb->cluster_MB[i].ap_base_mac, MAC_LEN);
		ProtocolStore8(msgPtr, cluster_mb->cluster_MB[i].role);
    	ProtocolStore8(msgPtr, cluster_mb->cluster_MB[i].status);
	}
	
	return CW_TRUE;
}

CWBool AssembleRSCP(ProtocolMessage **messagesPtr, HCCPRSCP *RSCPVal) 
{
    int k = -1;
    int i = 0;
    ProtocolMessage *msgElems = NULL;
    const int MsgElemCount = 2;
    ProtocolMessage *msgElemsBinding = NULL;
    int msgElemBindingCount = 0;
    
    if (messagesPtr == NULL)
    {
        return CW_FALSE;
    }
    
    CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, MsgElemCount, return CW_FALSE;);
    
    if ((!(AssembleWTPDescriptor(&(msgElems[++k]), &RSCPVal->wtpdesc)))
        || (!(AssembleMemberRoles(&(msgElems[++k]), &RSCPVal->cluster_mb))))
    {
        for (i = 0; i <= k; i++)
        {
            FREE_PROTOCOL_MESSAGE(msgElems[i]);
        }
        FREE_OBJECT(msgElems);

        return CW_FALSE;
    }
    wid_hex_dump((unsigned char *)msgElems[k].msg, msgElems[k].offset);
    
    if (!(AssembleHCCPProtocol(messagesPtr, 1, RSCP, msgElems, (k+1), msgElemsBinding, msgElemBindingCount))) 
    {
        return CW_FALSE;
    }
    
    //printf("%s-%d assembled RSCP message successful\n", __func__, __LINE__);
    
    return CW_TRUE;
}

CWBool AssembleRSRP(ProtocolMessage **messagesPtr, WTPDescriptor *protocolVal) 
{
    int k = -1;
    int i = 0;
    ProtocolMessage *msgElems = NULL;
    const int MsgElemCount = 1;
    ProtocolMessage *msgElemsBinding = NULL;
    int msgElemBindingCount = 0;
    
    if (messagesPtr == NULL)
    {
        return CW_FALSE;
    }
    
    CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, MsgElemCount, return CW_FALSE;);
    
    if (!(AssembleWTPDescriptor(&(msgElems[++k]), protocolVal)))
    {
        for (i = 0; i <= k; i++)
        {
            FREE_PROTOCOL_MESSAGE(msgElems[i]);
        }
        FREE_OBJECT(msgElems);

        return CW_FALSE;
    }
    //wid_hex_dump((unsigned char *)msgElems[k].msg, msgElems[k].offset);
    
    if (!(AssembleHCCPProtocol(messagesPtr, 1, RSRP, msgElems, (k+1), msgElemsBinding, msgElemBindingCount))) 
    {
        return CW_FALSE;
    }
    
    printf("%s-%d assembled message successful\n", __func__, __LINE__);
    
    return CW_TRUE;
}

CWBool AssembleWTPRFINFO(ProtocolMessage *msgPtr, RF_environment *valPtr)
{
    int i = 0;
    int j = 0;
    
	if (msgPtr == NULL || valPtr == NULL)
	{
		return CW_FALSE;
	}
		
	CREATE_PROTOCOL_MESSAGE(*msgPtr, (7+(MAX_CLUSTER_AP*(7+(L_RADIO_NUM*3)))), return CW_FALSE;);

	ProtocolStoreRawBytes(msgPtr, (char *)valPtr->ap_base_mac, MAC_LEN);

	ProtocolStore8(msgPtr, valPtr->neighbor_cnt);

	//printf("%s-%d ap["MACSTR"] neighbor_cnt= %d\n", __func__, __LINE__, MAC2STR(valPtr->ap_base_mac), valPtr->neighbor_cnt);

	for (i = 0; i < MAX_CLUSTER_AP && i < valPtr->neighbor_cnt; i++)
	{
		ProtocolStoreRawBytes(msgPtr, (char *)valPtr->rssi_of_others[i].ap_base_mac, MAC_LEN);
        ProtocolStore8(msgPtr, valPtr->rssi_of_others[i].radiocnt);
       		
	    /*printf("%s-%d neighbor%d["MACSTR"] radio_cnt= %d\n", __func__, __LINE__, i+1,
	           MAC2STR(valPtr->rssi_of_others[i].ap_base_mac), valPtr->rssi_of_others[i].radiocnt);*/

		for (j = 0; j < L_RADIO_NUM && j < valPtr->rssi_of_others[i].radiocnt; j++)
    	{
    		ProtocolStore8(msgPtr, valPtr->rssi_of_others[i].ap_radio[j].radioid);
    		ProtocolStore8(msgPtr, valPtr->rssi_of_others[i].ap_radio[j].channel);
    		ProtocolStore8(msgPtr, valPtr->rssi_of_others[i].ap_radio[j].rssi);
    	}
	}
	//printf("%s-%d offset= %d\n", __func__, __LINE__, msgPtr->offset);

	return CW_TRUE;
}

CWBool AssembleRIRP(ProtocolMessage **messagesPtr, RF_environment *RFInfo) 
{
    int k = -1;
    int i = 0;
    ProtocolMessage *msgElems = NULL;
    const int MsgElemCount = 1;
    ProtocolMessage *msgElemsBinding = NULL;
    int msgElemBindingCount = 0;
    
    if (messagesPtr == NULL)
    {
        return CW_FALSE;
    }
    
    CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, MsgElemCount, return CW_FALSE;);

    if (!(AssembleWTPRFINFO(&(msgElems[++k]), RFInfo)))
    {
        for (i = 0; i <= k; i++)
        {
            FREE_PROTOCOL_MESSAGE(msgElems[i]);
        }
        FREE_OBJECT(msgElems);

        return CW_FALSE;
    }

    //printf("%s-%d msgElems[%d].offset = %d\n", __func__, __LINE__, k, msgElems[k].offset);

    //wid_hex_dump((unsigned char *)msgElems[k].msg, msgElems[k].offset);
    
    if (!(AssembleHCCPProtocol(messagesPtr, 1, RIRP, msgElems, (k+1), msgElemsBinding, msgElemBindingCount))) 
    {
        return CW_FALSE;
    }
    
    //printf("%s-%d assembled message successful\n", __func__, __LINE__);
    
    return CW_TRUE;
}


CWBool AssembleClusterRFInfo(ProtocolMessage *msgPtr, CLUSTER_RF_environment *valPtr)
{
    int i = 0;
    int j = 0;
    int m = 0;
    
	if (msgPtr == NULL || valPtr == NULL)
	{
		return CW_FALSE;
	}
		
	CREATE_PROTOCOL_MESSAGE(*msgPtr, (1+MAX_CLUSTER_AP*(16+(MAX_CLUSTER_AP-1)*(7+(L_RADIO_NUM*3)))), return CW_FALSE;);
	
    ProtocolStore8(msgPtr, valPtr->ACS_sequence);
    
    for (m = 0; m < MAX_CLUSTER_AP && m < valPtr->Mem_num; m++)
    {
        ProtocolStoreRawBytes(msgPtr, (char *)valPtr->WTP_RF[m].ap_base_mac, MAC_LEN);
    	ProtocolStore32(msgPtr, valPtr->WTP_RF[m].ipaddr);
    	ProtocolStore32(msgPtr, valPtr->WTP_RF[m].priority);
    	ProtocolStore8(msgPtr, valPtr->WTP_RF[m].role);
        ProtocolStore8(msgPtr, valPtr->WTP_RF[m].neighbor_cnt);
        
        for (i = 0; i < MAX_CLUSTER_AP && i < valPtr->WTP_RF[m].neighbor_cnt; i++)
    	{
            ProtocolStoreRawBytes(msgPtr, (char *)valPtr->WTP_RF[m].rssi_of_others[i].ap_base_mac, MAC_LEN);
    	    ProtocolStore8(msgPtr, valPtr->WTP_RF[m].rssi_of_others[i].radiocnt);
            for (j = 0; j < L_RADIO_NUM && j < valPtr->WTP_RF[m].rssi_of_others[i].radiocnt; j++)
            {
                ProtocolStore8(msgPtr, valPtr->WTP_RF[m].rssi_of_others[i].ap_radio[j].radioid);
                ProtocolStore8(msgPtr, valPtr->WTP_RF[m].rssi_of_others[i].ap_radio[j].channel);
                ProtocolStore8(msgPtr, valPtr->WTP_RF[m].rssi_of_others[i].ap_radio[j].rssi);
            }
    	}
    }
    
	return CW_TRUE;
}

CWBool AssembleRISP(ProtocolMessage **messagesPtr, CLUSTER_RF_environment *RFInfo) 
{
    int k = -1;
    int i = 0;
    ProtocolMessage *msgElems = NULL;
    const int MsgElemCount = 1;
    ProtocolMessage *msgElemsBinding = NULL;
    int msgElemBindingCount = 0;
    
    if (messagesPtr == NULL)
    {
        return CW_FALSE;
    }
    
    CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, MsgElemCount, return CW_FALSE;);
    
    if (!(AssembleClusterRFInfo(&(msgElems[++k]), RFInfo)))
    {
        for (i = 0; i <= k; i++)
        {
            FREE_PROTOCOL_MESSAGE(msgElems[i]);
        }
        FREE_OBJECT(msgElems);

        return CW_FALSE;
    }
    //wid_hex_dump(msgElems[k].msg, msgElems[k].offset);
    
    if (!(AssembleHCCPProtocol(messagesPtr, 1, RISP, msgElems, (k+1), msgElemsBinding, msgElemBindingCount))) 
    {
        return CW_FALSE;
    }
    
    printf("%s-%d assembled RISP message successful\n", __func__, __LINE__);
    
    return CW_TRUE;
}


CWBool AssembleSequenseRequest(ProtocolMessage *msgPtr)
{
	if (msgPtr == NULL)
	{
		return CW_FALSE;
	}
		
	CREATE_PROTOCOL_MESSAGE(*msgPtr, 1, return CW_FALSE;);

	ProtocolStore8(msgPtr, Sequence_req);

	return CW_TRUE;
}


CWBool AssembleACSSequenceRequest(ProtocolMessage **messagesPtr) 
{
    int k = -1;
    int i = 0;
    ProtocolMessage *msgElems = NULL;
    const int MsgElemCount = 1;
    ProtocolMessage *msgElemsBinding = NULL;
    int msgElemBindingCount = 0;
    
    if (messagesPtr == NULL)
    {
        return CW_FALSE;
    }
    
	CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, MsgElemCount, return CW_FALSE;);
	
	if (!(AssembleSequenseRequest(&(msgElems[++k]))))
	{
		for (i = 0; i <= k; i++)
		{
			FREE_PROTOCOL_MESSAGE(msgElems[i]);
		}
		FREE_OBJECT(msgElems);
		
		return CW_FALSE;
    }
    
	if (!(AssembleHCCPProtocol(messagesPtr, 1, ACS, msgElems, (k+1), msgElemsBinding, msgElemBindingCount))) 
	{
		return CW_FALSE;
	}
	
	//printf("%s-%d assembled message successful\n", __func__, __LINE__);
	
	return CW_TRUE;
}


CWBool AssembleSequenseResponse(ProtocolMessage *msgPtr, int Seqnum)
{
	if (msgPtr == NULL)
	{
		return CW_FALSE;
	}
		
	CREATE_PROTOCOL_MESSAGE(*msgPtr, 5, return CW_FALSE;);

	ProtocolStore8(msgPtr, Sequence_resp);
	ProtocolStore32(msgPtr, Seqnum);

	return CW_TRUE;
}


CWBool AssembleACSSequenceResponse(ProtocolMessage **messagesPtr, int Seqnum) 
{
	int k = -1;
	int i = 0;
	ProtocolMessage *msgElems = NULL;
	const int MsgElemCount = 1;
	ProtocolMessage *msgElemsBinding = NULL;
	int msgElemBindingCount = 0;
	
	if (messagesPtr == NULL)
	{
		return CW_FALSE;
	}
	
	CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, MsgElemCount, return CW_FALSE;);
	
	if (!(AssembleSequenseResponse(&(msgElems[++k]), Seqnum)))
	{
		for (i = 0; i <= k; i++)
		{
			FREE_PROTOCOL_MESSAGE(msgElems[i]);
		}
		FREE_OBJECT(msgElems);
		
		return CW_FALSE;
	}
	
	if (!(AssembleHCCPProtocol(messagesPtr, 1, ACS, msgElems, (k+1), msgElemsBinding, msgElemBindingCount))) 
	{
		return CW_FALSE;
	}
	
	//printf("%s-%d assembled message successful\n", __func__, __LINE__);
	
	return CW_TRUE;
}


CWBool AssembleTokenRequest(ProtocolMessage *msgPtr, unsigned char *mac, unsigned int Seqnum)
{
	if (msgPtr == NULL)
	{
		return CW_FALSE;
	}
		
	CREATE_PROTOCOL_MESSAGE(*msgPtr, 11, return CW_FALSE;);

	ProtocolStore8(msgPtr, Token_req);
	ProtocolStore32(msgPtr, Seqnum);
	ProtocolStoreRawBytes(msgPtr, (char *)mac, MAC_LEN);

	return CW_TRUE;
}


CWBool AssembleACSTokenRequest(ProtocolMessage **messagesPtr, unsigned char *apmac, unsigned int Seqnum) 
{
    int k = -1;
    int i = 0;
    ProtocolMessage *msgElems = NULL;
    const int MsgElemCount = 1;
    ProtocolMessage *msgElemsBinding = NULL;
    int msgElemBindingCount = 0;
    
    if (messagesPtr == NULL)
    {
        return CW_FALSE;
    }
    
    CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, MsgElemCount, return CW_FALSE;);
    
    if (!(AssembleTokenRequest(&(msgElems[++k]), apmac, Seqnum)))
    {
        for (i = 0; i <= k; i++)
        {
            FREE_PROTOCOL_MESSAGE(msgElems[i]);
        }
        FREE_OBJECT(msgElems);

        return CW_FALSE;
    }
    
    if (!(AssembleHCCPProtocol(messagesPtr, 1, ACS, msgElems, (k+1), msgElemsBinding, msgElemBindingCount))) 
    {
        return CW_FALSE;
    }
    
    //printf("%s-%d assembled message successful\n", __func__, __LINE__);
    
    return CW_TRUE;
}


CWBool AssembleTokenResponse(ProtocolMessage *msgPtr, unsigned char *mac, unsigned int Seqnum)
{
	if (msgPtr == NULL)
	{
		return CW_FALSE;
	}
		
	CREATE_PROTOCOL_MESSAGE(*msgPtr, 11, return CW_FALSE;);

	ProtocolStore8(msgPtr, Token_resp);
	ProtocolStore32(msgPtr, Seqnum);
	ProtocolStoreRawBytes(msgPtr, (char *)mac, MAC_LEN);

	return CW_TRUE;
}


CWBool AssembleACSTokenResponse(ProtocolMessage **messagesPtr, unsigned char *apmac, unsigned int Seqnum) 
{
    int k = -1;
    int i = 0;
    ProtocolMessage *msgElems = NULL;
    const int MsgElemCount = 1;
    ProtocolMessage *msgElemsBinding = NULL;
    int msgElemBindingCount = 0;
    
    if (messagesPtr == NULL)
    {
        return CW_FALSE;
    }
    
    CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, MsgElemCount, return CW_FALSE;);
    
    if (!(AssembleTokenResponse(&(msgElems[++k]), apmac, Seqnum)))
    {
        for (i = 0; i <= k; i++)
        {
            FREE_PROTOCOL_MESSAGE(msgElems[i]);
        }
        FREE_OBJECT(msgElems);

        return CW_FALSE;
    }
    
    if (!(AssembleHCCPProtocol(messagesPtr, 1, ACS, msgElems, (k+1), msgElemsBinding, msgElemBindingCount))) 
    {
        return CW_FALSE;
    }
    
	//printf("%s-%d assembled message successful\n", __func__, __LINE__);
    
    return CW_TRUE;
}

CWBool ProtocolParseFragment
(
	char *buf,
	int readBytes,
	HCCPHeader *values,
	ProtocolMessage *reassembledMsg
)
{
	ProtocolMessage msg;
	
	msg.msg = buf;
	msg.offset = 0;
	
	if(!ParseHCCPHeader(&msg, values))
	{
		return CW_FALSE;
	}

	CREATE_PROTOCOL_MESSAGE(*reassembledMsg, (readBytes-msg.offset), return CW_FALSE;);

	ProtocolStoreRawBytes(reassembledMsg, &(buf[msg.offset]), (readBytes-msg.offset));
	
	return CW_TRUE;
}

CWBool ParseWTPDescriptor
(
	char *buf,
	int len,
	WTPDescriptor *valuesPtr,
	ProtocolMessage *reassembledMsg
)
{
	char *mac = NULL;
	ProtocolMessage completeMsg;
	
	if (buf == NULL || valuesPtr == NULL || reassembledMsg == NULL)
	{
	    return CW_FALSE;
	}
	
	memset(&completeMsg, 0, sizeof(ProtocolMessage));
	completeMsg.msg = buf;
	completeMsg.offset = 0;
	valuesPtr->priority = ProtocolRetrieve8(&completeMsg);
	valuesPtr->config_sequence = ProtocolRetrieve8(&completeMsg);
	valuesPtr->product_type = ProtocolRetrieve8(&completeMsg);
	mac = ProtocolRetrieveRawBytes(&completeMsg, MAC_LEN);
	memcpy(valuesPtr->mac, mac, MAC_LEN);
	FREE_OBJECT(mac);
	
	printf("%s-%d priority= %d config_sequence= %d product_type= %d mac=["MACSTR"]\n",
	        __func__, __LINE__,valuesPtr->priority,valuesPtr->config_sequence,
	        valuesPtr->product_type, MAC2STR(valuesPtr->mac));
	
	if (completeMsg.offset != len)
	{
		CREATE_PROTOCOL_MESSAGE(*reassembledMsg, (len-completeMsg.offset), return CW_FALSE;);
		
		ProtocolStoreRawBytes(reassembledMsg, &(buf[completeMsg.offset]), (len-completeMsg.offset));
	}
		
	return CW_TRUE;
}

CWBool ParseDBCP(ProtocolMessage *msgPtr, WTPDescriptor *DBCPRequest)
{
	//int ret = 0;
	ProtocolMessage msgElem;
	
	if (msgPtr == NULL) 
	{
		return CW_FALSE;
	}
	
	memset(&msgElem, 0, sizeof(ProtocolMessage));
	msgElem.msg = NULL;
	msgElem.offset = 0;

	if (!(ParseWTPDescriptor(msgPtr->msg, msgPtr->offset, DBCPRequest, &msgElem)))
	{
		printf("%s-%d parse error\n", __func__, __LINE__);
		return CW_FALSE;
	}
	
	if (msgElem.msg)
	{
        	FREE_PROTOCOL_MESSAGE(msgElem);
	}

	return CW_TRUE;
}

CWBool ParseMemberRoles(char *buf, int len, struct CLUSTER_INF *cluster_mb)
{
	int k = 0;
	char *mac = NULL;
	ProtocolMessage completeMsg;    
	
	if (buf == NULL || cluster_mb == NULL)
	{
		return CW_FALSE;
	}
	
	memset(&completeMsg, 0, sizeof(ProtocolMessage));
	completeMsg.msg = buf;
	completeMsg.offset = 0;
    
	cluster_mb->mem_num = ProtocolRetrieve8(&completeMsg);
	printf("%s-%d num= %d msglen= %d\n", __func__, __LINE__, cluster_mb->mem_num, len);
	while (len - completeMsg.offset >= 8)
	{
		mac = ProtocolRetrieveStr(&completeMsg, MAC_LEN);
		if (mac)
		{
			memcpy(cluster_mb->cluster_MB[k].ap_base_mac, mac, MAC_LEN);
			cluster_mb->cluster_MB[k].role = ProtocolRetrieve8(&completeMsg);
			cluster_mb->cluster_MB[k].status = ProtocolRetrieve8(&completeMsg);
			
            FREE_OBJECT(mac);
			
	    	k++;
        }
        else
        {
            completeMsg.offset += 8;
        }
    }

    if (completeMsg.offset != len || cluster_mb->mem_num != k)
    {
		printf("%s-%d offset= %d msglen= %d apnum= %d count= %d\n",
				__func__, __LINE__, completeMsg.offset, len, cluster_mb->mem_num, k);
        return CW_FALSE;
    }

    return CW_TRUE;
}


CWBool ParseRSCP(ProtocolMessage *msgPtr, HCCPRSCP *RSCPRequest)
{
	ProtocolMessage msgElem;
	
	if (msgPtr == NULL || RSCPRequest == NULL) 
	{
		return CW_FALSE;
	}
	
	memset(&msgElem, 0, sizeof(ProtocolMessage));
	msgElem.msg = NULL;
	msgElem.offset = 0;
	
	if (!(ParseWTPDescriptor(msgPtr->msg, msgPtr->offset, &(RSCPRequest->wtpdesc), &msgElem)))
	{
		printf("%s-%d parse WTP Descriptor error\n", __func__, __LINE__);
		return CW_FALSE;
	}
	
	if (msgElem.msg && msgElem.offset)
	{
		if (!(ParseMemberRoles(msgElem.msg, msgElem.offset, &(RSCPRequest->cluster_mb))))
		{
			printf("%s-%d parse Member Roles error\n", __func__, __LINE__);
			
			FREE_PROTOCOL_MESSAGE(msgElem);
			return CW_FALSE;
		}
		FREE_PROTOCOL_MESSAGE(msgElem);
	}
	
	return CW_TRUE;
}

CWBool ParseRSRP(ProtocolMessage *msgPtr, WTPDescriptor *RSRPRequest)
{
    ProtocolMessage msgElem;
    
    if (msgPtr == NULL) 
    {
        return CW_FALSE;
    }
    
    memset(&msgElem, 0, sizeof(ProtocolMessage));
    msgElem.msg = NULL;
    msgElem.offset = 0;
    
    if (!(ParseWTPDescriptor(msgPtr->msg, msgPtr->offset, RSRPRequest, &msgElem)))
    {
        printf("%s-%d parse error\n", __func__, __LINE__);
        return CW_FALSE;
    }
    if (msgElem.msg)
    {
        FREE_PROTOCOL_MESSAGE(msgElem);
    }
    
    return CW_TRUE;
}

CWBool ParseWTPRFINFO
(
	char *buf,
	int len,
	RF_environment *valuesPtr,
	ProtocolMessage *reassembledMsg
)
{
    int i = 0, j = 0;
    unsigned char radio_num = 0;
	int offsetTillMessages = 0;
    unsigned char *mac = NULL;                
	ProtocolMessage completeMsg;
	
	if (buf == NULL || valuesPtr == NULL || reassembledMsg == NULL)
	{
	    return CW_FALSE;
	}
	
	memset(&completeMsg, 0, sizeof(ProtocolMessage));
	completeMsg.msg = buf;
	completeMsg.offset = 0;

//	mac = (unsigned char*)(CWProtocolRetrieveRawBytes(&completeMsg, MAC_LEN));
    mac = (unsigned char *)(ProtocolRetrieveStr(&completeMsg, MAC_LEN));
    printf("%s-%d offset= %d\n", __func__, __LINE__, completeMsg.offset);


	memcpy(valuesPtr->ap_base_mac, mac, MAC_LEN);
	FREE_OBJECT(mac);	

	valuesPtr->neighbor_cnt = ProtocolRetrieve8(&completeMsg);

	printf("%s-%d ap["MACSTR"] neighbor_cnt= %d\n", __func__, __LINE__, MAC2STR(valuesPtr->ap_base_mac),valuesPtr->neighbor_cnt);

    while (completeMsg.offset - offsetTillMessages < len)
    {
        mac = (unsigned char *)ProtocolRetrieveStr(&completeMsg, MAC_LEN);
        if (mac)
        {
            radio_num = ProtocolRetrieve8(&completeMsg);
            
            memcpy(valuesPtr->rssi_of_others[i].ap_base_mac, mac, MAC_LEN);
            FREE_OBJECT(mac);

            valuesPtr->rssi_of_others[i].radiocnt = radio_num;
            
            for (j = 0; j < radio_num; j++)
            {
                valuesPtr->rssi_of_others[i].ap_radio[j].radioid = ProtocolRetrieve8(&completeMsg);
                valuesPtr->rssi_of_others[i].ap_radio[j].channel = ProtocolRetrieve8(&completeMsg);
                valuesPtr->rssi_of_others[i].ap_radio[j].rssi = ProtocolRetrieve8(&completeMsg);
            }

            i++;
        }
        else
        {
            completeMsg.offset += 6;
            radio_num = ProtocolRetrieve8(&completeMsg);
            completeMsg.offset += radio_num*3;            
        }
    }
	
	printf("%s-%d mac["MACSTR"]neighbor_cnt= %d num= %d\n",
	        __func__, __LINE__,MAC2STR(valuesPtr->ap_base_mac),valuesPtr->neighbor_cnt, i);
	
	if (completeMsg.offset != len)
	{
        CREATE_PROTOCOL_MESSAGE(*reassembledMsg, (len-completeMsg.offset), return CW_FALSE;);
        
        ProtocolStoreRawBytes(reassembledMsg, &(buf[completeMsg.offset]), (len-completeMsg.offset));       
	}
		
	return CW_TRUE;
}

CWBool ParseRIRP(ProtocolMessage *msgPtr, RF_environment *RIRPRequest)
{
    ProtocolMessage msgElem;
    
    if (msgPtr == NULL || RIRPRequest == NULL) 
    {
        return CW_FALSE;
    }
    
    memset(&msgElem, 0, sizeof(ProtocolMessage));
    msgElem.msg = NULL;
    msgElem.offset = 0;
    
    if (!(ParseWTPRFINFO(msgPtr->msg, msgPtr->offset, RIRPRequest, &msgElem)))
    {
        printf("%s-%d parse error\n", __func__, __LINE__);
        return CW_FALSE;
    }
    if (msgElem.msg)
    {
        FREE_PROTOCOL_MESSAGE(msgElem);
    }
    
    return CW_TRUE; 
}

CWBool ParseClusterRFInfo
(
	char *buf,
	int len,
	CLUSTER_RF_environment *valuesPtr,
	ProtocolMessage *reassembledMsg
)
{
    int i = 0, j = 0;
    int m = 0;
    unsigned char radio_num = 0;
	int offsetTillMessages = 0;
    unsigned char *mac = NULL;                
	ProtocolMessage completeMsg;
	
	if (buf == NULL || valuesPtr == NULL || reassembledMsg == NULL)
	{
	    return CW_FALSE;
	}
	
	memset(&completeMsg, 0, sizeof(ProtocolMessage));
	completeMsg.msg = buf;
	completeMsg.offset = 0;

	valuesPtr->ACS_sequence = ProtocolRetrieve8(&completeMsg);
	printf("%s-%d ACS_sequence= %d\n", __func__, __LINE__,valuesPtr->ACS_sequence);
	
    while (completeMsg.offset - offsetTillMessages < len)
    {
        mac = (unsigned char *)ProtocolRetrieveStr(&completeMsg, MAC_LEN);      
        if (mac)
        {
            memcpy(valuesPtr->WTP_RF[m].ap_base_mac, mac, MAC_LEN);
            FREE_OBJECT(mac);

	        valuesPtr->WTP_RF[m].ipaddr = ProtocolRetrieve32(&completeMsg);
	        valuesPtr->WTP_RF[m].priority = ProtocolRetrieve32(&completeMsg);
            valuesPtr->WTP_RF[m].role = ProtocolRetrieve8(&completeMsg);
            valuesPtr->WTP_RF[m].neighbor_cnt = ProtocolRetrieve8(&completeMsg);

            printf("%s-%d member%d["MACSTR"] role= %d priority= %d neighbor_cnt= %d\n",
                    __func__, __LINE__, m+1, MAC2STR(valuesPtr->WTP_RF[m].ap_base_mac),
                    valuesPtr->WTP_RF[m].role, valuesPtr->WTP_RF[m].priority, valuesPtr->WTP_RF[m].neighbor_cnt);
     
            int n = 0;
            for (i = 0; i < MAX_CLUSTER_AP && i < valuesPtr->WTP_RF[m].neighbor_cnt; i++)
        	{
                mac = (unsigned char *)ProtocolRetrieveStr(&completeMsg, MAC_LEN);      
                if (mac)
                {
                    memcpy(valuesPtr->WTP_RF[m].rssi_of_others[n].ap_base_mac, mac, MAC_LEN);
                    FREE_OBJECT(mac);

                    radio_num = ProtocolRetrieve8(&completeMsg);
                    valuesPtr->WTP_RF[m].rssi_of_others[n].radiocnt = radio_num;
                    printf("%s-%d neighbor%d["MACSTR"] radio num= %d\n",
                            __func__, __LINE__, n+1, MAC2STR(valuesPtr->WTP_RF[m].rssi_of_others[n].ap_base_mac), radio_num);
                    
                    for (j = 0; j < L_RADIO_NUM && j < radio_num; j++)
                    {
                        valuesPtr->WTP_RF[m].rssi_of_others[n].ap_radio[j].radioid = ProtocolRetrieve8(&completeMsg);
                        valuesPtr->WTP_RF[m].rssi_of_others[n].ap_radio[j].channel = ProtocolRetrieve8(&completeMsg);
                        valuesPtr->WTP_RF[m].rssi_of_others[n].ap_radio[j].rssi = ProtocolRetrieve8(&completeMsg);
                        
                        printf("%s-%d radio %d channel= %d rssi= %d\n", __func__, __LINE__, 
                                valuesPtr->WTP_RF[m].rssi_of_others[n].ap_radio[j].radioid,
                                valuesPtr->WTP_RF[m].rssi_of_others[n].ap_radio[j].channel,
                                valuesPtr->WTP_RF[m].rssi_of_others[n].ap_radio[j].rssi);
                    }
                    n++;
                }
                else
                {
                    completeMsg.offset += 6;
                    radio_num = ProtocolRetrieve8(&completeMsg);
                    completeMsg.offset += radio_num*3;
                }
        	}
        	if (n != valuesPtr->WTP_RF[m].neighbor_cnt)
        	{
			    printf("%s-%d wtp%d neighbor_cnt= %d count= %d\n", __func__, __LINE__, m+1, valuesPtr->WTP_RF[m].neighbor_cnt, n);
        	}
            m++;
        }
        else
        {
            completeMsg.offset += 15;
            valuesPtr->WTP_RF[m].neighbor_cnt = ProtocolRetrieve8(&completeMsg);

            for (i = 0; i < MAX_CLUSTER_AP && i < valuesPtr->WTP_RF[m].neighbor_cnt; i++)
            {
                completeMsg.offset += 6;
                radio_num = ProtocolRetrieve8(&completeMsg);
                completeMsg.offset += radio_num*3;            
            }
        }
    }
	
	printf("%s-%d offset= %d msglen= %d cluster member num= %d\n", __func__, __LINE__, completeMsg.offset, len, m);
	
	if (completeMsg.offset != len)
	{
        CREATE_PROTOCOL_MESSAGE(*reassembledMsg, (len-completeMsg.offset), return CW_FALSE;);
        
        ProtocolStoreRawBytes(reassembledMsg, &(buf[completeMsg.offset]), (len-completeMsg.offset));       
	}
		
	return CW_TRUE;
}

CWBool ParseRISP(ProtocolMessage *msgPtr, CLUSTER_RF_environment *RISPRequest)
{
    ProtocolMessage msgElem;
    
    if (msgPtr == NULL) 
    {
        return CW_FALSE;
    }

    memset(&msgElem, 0, sizeof(ProtocolMessage));
    msgElem.msg = NULL;
    msgElem.offset = 0;
    
    if (!(ParseClusterRFInfo(msgPtr->msg, msgPtr->offset, RISPRequest, &msgElem)))
    {
        printf("%s-%d parse error\n", __func__, __LINE__);
        return CW_FALSE;
    }
    if (msgElem.msg)
    {
        FREE_PROTOCOL_MESSAGE(msgElem);
    }
    
    return CW_TRUE;
}

/*
CWBool ParseACS(ProtocolMessage *msgPtr, ProtocolMessage **messages)
{
	unsigned int msgtype = 0;
	unsigned int seq_num = 0;
	unsigned char *apmac = NULL;
	ProtocolMessage completeMsg;
	time_t timenow;
	//struct tm *p = NULL;
	
	if (msgPtr == NULL || msgPtr->msg == NULL) 
	{
		return CW_FALSE;
	}
	
	memset(&completeMsg, 0, sizeof(ProtocolMessage));
	completeMsg.msg = msgPtr->msg;
	completeMsg.offset = 0;
	
	msgtype = ProtocolRetrieve8(&completeMsg);
	switch (msgtype) 
	{
        case Sequence_req:
        {                   
            printf("%s-%d msgType:Sequence_req\n", __func__, __LINE__);

            break;
        }

        case Sequence_resp:
        {            
            printf("%s-%d msgType:Sequence_resp seq_num= %d\n", __func__, __LINE__, seq_num);
            break;
        }

        case Token_req:
        {
			time(&timenow);
            seq_num = ProtocolRetrieve32(&completeMsg);
	    
		    if ((0 == seq_num && (timenow - timep >= 2)) || gSeqnum == seq_num)
		    {
		    	apmac = (unsigned char *)ProtocolRetrieveRawBytes(&completeMsg, MAC_LEN);
            	printf("%s-%d msgType:Token_req mac["MACSTR"] seq_num %d\n",
                    	__func__, __LINE__, MAC2STR(apmac), seq_num);

           		AssembleACSTokenResponse(messages, apmac, ++gSeqnum);
            	printf("%s-%d send Token_resp mac["MACSTR"] seq_num %d\n",
                    	__func__, __LINE__, MAC2STR(apmac), seq_num);

	    	}
            break;
        }
        
        case Token_resp:
        {
            gSeqnum = ProtocolRetrieve32(&completeMsg);
            apmac = (unsigned char *)ProtocolRetrieveRawBytes(&completeMsg, MAC_LEN);
            printf("%s-%d msgType:Token_resp mac["MACSTR"] seq_num %d\n", __func__, __LINE__, MAC2STR(apmac), gSeqnum);
            
            break;
        }
        
        default:
        {
            printf("%s-%d msgType %d\n", __func__, __LINE__, msgtype);
            break;
        }
    }

    return CW_TRUE;  
}
*/


