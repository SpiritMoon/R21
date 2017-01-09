/******************************************************************************
  File Name    : parse_message.h
  Author       : zhaoej
  Date         : 20160229
  Description  : parse_message.c
******************************************************************************/
#ifndef _ROGUEAP_MESSAGE_H_
#define _ROGUEAP_MESSAGE_H_

#include <string.h>

#define BUF_MAX_LEN 2048 //8192
#define MESSAGE_PROCOTOL_VERSION	0
#define MESSAGE_PROCOTOL_RESERVED	0


/*operation type*/
typedef enum{
	OP_REQUEST = 1,
	OP_RESPONSE = 2,
}Operate;


typedef enum {
	FALSE = 0,
	TRUE = 1
}Bool;

typedef struct protocolMsg{
	unsigned char *msg;
	u_int32_t 	offset;
	u_int8_t	msgLen;
} elementmsg;

/*message header*/
struct protocolHeader{
	u_int8_t	version;
	u_int8_t	op;
	u_int16_t	reserved;
	u_int16_t	msg_type;
	u_int16_t	msg_len;
};

struct protocolAttack{
	u_int16_t MsgType;
	u_int16_t MsgLen;
};

// Message Type Values
#define		ROGUE_MSG_TYPE_VALUE_SCANNING_AP_INFO		0x01
#define		ROGUE_MSG_TYPE_VALUE_PVC_STATE				0x02
#define		ROGUE_MSG_TYPE_VALUE_CLUSTER_MEMBER_STATE	0x03
#define		ROGUE_MSG_TYPE_VALUE_CLUSTER_RF_INFO		0x04
#define		ROGUE_MSG_TYPE_VALUE_SCANNING_STA_INFO		0x05
#define		ROGUE_MSG_TYPE_VALUE_ATTACK_MESSAGE			0x06

/* Message Elements Type Values [TLV] sub element type code*/
typedef enum{
	ROGUE_MSG_ELEMENT_TYPE_WTP_INFO	= 1,
	ROGUE_MSG_ELEMENT_TYPE_WTP_MAC  = 4,  //ap basic mac
	ROGUE_MSG_ELEMENT_TYPE_WTP_PRIORITY = 5,
	ROGUE_MSG_ELEMENT_TYPE_WTP_STATUS = 6,
	
	ROGUE_MSG_ELEMENT_TYPE_AP_MAC	= 63, //vap mac
	ROGUE_MSG_ELEMENT_TYPE_CHANNEL	= 64,
	ROGUE_MSG_ELEMENT_TYPE_RSSI		= 65,
	ROGUE_MSG_ELEMENT_TYPE_SSID		= 66,
	ROGUE_MSG_ELEMENT_TYPE_ENCRYPT	= 67,

	ROGUE_MSG_ELEMENT_TYPE_STA_MAC	= 90,
	ROGUE_MSG_ELEMENT_TYPE_STA_IP	= 91,
	ROGUE_MSG_ELEMENT_TYPE_STA_QOS   = 92,
	
	ROGUE_MSG_ELEMENT_TYPE_ARP		= 9,
	ROGUE_MSG_ELEMENT_TYPE_DEAUTH 	= 10,
	ROGUE_MSG_ELEMENT_TYPE_DISASSOC	= 11
	
}ElementType;

 
#define RG_COPY_MEMORY(dst, src, len)	memcpy(dst, src, len)

void ProtocolStore8(elementmsg *msgPtr, unsigned char val);
void ProtocolStore16(elementmsg *msgPtr, unsigned short val);
void ProtocolStore32(elementmsg *msgPtr, unsigned int val);

void ProtocolStoreStr(elementmsg *msgPtr, char *str);
void ProtocolStoreRawBytes(elementmsg *msgPtr, char *bytes, int len);


unsigned char ProtocolRetrieve8(elementmsg *msgPtr);
u_int16_t ProtocolRetrieve16(elementmsg *msgPtr);
u_int32_t ProtocolRetrieve32(elementmsg *msgPtr);
char *ProtocolRetrieveStr(elementmsg *msgPtr, int len);

Bool parse_format_element(elementmsg *msgPtr,u_int8_t *type, u_int8_t *len);
Bool parse_msg_header(elementmsg *msgPtr, struct protocolHeader *msgheader);


#endif
