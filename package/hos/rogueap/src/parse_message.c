/******************************************************************************
  File Name    : parse_message.c
  Author       : zhaoej
  Date         : 20160225
  Description  : local socket message parsing
******************************************************************************/
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "debug.h"
#include "parse_message.h"
#define	RG_CREATE_OBJECT_SIZE(obj_name, obj_size, err)	{obj_name = (malloc(obj_size)); if(obj_name == NULL) {err} else { memset(obj_name, 0, obj_size); }}

// stores 8 bits in the message, increments the current offset in bytes
void ProtocolStore8(elementmsg *msgPtr, unsigned char val) {
	RG_COPY_MEMORY(&((msgPtr->msg)[(msgPtr->offset)]), &(val), 1);
	(msgPtr->offset) += 1;
}

// stores 16 bits in the message, increments the current offset in bytes
void ProtocolStore16(elementmsg *msgPtr, unsigned short val) {
	//val = htons(val);
	RG_COPY_MEMORY(&((msgPtr->msg)[(msgPtr->offset)]), &(val), 2);
	(msgPtr->offset) += 2;
}

// stores 32 bits in the message, increments the current offset in bytes
void ProtocolStore32(elementmsg *msgPtr, unsigned int val) {
	//val = htonl(val);
	RG_COPY_MEMORY(&((msgPtr->msg)[(msgPtr->offset)]), &(val), 4);
	(msgPtr->offset) += 4;
}

// stores a string in the message, increments the current offset in bytes. Doesn't store
// the '\0' final character.
void ProtocolStoreStr(elementmsg *msgPtr, char *str) {
	int len = strlen(str);
	RG_COPY_MEMORY(&((msgPtr->msg)[(msgPtr->offset)]), str, len);
	(msgPtr->offset) += len;
}


// stores len bytes in the message, increments the current offset in bytes.
void ProtocolStoreRawBytes(elementmsg *msgPtr, char *bytes, int len) {
	RG_COPY_MEMORY(&((msgPtr->msg)[(msgPtr->offset)]), bytes, len);
	(msgPtr->offset) += len;
}

// retrieves 8 bits from the message, increments the current offset in bytes.
unsigned char ProtocolRetrieve8(elementmsg *msgPtr)
{
	unsigned char val;
	RG_COPY_MEMORY(&val, &((msgPtr->msg)[(msgPtr->offset)]), 1);
	(msgPtr->offset) += 1;
	return val;
}


u_int16_t ProtocolRetrieve16( elementmsg *msgPtr) 
{
	u_int16_t val;
	RG_COPY_MEMORY(&val, &((msgPtr->msg)[(msgPtr->offset)]), 2);
	(msgPtr->offset) += 2;
	return ntohs(val);
}

u_int32_t ProtocolRetrieve32(elementmsg *msgPtr) 
{
	u_int32_t val;
	RG_COPY_MEMORY(&val, &((msgPtr->msg)[(msgPtr->offset)]), 4);
	(msgPtr->offset) += 4;
	return ntohl(val);
}
char *ProtocolRetrieveStr(elementmsg *msgPtr, int len) {
	char *str;
	RG_CREATE_OBJECT_SIZE(str, (len+1), return NULL;);
	RG_COPY_MEMORY(str, &((msgPtr->msg)[(msgPtr->offset)]), len);
	str[len] = '\0';
	(msgPtr->offset) += len;
	
	return str;
}

char *ProtocolRetrieveRawBytes(elementmsg *msgPtr, int len) {
	char *str;
	
	RG_CREATE_OBJECT_SIZE(str, len, return NULL;);
	RG_COPY_MEMORY(str, &((msgPtr->msg)[(msgPtr->offset)]), len);
	(msgPtr->offset) += len;
	return str;
}


//void *memcpy(void *dest, const void *src, size_t n);
Bool parse_format_element(elementmsg *msgPtr,u_int8_t *type, u_int8_t *len)
{
	*type = ProtocolRetrieve8(msgPtr);
	*len = ProtocolRetrieve8(msgPtr);
	return TRUE;
}

Bool parse_msg_header(elementmsg *msgPtr, struct protocolHeader *msgheader)
{
	if(msgPtr == NULL|| msgheader == NULL){
		rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_WARNING,"parse msg header is NULL");
		return FALSE;
	}
	msgheader->version = ProtocolRetrieve8(msgPtr);
	msgheader->op = ProtocolRetrieve8(msgPtr);
	msgheader->reserved = ProtocolRetrieve16(msgPtr);
	msgheader->msg_type = ProtocolRetrieve16(msgPtr);
	msgheader->msg_len = ProtocolRetrieve16(msgPtr);
	printf("*------- OPERATE=%u\tMSG_TYPE=%u\tMSG_LEN=%u  -------*\n",msgheader->op,msgheader->msg_type,msgheader->msg_len);
	return TRUE;
}
