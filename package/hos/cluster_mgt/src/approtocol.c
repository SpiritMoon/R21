#include "approtocol.h"


// stores 8 bits in the message, increments the current offset in bytes
void ProtocolStore8(ProtocolMessage *msgPtr, unsigned char val)
{
	COPY_MEMORY(&((msgPtr->msg)[(msgPtr->offset)]), &(val), 1);
	(msgPtr->offset) += 1;
}

// stores 16 bits in the message, increments the current offset in bytes
void ProtocolStore16(ProtocolMessage *msgPtr, unsigned short val)
{
	val = htons(val);
	COPY_MEMORY(&((msgPtr->msg)[(msgPtr->offset)]), &(val), 2);
	(msgPtr->offset) += 2;
}

// stores 32 bits in the message, increments the current offset in bytes
void ProtocolStore32(ProtocolMessage *msgPtr, unsigned int val)
{
	val = htonl(val);
	COPY_MEMORY(&((msgPtr->msg)[(msgPtr->offset)]), &(val), 4);
	(msgPtr->offset) += 4;
}

// stores a string in the message, increments the current offset in bytes. Doesn't store
// the '\0' final character.
void ProtocolStoreStr(ProtocolMessage *msgPtr, char *str)
{
	int len = strlen(str);
	COPY_MEMORY(&((msgPtr->msg)[(msgPtr->offset)]), str, len);
	(msgPtr->offset) += len;
}

// stores another message in the message, increments the current offset in bytes.
void ProtocolStoreMessage(ProtocolMessage *msgPtr, ProtocolMessage *msgToStorePtr)
{
	COPY_MEMORY(&((msgPtr->msg)[(msgPtr->offset)]), msgToStorePtr->msg, msgToStorePtr->offset);
	(msgPtr->offset) += msgToStorePtr->offset;
}

// stores len bytes in the message, increments the current offset in bytes.
void ProtocolStoreRawBytes(ProtocolMessage *msgPtr, char *bytes, int len)
{
	COPY_MEMORY(&((msgPtr->msg)[(msgPtr->offset)]), bytes, len);
	(msgPtr->offset) += len;
}

// retrieves 8 bits from the message, increments the current offset in bytes.
unsigned char ProtocolRetrieve8(ProtocolMessage *msgPtr)
{
	unsigned char val = 0;
	
	COPY_MEMORY(&val, &((msgPtr->msg)[(msgPtr->offset)]), 1);
	(msgPtr->offset) += 1;
	
	return val;
}

// retrieves 16 bits from the message, increments the current offset in bytes.
unsigned short ProtocolRetrieve16(ProtocolMessage *msgPtr)
{
	unsigned short val = 0;
	
	COPY_MEMORY(&val, &((msgPtr->msg)[(msgPtr->offset)]), 2);
	(msgPtr->offset) += 2;
	
	return ntohs(val);
}

// retrieves 32 bits from the message, increments the current offset in bytes.
unsigned int ProtocolRetrieve32(ProtocolMessage *msgPtr)
{
	unsigned int val = 0;
	
	COPY_MEMORY(&val, &((msgPtr->msg)[(msgPtr->offset)]), 4);
	(msgPtr->offset) += 4;
	
	return ntohl(val);
}
/*
void ProtocolRetrieve64(ProtocolMessage *msgPtr,unsigned long long *val)
{
	COPY_MEMORY(val, &((msgPtr->msg)[(msgPtr->offset)]), 8);
	(msgPtr->offset) += 8;
	
	if (__BYTE_ORDER == __LITTLE_ENDIAN)
    {    
        *val = (((unsigned long long )htonl((int)((*val << 32) >> 32))) << 32) | (unsigned int)htonl((int)(*val >> 32));
    }
	return ;
}*/

// retrieves a string (not null-terminated) from the message, increments the current offset in bytes.
// Adds the '\0' char at the end of the string which is returned
char *ProtocolRetrieveStr(ProtocolMessage *msgPtr, int len)
{
	char *str = NULL;
	
	CREATE_OBJECT_SIZE_ERR(str, (len+1), return NULL;);
	
	COPY_MEMORY(str, &((msgPtr->msg)[(msgPtr->offset)]), len);
	str[len] = '\0';
	(msgPtr->offset) += len;
	
	return str;
}

// retrieves len bytes from the message, increments the current offset in bytes.
char *ProtocolRetrieveRawBytes(ProtocolMessage *msgPtr, int len)
{
	char *bytes = NULL;
	
	CREATE_OBJECT_SIZE_ERR(bytes, len+1, return NULL;);
	memset(bytes, 0, len+1);	
	COPY_MEMORY(bytes, &((msgPtr->msg)[(msgPtr->offset)]), len);
	bytes[len] = '\0';
	(msgPtr->offset) += len;
	
	return bytes;
}

// retrieves len bytes from the message, increments the current offset in bytes.
char *ProtocolGetRawBytes(ProtocolMessage *msgPtr, char *val, int len) 
{
	COPY_MEMORY(val, &((msgPtr->msg)[(msgPtr->offset)]), len);
	(msgPtr->offset) += len;
	
	return val;
}

// peep 8 bits from the message, increments the current offset in bytes.
unsigned char ProtocolPeep8(ProtocolMessage *msgPtr)
{
	unsigned char val = 0;
	
	COPY_MEMORY(&val, &((msgPtr->msg)[(msgPtr->offset)]), 1);
	
	return val;
}

unsigned short ProtocolPeep16(ProtocolMessage *msgPtr)
{
	unsigned short val = 0;
	
	COPY_MEMORY(&val, &((msgPtr->msg)[(msgPtr->offset)]), 2);
	
	return ntohs(val);
}


