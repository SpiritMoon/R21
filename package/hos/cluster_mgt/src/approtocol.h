#ifndef AP_PROTOCOL_H
#define AP_PROTOCOL_H

#include "common.h"

typedef struct {
    char *msg;
    int offset;
    int msgLen;
} ProtocolMessage;


void ProtocolStore8(ProtocolMessage *msgPtr, unsigned char val);
void ProtocolStore16(ProtocolMessage *msgPtr, unsigned short val);
void ProtocolStore32(ProtocolMessage *msgPtr, unsigned int val);
void ProtocolStoreStr(ProtocolMessage *msgPtr, char *str);
void ProtocolStoreMessage(ProtocolMessage *msgPtr, ProtocolMessage *msgToStorePtr);
void ProtocolStoreRawBytes(ProtocolMessage *msgPtr, char *bytes, int len);

unsigned char ProtocolRetrieve8(ProtocolMessage *msgPtr);
unsigned short ProtocolRetrieve16(ProtocolMessage *msgPtr);
unsigned int ProtocolRetrieve32(ProtocolMessage *msgPtr);
//void ProtocolRetrieve64(ProtocolMessage *msgPtr,unsigned long long *val)
char *ProtocolRetrieveStr(ProtocolMessage *msgPtr, int len);
char *ProtocolRetrieveRawBytes(ProtocolMessage *msgPtr, int len);
char *ProtocolGetRawBytes(ProtocolMessage *msgPtr, char *val, int len);

unsigned char ProtocolPeep8(ProtocolMessage *msgPtr);
unsigned short ProtocolPeep16(ProtocolMessage *msgPtr);

#endif
