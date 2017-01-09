#ifndef HCCPP_PROTOCOL_H
#define HCCPP_PROTOCOL_H

#include "common.h"
#include "approtocol.h"
#include "libhccp.h"

extern int gSeqnum;
extern int gclusterID;
extern int HAP_priority;


typedef struct {
	unsigned char apver;
	unsigned char operation;
	unsigned short reserved;
	unsigned short messageType;
	unsigned short msgElemsLen;
} MessageHeader;

typedef struct {
	unsigned char protocolver;
	unsigned char protocolType;
	unsigned short protocolLen;
	unsigned short seqnum;
	unsigned int clusterID;
}HCCPHeader;


typedef struct {
	u_int8_t  type;
	u_int8_t  length;
}TLVHeader;

typedef enum{
    SCAN_AP_INFO = 1,
    PVC_STATE_INFO = 2,
    CLUSTER_MEMBER_INFO = 3,
    CLUSTER_ENV_INFO = 4,
}MsgType;

typedef enum{
	MSG_REQUEST = 1,
	MSG_RESPONSE = 2 
}MsgOP;
/*
typedef enum{
    DBCP = 1,
    RSCP = 2,
    RSRP = 3,
    RIRP = 4,
    RISP = 5,
    ACS = 6,
}HCCPType;

typedef enum{
    Sequence_req = 1,
    Sequence_resp = 2,
    Token_req = 3,
    Token_resp = 4,
}ACSType;
*/

#define MSG_OP_TYPE_STR(m)	\
		      ((MSG_REQUEST == m) ? "request" :\
			(MSG_RESPONSE == m) ? "response" : "unkown")

typedef enum {
	MSG_ELEMENT_TYPE_WTP_NUM = 0,
	MSG_ELEMENT_TYPE_WTP_INFO = 1,
	MSG_ELEMENT_TYPE_WTP_CLUSTERID = 2,
	MSG_ELEMENT_TYPE_WTP_IP = 3,
	MSG_ELEMENT_TYPE_WTP_MAC = 4,
	MSG_ELEMENT_TYPE_WTP_PRIORITY = 5,
	MSG_ELEMENT_TYPE_WTP_STATUS = 6,

	MSG_ELEMENT_TYPE_WTP_ROLE = 10,

    
	MSG_ELEMENT_TYPE_RADIO_CNT = 29,
	MSG_ELEMENT_TYPE_RADIO_INFO = 30,
	MSG_ELEMENT_TYPE_RADIO_ID = 31,
	MSG_ELEMENT_TYPE_RADIO_CHAN = 32,
	MSG_ELEMENT_TYPE_RADIO_TXP = 33,
	MSG_ELEMENT_TYPE_RADIO_RSSI = 34,


	MSG_ELEMENT_TYPE_SCAN_INFO = 60,
	MSG_ELEMENT_TYPE_VAP_NUM = 61,
	MSG_ELEMENT_TYPE_VAP_INFO = 62,
	MSG_ELEMENT_TYPE_VAP_MAC = 63,
	MSG_ELEMENT_TYPE_VAP_CHAN = 64,
	MSG_ELEMENT_TYPE_VAP_RSSI = 65,
    
}MSG_ELEM;

#define MSG_ELEM_TYPE_STR(m)	\
		      ((MSG_ELEMENT_TYPE_WTP_NUM == m) ? "wtp-num" :\
			(MSG_ELEMENT_TYPE_WTP_INFO == m) ? "wtp-info" :\
			(MSG_ELEMENT_TYPE_WTP_CLUSTERID == m) ? "clusterID" :\
			(MSG_ELEMENT_TYPE_WTP_IP == m) ? "wtp-ip" :\
			(MSG_ELEMENT_TYPE_WTP_MAC == m) ? "wtp-mac" :\
			(MSG_ELEMENT_TYPE_WTP_PRIORITY == m) ? "wtp-priority" :\
			(MSG_ELEMENT_TYPE_WTP_STATUS == m) ? "wtp-status" :\
			(MSG_ELEMENT_TYPE_RADIO_CNT == m) ? "radio-count" :\
			(MSG_ELEMENT_TYPE_RADIO_INFO == m) ? "radio-info" :\
			(MSG_ELEMENT_TYPE_RADIO_ID == m) ? "radioID" :\
			(MSG_ELEMENT_TYPE_RADIO_CHAN == m) ? "radio-channel" :\
			(MSG_ELEMENT_TYPE_RADIO_TXP == m) ? "radio-txp" :\
			(MSG_ELEMENT_TYPE_RADIO_RSSI == m) ? "radio-rssi" :\
			(MSG_ELEMENT_TYPE_SCAN_INFO == m) ? "scan-info" :\
			(MSG_ELEMENT_TYPE_VAP_NUM == m) ? "vap-num" :\
			(MSG_ELEMENT_TYPE_VAP_INFO == m) ? "vap-info" :\
			(MSG_ELEMENT_TYPE_VAP_MAC == m) ? "vap-mac" :\
			(MSG_ELEMENT_TYPE_VAP_CHAN == m) ? "vap-channel" :\
			(MSG_ELEMENT_TYPE_VAP_RSSI == m) ? "vap-rssi" :\
			"unkown")

typedef struct
{
 	u_int8_t vap_mac[MAC_LEN];
 	char channel;
	char rssi;
} Msg_Scan;


struct radio{
	unsigned char radio_mac[MAC_LEN];
	u_int8_t radioid;
	u_int8_t channel;            /*Channel*/
	u_int16_t txpower;           /*TX power*/
	u_int8_t cwmode;				//0:ht20 1:ht20/40 2:ht40 3:VHT20 4:VHT40 5:VHT80
	u_int8_t rssi;
	time_t rssi_stamp;
	u_int32_t Radio_Type;         /*a/b/g/n/ac*/
	u_int32_t Radio_Type_Bank;
	int 	radio_country_code;
};
typedef struct radio WTP_RADIO;


struct scan_info{
	u_int8_t ap_base_mac[MAC_LEN];
    u_int8_t radiocnt;
	WTP_RADIO ap_radio[L_RADIO_NUM];
};
typedef struct scan_info SCAN_INFO;


struct CLUSTER_AP
{
    u_int32_t wtpid;
    u_int8_t self_flag;
    u_int8_t role; 	/* 1:PVC   2:SVC   3:VC */
    u_int8_t HAN_priority;
    u_int8_t status;
    u_int8_t radiocnt;
    u_int8_t use;
    u_int8_t scan_tag;
    u_int8_t ap_base_mac[MAC_LEN];
    u_int32_t ipaddr;
    u_int32_t priority;
    CWNetworkLev4Address address;
    u_int32_t active_time;
    u_int32_t clusterID;
    WTP_RADIO WTP_Radio[L_RADIO_NUM];
	TimerID SyncTimer;
	TimerID ScanTimer; 
};

struct rf_rssi{
	u_int8_t	signum;
	u_int8_t	rssi;
	u_int16_t	rssi_total;
};
typedef struct rf_rssi RF_RSSI;

struct rf_siginfo{
    u_int8_t use;
    u_int8_t ap_mac[MAC_LEN];
	RF_RSSI	radio_rssi[L_RADIO_NUM];
};
typedef struct rf_siginfo CLUSTER_RSSI;

extern struct CLUSTER_AP ap_table[MAX_CLUSTER_AP+1];
extern struct CLUSTER_AP *own_ap;

struct CLUSTER_Mem
{
	u_int32_t wtpid;
	u_int32_t clusterID;
	u_int8_t role;	/* 1:PVC	2:SVC	3:VC */
	u_int8_t HAN_priority;
	u_int8_t status;
	u_int8_t radiocnt;
	u_int8_t scancnt;
	u_int8_t ap_base_mac[MAC_LEN];
	u_int32_t ipaddr;
	u_int32_t priority;
	CWNetworkLev4Address address;
	WTP_RADIO WTP_Radio[L_RADIO_NUM];
};

struct CLUSTER_INF
{
    u_int32_t mem_num;
    struct CLUSTER_Mem cluster_MB[MAX_CLUSTER_AP];
};

typedef struct
{
	int clusterID;
	unsigned char priority;
	unsigned char config_sequence;
	unsigned char product_type;
	unsigned char mac[MAC_LEN];
}WTPDescriptor;


typedef struct
{
    u_int8_t role; 	/* 1:PVC   2:SVC   3:VC */
    u_int8_t radiocnt;
    unsigned char neighbor_cnt;
	unsigned char ap_base_mac[MAC_LEN];
	unsigned int ipaddr;
	unsigned int priority;
	SCAN_INFO rssi_of_others[MAX_CLUSTER_AP];
} RF_environment;

typedef struct
{
    unsigned int Mem_num;
    unsigned int ACS_sequence;
    RF_environment WTP_RF[MAX_CLUSTER_AP];
}CLUSTER_RF_environment;

typedef struct
{
    WTPDescriptor wtpdesc;
    struct CLUSTER_INF cluster_mb;
}HCCPRSCP;


typedef enum cluster_state
{
	DISCOVERY,
	JOIN,
	CHECK,
	RUN,
	LOST
}CLUSTER_STATE;

#define STATE_STR(m)	\
        ((DISCOVERY == m) ? "discovery" :\
        (JOIN == m) ? "join" :\
        (CHECK == m) ? "check" :\
        (RUN == m) ? "run" :\
        (LOST == m) ? "lost" : "unkown")


typedef enum cluster_role
{
	PVC = 1,
	SVC,
	VC
}ROLE;

#define ROLE_STR(m)	\
        ((PVC == m) ? "PVC" :\
        (SVC == m) ? "SVC" :\
        (VC == m) ? "VC" : "unkown")
        

typedef struct priority{
	u_int8_t overload[2];
	u_int8_t priority;
	u_int8_t config_seq;
	u_int8_t product_type;
	u_int8_t mac_tail[3];
}PRI;

typedef union cluster_priority
{
	u_int64_t hap_priority;
	PRI priority;
}CLUSTER_PRI;

typedef struct ap_state
{
	u_int32_t cluster_id;
	u_int32_t ap_ipaddr;
	ROLE ap_role;
	CLUSTER_PRI ap_priority;
	u_int8_t ap_mac[MAC_LEN];
	u_int8_t ap_state;
	u_int8_t radiocnt;
	WTP_RADIO WTP_Radio[L_RADIO_NUM];
	char model[PATH_LEN];
	char SN[BOARD_ID_LEN];
}AP_STAT,*P_AP_STAT;	 

typedef struct pvc_state
{
	CLUSTER_PRI pvc_priority;
	u_int8_t pvc_mac[MAC_LEN];
	u_int8_t svc_mac[MAC_LEN];
	u_int32_t pvc_ipaddr;
	u_int8_t pvc_state;
	u_int8_t  timer;
}PVC_STAT,*P_PVC_STAT;


typedef struct cluster_member
{
	u_int8_t mac_addr[MAC_LEN];
	u_int8_t scan_tag;
	u_int8_t self_flag;
	u_int8_t role;  /* 1:PVC   2:SVC   3:VC */
	u_int8_t status;
	u_int8_t radiocnt;
	u_int32_t ipaddr;
	CLUSTER_PRI priority;
	CWNetworkLev4Address address;
	u_int32_t active_time;
	u_int32_t clusterID;
	WTP_RADIO WTP_Radio[L_RADIO_NUM];
	TimerID SyncTimer;
	TimerID ScanTimer; 	
	struct cluster_member *next;
}CLUSTER_MB,*P_CLUSTER_MB;

typedef struct cluster_member_list
{
	int member_count;
	CLUSTER_MB cluster_member[MAX_CLUSTER_AP];
}CLUSTER_MB_LIST,*P_CLUSTER_MB_LIST;

typedef struct
{
	int member_count;
	CLUSTER_MB *cluster_member_list_head;
}CLUSTER_MEMBER_LIST;
extern CLUSTER_MEMBER_LIST cluster_member_list;


typedef struct elect_member
{
	u_int8_t mac_addr[MAC_LEN];
	CLUSTER_PRI cluster_pri;
	u_int8_t timeout_flag;
	struct elect_member *next;
	
}ELECT_MB,*P_ELECT_MB;


typedef struct elect_member_list
{
	int elect_mb_count;
	P_ELECT_MB ptr_elect_mb;
}ELECT_MB_LIST, *P_ELECT_MB_LIST;



CWBool AssembleTLVHeader(ProtocolMessage *tlvPtr, TLVHeader *valPtr);
CWBool AssembleTLVMsgElem(ProtocolMessage *msgPtr, int type);
CWBool AssembleWTPIP(ProtocolMessage *msgPtr, unsigned int WTPIP);
CWBool AssembleWTPMAC(ProtocolMessage *msgPtr, unsigned char *mac);
CWBool AssembleCLUSTERID(ProtocolMessage *msgPtr, unsigned int ClusterID);
CWBool AssembleWTPSTATUS(ProtocolMessage *msgPtr, unsigned char STATUS);
CWBool AssembleRadioCnt(ProtocolMessage *msgPtr, unsigned char radiocnt);
CWBool AssembleRadioID(ProtocolMessage *msgPtr, unsigned char radioid);
CWBool AssembleRadioChan(ProtocolMessage *msgPtr, WTP_RADIO *radio);
CWBool AssembleRadioTXP(ProtocolMessage *msgPtr, WTP_RADIO *radio);
CWBool AssembleRadioRssi(ProtocolMessage *msgPtr, WTP_RADIO *radio);

CWBool AssembleMessageHeader(ProtocolMessage *msgHdrPtr, MessageHeader *valPtr);

CWBool AssembleMessage
(
	ProtocolMessage **completeMsgPtr, 
	int msgTypeValue,
	int msgoperation,
	ProtocolMessage *msgElems,
	const int msgElemNum, 
	ProtocolMessage *msgElemsBinding,
	const int msgElemBindingNum
);


CWBool AssembleMessageElem
(
	ProtocolMessage *completeMsgPtr, 
	int ElemTypeValue,
	ProtocolMessage *msgElems,
	const int msgElemNum, 
	ProtocolMessage *msgElemsBinding,
	const int msgElemBindingNum
);

CWBool AssemblePVCInfo(ProtocolMessage **messagesPtr, struct CLUSTER_INF *cluster_ap);
CWBool AssembleRADIOINFO(ProtocolMessage *msgPtr, struct CLUSTER_Mem *cluster_ap);
CWBool AssembleClusterMemberInfo(ProtocolMessage **messagesPtr, struct CLUSTER_INF *cluster_ap);
CWBool AssembleRFINFO(ProtocolMessage *msgPtr, WTP_RADIO *Radio);
CWBool AssembleClusterRFINFO(ProtocolMessage *msgPtr, struct CLUSTER_Mem *cluster_ap);
CWBool AssembleAPInfo(ProtocolMessage *msgPtr, struct CLUSTER_Mem *cluster_ap);
CWBool AssembleEnvInfo(ProtocolMessage **messagesPtr, struct CLUSTER_INF *cluster_ap);

CWBool AssembleHCCPHeader(ProtocolMessage *proPtr, HCCPHeader *valPtr);

CWBool AssembleHCCPProtocol
(
	ProtocolMessage **completeMsgPtr, 
	int seqNum, 
	int msgTypeValue, 
	ProtocolMessage *msgElems,
	const int msgElemNum, 
	ProtocolMessage *msgElemsBinding,
	const int msgElemBindingNum
);

CWBool AssembleWTPDescriptor(ProtocolMessage *msgPtr, WTPDescriptor *valPtr);

CWBool AssembleDBCP(ProtocolMessage **messagesPtr, WTPDescriptor *protocolVal);
CWBool AssembleMemberRoles(ProtocolMessage *msgPtr, struct CLUSTER_INF *cluster_mb);
CWBool AssembleRSCP(ProtocolMessage **messagesPtr, HCCPRSCP *RSCPVal);
CWBool AssembleRSRP(ProtocolMessage **messagesPtr, WTPDescriptor *protocolVal);
CWBool AssembleWTPRFINFO(ProtocolMessage *msgPtr, RF_environment *valPtr);
CWBool AssembleClusterRFInfo(ProtocolMessage *msgPtr, CLUSTER_RF_environment *valPtr);
CWBool AssembleRISP(ProtocolMessage **messagesPtr, CLUSTER_RF_environment *RFInfo);
CWBool AssembleScanResquest(ProtocolMessage **messagesPtr);

CWBool ParseTLVHeader(ProtocolMessage *tlvPtr, TLVHeader *valPtr);

CWBool ParseMessageHeader(ProtocolMessage *msgPtr, MessageHeader *valPtr);

CWBool ParseHCCPHeader(ProtocolMessage *protocolPtr, HCCPHeader *valPtr);

CWBool ProtocolParseFragment
(
	char *buf,
	int readBytes,
	HCCPHeader *values,
	ProtocolMessage *reassembledMsg
);

CWBool ParseWTPDescriptor
(
	char *buf,
	int len,
	WTPDescriptor *valuesPtr,
	ProtocolMessage *reassembledMsg
);

CWBool ParseDBCP(ProtocolMessage *msgPtr, WTPDescriptor *DBCPRequest);
CWBool ParseMemberRoles(char *buf, int len, struct CLUSTER_INF *cluster_mb);
CWBool ParseRSCP(ProtocolMessage *msgPtr, HCCPRSCP *RSCPRequest);
CWBool ParseRSRP(ProtocolMessage *msgPtr, WTPDescriptor *RSRPRequest);

CWBool ParseWTPRFINFO
(
	char *buf,
	int len,
	RF_environment *valuesPtr,
	ProtocolMessage *reassembledMsg
);

CWBool ParseRIRP(ProtocolMessage *msgPtr, RF_environment *RIRPRequest);

CWBool ParseClusterRFInfo
(
	char *buf,
	int len,
	CLUSTER_RF_environment *valuesPtr,
	ProtocolMessage *reassembledMsg
);

CWBool ParseRISP(ProtocolMessage *msgPtr, CLUSTER_RF_environment *RISPRequest);


#endif
