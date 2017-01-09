
#ifndef LIBHCCP_H 
#define LIBHCCP_H

typedef enum {
	HCCP_ELEM_END = 0,

	HCCP_HEAD_PROTOCOLVER = 5,
	HCCP_HEAD_PROTOCOLTYPE = 6,
	HCCP_HEAD_PROTOCOLLEN = 7,
	HCCP_HEAD_SEQNUM = 8,
	HCCP_HEAD_CLUSTERID = 9,
	
	DBCP_PKT_PRIORITY = 15,
	DBCP_PKT_CONFIG_SEQUENCE = 16,
	DBCP_PKT_PRODUCT_TYPE = 17,
	DBCP_PKT_MAC = 18,
	DBCP_PKT_STATE = 19,
	DBCP_PKT_RADIOCNT = 20,
	DBCP_PKT_RADIOCNT_END = 21,
	DBCP_PKT_WTP_RADIO_RADIOID = 22,
	DBCP_PKT_WTP_RADIO_CHANNEL = 23,
	DBCP_PKT_WTP_RADIO_TXPOWER = 24,
	DBCP_PKT_WTP_RADIO_RSSI = 25,

	RSCP_PKT_PRIORITY = 31,
	RSCP_PKT_CONFIG_SEQUENCE = 32,
	RSCP_PKT_PRODUCT_TYPE = 33,
	RSCP_PKT_MAC = 34,
	RSCP_PKT_COUNT = 35,
	RSCP_PKT_COUNT_END = 36,
    RSCP_PKT_CLUSTER_MEMBER_MAC = 37,
    RSCP_PKT_CLUSTER_MEMBER_ROLE = 38,
    RSCP_PKT_CLUSTER_MEMBER_STATE = 39,
    RSCP_PKT_CLUSTER_MEMBER_IP = 40,
    RSCP_PKT_CLUSTER_MEMBER_RADIOCNT = 41,
    RSCP_PKT_CLUSTER_MEMBER_RADIOCNT_END = 42,
    RSCP_PKT_CLUSTER_MEMBER_WTP_RADIO_RADIOID = 43,
    RSCP_PKT_CLUSTER_MEMBER_WTP_RADIO_CHANNEL = 44,
    RSCP_PKT_CLUSTER_MEMBER_WTP_RADIO_TXPOWER = 45,
    RSCP_PKT_CLUSTER_MEMBER_WTP_RADIO_RSSI = 46,

	RSRP_PKT_PRIORITY = 51,
	RSRP_PKT_CONFIG_SEQUENCE = 52,
	RSRP_PKT_PRODUCT_TYPE = 53,
	RSRP_PKT_MAC = 54,
	RSRP_PKT_STATE = 55,
	RSRP_PKT_IP = 56,
	RSRP_PKT_AP_VERSION = 57,
	RSRP_PKT_AP_NAME = 58,
	RSRP_PKT_RADIOCNT = 59,
	RSRP_PKT_RADIOCNT_END = 60,
	RSRP_PKT_WTP_RADIO_RADIOID = 61,
	RSRP_PKT_WTP_RADIO_CHANNEL = 62,
	RSRP_PKT_WTP_RADIO_TXPOWER = 63,
	RSRP_PKT_WTP_RADIO_RSSI = 64,

	RIRP_PKT_MAC = 70,
	RIRP_PKT_NEIGHBOR_COUNT = 71,
	RIRP_PKT_NEIGHBOR_COUNT_END = 72,
	RIRP_PKT_CLUSTER_NEIGHBOR_MAC = 73,
	RIRP_PKT_CLUSTER_NEIGHBOR_RADIOCNT = 74,
	RIRP_PKT_CLUSTER_NEIGHBOR_RADIOCNT_END = 75,
	RIRP_PKT_CLUSTER_NEIGHBOR_WTP_RADIO_RADIOID = 76,
	RIRP_PKT_CLUSTER_NEIGHBOR_WTP_RADIO_CHANNEL = 77,
	RIRP_PKT_CLUSTER_NEIGHBOR_WTP_RADIO_TXPOWER = 78,
	RIRP_PKT_CLUSTER_NEIGHBOR_WTP_RADIO_RSSI = 79,

	RICP_PKT_OP = 81,
	RICP_PKT_VIP = 82,
	RICP_PKT_COUNT = 83,
	RICP_PKT_COUNT_END = 84,
	RICP_PKT_MAC = 85,
	RICP_PKT_VIP_NETMASK = 86,
	
	RISP_PKT_ACS_SEQUENCE = 89,
	RISP_PKT_MEM_NUM = 90,
	RISP_PKT_MEM_NUM_END = 91,
	RISP_PKT_WTP_RF_ROLE = 92,
	RISP_PKT_WTP_RF_AP_BASE_MAC = 93,
	RISP_PKT_WTP_RF_IPADDR = 94,
	RISP_PKT_WTP_RF_PRIORITY = 95,
	RISP_PKT_WTP_RF_RADIOCNT = 96,
	RISP_PKT_WTP_RF_RADIOCNT_END = 97,
	RISP_PKT_WTP_RF_WTP_RADIO_RADIOID = 98,
	RISP_PKT_WTP_RF_WTP_RADIO_CHANNEL = 99,
	RISP_PKT_WTP_RF_WTP_RADIO_TXPOWER = 100,
	RISP_PKT_WTP_RF_WTP_RADIO_RSSI = 101,
	RISP_PKT_WTP_RF_NEIGHBOR_CNT = 102,
	RISP_PKT_WTP_RF_NEIGHBOR_CNT_END = 103,
	RISP_PKT_WTP_RF_RSSI_OF_OTHERS_AP_BASE_MAC = 104,
	RISP_PKT_WTP_RF_RSSI_OF_OTHERS_RADIOCNT = 105,
	RISP_PKT_WTP_RF_RSSI_OF_OTHERS_RADIOCNT_END = 106,
	RISP_PKT_WTP_RF_RSSI_OF_OTHERS_AP_RADIO_RADIOID = 107,
	RISP_PKT_WTP_RF_RSSI_OF_OTHERS_AP_RADIO_CHANNEL = 108,
	RISP_PKT_WTP_RF_RSSI_OF_OTHERS_AP_RADIO_TXPOWER = 109,
	RISP_PKT_WTP_RF_RSSI_OF_OTHERS_AP_RADIO_RSSI = 110,
	
	ACS_PKT_MSGTYPE = 115,
	ACS_PKT_SEQ_NUM = 116,
	ACS_PKT_MAC = 117,

	DCM_PKT_RADIONUM = 123,
	DCM_PKT_RADIONUM_END = 124,
	DCM_PKT_RADIO_UTIL = 125,
	DCM_PKT_RADIO_STANUM = 126,
	DCM_PKT_RADIO_BANDTYPE = 127,
}HCCP_PKT_TYPE;

typedef enum {
	HAN_FALSE = 0,
	HAN_TRUE = 1
} HANBool;

#define MAX_CLUSTER_AP 16
#define MAC_LEN  6       
#define L_RADIO_NUM		4
#define VERSION_MAX_LEN 16
#define AP_NAME_MAX_LEN 32
#define TYPE_LEN 2
#define LENGTH_LEN 2
#define RSRP_PKT_LEN 23
#define TLV_SWITCH 0

typedef struct {
	unsigned char protocolver;
	unsigned char protocolType;
	unsigned short protocolLen;
	unsigned short seqnum;
	unsigned int clusterID;
}HCCPHeaderValues;


typedef enum{
    DBCP = 1,
    RSCP = 2,
    RSRP = 3,
    RIRP = 4,
    RISP = 5,
    RICP = 6,
    ACS = 15,
    DCM = 16,

	DBCP_TLV = 21,
    RSCP_TLV = 22,
    RSRP_TLV = 23,
    RIRP_TLV = 24,
    RISP_TLV = 25,
    RICP_TLV = 26,
}HCCPType;

typedef enum{
    Sequence_req = 1,
    Sequence_resp = 2,
    Token_req = 3,
    Token_resp = 4,
}ACSType;


typedef struct
{
	unsigned char radioid;
	unsigned char channel;            
	unsigned char txpower;           
	unsigned char rssi;
}WTP_RADIO_H;

typedef struct 
{	
	HCCPHeaderValues head;
	unsigned short msgtype;
	unsigned int seq_num;
	unsigned char mac[MAC_LEN];

}ACS_format;

typedef struct
{
	HCCPHeaderValues head;
	unsigned char priority;
	unsigned char config_sequence;
	unsigned char product_type;
	unsigned char mac[MAC_LEN];
	unsigned char state;
	unsigned char radiocnt;
	WTP_RADIO_H WTP_Radio[L_RADIO_NUM];
}DBCP_format;

typedef struct
{
	HCCPHeaderValues head;
	unsigned char priority;
	unsigned char config_sequence;
	unsigned char product_type;
	unsigned char mac[MAC_LEN];
	unsigned char state;
	unsigned char radiocnt;
	WTP_RADIO_H WTP_Radio[L_RADIO_NUM];
	unsigned int ip;
	unsigned char ap_version[VERSION_MAX_LEN];
	unsigned char ap_name[AP_NAME_MAX_LEN];
}RSRP_format;

typedef struct
{
	unsigned char mac[MAC_LEN];
	unsigned char role;
	unsigned char state;
	unsigned int ip;
	unsigned char radiocnt;
	WTP_RADIO_H WTP_Radio[L_RADIO_NUM];
}RSCP_cluster_member;

typedef struct
{
	HCCPHeaderValues head;
	unsigned char priority;
	unsigned char config_sequence;
	unsigned char product_type;
	unsigned char mac[MAC_LEN];
	unsigned char count;
	RSCP_cluster_member cluster_member[MAX_CLUSTER_AP];
}RSCP_format;

typedef struct
{
	unsigned char mac[MAC_LEN];
	unsigned char radiocnt;
	WTP_RADIO_H WTP_Radio[L_RADIO_NUM];
}RIRP_cluster_neighbor;

typedef struct
{	
	HCCPHeaderValues head;
	unsigned char mac[MAC_LEN];
	unsigned char neighbor_count;
	RIRP_cluster_neighbor cluster_neighbor[MAX_CLUSTER_AP];

}RIRP_format;


typedef struct
{	
	HCCPHeaderValues head;
	unsigned char op;
	unsigned int vip;
	unsigned int vip_netmask;
	unsigned char count;
	unsigned char mac[MAX_CLUSTER_AP][MAC_LEN];
}RICP_format;

typedef struct
{
	unsigned char ap_base_mac[MAC_LEN];
    unsigned char radiocnt;
	WTP_RADIO_H ap_radio[L_RADIO_NUM];
}Scan_Info;

typedef struct
{
    unsigned char role;
    unsigned char radiocnt;
    unsigned char neighbor_cnt;
	unsigned char ap_base_mac[MAC_LEN];
	unsigned int ipaddr;
	unsigned int priority;
	WTP_RADIO_H WTP_Radio[L_RADIO_NUM];
	Scan_Info rssi_of_others[MAX_CLUSTER_AP];
} RF_Environment;

typedef struct
{	
	HCCPHeaderValues head;
	unsigned int ACS_sequence;
	unsigned int Mem_num;
	RF_Environment WTP_RF[MAX_CLUSTER_AP];
}RISP_format;

typedef struct
{
	unsigned char  util;
	unsigned char  stanum;
	unsigned char  bandtype;
}Radio_Info;

typedef struct
{	
	HCCPHeaderValues head;
	unsigned char radionum;
	Radio_Info radio[L_RADIO_NUM];

}DCM_format;

typedef union data
{
	DBCP_format dbcp;
	RSRP_format rsrp;
	RSCP_format rscp;
	RIRP_format rirp;
	RICP_format ricp;
	RISP_format risp;
	ACS_format  acs;
	DCM_format dcm;
}Hccp_Protocol_Union;

typedef struct
{
	unsigned char type;
	Hccp_Protocol_Union u;
}Hccp_Protocol_Struct;

HANBool Assemble_DBCP(char *buf, DBCP_format *dbcp) ;
HANBool Assemble_RSRP(char *buf, RSRP_format *rsrp) ;
HANBool Assemble_RSCP(char *buf, RSCP_format *rscp) ;
HANBool Assemble_RIRP(char *buf, RIRP_format *rirp) ;
HANBool Assemble_RICP(char *buf, RICP_format *ricp) ;
HANBool Assemble_RISP(char *buf, RISP_format *risp) ;


HANBool Assemble_DCM(char *buf, DCM_format *dcm) ;

HANBool Assemble_ACS_SequenceRequest(char *buf, ACS_format *acs_packet) ;
HANBool Assemble_ACS_SequenceResponse(char *buf, ACS_format *acs_packet) ;
HANBool Assemble_ACS_TokenRequest(char *buf, ACS_format *acs_packet) ;
HANBool Assemble_ACS_TokenResponse(char *buf, ACS_format *acs_packet) ;

HANBool Parse_HCCPProtocol(char *buf,  Hccp_Protocol_Struct *parse_packet) ;




#endif
