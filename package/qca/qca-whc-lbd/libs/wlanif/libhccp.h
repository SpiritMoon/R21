
#ifndef LIBHCCP_H 
#define LIBHCCP_H

typedef enum {
	HAN_FALSE = 0,
	HAN_TRUE = 1
} HANBool;

#define MAX_CLUSTER_AP 16
#define MAC_LEN  6       


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
    ACS = 6,
    DCM = 7,
}HCCPType;

typedef enum{
    Sequence_req = 1,
    Sequence_resp = 2,
    Token_req = 3,
    Token_resp = 4,
}ACSType;


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
}DBCP_format;

typedef struct
{
	HCCPHeaderValues head;
	unsigned char priority;
	unsigned char config_sequence;
	unsigned char product_type;
	unsigned char mac[MAC_LEN];
	unsigned char state;
}RSRP_format;

typedef struct
{
	unsigned char mac[MAC_LEN];
	unsigned char role;
	unsigned char state;
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
	unsigned char _2g_channel;
	unsigned char _2g_rssi;
	unsigned char _5g_channel;	
	unsigned char _5g_rssi;
}RIRP_cluster_neighbor;

typedef struct
{	
	HCCPHeaderValues head;
	unsigned char mac[MAC_LEN];
	unsigned char neighbor_count;
	RIRP_cluster_neighbor cluster_neighbor[MAX_CLUSTER_AP];

}RIRP_format;

typedef struct radio_info
{
	unsigned char  util;
	unsigned char  stanum;
	unsigned char  bandtype;
}Radio_Info;

typedef struct ap_info
{	
	HCCPHeaderValues head;
	unsigned char radionum;
	unsigned char mac[MAC_LEN];
	Radio_Info radio[3];
}DCM_format;

typedef union data
{
	DBCP_format dbcp;
	RSRP_format rsrp;
	RSCP_format rscp;
	RIRP_format rirp;
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
HANBool Assemble_DCM(char *buf, DCM_format *dcm) ;

HANBool Assemble_ACS_SequenceRequest(char *buf, ACS_format *acs_packet) ;
HANBool Assemble_ACS_SequenceResponse(char *buf, ACS_format *acs_packet) ;
HANBool Assemble_ACS_TokenRequest(char *buf, ACS_format *acs_packet) ;
HANBool Assemble_ACS_TokenResponse(char *buf, ACS_format *acs_packet) ;

HANBool Parse_HCCPProtocol(char *buf,  Hccp_Protocol_Struct *parse_packet) ;




#endif
