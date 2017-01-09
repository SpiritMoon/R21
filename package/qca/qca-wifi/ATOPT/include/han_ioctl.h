#ifndef __HAN_IOCTL_H
#define __HAN_IOCTL_H


#pragma pack(push, 1)

enum han_ioctl_priv {
	HAN_IOCTL_PRIV_BANDSTEERING = 0,
	HAN_IOCTL_PRIV_WIRELESSQOS = 1,
	HAN_IOCTL_PRIV_IGMP_SNP = 2,
	HAN_IOCTL_PRIV_UTIL_TIMER_ENBLE = 3, 
	HAN_IOCTL_PRIV_TRAFFIC_LIMIT = 4,
	HAN_IOCTL_PRIV_DCM = 5,
};

#define HAN_IOCTL_WMM_ENABLE 0
#define HAN_IOCTL_WMM_DSCP_ENABLE 1
#define HAN_IOCTL_WMM_8021P_ENABLE 2
#define HAN_IOCTL_WMM_DSCP_TO_BK 3
#define HAN_IOCTL_WMM_DSCP_TO_BE 4
#define HAN_IOCTL_WMM_DSCP_TO_VI 5
#define HAN_IOCTL_WMM_DSCP_TO_VO 6
#define HAN_IOCTL_WMM_BK_TO_DSCP 7
#define HAN_IOCTL_WMM_BE_TO_DSCP 8
#define HAN_IOCTL_WMM_VI_TO_DSCP 9
#define HAN_IOCTL_WMM_VO_TO_DSCP 10
#define HAN_IOCTL_WMM_8021P_TO_BK 11
#define HAN_IOCTL_WMM_8021P_TO_BE 12
#define HAN_IOCTL_WMM_8021P_TO_VI 13
#define HAN_IOCTL_WMM_8021P_TO_VO 14
#define HAN_IOCTL_WMM_BK_TO_8021P 15
#define HAN_IOCTL_WMM_BE_TO_8021P 16
#define HAN_IOCTL_WMM_VI_TO_8021P 17
#define HAN_IOCTL_WMM_VO_TO_8021P 18
#define HAN_IOCTL_WMM_STATISTICS  19
#define HAN_IOCTL_WMM_DEBUG  20
#define HAN_IOCTL_WMM_DSCP_RESET  21
#define HAN_IOCTL_WMM_8021P_RESET  22

#define OP_SET 	0x01
#define OP_GET	0x02
#define AC_MAX_ARGS  8

struct wireless_qos{
		unsigned int subtype;
		unsigned int op;
		unsigned int arg_num;
		union wmm_args {
			/*Switch*/
			u_int8_t wmm_enable;
			u_int8_t dscp_enable;
			u_int8_t vlan_enable;
			u_int8_t debug;
			/*WMM priority to DSCP prioriy*/
			u_int8_t bk_to_dscp;
			u_int8_t be_to_dscp;
			u_int8_t vi_to_dscp;
			u_int8_t vo_to_dscp;
			/*DSCP prioriy to WMM priority*/
			u_int8_t dscp_to_bk[AC_MAX_ARGS];
			u_int8_t dscp_to_be[AC_MAX_ARGS];
			u_int8_t dscp_to_vi[AC_MAX_ARGS];
			u_int8_t dscp_to_vo[AC_MAX_ARGS];
			
			/*WMM priority to 8021p prioriy*/
			u_int8_t bk_to_vlan;
			u_int8_t be_to_vlan;
			u_int8_t vi_to_vlan;
			u_int8_t vo_to_vlan;
			
			/*8021p prioriy to WMM priority*/
			u_int8_t vlan_to_bk[AC_MAX_ARGS];
			u_int8_t vlan_to_be[AC_MAX_ARGS];
			u_int8_t vlan_to_vi[AC_MAX_ARGS];
			u_int8_t vlan_to_vo[AC_MAX_ARGS];
		}wmm_args;
		struct wmm_stat {
			u_int8_t wmm_enable;
			u_int8_t dscp_enable;
			u_int8_t vlan_enable;
			u_int64_t dscp_to_wmm_packets_ok;
			u_int64_t dscp_to_wmm_packets_error;
			u_int64_t wmm_to_dscp_packets_ok;
			u_int64_t wmm_to_dscp_packets_error;
			u_int64_t vlan_to_wmm_packets_ok;
			u_int64_t vlan_to_wmm_packets_error;
			u_int64_t wmm_to_vlan_packets_ok;
			u_int64_t wmm_to_vlan_packets_error;

		}wmm_stat;
};

struct han_igmpsnp{
#define HAN_IOCTL_IGMPSNP_ENABLE 0
#define HAN_IOCTL_IGMPSNP_MUTOUN 1
#define HAN_IOCTL_IGMPSNP_STATUS 2
#define HAN_IOCTL_IGMPSNP_DEBUG 3


#define OP_SET 	0x01
#define OP_GET	0x02
	unsigned int subtype;
	unsigned int op;
	int value;
};

#ifndef IEEE80211_ADDR_LEN
#define IEEE80211_ADDR_LEN	6
#endif

struct ieee80211_han_traffic_limit {

#define SET_VAP_TRAFFIC_LIMIT	1
#define GET_VAP_TRAFFIC_LIMIT	2
#define SET_SPECIFIC_NODE_TRAFFIC_LIMIT	3
#define GET_SPECIFIC_NODE_TRAFFIC_LIMIT	4
#define SET_EVERY_NODE_TRAFFIC_LIMIT	5
#define GET_EVERY_NODE_TRAFFIC_LIMIT	6
#define SET_VAP_TRAFFIC_LIMIT_FLAG	7
#define GET_VAP_TRAFFIC_LIMIT_FLAG	8
#define SET_EVERY_NODE_TRAFFIC_LIMIT_FLAG	9
#define GET_EVERY_NODE_TRAFFIC_LIMIT_FLAG	10
#define SET_SPECIFIC_NODE_TRAFFIC_LIMIT_FLAG	11
#define GET_SPECIFIC_NODE_TRAFFIC_LIMIT_FLAG	12

#define SET_VAP_TRAFFIC_LIMIT_SEND	13
#define GET_VAP_TRAFFIC_LIMIT_SEND	14
#define SET_SPECIFIC_NODE_TRAFFIC_LIMIT_SEND	15
#define GET_SPECIFIC_NODE_TRAFFIC_LIMIT_SEND	16
#define SET_EVERY_NODE_TRAFFIC_LIMIT_SEND	17
#define GET_EVERY_NODE_TRAFFIC_LIMIT_SEND	18

#define TL_GET_TRAFFIC_LIMIT_STATUS 19
#define TL_SET_TASKLET_TIMESLICE    20
#define TL_GET_TASKLET_TIMESLICE    21
#define TL_SET_DEQUEUE_THRESHOLD    22
#define TL_GET_DEQUEUE_THRESHOLD    23
#define TL_GET_EVERYNODE_QUEUE_LEN  24
#define TL_SET_DEBUG_FLAG           25
#define TL_GET_DEBUG_FLAG           26

	unsigned char   type;  			/* request type*/
	unsigned int 	arg1;
	u_int8_t macaddr[IEEE80211_ADDR_LEN];
};


#define HAN_IOCTL_DCM_LBD_DELMAC 0
#define HAN_IOCTL_DCM_LBD_ADDMAC 1
#define HAN_IOCTL_DCM_FLUSH 2
#define HAN_IOCTL_DCM_BLANCE_DELMAC 3
#define HAN_IOCTL_DCM_BLANCE_ADDMAC 4
#define HAN_IOCTL_DCM_PRINT_LIST 5
#define HAN_IOCTL_DCM_DEBUG 6
#define HAN_IOCTL_DCM_GET_CLIENT 7
#define HAN_IOCTL_DCM_GET_CLIENT_NUM 8
#define HAN_IOCTL_DCM_LOWRSSI_THRESH 9
#define HAN_IOCTL_DCM_LOWRSSI_STATUS 10
struct han_ioctl_priv_args {
	enum han_ioctl_priv type;
	union {
		struct {
#define HAN_IOCTL_BANDSTEERING_ENABLE 0
#define HAN_IOCTL_BANDSTEERING_RSS_THRESHOLD 1
#define HAN_IOCTL_BANDSTEERING_ACCESS_LOAD 2
#define HAN_IOCTL_BANDSTEERING_DENY_COUNT 3
#define HAN_IOCTL_BANDSTEERING_DEBUG 4
#define HAN_IOCTL_BANDSTEERING_STATISTICS 5
#define OP_SET 	0x01
#define OP_GET	0x02

			unsigned int subtype;
			unsigned int op;
			int value;
			struct  {
				//non 5G capable
				u_int32_t	non_5g_capable;
				//5G capable
				u_int32_t	persist_to_2g;
				u_int32_t	excessive_load_5g_capable_to_5g;
				u_int32_t	excessive_load_5g_capable_to_2g;
				u_int32_t	steer_to_5g;
				u_int32_t	weak_2g_signal;
				//totally
				u_int32_t	total_2g;
				u_int32_t	total_5g;
			} bs_stat;
			
		} bandsteering;
		
	    struct{
#define HAN_IOCTL_TIMER_ENBLE 0
			unsigned int subtype;
			unsigned int op;
			unsigned char enable;	
	    }util_timer_en;
		struct{
			unsigned int subtype;
			unsigned int op;
			unsigned int value;
			unsigned char denycnt ;	
			unsigned char mac[6];
			unsigned char channel;
			struct {
		    unsigned char channel;
			unsigned char occupyflag;
			unsigned char ce_flags;
			}wifi[3];
	    }dcm;
		struct wireless_qos wmm;
		struct han_igmpsnp  igmp;
		struct ieee80211_han_traffic_limit traffic_limit;

		/*New cmd struct*/
	} u;
};


int ieee80211_ioctl_han_traffic_limit(struct net_device *dev, struct iwreq *iwr);

#pragma pack(pop)

#endif
