/******************************************************************************
  File Name    : wireless_header.c
  Author       : zhaoej
  Date         : 20160218
  Description  : wireless.c 
******************************************************************************/
#ifndef _WLAN_HEADER_H_
#define _WLAN_HEADER_H_

#include <sys/types.h>

#define MAC_ADDR_LEN  6

#define EPT_IP			0x0800    /* type: IP */
#define EPT_ARP			0x0806    /* type: ARP */
#define ARPHRD_ETHER	0x0001    /* Dummy type for 802.3 frames */
#define ARP_HDR_LEN		0x0006
#define ARP_PRO_LEN		0x0004
#define ARP_REQUEST		0x0001    /* ARP request */
#define ARP_REPLY		0x0002    /* ARP reply */

typedef struct arphdr
{
	unsigned short arp_hdr;    /* format of hardware address */
	unsigned short arp_pro;    /* format of protocol address */
	unsigned char arp_hln;    /* length of hardware address */
	unsigned char arp_pln;    /* length of protocol address */
	unsigned short arp_op;     /* ARP/RARP operation */

	unsigned char arp_sha[6];    /* sender hardware address */
	unsigned char arp_spa[4];   /* sender protocol address */
	unsigned char arp_tha[6];    /* target hardware address */
	unsigned char arp_tpa[4];    /* target protocol address */
}ARPHDR;


/*Structure of a 10Mb/s Ethernet header*/
#ifndef __packed
#define __packed    __attribute__((__packed__))
#endif

struct	ether_header {
	//u_int8_t	ether_dhost[MAC_ADDR_LEN];
	unsigned char ether_dhost[MAC_ADDR_LEN];
	//u_int8_t	ether_shost[MAC_ADDR_LEN];
	unsigned char ether_shost[MAC_ADDR_LEN];
	u_int16_t	ether_type;
};

/*
 * generic definitions for IEEE 802.11 frames
 */
struct ieee80211_frame {
	u_int8_t	i_fc[2];
	u_int8_t	i_dur[2];
	union{
		struct{
			u_int8_t	i_addr1[MAC_ADDR_LEN];
			u_int8_t	i_addr2[MAC_ADDR_LEN];
			u_int8_t	i_addr3[MAC_ADDR_LEN];
		};
		u_int8_t	i_addr_all[3 * MAC_ADDR_LEN];
	};
	u_int8_t	i_seq[2];
}__packed;



#define IEEE80211_FC_VERSION_MASK          0x0003
#define IEEE80211_FC_VERSION_0             0x0000



#define IEEE80211_FC_TYPE_MASK             0x000C
#define IEEE80211_FC_TYPE_MGT              0x0000
#define IEEE80211_FC_TYPE_DATA             0x0008


#define IEEE80211_FC_SUBTYPE_MASK          0x00F0
#define IEEE80211_FC_SUBTYPE_DISASSOC      0x00A0
#define IEEE80211_FC_SUBTYPE_DEAUTH        0x00C0
#define IEEE80211_FC_SUBTYPE_QOS           0x0080

#define IEEE80211_FC_SUBTYPE_QOS_NULL      0x00C0


#define IEEE80211_FC_DIR_MASK              0x0300
#define IEEE80211_FC_DIR_NODS              0x0000    /* STA->STA */
#define IEEE80211_FC_DIR_TODS              0x0100    /* STA->AP  */
#define IEEE80211_FC_DIR_FROMDS            0x0200    /* AP ->STA */
#define IEEE80211_FC_DIR_DSTODS            0x0300    /* AP ->AP  */

#define IEEE80211_FC_MORE_FRAG             0x0400
#define IEEE80211_FC_RETRY                 0x0800
#define IEEE80211_FC_PWR_MGT               0x1000
#define IEEE80211_FC_MORE_DATA             0x2000
#define IEEE80211_FC_WEP                   0x4000
#define IEEE80211_FC_ORDER                 0x8000


/*
 * Reason codes and status codes
 */

enum{
	IEEE80211_REASON_UNSPECIFIED        = 1,
	IEEE80211_REASON_AUTH_EXPIRE        = 2,
	IEEE80211_REASON_AUTH_LEAVE         = 3,
	IEEE80211_REASON_ASSOC_EXPIRE       = 4,
	IEEE80211_REASON_ASSOC_TOOMANY      = 5,
	IEEE80211_REASON_NOT_AUTHED         = 6,
	IEEE80211_REASON_NOT_ASSOCED        = 7,
	IEEE80211_REASON_ASSOC_LEAVE        = 8,
	IEEE80211_REASON_ASSOC_NOT_AUTHED   = 9,


	IEEE80211_STATUS_SUCCESS            = 0,
	IEEE80211_STATUS_UNSPECIFIED        = 1,
	IEEE80211_STATUS_CAPINFO            = 10,
	IEEE80211_STATUS_NOT_ASSOCED        = 11,

};

#define LLC_SNAP_LSAP 0xaa
#define LLC_UI		0x03

#define RFC1042_SNAP_ORGCODE_0 0x00
#define RFC1042_SNAP_ORGCODE_1 0x00
#define RFC1042_SNAP_ORGCODE_2 0x00



struct llc {
	u_int8_t llc_dsap;
	u_int8_t llc_ssap;
	union {
	    struct {
		u_int8_t control;
		u_int8_t format_id;
		u_int8_t class;
		u_int8_t window_x2;
	    } __packed type_u;
	    struct {
		u_int8_t num_snd_x2;
		u_int8_t num_rcv_x2;
	    } __packed type_i;
	    struct {
		u_int8_t control;
		u_int8_t num_rcv_x2;
	    } __packed type_s;
	    struct {
	        u_int8_t control;
		/*
		 * We cannot put the following fields in a structure because
		 * the structure rounding might cause padding.
		 */
		u_int8_t frmr_rej_pdu0;
		u_int8_t frmr_rej_pdu1;
		u_int8_t frmr_control;
		u_int8_t frmr_control_ext;
		u_int8_t frmr_cause;
	    } __packed type_frmr;
	    struct {
		u_int8_t  control;
		u_int8_t  org_code[3];
		u_int16_t ether_type;
	    } __packed type_snap;
	    struct {
		u_int8_t control;
		u_int8_t control_ext;
	    } __packed type_raw;
	} llc_un /* XXX __packed ??? */;
} __packed;
#define	llc_control		llc_un.type_u.control
#define	llc_snap		llc_un.type_snap

#endif



