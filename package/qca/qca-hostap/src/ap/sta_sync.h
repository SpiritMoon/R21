#ifndef STA_SYNC_H
#define STA_SYNC_H

#define SYNC_PORT  3000
#define SYNC_ADDR "192.168.15.80"
#define FT_KEY "000102030405060708090a0b0c0d0e0f"
#define FT_R1KH_ID_LEN 6
struct sta_sync{
    u8 addr[6];
	u32 ipaddr;
	u8 vap_mac[6];
	char iface[IFNAMSIZ + 1];
	char bridge[IFNAMSIZ + 1];
	char ssid[HOSTAPD_MAX_SSID_LEN + 1];
	struct sta_sync *next;
};

struct rsn_80211r{
    char ssid[HOSTAPD_MAX_SSID_LEN + 1];
	u8 vap_mac[6];
	u8 r1_kh[FT_R1KH_ID_LEN];
	u8 nas_id[48];
};

struct sta_sync_list{
    u8 sta_num;
	u8 vap_mac[6];
	char ssid[HOSTAPD_MAX_SSID_LEN + 1];
	u8 buf[1000];
};

typedef enum{
    SYNC_STA_ADD = 0,
	SYNC_STA_DEL =1,
	SYNC_STA_ROAMING =2,
	SYNC_80211R_REQUEST =3,
	SYNC_80211R_RESPONSE =4,
	SYNC_EAG_INFO =5,
	SYNC_STA_LIST =6,
	SYNC_PMKSA_OKC =7,
}SyncType;
struct sta_sync *sta_sync_hash[STA_HASH_SIZE];
#if 0
typedef struct{
    SyncOp op;
	union{
        struct sta_sync sta;
		struct rsn_80211r ftauth;
		EAG_MSG eag_msg;
	}u;
}SYNC_MSG;
#endif
typedef struct{
    SyncType type;
	u16 data_len;
	u8 data[1280];	
}SYNC_MSG;

int hostapd_sync_iface_init(struct hostapd_data *hapd);
void hostapd_sync_iface_deinit(struct hostapd_data *hapd);
int send_user_sync_info(struct hostapd_data *hapd,struct sta_info *sta,SyncType op);
int send_user_roaming_info(struct hostapd_data *hapd,struct sta_sync *old_sta);
struct sta_sync * sta_sync_hash_get(const u8 *sta);


#endif