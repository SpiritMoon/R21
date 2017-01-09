#include "utils/includes.h"
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "utils/common.h"
#include "l2_packet/l2_packet.h"
#include "hostapd.h"
#include "sta_info.h"
#include "ap_drv_ops.h"
#include "x_snoop.h"
#include "sta_sync.h"
#include "ap_config.h"
#include "wpa_auth.h"
#include "hostapd.h"
#include "pmksa_cache_auth.h"
#include "wpa_auth_i.h"


static const int pmksa_cache_max_entries = 1024;
static const int dot11RSNAConfigPMKLifetime = 43200;

struct rsn_pmksa_cache {
#define PMKID_HASH_SIZE 128
#define PMKID_HASH(pmkid) (unsigned int) ((pmkid)[0] & 0x7f)
	struct rsn_pmksa_cache_entry *pmkid[PMKID_HASH_SIZE];
	struct rsn_pmksa_cache_entry *pmksa;
	int pmksa_count;

	void (*free_cb)(struct rsn_pmksa_cache_entry *entry, void *ctx);
	void *ctx;
};

struct pmksa_okc_entry{
    char ssid[HOSTAPD_MAX_SSID_LEN + 1];
	u8 vap_mac[6];
	struct rsn_pmksa_cache_entry entry;
};

static void _pmksa_cache_free_entry(struct rsn_pmksa_cache_entry *entry)
{
	if (entry == NULL)
		return;
	os_free(entry->identity);
	wpabuf_free(entry->cui);
#ifndef CONFIG_NO_RADIUS
	radius_free_class(&entry->radius_class);
#endif /* CONFIG_NO_RADIUS */
	os_free(entry);
}


static void pmksa_cache_free_entry(struct rsn_pmksa_cache *pmksa,
				   struct rsn_pmksa_cache_entry *entry)
{
	struct rsn_pmksa_cache_entry *pos, *prev;

	pmksa->pmksa_count--;
	pmksa->free_cb(entry, pmksa->ctx);
	pos = pmksa->pmkid[PMKID_HASH(entry->pmkid)];
	prev = NULL;
	while (pos) {
		if (pos == entry) {
			if (prev != NULL) {
				prev->hnext = pos->hnext;
			} else {
				pmksa->pmkid[PMKID_HASH(entry->pmkid)] =
					pos->hnext;
			}
			break;
		}
		prev = pos;
		pos = pos->hnext;
	}

	pos = pmksa->pmksa;
	prev = NULL;
	while (pos) {
		if (pos == entry) {
			if (prev != NULL)
				prev->next = pos->next;
			else
				pmksa->pmksa = pos->next;
			break;
		}
		prev = pos;
		pos = pos->next;
	}
	_pmksa_cache_free_entry(entry);
}
static void pmksa_cache_link_entry(struct rsn_pmksa_cache *pmksa,
				   struct rsn_pmksa_cache_entry *entry)
{
	struct rsn_pmksa_cache_entry *pos, *prev;

	/* Add the new entry; order by expiration time */
	pos = pmksa->pmksa;
	prev = NULL;
	while (pos) {
		if (pos->expiration > entry->expiration)
			break;
		prev = pos;
		pos = pos->next;
	}
	if (prev == NULL) {
		entry->next = pmksa->pmksa;
		pmksa->pmksa = entry;
	} else {
		entry->next = prev->next;
		prev->next = entry;
	}
	entry->hnext = pmksa->pmkid[PMKID_HASH(entry->pmkid)];
	pmksa->pmkid[PMKID_HASH(entry->pmkid)] = entry;

	pmksa->pmksa_count++;
	wpa_printf(MSG_DEBUG, "RSN: added PMKSA cache entry for " MACSTR,
		   MAC2STR(entry->spa));
	wpa_hexdump(MSG_DEBUG, "RSN: added PMKID", entry->pmkid, PMKID_LEN);
}


static void handle_sync(void *ctx, const u8 *src_addr, const u8 *buf, size_t len)
{
    struct hostapd_data *hapd = ctx;
	SYNC_MSG *msg;
	struct iphdr *iph;
	struct rsn_80211r *ftauth;
    EAG_MSG *eag_msg;
	struct sta_sync_list *sta_list;
	struct rsn_pmksa_cache_entry *entry,*pos;
	wpa_printf(MSG_DEBUG,"packet len =%d",len);
	struct rsn_pmksa_cache *pmksa;
	struct pmksa_okc_entry *okc_entry;
	//wpa_hexdump_key(MSG_DEBUG,"receive packet:",buf,len);

	buf += ETH_HLEN;
	iph = (struct iphdr *)buf;
    buf +=sizeof(struct iphdr);
	buf +=sizeof(struct udphdr);

	msg = (SYNC_MSG *)buf;

    wpa_printf(MSG_DEBUG,"op = %d",msg->type);
	//wpa_hexdump_key(MSG_DEBUG,"sync packet:",buf,len-42);
    switch(msg->type){
        case SYNC_STA_ADD:
			sta_sync_add(hapd, msg);
			break;
		case SYNC_STA_DEL:
			sta_sync_del(hapd, msg);
			break;
		case SYNC_STA_ROAMING:
			sta_sync_roaming(hapd, msg);
			break;
		case SYNC_80211R_REQUEST:
			if ((hapd->conf->wpa_key_mgmt & WPA_KEY_MGMT_FT_PSK) || 
		            (hapd->conf->wpa_key_mgmt & WPA_KEY_MGMT_FT_IEEE8021X)){
			    ftauth = (struct rsn_80211r *)msg->data;
			    if(os_strcmp(hapd->conf->ssid.ssid, ftauth->ssid)){
                    wpa_printf(MSG_DEBUG,"ssid is different,needn't sync");
		            return;
	            }

			    if(os_memcmp(ftauth->vap_mac,hapd->own_addr,ETH_ALEN) == 0)
				    return;
			    set_r0kh_r1kh(hapd,ftauth);
			    send_80211r_ft_info(hapd,SYNC_80211R_RESPONSE,iph->saddr);
			    show(hapd);
			}
			break;
		case SYNC_80211R_RESPONSE:
			if ((hapd->conf->wpa_key_mgmt & WPA_KEY_MGMT_FT_PSK) || 
		            (hapd->conf->wpa_key_mgmt & WPA_KEY_MGMT_FT_IEEE8021X)){
			    ftauth = (struct rsn_80211r *)msg->data;
			    if(os_strcmp(hapd->conf->ssid.ssid, ftauth->ssid)){
                    wpa_printf(MSG_DEBUG,"ssid is different,needn't sync");
		            return;
	            }
			    if(os_memcmp(ftauth->vap_mac,hapd->own_addr,ETH_ALEN) == 0)
				    return;
			    set_r0kh_r1kh(hapd,ftauth);
			    show(hapd);
			}
			break;
		case SYNC_EAG_INFO:
			eag_msg =(EAG_MSG *)msg->data;
			os_memcpy(eag_msg->sta.iface,hapd->conf->iface, IFNAMSIZ+1);
			send_sync_to_eag(hapd,eag_msg);
			break;
		case SYNC_STA_LIST:
			sta_sync_list_add(hapd,msg);
	        break;
		case SYNC_PMKSA_OKC:
			okc_entry = (struct pmksa_okc_entry *)msg->data; 
			if(os_strcmp(hapd->conf->ssid.ssid, okc_entry->ssid)){
                wpa_printf(MSG_DEBUG,"ssid is different,needn't sync pmksa");
		        return;
	        }
			pmksa = hapd->wpa_auth->pmksa;
			entry = os_zalloc(sizeof(struct rsn_pmksa_cache_entry));
		    os_memcpy(entry,&okc_entry->entry,sizeof(*entry));
		    wpa_hexdump(MSG_DEBUG, "SYNC_PMKSA_OKC,PMKID", entry->pmkid, 16);
			pos = pmksa_cache_auth_get(pmksa, entry->spa, NULL);
	        if (pos)
		        pmksa_cache_free_entry(pmksa, pos);
	        if (pmksa->pmksa_count >= pmksa_cache_max_entries && pmksa->pmksa) {
		    /* Remove the oldest entry to make room for the new entry */
		        wpa_printf(MSG_DEBUG, "RSN: removed the oldest PMKSA cache "
			        "entry (for " MACSTR ") to make room for new one",
			        MAC2STR(pmksa->pmksa->spa));
		        pmksa_cache_free_entry(pmksa, pmksa->pmksa);
	        }
            pmksa_cache_link_entry(pmksa, entry);
			break;
		default:
			break;      
    }
	
	
}

int hostapd_sync_iface_init(struct hostapd_data *hapd)
{


	int s;
	
	//hapd->sock_sync = x_snoop_get_l2_packet(hapd, handle_sync,
	//					L2_PACKET_FILTER_SYNC);
    struct hostapd_bss_config *conf = hapd->conf;
	struct l2_packet_data *l2;

	l2 = l2_packet_init("br-wan", NULL, ETH_P_IP, handle_sync, hapd, 1);
	if (l2 == NULL) {
		wpa_printf(MSG_DEBUG,
			   "x_snoop: Failed to initialize L2 packet processing %s",
			   strerror(errno));
		return -1;
	}

	if (l2_packet_set_packet_filter(l2, L2_PACKET_FILTER_SYNC)) {
		wpa_printf(MSG_DEBUG,
			   "x_snoop: Failed to set L2 packet filter for type: L2_PACKET_FILTER_SYNC");
		l2_packet_deinit(l2);
		return -1;
	}

    hapd->sock_sync = l2;
    
	if(hapd->sync_send_sock < 0){
	    s = socket(AF_INET,SOCK_DGRAM,0);
        if(s < 0){
            perror("sync_xmit_sock");
		    wpa_printf(MSG_ERROR,"create sync_send_sock failed");
		    return -1;
	    }
		hapd->sync_send_sock = s;
    }
    wpa_printf(MSG_DEBUG,"wam_sync_iface_init finish!");
	return 0;
}

void sta_sync_hash_add(struct sta_sync *sta)
{
	sta->next= sta_sync_hash[STA_HASH(sta->addr)];
	sta_sync_hash[STA_HASH(sta->addr)] = sta;
	wpa_printf(MSG_DEBUG, "add STA " MACSTR
			   " into sta_sync_hash table", MAC2STR(sta->addr));
}


void sta_sync_hash_del(struct sta_sync *sta)
{
	struct sta_sync *s;
	struct sta_sync *tmp;

	s = sta_sync_hash[STA_HASH(sta->addr)];
	if (s == NULL) return;
	if (os_memcmp(s->addr, sta->addr, 6) == 0) {
		sta_sync_hash[STA_HASH(sta->addr)] = s->next;
		wpa_printf(MSG_DEBUG, "delete STA " MACSTR
			   " from sta_sync_hash table", MAC2STR(sta->addr));
		os_free(s);
		return;
	}

	while (s->next != NULL &&
	       os_memcmp(s->next->addr, sta->addr, ETH_ALEN) != 0)
		s = s->next;
	if (s->next != NULL){
		tmp = s->next;
		s->next = s->next->next;
		os_free(tmp);
		wpa_printf(MSG_DEBUG, "delete STA " MACSTR
			   " from sta_sync_hash table", MAC2STR(sta->addr));
	}
	else
		wpa_printf(MSG_DEBUG, "could not delete STA " MACSTR
			   " from sta_sync_hash table", MAC2STR(sta->addr));
}
struct sta_sync * sta_sync_hash_get(const u8 *sta)
{
	struct sta_sync *s;

	s = sta_sync_hash[STA_HASH(sta)];
	while (s != NULL && os_memcmp(s->addr, sta, 6) != 0)
		s = s->next;
	return s;
}
int sta_sync_add(struct hostapd_data *hapd, SYNC_MSG *msg)
{
	struct sta_sync *sta;
	struct sta_info *old_sta;
    
	sta = os_zalloc(sizeof(struct sta_sync));
	if(sta == NULL){
        wpa_printf(MSG_ERROR,"malloc failed for sync add sta");
        return -1;
	}
    os_memcpy(sta,msg->data,sizeof(struct sta_sync)) ;  
	if(os_memcmp(hapd->own_addr, sta->vap_mac, ETH_ALEN) ==0){
        wpa_printf(MSG_DEBUG,"receive msg from myself,need not sync add sta");
		os_free(sta);
		return 0;
	}
        
	if(os_strcmp(hapd->conf->ssid.ssid, sta->ssid)){
        wpa_printf(MSG_DEBUG,"ssid is different,need not sync add sta");
        os_free(sta);
		return 0;
	}
	sta_sync_hash_del(sta);
	sta_sync_hash_add(sta);
	
	old_sta = ap_get_sta(hapd, sta->addr);
	if (old_sta == NULL)
		return 0;
	wpa_printf(MSG_DEBUG, "STA " MACSTR
        " has assoicate to other ap,disassociated current ap", MAC2STR(old_sta->addr));
	send_msg_to_eag(hapd,old_sta,OPEN_ROAM);
	ap_sta_set_authorized(hapd, old_sta, 0);
	old_sta->flags &= ~(WLAN_STA_AUTH | WLAN_STA_ASSOC);
	wpa_auth_sm_event(old_sta->wpa_sm, WPA_DISASSOC);
	old_sta->acct_terminate_cause = RADIUS_ACCT_TERMINATE_CAUSE_USER_REQUEST;
	ieee802_1x_notify_port_enabled(old_sta->eapol_sm, 0);
	ap_free_sta_no_notice(hapd, old_sta);
		
	return 0;
}

int sta_sync_list_add(struct hostapd_data *hapd, SYNC_MSG *msg)
{
    int i;
	struct sta_sync *sta;
    struct sta_sync_list *sta_list =(struct sta_sync_list *)msg->data;

    if(os_memcmp(hapd->own_addr, sta_list->vap_mac, ETH_ALEN) ==0){
        wpa_printf(MSG_DEBUG,"receive msg from myself,need not sync add sta list");
		return 0;
	}
	if(os_strcmp(hapd->conf->ssid.ssid, sta_list->ssid)){
        wpa_printf(MSG_DEBUG,"ssid is different,need not sync add sta list");
		return 0;
	}
	u8 *pos = sta_list->buf;
	for(i = 0;i < sta_list->sta_num;i++){
        sta = os_zalloc(sizeof(struct sta_sync));
		if(sta == NULL){
            wpa_printf(MSG_ERROR,"malloc failed for sync add sta");
            return -1;
	    }
		os_memcpy(sta,pos,sizeof(struct sta_sync));
		pos += sizeof(struct sta_sync);
		sta_sync_hash_add(sta);
	}
}
int sta_sync_del(struct hostapd_data *hapd, SYNC_MSG *msg)
{

	struct sta_sync *sta = (struct sta_sync *)msg->data;

	if(os_memcmp(hapd->own_addr, sta->vap_mac, ETH_ALEN) ==0){
        wpa_printf(MSG_DEBUG,"receive msg from myself,need not sync del sta");
		return 0;
	}
	if(os_strcmp(hapd->conf->ssid.ssid, sta->ssid)){
        wpa_printf(MSG_DEBUG,"ssid is different,need not sync del sta");
		return 0;
	}
    
	sta_sync_hash_del(sta);
	return 0;
}

int sta_sync_roaming(struct hostapd_data *hapd, SYNC_MSG *msg)
{
	  struct sta_sync *sta = (struct sta_sync *)msg->data;
	  struct sta_info *sta_tmp;
      if(os_strcmp(hapd->conf->ssid.ssid, sta->ssid)){

	        wpa_printf(MSG_DEBUG,"ssid is different,needn't sync!");
	        return 0;
	  }
      if(os_memcmp(hapd->own_addr, sta->vap_mac, ETH_ALEN) ==0){

			wpa_printf(MSG_INFO,"sta:" MACSTR "has roaming!disassoc current ap!",  \
				        MAC2STR(sta->addr));
		    sta_tmp = ap_get_sta(hapd,sta->addr);
			if(sta_tmp != NULL){
                send_msg_to_eag(hapd,sta_tmp,OPEN_ROAM);
			}
			hostapd_notif_disassoc(hapd,sta->addr);
	  }

	  sta_sync_del(hapd,msg);
	  
	  return 0;
	  
}

int send_user_sync_msg(struct hostapd_data *hapd,SYNC_MSG msg,u32 dst_addr)
{
    struct sockaddr_in addr;
	char ip[18];
	int len;
	os_memset(&addr,0,sizeof(addr));
	addr.sin_family=AF_INET;

	addr.sin_addr.s_addr=htonl(dst_addr);
	addr.sin_port=htons(SYNC_PORT);

	if (sendto(hapd->sync_send_sock,&msg, sizeof(msg), 0, (struct sockaddr *) &addr, sizeof(addr)) < 0){
        perror("sendto");
		wpa_printf(MSG_ERROR,"send user sync information failed");
		return -1;
	}
    
	wpa_printf(MSG_DEBUG,"send_user_sync_msg");
	return 0;
}


int send_user_sync_info(struct hostapd_data *hapd,struct sta_info *sta,SyncType type)
{
    SYNC_MSG msg;
	os_memset(&msg,0,sizeof(msg));
	int i;
    struct sta_sync msg_sta;
	os_memset(&msg_sta,0,sizeof(msg_sta));

	msg.type = type;
	os_memcpy(msg_sta.vap_mac,hapd->own_addr,ETH_ALEN);
	os_memcpy(msg_sta.addr,sta->addr,ETH_ALEN);
	os_strncpy(msg_sta.iface, hapd->conf->iface, IFNAMSIZ+1);
	os_strncpy(msg_sta.bridge, hapd->conf->bridge, IFNAMSIZ+1);
	os_strncpy(msg_sta.ssid, hapd->conf->ssid.ssid, hapd->conf->ssid.ssid_len);
	msg_sta.ipaddr = sta->ipaddr;
	
    if(sta->roam_flag){
        sta_sync_hash_del(&msg_sta);
	}
	
	msg.data_len = sizeof(msg_sta);
	os_memcpy(msg.data,&msg_sta,msg.data_len);
		
	for(i = 0;i < hapd->cluster_ap_num;i++){
		if(hapd->ap_data[i].state == RUN)
	        send_user_sync_msg(hapd,msg,hapd->ap_data[i].ip_addr);
	}
	return 0;
	
}
int send_user_roaming_info(struct hostapd_data *hapd,struct sta_sync *old_sta)
{
    SYNC_MSG msg;
	os_memset(&msg,0,sizeof(msg));
    int i;
	struct sta_sync msg_sta;
	
	msg.type = SYNC_STA_ROAMING;
	os_memcpy(msg_sta.vap_mac,old_sta->vap_mac,ETH_ALEN);
	os_memcpy(msg_sta.addr,old_sta->addr,ETH_ALEN);
	os_strncpy(msg_sta.iface, old_sta->iface, IFNAMSIZ+1);
	os_strncpy(msg_sta.bridge, old_sta->bridge, IFNAMSIZ+1);
	os_strncpy(msg_sta.ssid, hapd->conf->ssid.ssid, hapd->conf->ssid.ssid_len);
	msg_sta.ipaddr = old_sta->ipaddr;
    msg.data_len = sizeof(msg_sta);
	os_memcpy(msg.data,&msg_sta,msg.data_len);
	
	for(i = 0;i < hapd->cluster_ap_num;i++){
		if(hapd->ap_data[i].state == RUN)
	        send_user_sync_msg(hapd,msg,hapd->ap_data[i].ip_addr);
	}
	return 0;
	
}

int send_80211r_ft_info(struct hostapd_data *hapd,SyncType type,u32 dst_addr)
{
    SYNC_MSG msg;
	os_memset(&msg,0,sizeof(msg));
    struct rsn_80211r ftauth;
	os_memset(&ftauth, 0, sizeof(ftauth));
	
	msg.type = type;
	os_memcpy(ftauth.vap_mac,hapd->own_addr,ETH_ALEN);
	os_strncpy(ftauth.ssid, hapd->conf->ssid.ssid, hapd->conf->ssid.ssid_len);
	os_strncpy(ftauth.nas_id,hapd->conf->nas_identifier,os_strlen(hapd->conf->nas_identifier));
    os_memcpy(ftauth.r1_kh,hapd->conf->r1_key_holder,ETH_ALEN);
	msg.data_len = sizeof(ftauth);
	os_memcpy(msg.data,&ftauth,msg.data_len);
	send_user_sync_msg(hapd,msg,dst_addr);
	return 0;
	
}
int send_eag_sync_info(struct hostapd_data *hapd,SYNC_MSG msg)
{
    int i;
	for(i = 0;i < hapd->cluster_ap_num;i++){
		if(hapd->ap_data[i].state == RUN)
	        send_user_sync_msg(hapd,msg,hapd->ap_data[i].ip_addr);
	}
}
int send_user_list_info(struct hostapd_data *hapd,u32 dst_addr)
{
	
	struct sta_sync msg_sta;
    struct sta_info *sta = hapd->sta_list;
	
	while(sta != NULL){
        int i;
		SYNC_MSG msg;
		struct sta_sync_list sta_list;

		os_memset(&msg,0,sizeof(msg));
		os_memset(&sta_list,0,sizeof(sta_list));
        msg.type = SYNC_STA_LIST;
		msg.data_len = sizeof(sta_list);
		u8* pos = sta_list.buf;
        for(i = 0;i < 10;i++){
			if(sta != NULL){
				os_memset(&msg_sta, 0, sizeof(msg_sta));
                os_memcpy(msg_sta.vap_mac,hapd->own_addr,ETH_ALEN);
	            os_memcpy(msg_sta.addr,sta->addr,ETH_ALEN);
	            os_strncpy(msg_sta.iface, hapd->conf->iface, IFNAMSIZ+1);
	            os_strncpy(msg_sta.bridge, hapd->conf->bridge, IFNAMSIZ+1);
	            os_strncpy(msg_sta.ssid, hapd->conf->ssid.ssid, hapd->conf->ssid.ssid_len);
	            msg_sta.ipaddr = sta->ipaddr;
				os_memcpy(sta_list.buf,&msg_sta, sizeof(msg_sta));
				sta_list.sta_num++;
				pos += sizeof(msg_sta);
				sta = sta->next;
			}else{
                break;
			}
			
        }

		os_strncpy(sta_list.ssid, hapd->conf->ssid.ssid, hapd->conf->ssid.ssid_len);
		os_memcpy(sta_list.vap_mac, hapd->own_addr,ETH_ALEN);
		os_memcpy(msg.data, &sta_list, sizeof(sta_list));
		send_user_sync_msg(hapd,msg,dst_addr);				
	}
}

int send_pmksa_okc_info(struct hostapd_data *hapd,struct rsn_pmksa_cache_entry *entry)
{
    SYNC_MSG msg;
	os_memset(&msg,0,sizeof(msg));
	struct pmksa_okc_entry okc_entry;
	os_memset(&okc_entry,0,sizeof(okc_entry));
	int i;

    os_strncpy(okc_entry.ssid, hapd->conf->ssid.ssid, hapd->conf->ssid.ssid_len);
    os_memcpy(okc_entry.vap_mac,hapd->own_addr,ETH_ALEN);
	os_memcpy(&okc_entry.entry,entry,sizeof(*entry));
    
	msg.type = SYNC_PMKSA_OKC;
	msg.data_len = sizeof(okc_entry);
	
	os_memcpy(msg.data,&okc_entry,msg.data_len);
	
    for(i = 0;i < hapd->cluster_ap_num;i++){
		if(hapd->ap_data[i].state == RUN)
	        send_user_sync_msg(hapd,msg,hapd->ap_data[i].ip_addr);
	}
}
int set_own_r0kh(struct hostapd_data *hapd)
{
    struct ft_remote_r0kh *r0kh;

	r0kh = os_zalloc(sizeof(*r0kh));
	if (r0kh == NULL)
		return -1;
	os_memcpy(r0kh->addr,hapd->own_addr,ETH_ALEN);
	r0kh->id_len = os_strlen(hapd->conf->nas_identifier);
	os_memcpy(r0kh->id,hapd->conf->nas_identifier,r0kh->id_len);
	hexstr2bin(FT_KEY, r0kh->key, sizeof(r0kh->key));
	r0kh->next = hapd->conf->r0kh_list;
	hapd->conf->r0kh_list = r0kh;

}
struct ft_remote_r0kh * get_r0kh(struct hostapd_data *hapd,u8 *vap_mac)
{
    struct ft_remote_r0kh *r0kh;
	r0kh = hapd->conf->r0kh_list;
	while(r0kh){
        if(os_memcmp(r0kh->addr,vap_mac,ETH_ALEN) == 0)
			return r0kh;
		r0kh = r0kh->next;
	}
	return r0kh;
}
struct ft_remote_r1kh * get_r1kh(struct hostapd_data *hapd,u8 *vap_mac)
{
    struct ft_remote_r1kh *r1kh;
	r1kh = hapd->conf->r1kh_list;
	while(r1kh){
        if(os_memcmp(r1kh->addr,vap_mac,ETH_ALEN) == 0)
			return r1kh;
		r1kh = r1kh->next;
	}
	return r1kh;
}
int set_r0kh_r1kh(struct hostapd_data *hapd,struct rsn_80211r *ftauth)
{
    struct ft_remote_r0kh *r0kh;
	struct ft_remote_r1kh *r1kh;
	
    r0kh = get_r0kh(hapd,ftauth->vap_mac);
	if(r0kh == NULL){
	    r0kh = os_zalloc(sizeof(*r0kh));
	    if (r0kh == NULL)
		    return -1;
	    os_memcpy(r0kh->addr,ftauth->vap_mac,ETH_ALEN);
	    r0kh->id_len = os_strlen(ftauth->nas_id);
	    os_memcpy(r0kh->id,ftauth->nas_id,r0kh->id_len);
	    hexstr2bin(FT_KEY, r0kh->key, sizeof(r0kh->key));
	    r0kh->next = hapd->conf->r0kh_list;
	    hapd->conf->r0kh_list = r0kh;
	}

	r1kh = get_r1kh(hapd,ftauth->vap_mac);
	if(r1kh == NULL){
	    r1kh = os_zalloc(sizeof(*r1kh));
	    if (r1kh == NULL)
		    return -1;
        os_memcpy(r1kh->addr,ftauth->vap_mac,ETH_ALEN);
	    os_memcpy(r1kh->id,ftauth->r1_kh,FT_R1KH_ID_LEN);
	    hexstr2bin(FT_KEY, r1kh->key, sizeof(r1kh->key));
	    r1kh->next = hapd->conf->r1kh_list;
    	hapd->conf->r1kh_list = r1kh;
	}
	return 0;

}


int show(struct hostapd_data *hapd)
{
	struct ft_remote_r0kh *r0kh = hapd->conf->r0kh_list;
	struct ft_remote_r1kh *r1kh = hapd->conf->r1kh_list;

	while(r0kh) {
		wpa_printf(MSG_DEBUG, "r0kh = "MACSTR" %s %s", MAC2STR(r0kh->addr), r0kh->id, FT_KEY);
		r0kh = r0kh->next;
	}

	while(r1kh) {
		wpa_printf(MSG_DEBUG, "r1kh = "MACSTR" "MACSTR" %s", MAC2STR(r1kh->addr), MAC2STR(r1kh->id), FT_KEY);
		r1kh = r1kh->next;
	}
}
void hostapd_sync_iface_deinit(struct hostapd_data *hapd)
{
	l2_packet_deinit(hapd->sock_sync);
}



