
#include <han_dcm.h>
#include <ieee80211_var.h>
#include <osif_private.h>
#include "ieee80211_ioctl.h"
#include "han_ioctl.h"
#include "if_athvar.h"

#define	DCM_HASHSIZE	256 //256
#define TABLE_LIMIT		512

#define __lbMidx(_arg, _i) (((u_int8_t *)_arg)[_i])
/*
 * Create a Hash out of a MAC address
 */
#define DCM_MAC_HASH(_arg) (__lbMidx(_arg, 0) ^ __lbMidx(_arg, 1) ^ __lbMidx(_arg, 2) \
		^ __lbMidx(_arg, 3) ^ __lbMidx(_arg, 4) ^ __lbMidx(_arg, 5)) /* convert to use the HD_ETH_ADDR_LEN constant */

#pragma pack(push, 1)
struct dcm_client_entry {
    /* 
     * list element for linking on acl_list 
     */
    TAILQ_ENTRY(dcm_client_entry)     ce_list; 
	
    /* 
     * list element for linking on acl_hash list 
     */
    LIST_ENTRY(dcm_client_entry)      ce_hash; 
	
	u_int8_t    mac[IEEE80211_ADDR_LEN];
	struct {
	u_int8_t    channel;
	u_int8_t    occupyflag;
	u_int8_t    ce_flags;
	struct ieee80211com  *ic;
	}wifi[3];
	u_int8_t	denycnt;
	u_int32_t	timestamp;
};


struct ieee80211_dcm
{
	spinlock_t 				 dcm_lock;
	unsigned int                      	 dcm_debug;
	struct ieee80211com  		*ic[3];
	TAILQ_HEAD(, dcm_client_entry)    dcm_list; /* list of all dcm_entries */
	ATH_LIST_HEAD(, dcm_client_entry) dcm_hash[DCM_HASHSIZE];
};

#pragma pack(pop)


static struct  ieee80211_dcm *g_dcm = NULL;

static unsigned int g_dcm_debug = 0;
static unsigned long g_dcm_entry_num = 0;


static void dcm_free_all_locked(struct ieee80211_dcm *dcm);

static inline int HAN_MACCMP(const void *_mac1, const void *_mac2)
{
	const u8 *mac1 = _mac1;
	const u8 *mac2 = _mac2;
	if(NULL == mac1){
		printk("_mac1 is NULL\n");
		return -1;
	}
	if(NULL == mac2){
		printk("_mac2 is NULL\n");
		return -1;
	}
	return ((mac1[0] ^ mac2[0]) | (mac1[1] ^ mac2[1]) | (mac1[2] ^ mac2[2]) | (mac1[3] ^ mac2[3]) | (mac1[4] ^ mac2[4]) | (mac1[5] ^ mac2[5]));
}

#define HAN_ADDR_EQ(a1,a2)        (HAN_MACCMP(a1, a2) == 0)

static __inline struct dcm_client_entry * 
_find_dcm(struct ieee80211_dcm *dcm, const u_int8_t *macaddr)
{
    struct dcm_client_entry *entry;
    unsigned char hash =0;

    hash = DCM_MAC_HASH(macaddr);
	//printk("find dcm hash = %d\n",hash);
	
    LIST_FOREACH(entry, &dcm->dcm_hash[hash], ce_hash) {
        if (HAN_ADDR_EQ(entry->mac, macaddr))
            return entry;
    }
    return NULL;
}
static void
_dcm_free(struct  ieee80211_dcm *dcm, struct dcm_client_entry *entry)
{
    TAILQ_REMOVE(&dcm->dcm_list, entry, ce_list);
    LIST_REMOVE(entry, ce_hash);
    OS_FREE(entry);
}

int han_dcm_attach(void)
{
   // g_dcm = (struct  ieee80211_dcm *) OS_MALLOC(NULL,sizeof(struct ieee80211_dcm), 0);
    g_dcm = (struct  ieee80211_dcm *) kmalloc(sizeof(struct ieee80211_dcm), GFP_KERNEL);

    if (g_dcm) {
        //OS_MEMZERO(g_dcm, sizeof(struct ieee80211_dcm));
		memset(g_dcm,0x0,sizeof(struct ieee80211_dcm));
        spin_lock_init(&g_dcm->dcm_lock);
        TAILQ_INIT(&g_dcm->dcm_list);
		printk("g_dcm malloc ok!\n");
		g_dcm_entry_num = 0;
        return EOK;
    }
    return ENOMEM;
}

int han_dcm_detach(wlan_if_t vap)
{
    if (g_dcm == NULL)
        return EINPROGRESS; /* already detached or never attached */

    dcm_free_all_locked(g_dcm);
    spin_lock_destroy(&g_dcm->dcm_lock);
    OS_FREE(g_dcm);
    g_dcm = NULL;
    return EOK;
}
int han_dcm_send_deny_auth(struct ieee80211_node *ni,const u_int8_t mac[IEEE80211_ADDR_LEN], int status)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = ni->ni_ic;
	struct ieee80211_rsnparms *rsn;
	wbuf_t wbuf;
	struct ieee80211_frame *wh;
	u_int8_t *frm;

	wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
	if (wbuf == NULL)
		return -ENOMEM;
	IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
						  "[%s] send auth frmae \n ", ether_sprintf(ni->ni_macaddr)); 
	
	/* setup the wireless header */
	wh = (struct ieee80211_frame *)wbuf_header(wbuf);
	ieee80211_send_setup(vap, ni, wh,
						 IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_AUTH,
						 vap->iv_myaddr, mac, ni->ni_bssid);
	frm = (u_int8_t *)&wh[1];
	
	rsn = &vap->iv_rsn;


	if (RSN_AUTH_IS_SHARED_KEY(rsn) && (ni == vap->iv_bss || ni->ni_authmode == IEEE80211_AUTH_SHARED)) {
		*((u_int16_t *)frm) = htole16(IEEE80211_AUTH_ALG_SHARED);
		frm += 2;
	} else {
		*((u_int16_t *)frm) = htole16(ni->ni_authalg);
		frm += 2;
	}
	*((u_int16_t *)frm) = htole16(2); frm += 2;
	*((u_int16_t *)frm) = htole16(status); frm += 2;
	
	IEEE80211_VAP_LOCK(vap);
	if (vap->iv_app_ie[IEEE80211_FRAME_TYPE_AUTH].length) {
		OS_MEMCPY(frm, vap->iv_app_ie[IEEE80211_FRAME_TYPE_AUTH].ie, 
				  vap->iv_app_ie[IEEE80211_FRAME_TYPE_AUTH].length);
		frm += vap->iv_app_ie[IEEE80211_FRAME_TYPE_AUTH].length;
	}
#if ATH_SUPPORT_AOW
	if (IEEE80211_ENAB_AOW(ic)) {
		frm = ieee80211_mlme_app_ie_append(vap, IEEE80211_FRAME_TYPE_AUTH, frm);
	}
#endif  /* ATH_SUPPORT_AOW */    
	IEEE80211_VAP_UNLOCK(vap);


	wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));
	return ieee80211_send_mgmt(vap,ni, wbuf,false);
}

/*
* 
*return : 0  - two or three band has the same essid.
*           1  - only one band has the essid.
*/
int han_dcm_is_only_one_band(wlan_if_t vap)
{
	int i;
	struct ieee80211com  *ic = vap->iv_ic;
	struct ieee80211vap *tmpvap = NULL;
	
	if( g_dcm == NULL || vap == NULL)
		return 1;   //allow to acess.

	for ( i = 0; i < 3;i ++){
		if(g_dcm->ic[i] && (g_dcm->ic[i] != ic)){
		        tmpvap = TAILQ_FIRST(&g_dcm->ic[i]->ic_vaps);
		        while (tmpvap != NULL) {
					//printk("vap essid = %s ,esslen = %d\n",tmpvap->iv_bss->ni_essid,tmpvap->iv_bss->ni_esslen);
					if((tmpvap->iv_bss->ni_esslen == vap->iv_bss->ni_esslen) && \
						(strcmp(tmpvap->iv_bss->ni_essid,vap->iv_bss->ni_essid) == 0)){
						return 0;
					}
		            tmpvap = TAILQ_NEXT(tmpvap, iv_next);
		        }
		}
	}

	return 1;
}



//return 1 to report success
int han_dcm_check(wlan_if_t vap,const u_int8_t mac[IEEE80211_ADDR_LEN])
{
	int i ;
	int oneband = 0;
	struct dcm_client_entry *entry = NULL;

	if (g_dcm == NULL) return 1; //allow

	if(vap->iv_wps_mode){
		printk("\n WPS Enabled : Ignoring MAC Filtering\n");
		return 1; //allow 
	}

	spin_lock(&g_dcm->dcm_lock);
	entry = _find_dcm(g_dcm, mac);

	if(NULL == entry){
		spin_unlock(&g_dcm->dcm_lock);
		return 1;//allow
	}
	
	if(entry->denycnt){
		entry->denycnt --;
		if(g_dcm_debug == 1){
			printk("han_dcm_check %02X:%02X:%02X:%02X:%02X:%02X denycnt = %d\n",\
				mac[0],mac[1],mac[2],\
				mac[3],mac[4],mac[5],entry->denycnt);
		}

		IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
							  "[%s] auth: disallowed by dcm for  Load balance \n", ether_sprintf(mac));
		spin_unlock(&g_dcm->dcm_lock);

		return 0; //refused
	}else {
		for( i = 0; i < 3; i ++){
			if(entry->wifi[i].occupyflag && \
			    entry->wifi[i].ic == vap->iv_ic){
			    
			       /*if the vap essid is only on one band we allow the station*/
				oneband = han_dcm_is_only_one_band(vap);
				if(oneband){
					  IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
							  "[%s] auth: because only the essid is only on one band so allow\n", ether_sprintf(mac));
					  
					  spin_unlock(&g_dcm->dcm_lock);
					  return 1; //allow
				}
				
				if(entry->wifi[i].channel < 15){
				     IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
							  "[%s] auth: disallowed by dcm for 5G first  on 2.4G\n", ether_sprintf(mac));
				}else{
				    
				     IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
							  "[%s] auth: disallowed by dcm for 5G first  on 5G\n", ether_sprintf(mac));
				}
				
				if(g_dcm_debug == 1){
					printk("han_dcm_check %02X:%02X:%02X:%02X:%02X:%02X 5G first deny on channel = %d\n",\
						mac[0],mac[1],mac[2],\
						mac[3],mac[4],mac[5], entry->wifi[i].channel);
				}
				spin_unlock(&g_dcm->dcm_lock);
				return 0; //refused
			}
		}
		spin_unlock(&g_dcm->dcm_lock);
		return 1; //allow
	}
    spin_unlock(&g_dcm->dcm_lock);
    return entry != NULL;
}

int
han_dcm_flag_check(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN],
                         enum ieee80211_dcm_flag flag)
{
    struct dcm_client_entry *entry;
    int retval = 0;
	int i;

    if (g_dcm == NULL) return 0;
	
	if(g_dcm_debug == 1){
		printk("han_dcm_flag_check mac:\n");
		printk("%02X:%02X:%02X:%02X:%02X:%02X\n",\
			mac[0],mac[1],mac[2],\
			mac[3],mac[4],mac[5]);
	}

    spin_lock(&g_dcm->dcm_lock);
    entry = _find_dcm(g_dcm, mac);
    if(!entry){
		
		if(g_dcm_debug == 1){
			printk("han_dcm_flag_check can not find mac:\n ");
			printk("%02X:%02X:%02X:%02X:%02X:%02X\n",\
				mac[0],mac[1],mac[2],\
				mac[3],mac[4],mac[5]);
		}
	}
	
    if (entry) {
		for (i = 0; i < 3;i ++){
			if(entry->wifi[i].occupyflag && (entry->wifi[i].ic == vap->iv_ic)){
				if((entry->wifi[i].ce_flags & flag) == flag){
					retval = 1;
					break;
				}
			}
		}
    }
    spin_unlock(&g_dcm->dcm_lock);
    return retval;
}

int
han_dcm_set_flag(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN],
                       enum ieee80211_dcm_flag flag)
{
    struct dcm_client_entry *entry;
    int retval = -ENOENT;
	int i;
	
	if(g_dcm_debug == 1){
		printk("han_dcm_set_flag mac:\n");
		printk("%02X:%02X:%02X:%02X:%02X:%02X\n",\
			mac[0],mac[1],mac[2],\
			mac[3],mac[4],mac[5]);
	}

    if (g_dcm) {
        spin_lock(&g_dcm->dcm_lock);
        entry = _find_dcm(g_dcm, mac);
        if (entry) {
			for (i = 0; i < 3;i ++){
				if(entry->wifi[i].occupyflag &&(entry->wifi[i].ic == vap->iv_ic)){
					entry->wifi[i].ce_flags |= flag;
					retval = EOK;
					break;
				}
			}
        }
        spin_unlock(&g_dcm->dcm_lock);
    }

    return retval;
}
int
han_dcm_clr_flag(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN],
                       enum ieee80211_dcm_flag flag)
{
  //  ieee80211_acl_t acl = vap->iv_acl;
    struct dcm_client_entry *entry;
    int retval = -ENOENT;
	
	int i;
	
	if(g_dcm_debug == 1){
		printk("han_dcm_clr_flag mac:\n");
		printk("%02X:%02X:%02X:%02X:%02X:%02X\n",\
			mac[0],mac[1],mac[2],\
			mac[3],mac[4],mac[5]);
	}

    if (g_dcm) {
        spin_lock(&g_dcm->dcm_lock);
        entry = _find_dcm(g_dcm, mac);
        if (entry) {
			for (i = 0; i < 3;i ++){
				if(entry->wifi[i].occupyflag &&(entry->wifi[i].ic == vap->iv_ic)){
					entry->wifi[i].ce_flags &= ~flag;
					retval = EOK;
					break;
				}
			}
        }
        spin_unlock(&g_dcm->dcm_lock);
    }

    return retval;
}

struct dcm_client_entry * 
han_create_entry( const u_int8_t mac[IEEE80211_ADDR_LEN])
{
    struct dcm_client_entry *new;
    unsigned char hash;
	int  rc;
    if (g_dcm == NULL) {
        rc = han_dcm_attach();
        if (rc != EOK) return NULL;
    }

	
    hash = DCM_MAC_HASH(mac);

	if(g_dcm_debug == 2){
		printk("create_entry hash = %d\n",hash);
		return NULL;
	}

//    spin_lock_dpc(&g_dcm->dcm_lock);

    new = (struct dcm_client_entry *) OS_MALLOC(NULL,sizeof(struct dcm_client_entry), 0);
    if (new == NULL) return NULL;
    memset(new,0x0,sizeof(struct dcm_client_entry));
    IEEE80211_ADDR_COPY(new->mac, mac);
	
    TAILQ_INSERT_TAIL(&g_dcm->dcm_list, new, ce_list);
    LIST_INSERT_HEAD(&g_dcm->dcm_hash[hash], new, ce_hash);
 //   spin_unlock_dpc(&g_dcm->dcm_lock);

    return new;
}

struct dcm_client_entry * 
han_dcm_add(struct ieee80211com *ic,struct han_ioctl_priv_args *a)
{
    struct dcm_client_entry *entry, *new;
    int i, rc;
    if (g_dcm == NULL) {
        rc = han_dcm_attach();
        if (rc != EOK) return NULL;
    }	
	
	spin_lock_dpc(&g_dcm->dcm_lock);
	entry = _find_dcm(g_dcm,a->u.dcm.mac);
	if(entry){
		if(HAN_IOCTL_DCM_LBD_ADDMAC == a->u.dcm.subtype){
			for(i = 0; i < 3; i ++){
				/*has exist return*/
				if(entry->wifi[i].occupyflag && (entry->wifi[i].ic == ic)){
					spin_unlock_dpc(&g_dcm->dcm_lock);
					return entry;
				}
			}
			/*exist but not the same channel or not be add by lbd*/
			for(i = 0; i < 3; i ++){
				if(entry->wifi[i].occupyflag == 0){
					entry->wifi[i].occupyflag = 1;
					entry->wifi[i].channel = a->u.dcm.channel;
					entry->wifi[i].ic = ic;
					spin_unlock_dpc(&g_dcm->dcm_lock);
					return entry;
				}
			}
			
		}else if(HAN_IOCTL_DCM_BLANCE_ADDMAC == a->u.dcm.subtype){
			entry->denycnt =  a->u.dcm.denycnt;
		}
		spin_unlock_dpc(&g_dcm->dcm_lock);
		return entry;
	}
    /*not exist*/
	new = han_create_entry(a->u.dcm.mac);
	
	if(new){
		if(HAN_IOCTL_DCM_LBD_ADDMAC == a->u.dcm.subtype){
		 	new->wifi[0].occupyflag = 1;
			new->wifi[0].channel = a->u.dcm.channel;
			new->wifi[0].ic = ic;
		}else if(HAN_IOCTL_DCM_BLANCE_ADDMAC == a->u.dcm.subtype){
			new->denycnt =  a->u.dcm.denycnt;
		}
		g_dcm_entry_num ++;
	}
	spin_unlock_dpc(&g_dcm->dcm_lock);
    return new;
}


int 
han_dcm_remove(struct ieee80211com *ic,struct han_ioctl_priv_args *a)
{
	int i;
	int freeflag = 1;
    struct dcm_client_entry *entry = NULL;

    if (g_dcm == NULL) return EINVAL;

	if(g_dcm_debug == 1){
		printk("dcm delete mac:\n");
		printk("%02X:%02X:%02X:%02X:%02X:%02X\n",\
			a->u.dcm.mac[0],a->u.dcm.mac[1],a->u.dcm.mac[2],\
			a->u.dcm.mac[3],a->u.dcm.mac[4],a->u.dcm.mac[5]);
	}
	
    spin_lock_dpc(&g_dcm->dcm_lock);
    entry = _find_dcm(g_dcm, a->u.dcm.mac);
	if (entry != NULL){
		if(HAN_IOCTL_DCM_LBD_DELMAC == a->u.dcm.subtype){
			for(i = 0; i < 3; i ++){
				/*has exist */
				if(entry->wifi[i].occupyflag && (entry->wifi[i].ic == ic)){
					entry->wifi[i].occupyflag = 0;
					entry->wifi[i].channel = 0;
					entry->wifi[i].ic = NULL;
				}
				/*if other channel has set ,we do not free*/
				if(entry->wifi[i].occupyflag)
					freeflag = 0; 
			}
		}else if(HAN_IOCTL_DCM_BLANCE_DELMAC == a->u.dcm.subtype){
			entry->denycnt = 0;
		}
		
		/*if other channel has set ,we do not free*/
		for(i = 0; i < 3; i ++){
			if(entry->wifi[i].occupyflag)
				freeflag = 0; 
		}
		
		/*if blance is set ,we do not free*/
		if(entry->denycnt != 0)
			freeflag =0 ;
		
		if(freeflag){
			if(g_dcm_entry_num)
        	_dcm_free(g_dcm, entry);
			g_dcm_entry_num --;
		}
	}
	
    spin_unlock_dpc(&g_dcm->dcm_lock);
    return (entry == NULL ? ENOENT : 0);
}

static void
dcm_free_all_locked(struct ieee80211_dcm *dcm)
{
    struct dcm_client_entry *entry;
	
	if(dcm == NULL)
		return ;
	
    spin_lock_dpc(&dcm->dcm_lock); 
    while (!TAILQ_EMPTY(&dcm->dcm_list)) {
        entry = TAILQ_FIRST(&dcm->dcm_list);
        _dcm_free(dcm, entry);
    }
    spin_unlock_dpc(&dcm->dcm_lock);
}


int han_dcm_flush(void)
{
    if (g_dcm == NULL) return EINVAL;
    dcm_free_all_locked(g_dcm);
	g_dcm_entry_num = 0;
    return 0;
}

int han_dcm_print_client_info(void)
{
    struct dcm_client_entry *entry;
     unsigned char *mac = NULL;

    int i;
    if (g_dcm == NULL) {
		printk("han_dcm_print_client_info g_dcm == NULL\n");
        return 0;
    }
	
	if(g_dcm_debug == 1){
		printk("han_dcm_print_client_info\n");
	}
	
	printk("g_dcm_entry_num = %lu\n",g_dcm_entry_num);

    spin_lock_dpc(&g_dcm->dcm_lock); 

    TAILQ_FOREACH(entry, &g_dcm->dcm_list, ce_list) {
		if(entry){
			mac = entry->mac;
			printk("%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
			printk("\tLoad balance : deny cnt = %d\n",entry->denycnt);
			for (i = 0; i < 3;i ++){
				if(entry->wifi[i].occupyflag){
					if(entry->wifi[i].channel < 15){
						printk("5G first: deny on  2.4G\n");
					}else {
						printk("5G first: deny on  5G\n");
					}
				}
			}
		}
    }
    spin_unlock_dpc(&g_dcm->dcm_lock);
	return 0;
}

u_int32_t
get_ic_sta_assoc_from_wifi_name(const char* dev_name) 
{
	struct ath_softc_net80211 *scn = NULL;
	struct ieee80211com *ic = NULL;
	struct net_device *dev = NULL;


#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23))
			dev = dev_get_by_name(&init_net,dev_name);
#else
			dev = dev_get_by_name(dev_name);
#endif

	if (!dev) {
	//	printk("%s: device %s not Found! \n", __func__, dev_name);
		return 0;
	}

	scn = ath_netdev_priv(dev);
	if (scn == NULL)  {
		return 0;
	}

	ic = &scn->sc_ic;
	if (ic == NULL) {
		return 0;
	}
	
	return ic->ic_sta_assoc;

}


int han_dcm_get_client_num(struct ieee80211com *ic,struct han_ioctl_priv_args *a)
{
#if 0
	unsigned int stanum = 0;
	stanum += get_ic_sta_assoc_from_wifi_name("wifi0");
	stanum += get_ic_sta_assoc_from_wifi_name("wifi1");
	stanum += get_ic_sta_assoc_from_wifi_name("wifi2");
	a->u.dcm.value = stanum;
	
	if(g_dcm_debug == 1){
		printk("Now %d staions assoc this AP!\n",a->u.dcm.value);
	}
#endif
      a->u.dcm.value =  ic->ic_sta_assoc;

      return a->u.dcm.value;
}


int han_dcm_get_client(struct han_ioctl_priv_args *a)
{
    struct dcm_client_entry *entry;
    unsigned char *mac = NULL;

    int i;
    if (g_dcm == NULL) {
		printk("han_dcm_print_client_info g_dcm == NULL\n");
        return 0;
    }
	
	if(g_dcm_debug == 1){
		printk("han_dcm_get_client\n");
	}

    spin_lock_dpc(&g_dcm->dcm_lock); 
    entry = _find_dcm(g_dcm, a->u.dcm.mac);
	if(entry){
			mac = entry->mac;
			a->u.dcm.denycnt = entry->denycnt;
			a->u.dcm.value = 1;
			memcpy(a->u.dcm.mac,entry->mac,IEEE80211_ADDR_LEN);
			
			for (i = 0; i < 3;i ++){
				a->u.dcm.wifi[i].channel = entry->wifi[i].channel;
				a->u.dcm.wifi[i].occupyflag = entry->wifi[i].occupyflag;
				a->u.dcm.wifi[i].ce_flags = entry->wifi[i].ce_flags;
			}

			if(g_dcm_debug == 1){
				printk("%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
				printk("\tdeny cnt = %d\n",entry->denycnt);
				printk("a->u.dcm.value = %d\n",a->u.dcm.value);
				for (i = 0; i < 3;i ++){
					if(entry->wifi[i].occupyflag){
						printk("\twifi[%d]:\n",i);
						printk("\t	occupyflag	= %d\n",entry->wifi[i].occupyflag); 
						printk("\t	channel  = %d\n",entry->wifi[i].channel);					
						printk("\t	ce_flags = %d\n",entry->wifi[i].ce_flags);
					}
				}
			}
	}else {
		a->u.dcm.value = 0;
		if(g_dcm_debug == 1){
				printk("driver: No client %02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
				printk("a->u.dcm.value = %d\n",a->u.dcm.value);
		}
	}
    spin_unlock_dpc(&g_dcm->dcm_lock);
	return 0;
}


void han_dcm_debug(struct han_ioctl_priv_args *a)
{
    int rc;

	if (g_dcm == NULL) {
	   rc = han_dcm_attach();
	   if (rc != EOK){
		   printk("g_dcm init error!\n");
		   return ;
	   } 
	}
	
	if(OP_SET == a->u.dcm.op){
		printk("OP_SET value = %d \n",a->u.dcm.value);
		//g_dcm_debug = a->u.dcm.value;
		g_dcm_debug = a->u.dcm.value;
	}else {
		//a->u.dcm.value = g_dcm_debug;
		a->u.dcm.value = g_dcm_debug;
	}
}

void han_dcm_upgrade_ic_info(struct ieee80211com *ic)
{
	int i;
	
	if(NULL == ic || NULL == g_dcm)
		return;
	
	for(i = 0;i < 3;i ++){
		if(g_dcm->ic[i]){
			if(ic == g_dcm->ic[i])
			     return ;
			else
			     continue;
		}else{
			g_dcm->ic[i] = ic;
			return;
		}
	}

}

int han_dcm_ioctl(struct ieee80211com *ic,
	                 struct han_ioctl_priv_args *a,
	                 struct iwreq *iwr)
{

	if(g_dcm_debug == 1){
		printk("driver: MAC:%02X:%02X:%02X:%02X:%02X:%02X\n",
			   a->u.dcm.mac[0],a->u.dcm.mac[1],a->u.dcm.mac[2],\
			   a->u.dcm.mac[3],a->u.dcm.mac[4],a->u.dcm.mac[5]);

		printk("driver: subtype = %d ,op = %d ,channel = %d,denycnt = %d\n",
			  a->u.dcm.subtype,a->u.dcm.op,a->u.dcm.channel,a->u.dcm.denycnt);
	}
	han_dcm_upgrade_ic_info(ic);
	switch (a->u.dcm.subtype) {
		case HAN_IOCTL_DCM_LBD_DELMAC:
		case HAN_IOCTL_DCM_BLANCE_DELMAC:
			han_dcm_remove(ic,a);
			break;
		case HAN_IOCTL_DCM_LBD_ADDMAC:
		case HAN_IOCTL_DCM_BLANCE_ADDMAC:
			han_dcm_add(ic,a);
			break;
		case HAN_IOCTL_DCM_FLUSH:
			han_dcm_flush();
			break;
		case HAN_IOCTL_DCM_PRINT_LIST:
			han_dcm_print_client_info();
			break;
		case HAN_IOCTL_DCM_DEBUG:
			han_dcm_debug(a);
			break;
		case HAN_IOCTL_DCM_GET_CLIENT:
			han_dcm_get_client(a);
			break;
		case HAN_IOCTL_DCM_GET_CLIENT_NUM:
			han_dcm_get_client_num(ic,a);
			break;
		default:
			return -EFAULT; 	
	}
	
	if(OP_GET == a->u.dcm.op){
		copy_to_user(iwr->u.data.pointer,a, sizeof(struct han_ioctl_priv_args));
	}
	return 0;
}

int
ieee80211_dcm_ioctl(struct net_device *dev,struct han_ioctl_priv_args *a,struct iwreq *iwr)
{
#define HAN_IOCTL_DCM_LOWRSSI_THRESH 9
#define HAN_IOCTL_DCM_LOWRSSI_STATUS 10
	osif_dev *osifp = ath_netdev_priv(dev);
      wlan_if_t vap = osifp->os_if;
	
	switch (a->u.dcm.subtype) {
		case HAN_IOCTL_DCM_LOWRSSI_THRESH:
			if(OP_SET == a->u.dcm.op){
				vap->iv_lowrssi_threshold = a->u.dcm.value;
			}else {
                          a->u.dcm.value = vap->iv_lowrssi_threshold;
			}
			break;
		case HAN_IOCTL_DCM_LOWRSSI_STATUS:
			if(OP_GET == a->u.dcm.op){
			     a->u.dcm.value = vap->iv_lowrssi_refuse;
			}
			break;
		default:
			return -EFAULT; 	
	}
	
	if(OP_GET == a->u.wmm.op){
		copy_to_user(iwr->u.data.pointer, a, sizeof(struct han_ioctl_priv_args));
	}
	
	return 0;
}

