#ifndef __BAND_STEERING_H
#define __BAND_STEERING_H

#include <linux/types.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/list.h>
#include <ieee80211_var.h>
#include <han_ioctl.h>
#include "han_command.h"

enum ieee80211_dcm_flag {
    IEEE80211_DCM_FLAG_PROBE_RESP_WH = 1 << 0,  /* withhold probe responses */
};

int han_dcm_flag_check(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN],
                         enum ieee80211_dcm_flag flag);
int han_dcm_check(wlan_if_t vap,const u_int8_t mac[IEEE80211_ADDR_LEN]);
int han_dcm_set_flag(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN],
                       enum ieee80211_dcm_flag flag);
int han_dcm_clr_flag(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN],
                       enum ieee80211_dcm_flag flag);
int han_dcm_send_deny_auth(struct ieee80211_node *ni,const u_int8_t mac[IEEE80211_ADDR_LEN],int status);
int ieee80211_dcm_ioctl(struct net_device *dev,struct han_ioctl_priv_args *a,struct iwreq *iwr);

#endif
