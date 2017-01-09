// vim: set et sw=4 sts=4 cindent:
/*
 * @File: wlanifBSteerControl.c
 *
 * @Abstract: Load balancing daemon band steering control interface
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 *
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/types.h>
#define _LINUX_IF_H /* Avoid redefinition of stuff */
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/wireless.h>
#include <net/if_arp.h>   // for ARPHRD_ETHER
#include <errno.h>
#include <limits.h>

#include "ieee80211_external.h"

#ifdef GMOCK_UNIT_TESTS
#include "strlcpy.h"
#endif

#include <dbg.h>
#include <split.h>
#include <evloop.h>

#include <diaglog.h>

#include "profile.h"
#include "module.h"
#include "internal.h"
#include "lbd_assert.h"

#include "wlanifPrivate.h"
#include "wlanifBSteerControl.h"
#include "han_dcm.h"
// forward decls
static LBD_BOOL wlanifBSteerControlIsBandValid(wlanifBSteerControlHandle_t state, wlanif_band_e band);

static struct wlanifBSteerControlRadioInfo *wlanifBSteerControlLookupRadioByIfname(
        wlanifBSteerControlHandle_t state, const char *ifname);
static LBD_STATUS wlanifBSteerControlResolveRadioStatsIoctl(
        wlanifBSteerControlHandle_t state,
        struct wlanifBSteerControlRadioInfo *radio);
static void wlanifBSteerControlFindRadioStatsIoctl(
        wlanifBSteerControlHandle_t state,
        struct wlanifBSteerControlRadioInfo *radio,
        size_t numIoctls,
        struct iw_priv_args *privArgs);

static struct wlanifBSteerControlVapInfo * wlanifBSteerControlAllocateVap(wlanifBSteerControlHandle_t state,
                                                                          wlanif_band_e band);
static struct wlanifBSteerControlVapInfo * wlanifBSteerControlInitVapFromIfname(
        wlanifBSteerControlHandle_t state, const char *ifname,
        struct wlanifBSteerControlRadioInfo *radio);
static struct wlanifBSteerControlVapInfo *wlanifBSteerControlExtractVapHandle(
        const lbd_bssInfo_t *bss);
static LBD_STATUS wlanifBSteerControlDisableNoDebug(wlanifBSteerControlHandle_t state,
                                                     const lbd_bssInfo_t *bss);
static LBD_STATUS wlanifBSteerControlEnableNoDebug(wlanifBSteerControlHandle_t state,
                                                     const lbd_bssInfo_t *bss);
static LBD_STATUS wlanifBSteerControlStoreSSID(
    wlanifBSteerControlHandle_t state,
    const char *ifname,
    struct wlanifBSteerControlVapInfo *vap,
    u_int8_t length,
    u_int8_t *ssidStr);
static LBD_STATUS wlanifBSteerControlGetSSID(
    wlanifBSteerControlHandle_t state, const char *ifname,
    struct wlanifBSteerControlVapInfo *vap);

static LBD_STATUS wlanifBSteerControlResolveWlanIfaces(
        wlanifBSteerControlHandle_t state);

static LBD_STATUS wlanifBSteerControlInitializeACLs(
        wlanifBSteerControlHandle_t handle, wlanif_band_e band);
static void wlanifBSteerControlFlushACLs(
        wlanifBSteerControlHandle_t handle, wlanif_band_e band);
static void wlanifBSteerControlTeardownACLs(
        wlanifBSteerControlHandle_t handle, wlanif_band_e band);

static LBD_STATUS wlanifBSteerControlReadConfig(wlanifBSteerControlHandle_t state, wlanif_band_e band);
static LBD_STATUS wlanifBSteerControlSendEnable(wlanifBSteerControlHandle_t state, wlanif_band_e band, LBD_BOOL enable);
static LBD_STATUS wlanifBSteerControlSendSetParams(wlanifBSteerControlHandle_t state, wlanif_band_e band);
static LBD_STATUS wlanifBSteerControlSendRequestRSSI(wlanifBSteerControlHandle_t state,
                                                     struct wlanifBSteerControlVapInfo *vap,
                                                     const struct ether_addr * staAddr, u_int8_t numSamples);
static inline LBD_STATUS wlanifBSteerControlSendFirstVAP(wlanifBSteerControlHandle_t state,
                                                         wlanif_band_e band, u_int8_t cmd,
                                                         const struct ether_addr *destAddr,
                                                         void *data, int data_len);
static inline LBD_STATUS wlanifBSteerControlSendVAP(wlanifBSteerControlHandle_t state,
                                             const char *ifname, u_int8_t cmd,
                                             const struct ether_addr *destAddr,
                                             void *data, int data_len,
                                             void *output, int output_len);
static LBD_STATUS wlanifBSteerControlGetSendVAP(wlanifBSteerControlHandle_t state,
                                                const char *ifname, u_int8_t cmd,
                                                const struct ether_addr *destAddr,
                                                void *output, int output_len);
static LBD_STATUS wlanifBSteerControlSetSendVAP(wlanifBSteerControlHandle_t state,
                                                const char *ifname, u_int8_t cmd,
                                                const struct ether_addr *destAddr,
                                                void *data, int data_len);

static LBD_STATUS wlanifBSteerControlPrivIoctlSetParam(
        wlanifBSteerControlHandle_t state,
        struct wlanifBSteerControlRadioInfo *radio,
        int paramId, int val);

static LBD_STATUS wlanifBSteerControlResolvePHYCapInfo(wlanifBSteerControlHandle_t state);
static struct wlanifBSteerControlVapInfo *wlanifBSteerControlGetVAPFromSysIndex(
    wlanifBSteerControlHandle_t state,
    int sysIndex,
    wlanif_band_e indexBand);
static struct wlanifBSteerControlVapInfo *wlanifBSteerControlGetFirstVAPByChannel(
    wlanifBSteerControlHandle_t state,
    lbd_channelId_t channelId);
static LBD_STATUS wlanifBSteerControlDumpATFTableOneIface(
        wlanifBSteerControlHandle_t state,
        struct wlanifBSteerControlVapInfo *vap,
        wlanif_reservedAirtimeCB callback, void *cookie);
static void wlanifBSteerControlNotifyChanChangeObserver(
        wlanifBSteerControlHandle_t state,
        struct wlanifBSteerControlVapInfo *vap);
static void wlanifBSteerControlLogInterfaceInfo(wlanifBSteerControlHandle_t state,
                                                struct wlanifBSteerControlVapInfo *vap);

typedef LBD_STATUS (*wlanifBSteerControlNonCandidateCB)(wlanifBSteerControlHandle_t state,
                                                        struct wlanifBSteerControlVapInfo *vap,
                                                        void *cookie);
static void wlanifBSteerControlFindStrongestRadioOnBand(wlanifBSteerControlHandle_t state,
                                                        wlanif_band_e band);

// ====================================================================
// Internal types
// ====================================================================

// Maximum number of VAPs on a single band
#define MAX_VAP_PER_BAND 16

/**
 * @brief Structure used to define an ESS
 */
typedef struct wlanifBSteerControlEssInfo_t {
    // SSID length
    u_int8_t ssidLen;

    // SSID string
    u_int8_t ssidStr[IEEE80211_NWID_LEN+1];
} wlanifBSteerControlEssInfo_t;

/**
 * @brief Internal structure for the radios in the system.
 *
 * VAPs are enabled on a specific radio. This type is used to represent
 * characteristics and state of the radio that are shared across all
 * VAPs on the radio.
 */
struct wlanifBSteerControlRadioInfo {
    /// Flag indicating whether the entry is valid.
    LBD_BOOL valid : 1;

    /// Flag indicating if the radio has the highest Tx power on its band.
    /// For single radio, it is always LBD_TRUE
    LBD_BOOL strongestRadio : 1;

    /// Interface name, +1 to ensure it is null-terminated.
    char ifname[IFNAMSIZ + 1];

    /// The resolved number for the enable_ol_stats ioctl.
    int enableOLStatsIoctl;

    /// The resolved number for the Nodebug for direct attach hardware.
    int enableNoDebug;

    /// The number of calls to enable the stats that need to be disabled.
    size_t numEnableStats;

    /// Channel on which this radio is operating.
    lbd_channelId_t channel;

    /// Regulatory class in which this radio is operating.
    u_int8_t regClass;

    /// Maximum Tx power on this radio
    u_int8_t maxTxPower;
   u_int8_t  hassetParam;
    // a list of STAs whose RSSI measurement is requested
    list_head_t rssiWaitingList;
};

/**
 * @brief internal structure for VAP information
 */
struct wlanifBSteerControlVapInfo {
    // flag indicating if this VAP is valid
    LBD_BOOL valid;

    // interface name, +1 to ensure it is null-terminated
    char ifname[IFNAMSIZ + 1];

    /// Reference to the radio that "owns" this VAP.
    struct wlanifBSteerControlRadioInfo *radio;

    // system index
    int sysIndex;

    u_int8_t  rssi_threshold;//pengdecai for dcm.
    // Whether the interface is considered up or not
    LBD_BOOL ifaceUp;

    // MAC address of this VAP
    struct ether_addr macaddr;

    // PHY capabilities information
    wlanif_phyCapInfo_t phyCapInfo;

    // ID corresponding to the ESS
    lbd_essId_t essId;
};

/**
 * @brief internal structure for the STA whose RSSI is requested
 */
typedef struct {
    // Double-linked list for use in a given list
    list_head_t listChain;

    // The MAC address of the STA whose RSSI is requested
    struct ether_addr addr;

    // The VAP ths STA is associated with
    struct wlanifBSteerControlVapInfo *vap;

    // number of RSSI samples to average before reporting RSSI back
    u_int8_t numSamples;
} wlanifBSteerControlRSSIRequestEntry_t;

/**
 * @brief internal structure for band information
 */
struct wlanifBSteerControlBandInfo {
    // All VAPs on this band
    struct wlanifBSteerControlVapInfo vaps[MAX_VAP_PER_BAND];

    // config parameters
    ieee80211_bsteering_param_t configParams;

    // flag indicating if band steering is enabled on this band
    LBD_BOOL enabled;

    // duration for 802.11k beacon report
    u_int32_t bcnrptDurations[IEEE80211_RRM_BCNRPT_MEASMODE_RESERVED];
};

struct wlanifBSteerControlPriv_t {
    struct dbgModule *dbgModule;

    struct wlanifBSteerControlRadioInfo radioInfo[WLANIF_MAX_RADIOS];

    struct wlanifBSteerControlBandInfo bandInfo[wlanif_band_invalid];

    // Socket used to send control request down to driver
    int controlSock;

    /// Timer used to periodically check whether ACS and CAC have completed
    struct evloopTimeout vapReadyTimeout;

    /// Flag indicating whether band steering is currently enabled.
    LBD_BOOL bandSteeringEnabled;

    /// Number of ESSes supported on this device
    u_int8_t essCount;

    /// Structure used to map ESS string to an ID (for
    /// simpler comparisons.  Each VAP on a radio must have a
    /// unique ESSID.  Index into this array will be the
    /// essId.
    wlanifBSteerControlEssInfo_t essInfo[MAX_VAP_PER_BAND];

// For now, we are only permitting two observers, as it is likely that the
// following will need to observe channel change
//
// 1. Station database
// 2. Steering executor
#define MAX_CHAN_CHANGE_OBSERVERS 2
    /// Observer for channel change
    struct wlanifBSteerControlChanChangeObserver {
        LBD_BOOL isValid;
        wlanif_chanChangeObserverCB callback;
        void *cookie;
    } chanChangeObserver[MAX_CHAN_CHANGE_OBSERVERS];
};

typedef struct wlanifBSteerControlNonCandidateSet_t {
    const struct ether_addr *staAddr;
    LBD_BOOL enable;
    LBD_BOOL probeOnly;
} wlanifBSteerControlNonCandidateSet_t;

typedef struct wlanifBSteerControlNonCandidateGet_t {
    u_int8_t maxCandidateCount;
    u_int8_t outCandidateCount;
    lbd_bssInfo_t *outCandidateList;
} wlanifBSteerControlNonCandidateGet_t;


struct profileElement wlanifElementDefaultTable_24G[] = {
    {WLANIFBSTEERCONTROL_INACT_IDLE_THRESHOLD,        "10"},
    {WLANIFBSTEERCONTROL_INACT_OVERLOAD_THRESHOLD,    "10"},
    {WLANIFBSTEERCONTROL_INACT_RSSI_XING_HIGH_THRESHOLD, "45"},
    // Not expect RSSI crossing event from idle client when it
    // crosses this inact_low_threshold
    {WLANIFBSTEERCONTROL_INACT_RSSI_XING_LOW_THRESHOLD,  "0"},
    {WLANIFBSTEERCONTROL_LOW_RSSI_XING_THRESHOLD,     "10"},
    {WLANIFBSTEERCONTROL_MU_CHECK_INTERVAL,           "10"},
    {WLANIFBSTEERCONTROL_MU_AVG_PERIOD,               "60"},
    {WLANIFBSTEERCONTROL_INACT_CHECK_INTERVAL,        "1"},
    {WLANIFBSTEERCONTROL_BCNRPT_ACTIVE_DURATION,      "50"},
    {WLANIFBSTEERCONTROL_BCNRPT_PASSIVE_DURATION,     "200"},
    {WLANIFBSTEERCONTROL_HIGH_TX_RATE_XING_THRESHOLD, "50000"},
    // Note: Low Tx rate / Low rate RSSI crossing thresholds
    // not used for 2.4GHz interface,
    // set to 0, so an event will never be generated.
    {WLANIFBSTEERCONTROL_LOW_TX_RATE_XING_THRESHOLD,  "0"},
    {WLANIFBSTEERCONTROL_LOW_RATE_RSSI_XING_THRESHOLD,"0"},
    {WLANIFBSTEERCONTROL_HIGH_RATE_RSSI_XING_THRESHOLD,"40"},
    {NULL,                              NULL},
};

struct profileElement wlanifElementDefaultTable_5G[] = {
    {WLANIFBSTEERCONTROL_INACT_IDLE_THRESHOLD,        "10"},
    {WLANIFBSTEERCONTROL_INACT_OVERLOAD_THRESHOLD,    "10"},
    {WLANIFBSTEERCONTROL_INACT_RSSI_XING_HIGH_THRESHOLD, "30"},
    {WLANIFBSTEERCONTROL_INACT_RSSI_XING_LOW_THRESHOLD,  "0"},
    {WLANIFBSTEERCONTROL_LOW_RSSI_XING_THRESHOLD,     "10"},
    {WLANIFBSTEERCONTROL_MU_CHECK_INTERVAL,           "10"},
    {WLANIFBSTEERCONTROL_MU_AVG_PERIOD,               "60"},
    {WLANIFBSTEERCONTROL_INACT_CHECK_INTERVAL,        "1"},
    {WLANIFBSTEERCONTROL_BCNRPT_ACTIVE_DURATION,      "50"},
    {WLANIFBSTEERCONTROL_BCNRPT_PASSIVE_DURATION,     "200"},
    // Note: High Tx rate / High  crossing threshold not used for 5GHz interface,
    // set to maximum so an event will never be generated.
    {WLANIFBSTEERCONTROL_HIGH_TX_RATE_XING_THRESHOLD, "4294967295"},
    {WLANIFBSTEERCONTROL_LOW_TX_RATE_XING_THRESHOLD,  "6000"},
    {WLANIFBSTEERCONTROL_LOW_RATE_RSSI_XING_THRESHOLD,"0"},
    {WLANIFBSTEERCONTROL_HIGH_RATE_RSSI_XING_THRESHOLD,"255"},
    {NULL,                              NULL},
};

/*========================================================================*/
/*============ Internal handling =========================================*/
/*========================================================================*/

/**
 * @brief Enable or disable the band steering feature on a given band.
 *
 * @pre state and band are valid
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use to enable/disable band steering feature
 * @param [in] band  The band on which to enable/disable band steering feature
 * @param [in] enable  LBD_TRUE for enable, LBD_FALSE for disable
 *
 * @return LBD_OK on successful enable/disable; otherwise LBD_NOK
 */
static LBD_STATUS wlanifBSteerControlSetEnable(
        wlanifBSteerControlHandle_t state, wlanif_band_e band,
        LBD_BOOL enable) {
    // TODO Dan: There is no check for whether band is resolved here, since only
    //           after both bands are resolved, a valid handle will be returned.
    //           But it may be necessary after we add periodically VAP
    //           monitoring logic, some band may become invalid.

    if (enable && wlanifBSteerControlSendSetParams(state, band) == LBD_NOK) {
        dbgf(state->dbgModule, DBGERR, "%s: Failed to set band steering parameters on band %u",
             __func__, band);
        return LBD_NOK;
    }else {
        dbgf(state->dbgModule, DBGERR, "%s: successfull to set band steering parameters on band %u",
             __func__, band);
    }

    if (wlanifBSteerControlSendEnable(state, band, enable) == LBD_NOK) {
        dbgf(state->dbgModule, DBGERR, "%s: Failed to %s band steering on band %u",
             __func__, enable ? "enable" : "disable", band);
        return LBD_NOK;
    }else{
        dbgf(state->dbgModule, DBGERR, "%s: successfull to %s band steering on band %u",
             __func__, enable ? "enable" : "disable", band);

    }

    state->bandInfo[band].enabled = enable;

    dbgf(state->dbgModule, DBGINFO, "%s: Successfully %s band steering on band %u",
         __func__, enable ? "enabled" : "disabled", band);

    return LBD_OK;
}

/**
 * @brief Check if for a given band, there is at least one valid VAP
 *
 * @param [in] state  the "this" pointer
 * @param [in] band  the band to check
 *
 * @return LBD_TRUE if at least one VAP is valid; otherwise LBD_FALSE
 */
static LBD_BOOL
wlanifBSteerControlIsBandValid(wlanifBSteerControlHandle_t state,
                               wlanif_band_e band) {
    int i;
    for (i = 0; i < MAX_VAP_PER_BAND; ++i) {
        if (state->bandInfo[band].vaps[i].valid) {
            return LBD_TRUE;
        }
    }
    return LBD_FALSE;
}

/**
 * @brief For a given band, get an empty entry for VAP information
 *
 * @param [in] state  the "this" pointer
 * @param [in] band  the band to get VAP entry
 *
 * @return the empty VAP entry if any; otherwise NULL
 */
static struct wlanifBSteerControlVapInfo *
wlanifBSteerControlAllocateVap(wlanifBSteerControlHandle_t state,
                               wlanif_band_e band) {
    int i;
    for (i = 0; i < MAX_VAP_PER_BAND; ++i) {
        if (!state->bandInfo[band].vaps[i].valid) {
            memset(&state->bandInfo[band].vaps[i], 0, sizeof(state->bandInfo[band].vaps[i]));
            return &state->bandInfo[band].vaps[i];
        }
    }
    dbgf(state->dbgModule, DBGERR, "%s: No available VAP entry on band %u; "
                                   "maximum number of VAPs allowed on one band: %u",
        __func__, band, MAX_VAP_PER_BAND);
    return NULL;
}

/**
 * @brief Extract the VAP handle out of the BSS info and cast it to its proper
 *        type.
 *
 * @param [in] bss  the value from which to extract the VAP handle
 *
 * @return the VAP handle, or NULL if the BSS is invalid
 */
static struct wlanifBSteerControlVapInfo *wlanifBSteerControlExtractVapHandle(
        const lbd_bssInfo_t *bss) {
    if (bss) {
        return bss->vap;
    }

    return NULL;
}

/**
 * @brief For a given interface name, find the internal radio entry.
 *
 * If one does not exist, allocate it from one of the free slots.
 *
 * @param [in] state  the "this" pointer
 * @param [in] ifname  the interface name of the radio
 *
 * @return the found (or newly created) radio entry, or NULL if there are
 *         no more free slots for radios
 */
static struct wlanifBSteerControlRadioInfo *
wlanifBSteerControlLookupRadioByIfname(wlanifBSteerControlHandle_t state,
                                       const char *ifname) {
    struct wlanifBSteerControlRadioInfo *empty = NULL;

    size_t i;
    for (i = 0; i < sizeof(state->radioInfo) / sizeof(state->radioInfo[0]); ++i) {
        if (state->radioInfo[i].valid &&
            strcmp(ifname, state->radioInfo[i].ifname) == 0) {
            return &state->radioInfo[i];
        } else if (!state->radioInfo[i].valid && !empty) {
            empty = &state->radioInfo[i];
        }
    }
    if (empty) {
        strlcpy(empty->ifname, ifname, sizeof(empty->ifname));
        if (wlanifBSteerControlResolveRadioStatsIoctl(state, empty) != LBD_OK) {
            // A log will already have been generated.
            return NULL;
        }

        empty->valid = LBD_TRUE;

        // Set the channel to invalid, it will be filled in while adding VAPs.
        empty->channel = LBD_CHANNEL_INVALID;

        // Initialize waiting list for RSSI measurement to be empty
        list_set_head(&empty->rssiWaitingList);
    }

    return empty;
}

/**
 * @brief Examine the private ioctls to find the one to enable the offload
 *        stats.
 *
 * This will store the ioctl value in the radio object. If no matching ioctl
 * was found, a value of 0 is stored. This indicates it is not necessary to
 * enable/disable the stats.
 *
 * @param [in] state  the "this" pointer
 * @param [in] radio  the radio on which to resolve the ioctl
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerControlResolveRadioStatsIoctl(
        wlanifBSteerControlHandle_t state,
        struct wlanifBSteerControlRadioInfo *radio) {
    struct iw_priv_args *privArgs = NULL;

    // We do not know how many actual ioctls there are, so allocate a
    // reasonably large number to start with. If it is insufficient, the
    // kernel will tell us and we can re-allocate.
    size_t maxNumEntries = 256;
    privArgs = calloc(maxNumEntries, sizeof(struct iw_priv_args));
    if (!privArgs) {
        dbgf(state->dbgModule, DBGERR,
             "%s: Initial memory allocation failed for private ioctl buffer",
             __func__);
        return LBD_NOK;
    }

    struct iwreq wrq;
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, radio->ifname, sizeof(wrq.ifr_name));
    wrq.u.data.pointer = privArgs;
    wrq.u.data.length = maxNumEntries;

    LBD_STATUS result = LBD_OK;
    while (ioctl(state->controlSock, SIOCGIWPRIV, &wrq) < 0) {
        if (E2BIG == errno) {
            // Kernel can provide a hint of how many entries we need.
            if (wrq.u.data.length > maxNumEntries) {
                maxNumEntries = wrq.u.data.length;
            } else {
                maxNumEntries *= 2;
            }

            privArgs = realloc(privArgs, maxNumEntries * sizeof(struct iw_priv_args));
            if (!privArgs) {
                dbgf(state->dbgModule, DBGERR,
                     "%s: Failed to realloc for %u entries",
                     __func__, maxNumEntries);
                result = LBD_NOK;
                break;
            }

            wrq.u.data.pointer = privArgs;
            wrq.u.data.length = maxNumEntries;
        } else {
            dbgf(state->dbgModule, DBGERR,
                 "%s: ioctl failed on %s for unknown reason: %d",
                 __func__, wrq.ifr_name, errno);
            result = LBD_NOK;
            break;
        }
    }

    if (LBD_OK == result) {
        wlanifBSteerControlFindRadioStatsIoctl(state, radio,
                                                  wrq.u.data.length, privArgs);

        dbgf(state->dbgModule, DBGINFO,
             "%s: Resolved private stats ioctl on %s to %04x",
             __func__, radio->ifname, radio->enableOLStatsIoctl);
    }

    free(privArgs);
    return result;
}

/**
 * @brief Find the matching ioctl that can enable the offload stats.
 *
 * The value of the ioctl will be stored in the radio. If it is not found,
 * a value of 0 will be stored.
 *
 * @param [in] state  the "this" pointer
 * @param [in] radio  the radio on which to resolve the ioctl
 * @param [in] numIoctls  the number of ioctls described in privArgs
 * @param [in] privArgs  the description of the private ioctls
 */
void wlanifBSteerControlFindRadioStatsIoctl(
        wlanifBSteerControlHandle_t state,
        struct wlanifBSteerControlRadioInfo *radio,
        size_t numIoctls,
        struct iw_priv_args *privArgs) {
    // Loop over all of the entries looking for the match.
    size_t i = 0;
    radio->enableOLStatsIoctl = 0;
    radio->enableNoDebug = 0;

    for (i = 0; i < numIoctls; ++i) {
        if (strcmp(privArgs[i].name, "enable_ol_stats") == 0) {
            radio->enableOLStatsIoctl = privArgs[i].cmd;
            break;
        }
        if (strcmp(privArgs[i].name, "disablestats") == 0) {
            radio->enableNoDebug = privArgs[i].cmd;
            break;
        }
    }
}

/**
 * @brief Log the interface info
 *
 * @param [in] state  the "this" pointer
 * @param [in] vap  VAP to log interface info for
 */
static void wlanifBSteerControlLogInterfaceInfo(wlanifBSteerControlHandle_t state,
                                                struct wlanifBSteerControlVapInfo *vap) {
    if (diaglog_startEntry(mdModuleID_WlanIF, wlanif_msgId_interface,
                           diaglog_level_info)) {
        diaglog_writeMAC(&vap->macaddr);
        diaglog_write8(vap->radio->channel);
        diaglog_write8(vap->essId);
        diaglog_write8(state->essInfo[vap->essId].ssidLen);
        diaglog_write(state->essInfo[vap->essId].ssidStr,
                      state->essInfo[vap->essId].ssidLen);
        diaglog_write8(strlen(vap->ifname));
        diaglog_write(vap->ifname, strlen(vap->ifname));
        diaglog_finishEntry();
    }
}

/**
 * @brief Store the SSID that a VAP is operating on.  If this
 *        SSID is already known, just the essId index will be
 *        stored.  If the SSID is not known, a new essId index
 *        will be assigned.
 *
 * @param [in] state the "this" pointer
 * @param [in] ifname name of the interface this VAP is
 *                    operating on
 * @param [in] vap pointer to VAP structure
 * @param [in] length length of the SSID string for this VAP
 * @param [in] ssidStr SSID string for this VAP
 *
 * @return LBD_STATUS returns LBD_OK if the SSID is valid,
 *         LBD_NOK otherwise
 */
static LBD_STATUS
wlanifBSteerControlStoreSSID(wlanifBSteerControlHandle_t state,
                             const char *ifname,
                             struct wlanifBSteerControlVapInfo *vap,
                             u_int8_t length,
                             u_int8_t *ssidStr) {
    int i;

    if ((!length) || (length >= IEEE80211_NWID_LEN)) {
        dbgf(state->dbgModule, DBGERR, "%s: invalid ESSID length %d, ifName: %s",
             __func__, length, ifname);

        return LBD_NOK;
    }

    // Check if this ESSID is already known
    LBD_BOOL match = LBD_FALSE;
    for (i = 0; i < state->essCount; i++) {
        // Note memcmp is used here since the SSID string can theoretically have
        // embedded NULL characters
        if ((state->essInfo[i].ssidLen == length) &&
            (memcmp(&state->essInfo[i].ssidStr, ssidStr,
                    state->essInfo[i].ssidLen) == 0)) {
            dbgf(state->dbgModule, DBGINFO,
                 "%s: ESS %s found at index %d for interface %s",
                 __func__, state->essInfo[i].ssidStr, i, ifname);
            vap->essId = i;
            match = LBD_TRUE;
            break;
        }
    }

    if (!match) {
        // New ESS found

        // Should not be possible to have more unique ESSes than there are VAPs.
        // However, this may need to be revisited if all ESSes in the network are
        // recorded here.
        lbDbgAssertExit(state->dbgModule, state->essCount < MAX_VAP_PER_BAND);

        vap->essId = state->essCount;
        state->essInfo[i].ssidLen = length;

        // Note memcpy is used here since the SSID string can theoretically have
        // embedded NULL characters
        memcpy(&state->essInfo[state->essCount].ssidStr,
               ssidStr, length);

        dbgf(state->dbgModule, DBGINFO,
             "%s: Adding new ESS %s to index %d for interface %s",
             __func__, state->essInfo[i].ssidStr, i, ifname);
        state->essCount++;
    }

    return LBD_OK;
}

/**
 * @brief Fetch the SSID this VAP is operating on from the
 *        driver, and store in the local VAP structure.
 *
 * @param [in] state the "this" pointer
 * @param [in] ifname name of the interface this VAP is
 *                    operating on
 * @param [in] vap pointer to VAP structure
 *
 * @return LBD_STATUS returns LBD_OK if the SSID is valid,
 *                    LBD_NOK otherwise
 */
static LBD_STATUS
wlanifBSteerControlGetSSID(wlanifBSteerControlHandle_t state, const char *ifname,
                           struct wlanifBSteerControlVapInfo *vap) {
    struct iwreq Wrq;
    u_int8_t buf[IEEE80211_NWID_LEN + 1];

    memset(&Wrq, 0, sizeof(Wrq));
    strncpy(Wrq.ifr_name, ifname, sizeof(Wrq.ifr_name));
    Wrq.u.data.pointer = (void *)&buf;
    Wrq.u.data.length = IEEE80211_NWID_LEN + 1;
    if (ioctl(state->controlSock, SIOCGIWESSID, &Wrq) < 0) {
        dbgf(state->dbgModule, DBGERR, "%s: ioctl() SIOCGIWESSID failed, ifName: %s",
             __func__, ifname);

        return LBD_NOK;
    }

    return wlanifBSteerControlStoreSSID(state, ifname, vap, Wrq.u.data.length, buf);
}

/**
 * @brief If no channel is stored for the radio associated with
 *        this VAP, resolve the channel and regulatory class
 *        from the frequency.
 *
 * @param [in] state the "this" pointer
 * @param [in] frequency frequency the radio is operating on
 * @param [in] vap the VAP pointer
 *
 * @return LBD_STATUS LBD_OK if the channel / regulatory class
 *                    could be resolved, LBD_NOK otherwise
 */
static LBD_STATUS
wlanifBSteerControlUpdateRadioForFrequency(
        wlanifBSteerControlHandle_t state, int frequency,
        struct wlanifBSteerControlVapInfo *vap) {
    if (vap->radio->channel != LBD_CHANNEL_INVALID) {
        // Radio channel is already resolved, return
        return LBD_OK;
    }

    if (wlanifResolveRegclassAndChannum(frequency,
                                        &vap->radio->channel,
                                        &vap->radio->regClass) != LBD_OK) {
        dbgf(state->dbgModule, DBGERR,
             "%s: Invalid channel / regulatory class for radio %s, frequency is %d",
             __func__, vap->radio->ifname, frequency);
        return LBD_NOK;
    }

    return LBD_OK;
}






#define CMD_LEN 256
static int han_dcm_get_rssiThrehold(unsigned char * ssid)
{
    FILE *fp;
    char str_tmp_cmd[CMD_LEN];
    char szVal[CMD_LEN];  
    memset( str_tmp_cmd, 0, CMD_LEN );
    memset(szVal, 0x00, sizeof(szVal));
    sprintf(str_tmp_cmd,"%s %s %s", "config_wlan get_opt ssid ",ssid,"RSSIThreshold");
    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }
    return atoi(szVal);
}
static void han_dcm_set_rssiThreshold(const char * ifname, unsigned char  rssiThreshold)
{
    char str_tmp_cmd[CMD_LEN];
    memset( str_tmp_cmd, 0, CMD_LEN );
    sprintf(str_tmp_cmd,"wlanset dcm  %s  set_rssithreshold %d \n",ifname,rssiThreshold);
    printf("set_rssithreshold cmd =  %s\n",str_tmp_cmd);
    system(str_tmp_cmd);
}
/**
 * @brief For a given interface name, resolve a VAP entry on the corresponding band
 *
 * Once successfully resolved, the VAP entry will be marked
 * valid, with channel and system index information
 *
 * @param [in] state  the "this" pointer
 * @param [in] ifname  the interface name
 * @param [in] radio  the radio instance that owns this VAP
 *
 * @return the VAP entry containing interface name and channel
 *         on success; otherwise NULL
 */
static struct wlanifBSteerControlVapInfo *
wlanifBSteerControlInitVapFromIfname(wlanifBSteerControlHandle_t state,
                                     const char *ifname,
                                     struct wlanifBSteerControlRadioInfo *radio) {
    struct wlanifBSteerControlVapInfo *vap = NULL;
    struct iwreq Wrq;
    struct ifreq buffer;
    wlanif_band_e band;

    memset(&Wrq, 0, sizeof(Wrq));
    strncpy(Wrq.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(state->controlSock, SIOCGIWFREQ, &Wrq) < 0) {
        dbgf(state->dbgModule, DBGERR, "%s: ioctl() SIOCGIWFREQ failed, ifName: %s",
             __func__, ifname);
        return NULL;
    }

    band = wlanifMapFreqToBand(Wrq.u.freq.m);
    if (band >= wlanif_band_invalid) {
        dbgf(state->dbgModule, DBGERR, "%s: ioctl() SIOCGIWFREQ returned invalid frequency, ifName: %s",
             __func__, ifname);
        return NULL;
    }

    vap = wlanifBSteerControlAllocateVap(state, band);
    if (vap == NULL) {
        // Maximum number of VAPs reached on the given band
        return NULL;
    }
    strlcpy(vap->ifname, ifname, IFNAMSIZ + 1);
    vap->radio = radio;

    // Get the channel and store in the radio (if not already done)
    if (wlanifBSteerControlUpdateRadioForFrequency(state,
                                                   Wrq.u.freq.m, vap) != LBD_OK) {
        return NULL;
    }

    if (!(vap->sysIndex = if_nametoindex(ifname))) {
        dbgf(state->dbgModule, DBGERR, "%s: Resolve index failed, ifname: %s",
             __func__, ifname);
        return NULL;
    }

    strncpy(buffer.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(state->controlSock, SIOCGIFHWADDR, &buffer) < 0) {
        dbgf(state->dbgModule, DBGERR, "%s: ioctl() SIOCGIFHWADDR failed, ifName: %s",
             __func__, ifname);
        return NULL;
    }
    lbCopyMACAddr(buffer.ifr_hwaddr.sa_data, vap->macaddr.ether_addr_octet);

    // Get the SSID
    if (wlanifBSteerControlGetSSID(state, ifname, vap) != LBD_OK) {
        return NULL;
    }
    
      /*pengdecai*/
     if(!strstr(ifname,"athscan")){
           vap->rssi_threshold = han_dcm_get_rssiThrehold(state->essInfo[vap->essId].ssidStr);
           printf("%s ifname=%s,ESSID=%s,rssiThreshold = %d\n",__func__,ifname,state->essInfo[vap->essId].ssidStr,vap->rssi_threshold);
     	    han_dcm_set_rssiThreshold(ifname, vap->rssi_threshold);
    }
    vap->valid = LBD_TRUE;

    // Log the newly constructed interface
    wlanifBSteerControlLogInterfaceInfo(state, vap);

    return vap;
}

void han_dcm_get_all_rssithreshold(wlanifBSteerControlHandle_t state)
{
      printf("%s \n",__func__);
	int i,band ;
      struct wlanifBSteerControlVapInfo *vap = NULL;
	for(band = 0;band < wlanif_band_invalid;band ++){
		for (i = 0; i < MAX_VAP_PER_BAND; ++i) {
		        if (state->bandInfo[band].vaps[i].valid) {
		          vap=&state->bandInfo[band].vaps[i];
           		    vap->rssi_threshold = han_dcm_get_rssiThrehold(state->essInfo[vap->essId].ssidStr);
     	   		    han_dcm_set_rssiThreshold(vap->ifname, vap->rssi_threshold);  
		        }
	      }
	}
}




int han_find_str_cnt(const  char * str1, const char * str2) 
{ 
    int i,j; 
    int str1len=strlen(str1),str2len=strlen(str2); 
    int count=0; 
    for(i=0;i<str1len-str2len+1;i++)
     { 
       for(j=0;j<str2len;j++)    
       { 
         if(str2[j]!=str1[i+j]) 
           break;    
       } 
       if(j==str2len)
         count++;    
     }
     return count;
}
/**
 * @brief Resolve Wlan interfaces from configuration file and system.
 *
 * It will parse interface names from config file, then resolve
 * band and system index using ioctl() and if_nametoindex().
 *
 * @param [in] state  the "this" pointer
 *
 * @return LBD_OK if both bands are resolved; otherwise LBD_NOK
 */
static LBD_STATUS
wlanifBSteerControlResolveWlanIfaces(wlanifBSteerControlHandle_t state) {
    // The size here considers we have two interface names, separated by a
    // colon.
    char ifnamePair[MAX_VAP_PER_BAND * WLANIF_MAX_RADIOS][1 + 2 * (IFNAMSIZ + 1)];
    u_int8_t i = 0;
    const char *wlanInterfaces;
    int numInterfaces;
    int wifi0_cunt = 0;
    int wifi1_cunt=0;
    int wifi2_cunt=0;
    struct wlanifBSteerControlVapInfo *vap = NULL;

    wlanInterfaces = profileGetOpts(mdModuleID_WlanIF,
                                    WLANIFBSTEERCONTROL_WLAN_INTERFACES,
                                    NULL);

    if (!wlanInterfaces) {
        dbgf(state->dbgModule, DBGERR, "%s: No WLAN interface listed in config file", __func__);
        return LBD_NOK;
    }

    wifi0_cunt = han_find_str_cnt(wlanInterfaces, "wifi0");
    wifi1_cunt = han_find_str_cnt(wlanInterfaces, "wifi1");
    wifi2_cunt = han_find_str_cnt(wlanInterfaces, "wifi2");


     printf("wlanInterfaces = %s\n",wlanInterfaces);
     printf("wifi0_cunt = %d,wifi1_cunt = %d,wifi2_cunt = %d\n",wifi0_cunt,wifi1_cunt,wifi2_cunt);
	
    do {
        numInterfaces = splitByToken(wlanInterfaces,
                                     sizeof(ifnamePair) / sizeof(ifnamePair[0]),
                                     sizeof(ifnamePair[0]),
                                     (char *)ifnamePair, ',');
        if (numInterfaces < wlanif_band_invalid) {
            dbgf(state->dbgModule, DBGERR, "%s: Failed to resolve WLAN interfaces from %s:"
                                           " at least one interface per band is required",
                 __func__, wlanInterfaces);
            break;
        }

        if ((state->controlSock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            dbgf(state->dbgModule, DBGERR, "%s: Create ioctl socket failed", __func__);
            break;
        }

        if (fcntl(state->controlSock, F_SETFL, fcntl(state->controlSock, F_GETFL) | O_NONBLOCK)) {
            dbgf(state->dbgModule, DBGERR, "%s: fcntl() failed", __func__);
            break;
        }
    

        for (i = 0; i < numInterfaces; i++) {
            char ifnames[2][IFNAMSIZ + 1];
            if (splitByToken(ifnamePair[i], sizeof(ifnames) / sizeof(ifnames[0]),
                             sizeof(ifnames[0]), (char *) ifnames,
                             ':') != 2) {
                dbgf(state->dbgModule, DBGERR,
                     "%s: Failed to resolve radio and VAP names from %s",
                     __func__, ifnamePair[i]);
                vap = NULL;
                break;
            }

            struct wlanifBSteerControlRadioInfo *radio =
                wlanifBSteerControlLookupRadioByIfname(state, ifnames[0]);
            if (!radio) {
                vap = NULL;  // signal a failiure
                break;
            }
	    /*Begin:pengdecai added for lbd*/	
		if((!strcmp( ifnames[0],"wifi0") && (wifi0_cunt > 1)) ||\
		   (!strcmp( ifnames[0],"wifi1") && (wifi1_cunt > 1)) ||\
		   (!strcmp( ifnames[0],"wifi2") && (wifi2_cunt > 1))){
			if(strstr(ifnames[1],"athscan"))
				continue;

		}
        	/*End:pengdecai added for lbd*/	 
            vap = wlanifBSteerControlInitVapFromIfname(state, ifnames[1], radio);
            if (!vap) {
                break;
            }
        }

        if (!vap) {
            break;
        }

        if (wlanifBSteerControlIsBandValid(state, wlanif_band_24g) &&
            wlanifBSteerControlIsBandValid(state, wlanif_band_5g)) {
            free((char *)wlanInterfaces);
            return LBD_OK;
        }
    } while(0);

    if (state->controlSock > 0) {
        close(state->controlSock);
    }
    free((char *)wlanInterfaces);
    return LBD_NOK;
}

/**
 * @brief Read configuration parameters from config file and do sanity check
 *
 * If inactivity check period or MU check period from config file is invalid,
 * use the default one.
 *
 * @param [in] state  the "this" pointer
 * @param [in] band  the band to resolve configuration parameters
 *
 * @return LBD_NOK if the MU average period is shorter then MU sample period;
 *                 otherwise return LBD_OK
 */
static LBD_STATUS
wlanifBSteerControlReadConfig(wlanifBSteerControlHandle_t state,
                              wlanif_band_e band) {
    enum mdModuleID_e moduleID;
    struct profileElement *defaultProfiles;

    if (band == wlanif_band_24g) {
        moduleID = mdModuleID_WlanIF_Config_24G;
        defaultProfiles = wlanifElementDefaultTable_24G;
    } else {
        moduleID = mdModuleID_WlanIF_Config_5G;
        defaultProfiles = wlanifElementDefaultTable_5G;
    }

    state->bandInfo[band].configParams.inactivity_timeout_normal =
        profileGetOptsInt(moduleID,
                          WLANIFBSTEERCONTROL_INACT_IDLE_THRESHOLD,
                          defaultProfiles);

    state->bandInfo[band].configParams.inactivity_timeout_overload =
        profileGetOptsInt(moduleID,
                          WLANIFBSTEERCONTROL_INACT_OVERLOAD_THRESHOLD,
                          defaultProfiles);

    state->bandInfo[band].configParams.inactivity_check_period =
        profileGetOptsInt(moduleID,
                          WLANIFBSTEERCONTROL_INACT_CHECK_INTERVAL,
                          defaultProfiles);
    if (state->bandInfo[band].configParams.inactivity_check_period <= 0) {
        dbgf(state->dbgModule, DBGINFO, "[Band %u] Inactivity check period value is invalid (%d), use default one",
                band, state->bandInfo[band].configParams.inactivity_check_period);
        state->bandInfo[band].configParams.inactivity_check_period =
            atoi(profileElementDefault(WLANIFBSTEERCONTROL_INACT_CHECK_INTERVAL,
                                       defaultProfiles));
    }

    state->bandInfo[band].configParams.inactive_rssi_xing_high_threshold =
        profileGetOptsInt(moduleID,
                          WLANIFBSTEERCONTROL_INACT_RSSI_XING_HIGH_THRESHOLD,
                          defaultProfiles);

    state->bandInfo[band].configParams.inactive_rssi_xing_low_threshold =
        profileGetOptsInt(moduleID,
                          WLANIFBSTEERCONTROL_INACT_RSSI_XING_LOW_THRESHOLD,
                          defaultProfiles);

    state->bandInfo[band].configParams.low_rssi_crossing_threshold =
        profileGetOptsInt(moduleID,
                          WLANIFBSTEERCONTROL_LOW_RSSI_XING_THRESHOLD,
                          defaultProfiles);

    state->bandInfo[band].configParams.utilization_sample_period =
        profileGetOptsInt(moduleID,
                          WLANIFBSTEERCONTROL_MU_CHECK_INTERVAL,
                          defaultProfiles);
    // Sanity check to make sure unitlization check interval not zero
    if (state->bandInfo[band].configParams.utilization_sample_period <= 0) {
        dbgf(state->dbgModule, DBGINFO, "[Band %u] Utilization sample period value is invalid (%d), use default one",
                band, state->bandInfo[band].configParams.utilization_sample_period);
        state->bandInfo[band].configParams.utilization_sample_period =
            atoi(profileElementDefault(WLANIFBSTEERCONTROL_MU_CHECK_INTERVAL,
                                       defaultProfiles));
    }

    int muAvgPeriod = profileGetOptsInt(moduleID,
                                        WLANIFBSTEERCONTROL_MU_AVG_PERIOD,
                                        defaultProfiles);
    // Sanity check to make sure utilization average period is larger than sample interval
    if (muAvgPeriod <= state->bandInfo[band].configParams.utilization_sample_period) {
        dbgf(state->dbgModule, DBGINFO, "[Band %u] Utilization average period (%d seconds)is shorter than"
                                        " Utilization sample period (%d seconds).",
                band, muAvgPeriod, state->bandInfo[band].configParams.utilization_sample_period);
        return LBD_NOK;
    }
    state->bandInfo[band].configParams.utilization_average_num_samples = muAvgPeriod /
        state->bandInfo[band].configParams.utilization_sample_period;

    state->bandInfo[band].bcnrptDurations[IEEE80211_RRM_BCNRPT_MEASMODE_ACTIVE] =
        profileGetOptsInt(moduleID,
                          WLANIFBSTEERCONTROL_BCNRPT_ACTIVE_DURATION,
                          defaultProfiles);

    state->bandInfo[band].bcnrptDurations[IEEE80211_RRM_BCNRPT_MEASMODE_PASSIVE] =
        profileGetOptsInt(moduleID,
                          WLANIFBSTEERCONTROL_BCNRPT_PASSIVE_DURATION,
                          defaultProfiles);

    state->bandInfo[band].configParams.low_tx_rate_crossing_threshold =
        profileGetOptsInt(moduleID,
                          WLANIFBSTEERCONTROL_LOW_TX_RATE_XING_THRESHOLD,
                          defaultProfiles);

    state->bandInfo[band].configParams.high_tx_rate_crossing_threshold =
        profileGetOptsInt(moduleID,
                          WLANIFBSTEERCONTROL_HIGH_TX_RATE_XING_THRESHOLD,
                          defaultProfiles);

    // Sanity check that the high Tx rate threshold is greater than the low Tx rate
    // threshold.
    if (state->bandInfo[band].configParams.low_tx_rate_crossing_threshold >=
        state->bandInfo[band].configParams.high_tx_rate_crossing_threshold) {
        dbgf(state->dbgModule, DBGERR,
             "[Band %u] Low Tx rate crossing threshold (%u) is greater or equal to"
             " high Tx rate crossing threshold (%u).",
             band, state->bandInfo[band].configParams.low_tx_rate_crossing_threshold,
             state->bandInfo[band].configParams.high_tx_rate_crossing_threshold);
        return LBD_NOK;
    }

    state->bandInfo[band].configParams.low_rate_rssi_crossing_threshold =
        profileGetOptsInt(moduleID,
                          WLANIFBSTEERCONTROL_LOW_RATE_RSSI_XING_THRESHOLD,
                          defaultProfiles);

    state->bandInfo[band].configParams.high_rate_rssi_crossing_threshold =
        profileGetOptsInt(moduleID,
                          WLANIFBSTEERCONTROL_HIGH_RATE_RSSI_XING_THRESHOLD,
                          defaultProfiles);

    // Sanity check that the high rate RSSI threshold is greater than the low rate RSSI
    // threshold.
    if (state->bandInfo[band].configParams.low_rate_rssi_crossing_threshold >= 
        state->bandInfo[band].configParams.high_rate_rssi_crossing_threshold) {
        dbgf(state->dbgModule, DBGERR, 
             "[Band %u] Low rate RSSI crossing threshold (%u) is greater or equal to"
             " high rate RSSI crossing threshold (%u).",
             band, state->bandInfo[band].configParams.low_rate_rssi_crossing_threshold,
             state->bandInfo[band].configParams.high_rate_rssi_crossing_threshold);
        return LBD_NOK;
    }

    return LBD_OK;
}

/**
 * @brief Send IEEE80211_DBGREQ_BSTEERING_ENABLE request on the
 *        first VAP (to enable on the radio level), and
 *        IEEE80211_DBGREQ_BSTEERING_ENABLE_EVENTS on each VAP
 *        on the radio.
 *
 * @param [in] state  the "this" pointer
 * @param [in] band  The band on which to send this request
 * @param [in] enable  LBD_TRUE for enable, LBD_FALSE for disable
 *
 * @return LBD_OK if the request is sent sucessfully; otherwise LBD_NOK
 */
static LBD_STATUS
wlanifBSteerControlSendEnable(wlanifBSteerControlHandle_t state,
                              wlanif_band_e band, LBD_BOOL enable) {
    u_int8_t bsteering_enable;

    bsteering_enable = enable ? 1 : 0;
   //LBD_STATUS ret = LBD_NOK;
    // On enable: do the radio level enable first
    if (enable) {
        if (wlanifBSteerControlSendFirstVAP(state, band, 
                                           IEEE80211_DBGREQ_BSTEERING_ENABLE, NULL,
                                           (void *) &bsteering_enable,
                                           sizeof(bsteering_enable)) != LBD_OK) {
            return LBD_NOK;
        }
    }

    // Now do the individual enable / disable per VAP
    size_t vap;
    for (vap = 0; vap < MAX_VAP_PER_BAND; ++vap) {
        if (!state->bandInfo[band].vaps[vap].valid) {
            // No more valid VAPs, can exit the loop
            //break;
            continue;
        }
		
#if 0
	 printf("%s  band = %d ifname = %s,ifindex = %d\n",__func__,band,\
	 	state->bandInfo[band].vaps[vap].ifname,\
	 	state->bandInfo[band].vaps[vap].sysIndex);
 #endif      
 
        if (wlanifBSteerControlSendVAP(state, state->bandInfo[band].vaps[vap].ifname, 
                                       IEEE80211_DBGREQ_BSTEERING_ENABLE_EVENTS, NULL,
                                       (void *) &bsteering_enable,
                                       sizeof(bsteering_enable), NULL, 0) != LBD_OK) {
           // return LBD_NOK;
           return LBD_NOK;
        }
    }

    // On disable: do the radio level disable last
    if (!enable) {
        if (wlanifBSteerControlSendFirstVAP(state, band, 
                                           IEEE80211_DBGREQ_BSTEERING_ENABLE, NULL,
                                           (void *) &bsteering_enable,
                                           sizeof(bsteering_enable)) != LBD_OK) {
           return LBD_NOK;
        }
    }

    return LBD_OK;
}

/**
 * @brief Send IEEE80211_DBGREQ_BSTEERING_SET_PARAMS request
 *
 * @param [in] state  the "this" pointer
 * @param [in] band  The band on which to send this request
 *
 * @return LBD_OK if the request is sent sucessfully; otherwise LBD_NOK
 */
static LBD_STATUS
wlanifBSteerControlSendSetParams(wlanifBSteerControlHandle_t state,
                                 wlanif_band_e band) {

    return wlanifBSteerControlSendFirstVAP(state, band, IEEE80211_DBGREQ_BSTEERING_SET_PARAMS, NULL,
                                           (void *) &state->bandInfo[band].configParams,
                                           sizeof(state->bandInfo[band].configParams));
}

/**
 * @brief Send IEEE80211_DBGREQ_BSTEERING_GET_RSSI request
 *
 * @param [in] state  the "this" pointer
 * @param [in] band  The band on which to send this request
 * @param [in] staAddr  the MAC address of the station to request RSSI
 * @param [in] numSamples  number of RSSI measurements to average before reporting back
 *
 * @return LBD_OK if the request is sent sucessfully; otherwise LBD_NOK
 */
static LBD_STATUS
wlanifBSteerControlSendRequestRSSI(wlanifBSteerControlHandle_t state,
                                   struct wlanifBSteerControlVapInfo *vap,
                                   const struct ether_addr * staAddr, u_int8_t numSamples) {
    return wlanifBSteerControlSetSendVAP(state, vap->ifname,
                                         IEEE80211_DBGREQ_BSTEERING_GET_RSSI,
                                         staAddr, (void *) &numSamples, sizeof(numSamples));
}

/**
 * @brief Send 802.11k beacon report request
 *
 * If multiple channels are provided, current implementation will try to
 * send separate request with each channel until success.
 *
 * @param [in] state  the "this" pointer
 * @param [in] vap  the VAP to send the request
 * @param [in] staAddr  the MAC address of the specific station
 * @param [in] rrmCapable  flag indicating if the STA implements 802.11k feature
 * @param [in] numChannels  number of channels in channelList
 * @param [in] channelList  set of channels to measure downlink RSSI
 *
 * @return  LBD_OK if the request is sent successfully; otherwise LBD_NOK
 */
static LBD_STATUS wlanifBSteerControlSendRRMBcnrptRequest(
        wlanifBSteerControlHandle_t state,
        struct wlanifBSteerControlVapInfo *vap,
        const struct ether_addr *staAddr, size_t numChannels,
        const lbd_channelId_t *channels) {
    ieee80211_rrm_beaconreq_info_t bcnrpt = {0};
    LBD_STATUS status = LBD_NOK;
    size_t i;

    // For multiple channels, based on current testing, it's more reliable
    // to send a request for each channel, rather than relying on set 255
    // as channel number and append extra AP info element.
    for (i = 0; i < numChannels; ++i) {
        // Only handle single channel per band for now
        bcnrpt.channum = channels[i];
        if (LBD_OK != wlanifResolveRegclass(bcnrpt.channum, &bcnrpt.regclass)) {
            dbgf(state->dbgModule, DBGERR, "%s: Failed to resolve regulatory class from channel %d",
                 __func__, bcnrpt.channum);
            return LBD_NOK;
        }
        bcnrpt.req_ssid = 1;
        memset(bcnrpt.bssid, 0xff, HD_ETH_ADDR_LEN);
        switch (bcnrpt.regclass) {
            case IEEE80211_RRM_REGCLASS_112:
            case IEEE80211_RRM_REGCLASS_115:
            case IEEE80211_RRM_REGCLASS_124:
                bcnrpt.mode = IEEE80211_RRM_BCNRPT_MEASMODE_ACTIVE;
                bcnrpt.duration = state->bandInfo[wlanif_band_5g].bcnrptDurations[bcnrpt.mode];
                break;
            case IEEE80211_RRM_REGCLASS_81:
            case IEEE80211_RRM_REGCLASS_82:
                bcnrpt.mode = IEEE80211_RRM_BCNRPT_MEASMODE_ACTIVE;
                bcnrpt.duration = state->bandInfo[wlanif_band_24g].bcnrptDurations[bcnrpt.mode];
                break;
            case IEEE80211_RRM_REGCLASS_118:
            case IEEE80211_RRM_REGCLASS_121:
                bcnrpt.mode = IEEE80211_RRM_BCNRPT_MEASMODE_PASSIVE;
                bcnrpt.duration = state->bandInfo[wlanif_band_5g].bcnrptDurations[bcnrpt.mode];
                break;
            default:
                dbgf(state->dbgModule, DBGERR, "%s: Invalid regulatory class %d",
                     __func__, bcnrpt.regclass);
                return LBD_NOK;
        }

        if (LBD_OK == wlanifBSteerControlSetSendVAP(
                          state, vap->ifname,
                          IEEE80211_DBGREQ_SENDBCNRPT, staAddr,
                          (void *) &bcnrpt, sizeof(bcnrpt))) {
            // Based on our testing, most devices will reject multiple requests sent in a short
            // interval, so for now we only ensure one request is sent.
            status = LBD_OK;
            break;
        }
    }
    return status;
}

/**
 * @brief Send request down to driver using ioctl() on the first
 *        VAP operating on the specified band for each radio operating
 *        on that band.
 *
 * Note that this function will attempt the operation on all radios on the
 * band even if it fails on one of them.
 *
 * @param [in] band  the band on which this request should be sent
 * @param [in] cmd  the command contained in the request
 * @param [in] destAddr  optional parameters to specify the dest client of this
 *                       request
 * @param [in] data  the data contained in the request
 * @param [in] data_len  the length of data contained in the request
 *
 * @return LBD_OK if the request is sent successfully on all radios on the
 *         band; otherwise LBD_NOK
 */
#include <execinfo.h>
#if 0
void print_trace(void)
{
    int nptrs;
    #define SIZE 100
    void *buffer[100];
//    char **strings;
  
    nptrs = backtrace(buffer, SIZE);
    printf("backtrace() returned %d addresses\n", nptrs);
  
    backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO);
}
#endif
#if 0
  void backtrace()
{
        const int maxLevel = 200;
        void* buffer[maxLevel];
        int level = backtrace(buffer, maxLevel);
        const int SIZE = 1024;
        char cmd[SIZE] = "addr2line -C -f -e ";

        // let prog point to the end of "cmd"

        char* prog = cmd + strlen(cmd);

        int r = readlink("/proc/self/exe", prog, sizeof(cmd) - (prog-cmd)-1);

        FILE* fp = popen(cmd, "w");
        if (!fp)
        {
                perror("popen");
                return;
        }
        for (int i = 0; i < level; ++i)
        {
                fprintf(fp, "%p\n", buffer[i]);
        }

        fclose(fp);
}
#endif
static inline LBD_STATUS
wlanifBSteerControlSendFirstVAP(wlanifBSteerControlHandle_t state,
                                wlanif_band_e band, u_int8_t cmd,
                                const struct ether_addr *destAddr,
                                void *data, int data_len) {
    LBD_STATUS result = LBD_OK;
    size_t i;


   // unsigned char * pp= NULL;
    //*pp = 0;
	
    for (i = 0; i < WLANIF_MAX_RADIOS; ++i) {
        if (!state->radioInfo[i].valid) {
            break;
        } else if (wlanif_resolveBandFromChannelNumber(
                    state->radioInfo[i].channel) == band) {
#if 0
		/*pengdecai added for exit when create new wlan*/
		 if(cmd == IEEE80211_DBGREQ_BSTEERING_SET_PARAMS){
			 printf(" check cmd = IEEE80211_DBGREQ_BSTEERING_SET_PARAMS  radio[%d] hassetParam =%d\n",i,state->radioInfo[i].hassetParam);
			
		           if(state->radioInfo[i].hassetParam == 0xff){
		 	  		 continue;
		           }
   	       }
		/*pengdecai end*/	
#endif		
            struct wlanifBSteerControlVapInfo *vap =
                wlanifBSteerControlGetFirstVAPByChannel(
                        state, state->radioInfo[i].channel);
            if (!vap) {
                dbgf(state->dbgModule, DBGERR,
                     "%s: Failed to resolve VAP for channel [%u]",
                     __func__, state->radioInfo[i].channel);
                result = LBD_NOK;
            } else if (wlanifBSteerControlSetSendVAP(state, vap->ifname, cmd,
                                                     destAddr, data,
                                                     data_len) == LBD_OK) {
                dbgf(state->dbgModule, DBGDEBUG,
                     "%s: Successfully executed command [%u] on %s\n",
                     __func__, cmd, vap->ifname);
            } else {
                dbgf(state->dbgModule, DBGERR,
                     "%s: Failed to execute command [%u] on %s (errno=%d)\n",
                     __func__, cmd, vap->ifname, errno);
                result = LBD_NOK;
            }
#if 0
		/*pengdecai added for exit when create new wlan*/
		 if((result == LBD_OK) && (cmd == IEEE80211_DBGREQ_BSTEERING_SET_PARAMS)){
		 	    printf(" set cmd = IEEE80211_DBGREQ_BSTEERING_SET_PARAMS  radio[%d] hassetParam =%d\n",i,state->radioInfo[i].hassetParam);

		           state->radioInfo[i].hassetParam = 0xff;
   	       }
		/*pengdecai end*/
#endif

        }
    }

    return result;
}

/**
 * @brief Send request down to driver using ioctl() for GET operations.
 *
 * This function will record the ioctl() output on success.
 *
 * @see wlanifBSteerControlSendVAP for parameters and return value explanation
 */
static LBD_STATUS
wlanifBSteerControlGetSendVAP(wlanifBSteerControlHandle_t state,
                              const char *ifname, u_int8_t cmd,
                              const struct ether_addr *destAddr,
                              void *output, int output_len) {
    return wlanifBSteerControlSendVAP(state, ifname, cmd, destAddr,
                                      NULL /* data */, 0 /* data_len */,
                                      output, output_len);
}

/**
 * @brief Send request down to driver using ioctl() for SET operations.
 *
 * @see wlanifBSteerControlSendVAP for parameters and return value explanation
 */
static LBD_STATUS
wlanifBSteerControlSetSendVAP(wlanifBSteerControlHandle_t state,
                              const char *ifname, u_int8_t cmd,
                              const struct ether_addr *destAddr,
                              void *data, int data_len) {
    return wlanifBSteerControlSendVAP(state, ifname, cmd, destAddr, data,
                                      data_len, NULL /* output */,
                                      0 /* output_len */);
}



/**
 * @brief Send request down to driver using ioctl()
 *
 * @param [in] ifname  the name of the interface on which this request should
 *                     be done
 * @param [in] cmd  the command contained in the request
 * @param [in] destAddr  optional parameters to specify the dest client of this request
 * @param [in] data  the data contained in the request
 * @param [in] data_len  the length of data contained in the request
 * @param [out] output  if not NULL, fill in the response data from the request
 * @param [in] output_len  expected number of bytes of output
 *
 * @return LBD_OK if the request is sent successfully; otherwise LBD_NOK
 */
static LBD_STATUS
wlanifBSteerControlSendVAP(wlanifBSteerControlHandle_t state,
                           const char *ifname, u_int8_t cmd,
                           const struct ether_addr *destAddr,
                           void *data, int data_len,
                           void *output, int output_len) {
    struct iwreq iwr;
    struct ieee80211req_athdbg req;

    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    (void) memset(&iwr, 0, sizeof(iwr));
    (void) strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));

    if (destAddr) {
        lbCopyMACAddr(destAddr->ether_addr_octet, req.dstmac);
    }

    req.cmd = cmd;
    if (data) {
        memcpy(&req.data, data, data_len);
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));



	
    if (ioctl(state->controlSock, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
		 dbgf(state->dbgModule, DBGERR,
		             "%s: Send %d request failed (errno=%d) on %s",
		             __func__, cmd, errno, ifname);
				sleep(1);
		        //return LBD_NOK;
	}else {
		        dbgf(state->dbgModule, DBGERR,
		             "%s: Send %d request successfull  on %s",
		             __func__, cmd, ifname);

      }

#if 0
	/*pengdecai for dcm
	* when vap is athscan ,the ioctl return error,we shuld try wait 3 times.
	*/
	int i;
    int sendcnt = 0;
	for(i = 0;i < 3;i ++){
		if (ioctl(state->controlSock, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
			sendcnt ++;
			sleep(1);
			//usleep(120000);
		}else{
			break;
		}
	}

	if(sendcnt >= 3){
		printf("ioctl set error achieve 3 times!\n");
		dbgf(state->dbgModule, DBGERR,
			 "%s: Send %d request failed (errno=%d) on %s,sendcnt = %d",
			 __func__, cmd, errno, ifname,sendcnt);
		return LBD_NOK;
	}
	/*pengdecai end */
#endif

    if (output) {
        lbDbgAssertExit(state->dbgModule, output_len <= sizeof(req.data));
        memcpy(output, &req.data, output_len);
    }
    return LBD_OK;
}

/**
 * @brief Dump the associated STAs for a single interface
 *
 * @param [in] state the 'this' pointer
 * @param [in] vap  the vap to dump associated STAs for
 * @param [in] band  the current band on which the interface is operating
 * @param [in] callback  the callback function to invoke for each associated
 *                       STA
 * @param [in] cookie  the parameter to provide back in the callback
 *
 * @return LBD_OK if the dump succeeded on this interface; otherwise LBD_NOK
 */
static LBD_STATUS wlanifBSteerControlDumpAssociatedSTAsOneIface(
        wlanifBSteerControlHandle_t state,
        struct wlanifBSteerControlVapInfo *vap, wlanif_band_e band,
        wlanif_associatedSTAsCB callback, void *cookie) {
#define LIST_STATION_ALLOC_SIZE 24*1024
    u_int8_t *buf = malloc(LIST_STATION_ALLOC_SIZE);
    if (!buf) {
        dbgf(state->dbgModule, DBGERR,
             "%s: Failed to allocate buffer for iface %s", __func__, vap->ifname);
        return LBD_NOK;
    }

    int s = -1;
    LBD_STATUS result = LBD_OK;
    do {
        struct iwreq iwr;
        memset(&iwr, 0, sizeof(iwr));
        strncpy(iwr.ifr_name, vap->ifname, sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = LIST_STATION_ALLOC_SIZE;

        if (ioctl(state->controlSock, IEEE80211_IOCTL_STA_INFO, &iwr) < 0) {
            dbgf(state->dbgModule, DBGERR,
                 "%s: Failed to perform ioctl for iface %s", __func__, vap->ifname);
            result = LBD_NOK;
            break;
        }

        // Loop over all of the STAs, providing a callback for each one.
        u_int8_t *currentPtr = buf;
        u_int8_t *endPtr = buf + iwr.u.data.length;
        while (currentPtr + sizeof(struct ieee80211req_sta_info) <= endPtr) {
            const struct ieee80211req_sta_info *staInfo =
                (const struct ieee80211req_sta_info *) currentPtr;
            struct ether_addr addr;
            lbCopyMACAddr(staInfo->isi_macaddr, addr.ether_addr_octet);
            ieee80211_bsteering_datarate_info_t datarateInfo;
            wlanif_phyCapInfo_t phyCapInfo = {
                LBD_FALSE /* valid */, wlanif_chwidth_invalid, 0 /* numStreams */,
                wlanif_phymode_invalid, 0 /* maxMCS */, 0 /* maxTxPower */
            };
            if (LBD_OK ==
                    wlanifBSteerControlGetSendVAP(state, vap->ifname,
                                                  IEEE80211_DBGREQ_BSTEERING_GET_DATARATE_INFO,
                                                  &addr, (void *)&datarateInfo,
                                                  sizeof(ieee80211_bsteering_datarate_info_t))) {
                phyCapInfo.valid = LBD_TRUE;
                phyCapInfo.maxChWidth =
                        wlanifMapToBandwidth(state->dbgModule,
                                             (enum ieee80211_cwm_width)(datarateInfo.max_chwidth)),
                phyCapInfo.numStreams = datarateInfo.num_streams,
                phyCapInfo.phyMode =
                        wlanifMapToPhyMode(state->dbgModule,
                                           (enum ieee80211_phymode)datarateInfo.phymode),
                phyCapInfo.maxMCS =
                        wlanifConvertToSingleStreamMCSIndex(state->dbgModule,
                                (enum ieee80211_phymode)datarateInfo.phymode,
                                datarateInfo.max_MCS);
                phyCapInfo.maxTxPower = datarateInfo.max_txpower;
            }
            lbd_bssInfo_t bss;

            bss.apId = LBD_APID_SELF;
            bss.channelId = vap->radio->channel;
            bss.essId = vap->essId;
            bss.vap = vap;

            // When failed to get PHY capability info, still report the associated STA,
            // so we cannot estimate PHY capability for this STA but can still perform
            // other operations on it.
            callback(&addr, &bss, (LBD_BOOL)(staInfo->isi_ext_cap & IEEE80211_EXTCAPIE_BSSTRANSITION),
                     (LBD_BOOL)(staInfo->isi_capinfo & IEEE80211_CAPINFO_RADIOMEAS),
                     &phyCapInfo, cookie);

            currentPtr += staInfo->isi_len;
        }
    } while (0);

    free(buf);
    close(s);
    return result;
}

/**
 * @brief Run an ioctl operation that takes a single MAC address on all
 *        interfaces that operate on the provided band.
 *
 * @param [in] state  the handle returned from wlanifBSteerControlCreate()
 *                     to use for this operation
 * @param [in] ioctlReq  the operation to run
 * @param [in] band  the band on which to perform the operation
 * @param [in] staAddr  the MAC address of the STA
 *
 * @return LBD_OK if the operation was successful on all VAPs for that band;
 *         otherwise LBD_NOK
 */
static LBD_STATUS wlanifBSteerControlPerformIoctlWithMAC(
        wlanifBSteerControlHandle_t state, int ioctlReq,
        struct wlanifBSteerControlVapInfo *vap,
        const struct ether_addr *staAddr) {
    struct iwreq iwr;
    struct sockaddr addr;

    memset(&addr, 0, sizeof(addr));
    addr.sa_family = ARPHRD_ETHER;
    lbCopyMACAddr(staAddr->ether_addr_octet, addr.sa_data);

    memset(&iwr, 0, sizeof(iwr));

    // This parameter is small enough that it can fit in the name union
    // member.
    memcpy(iwr.u.name, &addr, sizeof(addr));

    strncpy(iwr.ifr_name, vap->ifname, IFNAMSIZ);

    if (ioctl(state->controlSock, ioctlReq, &iwr) < 0) {
        dbgf(state->dbgModule, DBGERR,
             "%s: ioctl 0x%04x failed with errno %u",
             __func__, ioctlReq, errno);
        return LBD_NOK;
    }

    return LBD_OK;
}

/**
 * @brief Run the maccmd ioctl with the provided value.
 *
 * @param [in] state  the handle returned from wlanifBSteerControlCreate()
 *                     to use for this operation
 * @param [in] cmd  the command to inject
 * @param [in] band  the band on which to perform the operation
 *
 * @return LBD_OK if the operation was successful on all VAPs for that band;
 *         otherwise LBD_NOK
 */
 #if 0 //pengdecai modified
static LBD_STATUS wlanifBSteerControlPerformMacCmdOnBand(
        wlanifBSteerControlHandle_t state, int cmd, wlanif_band_e band) {
    struct iwreq iwr;
    int params[2] = { IEEE80211_PARAM_MACCMD, cmd };

    memset(&iwr, 0, sizeof(iwr));

    // This parameter is small enough that it can fit in the name union
    // member.
    memcpy(iwr.u.name, &params, sizeof(params));

    size_t i;
    for (i = 0; i < MAX_VAP_PER_BAND; ++i) {
        if (state->bandInfo[band].vaps[i].valid) {
            strncpy(iwr.ifr_name, state->bandInfo[band].vaps[i].ifname,
                    IFNAMSIZ);

            if (ioctl(state->controlSock, IEEE80211_IOCTL_SETPARAM, &iwr) < 0) {
                dbgf(state->dbgModule, DBGERR,
                     "%s: ioctl (cmd=%u) failed with errno %u",
                     __func__, cmd, errno);
                return LBD_NOK;
            }
        }
    }

    return LBD_OK;
}
 #endif

/**
 * @brief Timeout handler that checks if the VAPs are ready and re-enables
 *        band steering if they are.
 *
 * @param [in] cookie  the state object for wlanifBSteerControl
 */
static void wlanifBSteerControlAreVAPsReadyTimeoutHandler(void *cookie) {
    wlanifBSteerControlHandle_t state =
        (wlanifBSteerControlHandle_t) cookie;

    LBD_BOOL enabled = LBD_FALSE;
    if (wlanifBSteerControlEnableWhenReady(state, &enabled) == LBD_NOK)  {
        dbgf(state->dbgModule, DBGERR,
             "%s: Re-enabling on both bands failed", __func__);
	  printf( "%s: Re-enabling on both bands failed", __func__);
	  wlanifBSteerControlDisable(state);
        exit(1);
    }
}

/**
 * @brief Determine if the interface state indicates that it is up.
 *
 * @param [in] state  the handle returned from wlanifBSteerControlCreate()
 *                     to use for this operation
 * @param [in] ifname  the name of the interface to check
 *
 * @return LBD_TRUE if the VAPs are ready; otherwise LBD_FALSE
 */
static LBD_BOOL wlanifBSteerControlIsLinkUp(
        wlanifBSteerControlHandle_t state, const char *ifname) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(state->controlSock, SIOCGIFFLAGS, &ifr) < 0) {
        dbgf(state->dbgModule, DBGERR,
             "%s: Failed to get interface flags for %s",
             __func__, ifname);
        return LBD_FALSE;
    }

    return (ifr.ifr_flags & IFF_RUNNING) != 0;
}

/**
 * @brief Determine if a WiFI interface has a valid BSSID. 
 *
 * @param [in] state  the handle returned from wlanifBSteerControlCreate()
 *                     to use for this operation
 * @param [in] ifname  the name of the interface to check
 *
 * @return LBD_TRUE if the VAP has a valid BSSID; otherwise
 *         LBD_FALSE
 */
static LBD_BOOL wlanifBSteerControlIsVAPAssociated(
        wlanifBSteerControlHandle_t state, const char *ifname) {
    struct iwreq wrq;
    memset(&wrq, 0, sizeof(wrq));

    static const struct ether_addr zeroAddr = {{0,0,0,0,0,0}};

    strlcpy(wrq.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(state->controlSock, SIOCGIWAP, &wrq) < 0) {
        dbgf(state->dbgModule, DBGERR,
             "%s: Failed to get WAP status for %s",
             __func__, ifname);
        return LBD_FALSE;
    }

    // An all-zeros address is returned if the interface does not have a valid BSSID
    if (lbAreEqualMACAddrs(&zeroAddr.ether_addr_octet, &wrq.u.ap_addr.sa_data)) {
        dbgf(state->dbgModule, DBGDEBUG,
             "%s: Interface %s does not have a valid BSSID",
             __func__, ifname);
        return LBD_FALSE;
    } else {
        dbgf(state->dbgModule, DBGDEBUG,
             "%s: Interface %s has BSSID " lbMACAddFmt(":"),
             __func__, ifname, lbMACAddData(&wrq.u.ap_addr.sa_data));
    }

    return LBD_TRUE;
}

/**
 * @brief Determine whether all VAPs are ready for band steering to be
 *        enabled.
 *
 * @pre state has already been checked for validity
 *
 * @param [in] state  the handle returned from wlanifBSteerControlCreate()
 *                     to use for this operation
 *
 * @return LBD_TRUE if the VAPs are ready; otherwise LBD_FALSE
 */
static LBD_BOOL wlanifBSteerControlAreAllVAPsReady(
        wlanifBSteerControlHandle_t state) {
    struct iwreq iwr;
    memset(&iwr, 0, sizeof(iwr));

    size_t i, j;
    for (i = 0; i < wlanif_band_invalid; ++i) {
        for (j = 0; j < MAX_VAP_PER_BAND; ++j) {
            if (!state->bandInfo[i].vaps[j].valid) {
                //break;
                continue;
            }

            // First check that the link is up. It may not be if the
            // operator made the interface administratively down.
            if (!wlanifBSteerControlIsLinkUp(state,
                                             state->bandInfo[i].vaps[j].ifname)) {
                return LBD_FALSE;
            }

            // Check the VAP has a valid BSSID.  This will always be immediately
            // true for an interface on a radio that only has AP VAPs.
            // For a VAP on a radio that has a STA VAP (range extender mode)
            // it will not be true until the STA associates with the CAP.
            if (!wlanifBSteerControlIsVAPAssociated(state,
                                                    state->bandInfo[i].vaps[j].ifname)) {
                return LBD_FALSE;
            }

            // This may not be necessary, but it should be more efficient
            // than checking it first.
            state->bandInfo[i].vaps[j].ifaceUp = LBD_TRUE;

            strncpy(iwr.ifr_name, state->bandInfo[i].vaps[j].ifname,
                    IFNAMSIZ);

            // This parameter is small enough that it can fit in the name union
            // member.
            int param = IEEE80211_PARAM_GET_ACS;
            memcpy(iwr.u.name, &param, sizeof(param));

            int acsState = 0;
            if (ioctl(state->controlSock, IEEE80211_IOCTL_GETPARAM, &iwr) < 0) {
                dbgf(state->dbgModule, DBGERR,
                     "%s: GET_ACS failed on %s with errno %u",
                     __func__, iwr.ifr_name, errno);
                return LBD_FALSE;
            }
            memcpy(&acsState, iwr.u.name, sizeof(acsState));

            if (acsState) {
                dbgf(state->dbgModule, DBGINFO,
                     "%s: ACS scan in progress on %s",
                     __func__, iwr.ifr_name);
                return LBD_FALSE;
            }

            param = IEEE80211_PARAM_GET_CAC;
            memcpy(iwr.u.name, &param, sizeof(param));

            int cacState = 0;
            if (ioctl(state->controlSock, IEEE80211_IOCTL_GETPARAM, &iwr) < 0) {
                dbgf(state->dbgModule, DBGERR,
                     "%s: GET_CAC failed on %s with errno %u",
                     __func__, iwr.ifr_name, errno);
                return LBD_FALSE;
            }
            memcpy(&cacState, iwr.u.name, sizeof(cacState));

            if (cacState) {
                dbgf(state->dbgModule, DBGINFO,
                     "%s: CAC in progress on %s",
                     __func__, iwr.ifr_name);
                return LBD_FALSE;
            }
        }
    }

    // Got this far, so all of them were ok.
    return LBD_TRUE;
}

/**
 * @brief Set a single private ioctl parameter at the radio level.
 *
 * The parameter is assumed to be an integer.
 *
 * @param [in] state  the handle returned from wlanifBSteerControlCreate()
 *                     to use for this operation
 * @param [in] radio  the radio on which to set it
 * @param [in] paramId  the identifier for the parameter
 * @param [in] val  the value to set
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
static LBD_STATUS wlanifBSteerControlPrivIoctlSetParam(
        wlanifBSteerControlHandle_t state,
        struct wlanifBSteerControlRadioInfo *radio,
        int paramId, int val) {
    struct iwreq iwr;
    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, radio->ifname, IFNAMSIZ);

    memcpy(iwr.u.name, &paramId, sizeof(paramId));
    memcpy(&iwr.u.name[sizeof(paramId)], &val, sizeof(val));
    if (ioctl(state->controlSock, IEEE80211_IOCTL_SETPARAM, &iwr) < 0) {
        dbgf(state->dbgModule, DBGERR,
             "%s: Failed to set %04x parameter on %s",
             __func__, paramId, radio->ifname);
        return LBD_NOK;
    }

    return LBD_OK;
}

/*pengdecai add for dcm*/
static int han_init_local_ap_info(struct wlanifBSteerControlPriv_t *state)
{
    int i=0,j=0;


    memset(&g_own_ap_state,0x0,sizeof(struct Local_AP_Info));

    for(i = 0,j=0; i < WLANIF_MAX_RADIOS; i ++){
	    if(state->radioInfo[i].valid){
                g_own_ap_state.radio[j].channelID = state->radioInfo[i].channel;
		   strlcpy( g_own_ap_state.radio[j].ifname, state->radioInfo[i].ifname, sizeof( g_own_ap_state.radio[j].ifname));
		    g_own_ap_state.radio[j].bandtype = wlanifMapFreqToBand(g_own_ap_state.radio[j].channelID);
		    g_own_ap_state.radio[j].valid = 1;
                j++;
	    }
    }
     g_own_ap_state.radionum = j;

#if 0
    for(i = 0; i < WLANIF_MAX_RADIOS; i ++){
         printf("%s  state->radioInfo[%d].valid = %d\n",__func__,i,state->radioInfo[i].valid);
         printf("%s  state->radioInfo[%d].channel = %d\n",__func__,i,state->radioInfo[i].channel);
         printf("%s  state->radioInfo[%d].ifname = %s\n",__func__,i,state->radioInfo[i].ifname);
   }

    for(i = 0; i < WLANIF_MAX_RADIOS; i ++){
         printf("%s  g_own_ap_state.radio[%d].valid = %d\n",__func__,i,g_own_ap_state.radio[i].valid);
         printf("%s  g_own_ap_state.radio[%d].channelID = %d\n",__func__,i,g_own_ap_state.radio[i].channelID);
         printf("%s  g_own_ap_state.radio[%d].ifname = %s\n",__func__,i,g_own_ap_state.radio[i].ifname);
         printf("%s  g_own_ap_state.radio[%d].bandtype = %d\n",__func__,i,g_own_ap_state.radio[i].bandtype);
   }
#endif
    return 0;	
}


// ====================================================================
// Package level functions
// ====================================================================

wlanifBSteerControlHandle_t
wlanifBSteerControlCreate(struct dbgModule *dbgModule) {
    struct wlanifBSteerControlPriv_t *state =
        calloc(1, sizeof(struct wlanifBSteerControlPriv_t));
    if (!state) {
        dbgf(dbgModule, DBGERR, "%s: Failed to allocate state structure",
             __func__);
        return NULL;
    }

    state->dbgModule = dbgModule;
    state->controlSock = -1;

    /* Resovlve WLAN interfaces */
    if (wlanifBSteerControlResolveWlanIfaces(state) == LBD_NOK) {
        free(state);
        return NULL;
    }


    // Socket is open at this point, so if an error is encountered, we need
    // to make sure to close it so as not to leak it.
    do {
        if (wlanifBSteerControlInitializeACLs(state, wlanif_band_24g) == LBD_NOK ||
            wlanifBSteerControlInitializeACLs(state, wlanif_band_5g) == LBD_NOK) {
            break;
        }

        /* Get configuration parameters from configuration file. */
        if (wlanifBSteerControlReadConfig(state, wlanif_band_24g) == LBD_NOK ||
            wlanifBSteerControlReadConfig(state, wlanif_band_5g) == LBD_NOK) {
            break;
        }
		
        han_init_local_ap_info(state); //pengdecai added for dcm

        evloopTimeoutCreate(&state->vapReadyTimeout, "vapReadyTimeout",
                            wlanifBSteerControlAreVAPsReadyTimeoutHandler,
                            state);

        return state;
    } while (0);

    // This will tear down the ACLs, close the socket, and then deallocate
    // the state object.
    wlanifBSteerControlDestroy(state);
    return NULL;
}

LBD_STATUS wlanifBSteerControlEnableWhenReady(
        wlanifBSteerControlHandle_t state, LBD_BOOL *enabled) {
    // Sanity check
    if (!state || !enabled) {
        return LBD_NOK;
    }

    *enabled = LBD_FALSE;

    // Check whether all VAPs on both bands are ready, and only
    // then perform the enable.
    if (wlanifBSteerControlAreAllVAPsReady(state)) {
        if (LBD_NOK == wlanifBSteerControlResolvePHYCapInfo(state)) {
            return LBD_NOK;
        }

        if (wlanifBSteerControlSetEnable(state,
                                         wlanif_band_24g, LBD_TRUE) == LBD_NOK ||
            wlanifBSteerControlSetEnable(state,
                                         wlanif_band_5g, LBD_TRUE) == LBD_NOK) {
            dbgf(state->dbgModule, DBGERR,
                 "%s: Enabling on both bands failed", __func__);
            return LBD_NOK;
        }

        *enabled = LBD_TRUE;
        state->bandSteeringEnabled = LBD_TRUE;

        wlanif_bandSteeringStateEvent_t bandSteeringStateEvent;
        bandSteeringStateEvent.enabled = LBD_TRUE;

        mdCreateEvent(mdModuleID_WlanIF, mdEventPriority_High,
                      wlanif_event_band_steering_state,
                      &bandSteeringStateEvent, sizeof(bandSteeringStateEvent));

        return LBD_OK;
    } else {
        evloopTimeoutRegister(&state->vapReadyTimeout,
                              VAP_READY_CHECK_PERIOD,
                              0 /* us */);

        return LBD_OK;
    }
}

LBD_STATUS wlanifBSteerControlDisable(wlanifBSteerControlHandle_t state) {
    // Sanity check
    if (!state) {
        return LBD_NOK;
    }

    if (wlanifBSteerControlSetEnable(state, wlanif_band_24g,
                                     LBD_FALSE) == LBD_NOK ||
        wlanifBSteerControlSetEnable(state, wlanif_band_5g,
                                     LBD_FALSE) == LBD_NOK) {
        return LBD_NOK;
    }

    state->bandSteeringEnabled = LBD_FALSE;
    return LBD_OK;
}

LBD_STATUS wlanifBSteerControlDestroy(wlanifBSteerControlHandle_t state) {
    if (state) {
        wlanifBSteerControlTeardownACLs(state, wlanif_band_24g);
        wlanifBSteerControlTeardownACLs(state, wlanif_band_5g);

        size_t i;
        struct wlanifBSteerControlRadioInfo *radio;
        for (i = 0; i < WLANIF_MAX_RADIOS; ++i) {
            radio = &state->radioInfo[i];
            if (radio->valid) {
                // Clear RSSI waiting list if any
                list_head_t *iter = radio->rssiWaitingList.next;
                while (iter != &radio->rssiWaitingList) {
                    wlanifBSteerControlRSSIRequestEntry_t *curEntry =
                        list_entry(iter, wlanifBSteerControlRSSIRequestEntry_t, listChain);

                    iter = iter->next;
                    free(curEntry);
                }
                if (radio->enableOLStatsIoctl && radio->numEnableStats) {
                    // Disable the stats on all radios where they are still active.
                    wlanifBSteerControlPrivIoctlSetParam(state, radio,
                                                         radio->enableOLStatsIoctl,
                                                         0);
                }
                else if (radio->enableNoDebug && radio->numEnableStats) {
                    // Disable the stats on all radios where they are still active.
                    wlanifBSteerControlPrivIoctlSetParam(state, radio,
                                                         radio->enableNoDebug,
                                                         1);
                }
            }
        }

        close(state->controlSock);
        evloopTimeoutUnregister(&state->vapReadyTimeout);

        free(state);
    }

    return LBD_OK;
}

LBD_STATUS wlanifBSteerControlSetOverload(wlanifBSteerControlHandle_t state,
                                          lbd_channelId_t channelId,
                                          LBD_BOOL overload) {
    wlanif_band_e band = wlanif_resolveBandFromChannelNumber(channelId);

    // Sanity check
    if (!state || band == wlanif_band_invalid) {
        return LBD_NOK;
    }

    struct wlanifBSteerControlVapInfo *vap =
        wlanifBSteerControlGetFirstVAPByChannel(state, channelId);
    if (!vap || !state->bandInfo[band].enabled) {
        dbgf(state->dbgModule, DBGERR, "%s: Band Steering is not enabled on band %u",
             __func__, band);
        return LBD_NOK;
    }

    u_int8_t bsteering_overload;
    bsteering_overload = overload ? 1 : 0;

    return wlanifBSteerControlSetSendVAP(
            state, vap->ifname, IEEE80211_DBGREQ_BSTEERING_SET_OVERLOAD, NULL,
            (void *) &bsteering_overload, sizeof(bsteering_overload));
}

wlanif_band_e wlanifBSteerControlResolveBandFromSystemIndex(wlanifBSteerControlHandle_t state,
                                                            int index) {
    wlanif_band_e band;
    int i;

    if (!state) {
         // Invalid control handle
        return wlanif_band_invalid;
    }

    for (band = wlanif_band_24g ; band < wlanif_band_invalid; ++band) {
        for (i = 0; i < MAX_VAP_PER_BAND; ++i) {
            if (state->bandInfo[band].vaps[i].valid &&
                state->bandInfo[band].vaps[i].sysIndex == index) {
                return band;
            }
        }
    }
    return wlanif_band_invalid;
}

/*pengdecai added for dcm*/
static int han_is_only_vap(wlanifBSteerControlHandle_t state,int sysIndex)
{
	lbDbgAssertExit(state->dbgModule, state);
      int i, vapnum;
	  
	wlanif_band_e band = wlanifBSteerControlResolveBandFromSystemIndex(state, sysIndex);

	vapnum = 0;
	
	for (i = 0; i < MAX_VAP_PER_BAND; ++i) {
		if (!state->bandInfo[band].vaps[i].valid) {
			//break;
			continue;
		}
		printf("%s vap = %s\n",__func__,state->bandInfo[band].vaps[i].ifname);
	      vapnum ++;
	}


	if(1 == vapnum){
		printf("%s band = %d  noly one vap\n",__func__,band);
		return 1;
	}
	else 
		return 0;

	return 0;
}
unsigned char  han_get_rssi_threshold_form_bss(const lbd_bssInfo_t *bss) 
{
    struct wlanifBSteerControlVapInfo * vap;
    if (bss) {
        vap =  bss->vap;
	 return vap->rssi_threshold;
    }
    return 0;
}
/*pengdecai end*/
void wlanifBSteerControlUpdateLinkState(wlanifBSteerControlHandle_t state,
                                        int sysIndex, LBD_BOOL ifaceUp,
                                        LBD_BOOL *changed) {
    if (state && changed) {
        *changed = LBD_FALSE;
        struct wlanifBSteerControlVapInfo *vap =
            wlanifBSteerControlGetVAPFromSysIndex(state, sysIndex, wlanif_band_invalid);

        if (vap) {
	      printf("%s vap = %s,old-ifaceup=%d,new-ifaceup = %d\n",__func__,vap->ifname,vap->ifaceUp,ifaceUp);
            if (vap->ifaceUp != ifaceUp) {
                *changed = LBD_TRUE;
                vap->ifaceUp = ifaceUp;
            }
		/*pengdecai added for dcm*/
		if(ifaceUp == LBD_FALSE){
			vap->ifaceUp = ifaceUp;
			if(!han_is_only_vap(state,sysIndex)){
				
			   vap->valid = LBD_FALSE;
			}
		}
		/*pengdecai end*/
        }
    }

    // Not found, invalid control handle, or invalid changed param. Do nothing.
}

#if 0
LBD_STATUS get_from_freq(u_int32_t freq,lbd_channelId_t *channel) {

    if (!channel ) {
        return LBD_NOK;
    }
	
    *channel = 0;
    freq /= 100000; // Convert to MHz
    if ((freq >= 2412) && (freq <= 2472)) {
        if (((freq - 2407) % 5) != 0) {
            /* error: freq not exact */
            return 0;
        }
        *channel = (freq - 2407) / 5;
        return LBD_OK;
    }

    if (freq == 2484) {
        *channel = 14;
        return LBD_OK;
    }

#define IS_CHAN_IN_PUBLIC_SAFETY_BAND(_c) ((_c) > 4940 && (_c) < 4990)
    if (freq >= 2512 && freq < 5000) {
        if (IS_CHAN_IN_PUBLIC_SAFETY_BAND(freq)) {
             *channel = ((freq * 10) +
                         (((freq % 5) == 2) ? 5 : 0) - 49400)/5;
        } else if ( freq > 4900 ) {
             *channel = (freq - 4000) / 5;
        } else {
             *channel = 15 + ((freq - 2512) / 20);
        }
        // Since our chipset does not support bands other than 2.4 Ghz or 5 GHz,
        // indicate failure here with channel resolved but regulatory class cannot
        // be resolved.
        return LBD_NOK;
    }

#define FREQ_5G_CH(_chan_num)   (5000 + (5 * _chan_num))

#define CASE_5G_FREQ(_chan_num)         \
    case FREQ_5G_CH(_chan_num):         \
        *channel = _chan_num;           \
        break;

    if ((freq >= FREQ_5G_CH(36)) && (freq <= FREQ_5G_CH(48))) {
        switch(freq) {
            CASE_5G_FREQ(36);
            CASE_5G_FREQ(40);
            CASE_5G_FREQ(44);
            CASE_5G_FREQ(48);
            default:
                /* No valid frequency in this range */
                return LBD_NOK;
        }
        return LBD_OK;
    }

    if ((freq >= FREQ_5G_CH(149)) && (freq <= FREQ_5G_CH(161))) {
        switch(freq) {
            CASE_5G_FREQ(149);
            CASE_5G_FREQ(153);
            CASE_5G_FREQ(157);
            CASE_5G_FREQ(161);
            default:
                /* No valid frequency in this range */
                return LBD_NOK;
        }
        return LBD_OK;
    }

    if ((freq >= FREQ_5G_CH(8)) && (freq <= FREQ_5G_CH(16))) {
        switch(freq) {
            CASE_5G_FREQ(8);
            CASE_5G_FREQ(12);
            CASE_5G_FREQ(16);
            default:
                /* No valid frequency in this range */
                return LBD_NOK;
        }
        return LBD_OK;
    }

    if ((freq >= FREQ_5G_CH(52)) && (freq <= FREQ_5G_CH(64))) {
        switch(freq) {
            CASE_5G_FREQ(52);
            CASE_5G_FREQ(56);
            CASE_5G_FREQ(60);
            CASE_5G_FREQ(64);
            default:
                /* No valid frequency in this range */
                return LBD_NOK;
        }
        return LBD_OK;
    }

    if ((freq >= FREQ_5G_CH(100)) && (freq <= FREQ_5G_CH(140))) {
        switch(freq) {
            CASE_5G_FREQ(100);
            CASE_5G_FREQ(104);
            CASE_5G_FREQ(108);
            CASE_5G_FREQ(112);
            CASE_5G_FREQ(116);
            CASE_5G_FREQ(120);
            CASE_5G_FREQ(124);
            CASE_5G_FREQ(128);
            CASE_5G_FREQ(132);
            CASE_5G_FREQ(136);
            CASE_5G_FREQ(140);
            default:
                /* No valid frequency in this range */
                return LBD_NOK;
        }
        return LBD_OK;
    }

    return LBD_NOK;

#undef IS_CHAN_IN_PUBLIC_SAFETY_BAND
#undef CASE_5G_FREQ
#undef FREQ_5G_CH
}
#endif


static struct wlanifBSteerControlVapInfo *
han_init_vap(wlanifBSteerControlHandle_t state,const char *ifname ,
                         int sysindex, struct wlanifBSteerControlVapInfo *vap) 
{

    struct iwreq Wrq;
    struct ifreq buffer;
    wlanif_band_e band;
    struct wlanifBSteerControlRadioInfo * radio =NULL;

printf("%s add vap start\n",__func__);
	
    memset(&Wrq, 0, sizeof(Wrq));
    strncpy(Wrq.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(state->controlSock, SIOCGIWFREQ, &Wrq) < 0) {
        dbgf(state->dbgModule, DBGERR, "%s: ioctl() SIOCGIWFREQ failed, ifName: %s",
             __func__, ifname);
        return NULL;
    }

    band = wlanifMapFreqToBand(Wrq.u.freq.m);
    if (band >= wlanif_band_invalid) {
        dbgf(state->dbgModule, DBGERR, "%s: ioctl() SIOCGIWFREQ returned invalid frequency, ifName: %s",
             __func__, ifname);
        return NULL;
    }
	
    if(NULL == vap){
    	vap = wlanifBSteerControlAllocateVap(state, band);
    }
	
    if(NULL == vap){
        // Maximum number of VAPs reached on the given band
        return NULL;
    }
	
    strlcpy(vap->ifname, ifname, IFNAMSIZ + 1);

 //  get_from_freq(Wrq.u.freq.m,&channel);
     if(strstr(ifname,"ath0")){
     		radio = wlanifBSteerControlLookupRadioByIfname(state,"wifi0");
     }else  if(strstr(ifname,"ath1")){
		radio = wlanifBSteerControlLookupRadioByIfname(state,"wifi1");
     }else  if(strstr(ifname,"ath2")){
		radio = wlanifBSteerControlLookupRadioByIfname(state,"wifi2");
     }
	 
     vap->radio = radio;
     if(NULL == vap->radio){
		printf("%s,vap init error when set radio\n",__func__);
		return NULL;
     }

     // Get the channel and store in the radio (if not already done)
     if (wlanifBSteerControlUpdateRadioForFrequency(state,
                                                   Wrq.u.freq.m, vap) != LBD_OK) {
		printf("%s,vap init error when get channel and store in the radio\n",__func__);
        return NULL;
    }

     vap->sysIndex =sysindex;
   	
    strncpy(buffer.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(state->controlSock, SIOCGIFHWADDR, &buffer) < 0) {
        dbgf(state->dbgModule, DBGERR, "%s: ioctl() SIOCGIFHWADDR failed, ifName: %s",
             __func__, ifname);
        return NULL;
    }
    lbCopyMACAddr(buffer.ifr_hwaddr.sa_data, vap->macaddr.ether_addr_octet);

    // Get the SSID
    if (wlanifBSteerControlGetSSID(state, ifname, vap) != LBD_OK) {
        return NULL;
    }

    vap->valid = LBD_TRUE;

    // Log the newly constructed interface
    wlanifBSteerControlLogInterfaceInfo(state, vap);
	
    printf("%s ifname=%s,ESSID=%s\n",__func__,ifname,state->essInfo[vap->essId].ssidStr);
printf("%s successfull add vap end\n",__func__);
    return vap;
}

static
struct wlanifBSteerControlVapInfo *han_get_vap_by_ifindex(
        wlanifBSteerControlHandle_t state, int sysIndex) {
    lbDbgAssertExit(state->dbgModule, state);

    wlanif_band_e band;
    wlanif_band_e startingBand = wlanif_band_24g;
    wlanif_band_e endingBand = wlanif_band_invalid;
    int i;

    for (band = startingBand; band <= endingBand; ++band) {
        for (i = 0; i < MAX_VAP_PER_BAND; ++i) {
             if (state->bandInfo[band].vaps[i].sysIndex == sysIndex) {
                return &state->bandInfo[band].vaps[i];
            }
        }
    }

    // Not found
    return NULL;
}

struct wlanifBSteerControlVapInfo *han_get_vap_by_ifname(
        wlanifBSteerControlHandle_t state, char * ifname) {
    lbDbgAssertExit(state->dbgModule, state);

    wlanif_band_e band;
    wlanif_band_e startingBand = wlanif_band_24g;
    wlanif_band_e endingBand = wlanif_band_invalid;
    int i;

    if(state == NULL || ifname ==NULL)
		return NULL;
	
    for (band = startingBand; band <= endingBand; ++band) {
        for (i = 0; i < MAX_VAP_PER_BAND; ++i) {
		if(strcmp(ifname, state->bandInfo[band].vaps[i].ifname) == 0){
                    return &state->bandInfo[band].vaps[i];
            }
        }
    }

    // Not found
    return NULL;
}

#if 1
LBD_STATUS  han_vap_set_stop(wlanifBSteerControlHandle_t state,int sysindex)
{
	if(state == NULL)
	return LBD_NOK;
	
	char ifname[IFNAMSIZ]={0};
	
	if_indextoname(sysindex,ifname);
	struct wlanifBSteerControlVapInfo *vap = han_get_vap_by_ifindex(state, sysindex);

	printf("%s  vap stop  ifi_index = %d ,ifname = %s \n",__func__,sysindex,ifname);

      if(vap){
            vap->ifaceUp = LBD_FALSE;
	      vap->valid = LBD_FALSE;
	      printf("%s  find the vap sysindex = %d infname = %s\n",__func__,sysindex,ifname);
	  
		return LBD_OK;
      }else{	 
              printf("%s can not find the vap sysindex = %d infname = %s\n",__func__,sysindex,ifname);
	  
	}
	return LBD_OK;

}
#endif

LBD_STATUS  han_check_and_add_vap(wlanifBSteerControlHandle_t state,int sysindex )
{
	if(state == NULL)
	 return LBD_NOK;
	
	char ifname[IFNAMSIZ]={0};
	
	if_indextoname(sysindex,ifname);
	struct wlanifBSteerControlVapInfo * vap = NULL;
	
	struct wlanifBSteerControlVapInfo *vap_index = han_get_vap_by_ifindex(state, sysindex);
	struct wlanifBSteerControlVapInfo *vap_ifname = han_get_vap_by_ifname(state, ifname);
	
      if(vap_index && vap_ifname &&  (vap_index == vap_ifname)){
            vap_index->ifaceUp = LBD_TRUE;
	      vap_index->valid = LBD_TRUE;
		  printf("%s  sysindex = %d,ifname = %s \n ",__func__,sysindex,ifname);
		return LBD_OK;
      }
	  
      vap = vap_index ? vap_index :vap_ifname;
	 
	if(han_init_vap(state,ifname,sysindex,vap))
		return LBD_OK;
	else {
		printf("%s  han init vap error\n",__func__);
	}
	return LBD_NOK;
    // Not found, invalid control handle, or invalid changed param. Do nothing.
}

LBD_STATUS wlanifBSteerControlDumpAssociatedSTAs(wlanifBSteerControlHandle_t state,
                                                 wlanif_associatedSTAsCB callback,
                                                 void *cookie) {
    size_t i;
    for (i = 0; i < wlanif_band_invalid; ++i) {
        size_t j;
        for (j = 0; j < MAX_VAP_PER_BAND; ++j) {
            if (state->bandInfo[i].vaps[j].valid) {
                if (wlanifBSteerControlDumpAssociatedSTAsOneIface(state,
                            &state->bandInfo[i].vaps[j],
                            (wlanif_band_e) i, callback, cookie) != LBD_OK) {
                    return LBD_NOK;
                }
            }
        }
    }

    return LBD_OK;
}

LBD_STATUS wlanifBSteerControlRequestStaRSSI(wlanifBSteerControlHandle_t state,
                                             const lbd_bssInfo_t *bss,
                                             const struct ether_addr * staAddr,
                                             u_int8_t numSamples) {
    LBD_STATUS status = LBD_NOK;

    struct wlanifBSteerControlVapInfo *vap =
        wlanifBSteerControlExtractVapHandle(bss);
    if (!state || !vap || !staAddr || !numSamples) {
        return status;
    }

    wlanif_band_e band = wlanif_resolveBandFromChannelNumber(bss->channelId);
    lbDbgAssertExit(state->dbgModule, band <= wlanif_band_invalid);

    struct wlanifBSteerControlRadioInfo *radio = vap->radio;
    lbDbgAssertExit(state->dbgModule, radio);
    LBD_BOOL measurementBusy = !list_is_empty(&radio->rssiWaitingList);

    if (measurementBusy) {
        status = LBD_OK;
    } else {
        status = wlanifBSteerControlSendRequestRSSI(state, vap, staAddr, numSamples);
    }

    if (status == LBD_OK) {
        list_head_t *iter = radio->rssiWaitingList.next;
        while (iter != &radio->rssiWaitingList) {
            wlanifBSteerControlRSSIRequestEntry_t *curEntry =
                list_entry(iter, wlanifBSteerControlRSSIRequestEntry_t, listChain);

            if (lbAreEqualMACAddrs(&curEntry->addr, staAddr)) {
                // RSSI measuremenet has been queued before, do nothing
                return LBD_OK;
            }
            iter = iter->next;
        }

        // Wait for other RSSI measurement done
        wlanifBSteerControlRSSIRequestEntry_t *entry = calloc(1,
                sizeof(wlanifBSteerControlRSSIRequestEntry_t));
        if (!entry) {
            dbgf(state->dbgModule, DBGERR, "%s: Failed to allocate entry for "
                                           "STA "lbMACAddFmt(":")".",
                 __func__, lbMACAddData(staAddr->ether_addr_octet));
            return LBD_NOK;
        }

        lbCopyMACAddr(staAddr, &entry->addr);
        entry->numSamples = numSamples;
        entry->vap = vap;

        if (measurementBusy) {
            dbgf(state->dbgModule, DBGDEBUG,
                 "%s: RSSI measurement request for STA " lbMACAddFmt(":")
                 " is queued on BSS " lbBSSInfoAddFmt(),
                 __func__, lbMACAddData(staAddr->ether_addr_octet),
                 lbBSSInfoAddData(bss));
        } // else the request has been sent and waiting for measurement back
        list_insert_entry(&entry->listChain, &radio->rssiWaitingList);
    }

    return status;
}

LBD_STATUS wlanifBSteerControlRequestDownlinkRSSI(
        wlanifBSteerControlHandle_t state, const lbd_bssInfo_t *bss,
        const struct ether_addr *staAddr, LBD_BOOL rrmCapable,
        size_t numChannels, const lbd_channelId_t *channelList) {
    struct wlanifBSteerControlVapInfo *vap =
        wlanifBSteerControlExtractVapHandle(bss);
    if (!state || !vap || !staAddr || !rrmCapable ||
        !numChannels || !channelList) {
        // Currently only support 11k capable device
        return LBD_NOK;
    }

    return wlanifBSteerControlSendRRMBcnrptRequest(
               state, vap, staAddr, numChannels, channelList);
}

/**
 * @brief Initialize the ACLs on the provided band (as being empty).
 *
 * @pre state and band are valid
 *
 * @param [in] state  the handle returned from wlanifBSteerControlCreate()
 *                    to use for the initilization
 * @param [in] band  the band on which to initialize
 *
 * @return LBD_OK if the ACLs were initialized; otherwise LBD_NOK
 */
static LBD_STATUS wlanifBSteerControlInitializeACLs(
        wlanifBSteerControlHandle_t state, wlanif_band_e band) {

   #if 0
    if (wlanifBSteerControlPerformMacCmdOnBand(
                state, IEEE80211_MACCMD_FLUSH, band) == LBD_OK &&
        wlanifBSteerControlPerformMacCmdOnBand(
            state, IEEE80211_MACCMD_POLICY_DENY, band) == LBD_OK) {
        return LBD_OK;
    }
	
   #endif

   if(han_flush_black_list()){//pengdecai modified
	   return LBD_NOK;
   }
   
   return LBD_OK;
}

/**
 * @brief Clear the ACLs on the provided band.
 *
 * @pre state and band are valid
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use for the teardown
 * @param [in] band  the band on which to teardown
 *
 * @return LBD_OK if the ACLs were flushed; otherwise LBD_NOK
 */
static void wlanifBSteerControlFlushACLs(
        wlanifBSteerControlHandle_t state, wlanif_band_e band) {
    // Note that errors are ignored here, as we want to clean up all the
    // way regardless.
    #if 0
    wlanifBSteerControlPerformMacCmdOnBand(
        state, IEEE80211_MACCMD_FLUSH, band);
	#endif
	 han_flush_black_list(); //pengdecai modified

}

/**
 * @brief Clear and disable the ACLs on the provided band.
 *
 * @pre state and band are valid
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use for the teardown
 * @param [in] band  the band on which to teardown
 *
 * @return LBD_OK if the ACLs were torn down; otherwise LBD_NOK
 */
static void wlanifBSteerControlTeardownACLs(
        wlanifBSteerControlHandle_t state, wlanif_band_e band) {
    // Note that errors are ignored here, as we want to clean up all the
    // way regardless.
    #if 0
    wlanifBSteerControlPerformMacCmdOnBand(
        state, IEEE80211_MACCMD_FLUSH, band);
    wlanifBSteerControlPerformMacCmdOnBand(
        state, IEEE80211_MACCMD_POLICY_OPEN, band);
	#endif
	//pengdecai modified
	han_flush_black_list(); //pengdecai modified
}

/**
 * @brief Resolve PHY capability information for all VAPs
 *
 * @pre state is valid
 *
 * @param [in] state  the handle returned from wlanifBSteerControlCreate()
 *                    to use for this operation
 *
 * @return LBD_OK if all VAPs' PHY capability info are resolved successfully;
 *         otherwise return LBD_NOK
 */
static LBD_STATUS wlanifBSteerControlResolvePHYCapInfo(wlanifBSteerControlHandle_t state) {
    ieee80211_bsteering_datarate_info_t datarateInfo;
    size_t band, i;
    struct wlanifBSteerControlVapInfo *vap = NULL;
    for (band = wlanif_band_24g; band < wlanif_band_invalid; ++band) {
        for (i = 0; i < MAX_VAP_PER_BAND; ++i) {
            vap = &state->bandInfo[band].vaps[i];
            if (!vap->valid) {
                //break;
                continue;
            }
            if (LBD_NOK == wlanifBSteerControlGetSendVAP(
                    state, vap->ifname, IEEE80211_DBGREQ_BSTEERING_GET_DATARATE_INFO,
                    &vap->macaddr, (void *)&datarateInfo,
                    sizeof(ieee80211_bsteering_datarate_info_t))) {
                // Error has already been printed in wlanifBSteerControlGetSendVAP function
                return LBD_NOK;
            }
            vap->phyCapInfo.valid = LBD_TRUE;
            vap->phyCapInfo.maxChWidth = wlanifMapToBandwidth(
                    state->dbgModule, (enum ieee80211_cwm_width)datarateInfo.max_chwidth),
            vap->phyCapInfo.numStreams = datarateInfo.num_streams;
            vap->phyCapInfo.phyMode = wlanifMapToPhyMode(
                    state->dbgModule, (enum ieee80211_phymode)datarateInfo.phymode),
            vap->phyCapInfo.maxMCS = datarateInfo.max_MCS;
            vap->phyCapInfo.maxMCS = wlanifConvertToSingleStreamMCSIndex(
                    state->dbgModule,
                    (enum ieee80211_phymode)datarateInfo.phymode,
                    datarateInfo.max_MCS);
            vap->phyCapInfo.maxTxPower = datarateInfo.max_txpower;
            dbgf(state->dbgModule, DBGDEBUG, "%s: Resolved PHY capability on %s: "
                 "maxChWidth %u, numStreams %u, phyMode %u maxMCS %u, maxTxPower %u",
                 __func__, vap->ifname, vap->phyCapInfo.maxChWidth,
                 vap->phyCapInfo.numStreams, vap->phyCapInfo.phyMode,
                 vap->phyCapInfo.maxMCS, vap->phyCapInfo.maxTxPower);
            if (vap->radio->maxTxPower && vap->phyCapInfo.maxTxPower != vap->radio->maxTxPower) {
                // Currently, on the same radio, Tx power is always the same for all VAPs.
                // Add a warning log here if it is no longer the case in the future.
                dbgf(state->dbgModule, DBGERR,
                     "%s: VAPs report different Tx power on %s",
                     __func__, vap->radio->ifname);
            }
            if (vap->phyCapInfo.maxTxPower > vap->radio->maxTxPower) {
                // If there is Tx power difference on the same radio, which should
                // not happen for now, the highest value will be used.
                vap->radio->maxTxPower = vap->phyCapInfo.maxTxPower;
            }
        }
    }

    wlanifBSteerControlFindStrongestRadioOnBand(state, wlanif_band_24g);
    wlanifBSteerControlFindStrongestRadioOnBand(state, wlanif_band_5g);

    return LBD_OK;
}

/*modified by pengdecai for lbd blacklist*/
LBD_STATUS wlanifBSteerControlSetChannelStateForSTA(
    wlanifBSteerControlHandle_t state,
    u_int8_t channelCount,
    const lbd_channelId_t *channelList,
    const struct ether_addr *staAddr,
    LBD_BOOL enable) {
    
    int i,radio;
    LBD_STATUS status = LBD_OK;
	
    if (!state || !channelCount || channelCount > WLANIF_MAX_RADIOS || !channelList || !staAddr) {
        return LBD_NOK;
    }

//	printf("\nwlanifBSteerControlSetChannelStateForSTA  ");

	u_int32_t operation = HAN_IOCTL_DCM_LBD_DELMAC;
	if (!enable) {
		operation = HAN_IOCTL_DCM_LBD_ADDMAC;
	}

	if(operation == HAN_IOCTL_DCM_LBD_DELMAC){
	//	printf("operation =HAN_IOCTL_DCM_LBD_DELMAC \n");
	}else{
//		printf("operation =HAN_IOCTL_DCM_LBD_ADDMAC \n");

	}

	return LBD_OK; //pengdecai added.
	
	for (i = 0; i < channelCount; i++) {
        u_int8_t changedCount = 0;
		for(radio = 0; radio  < WLANIF_MAX_RADIOS; radio ++){
			if(state->radioInfo[radio].channel == channelList[i]){
				if(han_dcm_ioctl(state->radioInfo[radio].ifname,\
					          operation,\
					          staAddr->ether_addr_octet,\
					          state->radioInfo[radio].channel,
					          0)){
					 dbgf(state->dbgModule, DBGERR,
                         "%s: ioctl to change state to %d for " lbMACAddFmt(":")
                         "on interface %s failed with errno %u",
                         __func__, enable, lbMACAddData(staAddr->ether_addr_octet),
                         state->radioInfo[radio].ifname,errno);
                    return LBD_NOK;
				}
				changedCount++;
			}
		}
		if (!changedCount) {
            dbgf(state->dbgModule, DBGERR,
                 "%s: Requested change state to %d on channel %d for STA " lbMACAddFmt(":")
                 ", but no VAPs operating on that channel",
                 __func__, enable, channelList[i], lbMACAddData(staAddr));
            status = LBD_NOK;
		 }
     }
	
    return status;
}

#if 0
LBD_STATUS wlanifBSteerControlSetChannelStateForSTA(
    wlanifBSteerControlHandle_t state,
    u_int8_t channelCount,
    const lbd_channelId_t *channelList,
    const struct ether_addr *staAddr,
    LBD_BOOL enable) {
    
    LBD_STATUS status = LBD_OK;
	
    if (!state || !channelCount || channelCount > WLANIF_MAX_RADIOS || !channelList || !staAddr) {
        return LBD_NOK;
    }

    u_int32_t operation = IEEE80211_IOCTL_DELMAC;
    if (!enable) {
        operation = IEEE80211_IOCTL_ADDMAC;
    }

    for (i = 0; i < channelCount; i++) {
        u_int8_t changedCount = 0;

        // Get the band
        wlanif_band_e band = wlanif_resolveBandFromChannelNumber(channelList[i]);
        if (band == wlanif_band_invalid) {
            dbgf(state->dbgModule, DBGERR,
                 "%s: Channel %u is not valid", __func__, channelList[i]);
            return LBD_NOK;
        }

        // Find all VAPs on this band that match channel
        for (vap = 0; vap < MAX_VAP_PER_BAND; ++vap) {
            if (!state->bandInfo[band].vaps[vap].valid) {
                // No more valid VAPs, can exit the loop
                break;
            }
            if (state->bandInfo[band].vaps[vap].radio->channel == channelList[i]) {

                // Found match
                if (wlanifBSteerControlPerformIoctlWithMAC(
                            state, operation, &state->bandInfo[band].vaps[vap],
                            staAddr) != LBD_OK) {
                    dbgf(state->dbgModule, DBGERR,
                         "%s: ioctl to change state to %d for " lbMACAddFmt(":")
                         "on interface %s failed with errno %u",
                         __func__, enable, lbMACAddData(staAddr->ether_addr_octet),
                         state->bandInfo[band].vaps[vap].ifname,
                         errno);
                    return LBD_NOK;
                }

                changedCount++;
            }
        }

        if (!changedCount) {
            dbgf(state->dbgModule, DBGERR,
                 "%s: Requested change state to %d on channel %d for STA " lbMACAddFmt(":")
                 ", but no VAPs operating on that channel",
                 __func__, enable, channelList[i], lbMACAddData(staAddr));
            status = LBD_NOK;
        }
    }
	
    return status;
}
#endif
/**
 * @brief Enable or disable association or just probe responses 
 *        on a VAP
 * 
 * @param [in] state the handle returned from 
 *                   wlanifBSteerControlCreate()
 * @param [in] vap  VAP to change the state on
 * @param [inout] cookie contains 
 *                       wlanifBSteerControlNonCandidateSet_t
 * 
 * @return LBD_OK on success; LBD_NOK otherwise
 */
 
/*modified by pengdecai for lbd blacklist*/
static LBD_STATUS wlanifBSteerControlNonCandidateSetCB(
    wlanifBSteerControlHandle_t state,
    struct wlanifBSteerControlVapInfo *vap,
    void *cookie) {

    wlanifBSteerControlNonCandidateSet_t *setParams = 
        (wlanifBSteerControlNonCandidateSet_t *)cookie;

    if (!setParams->probeOnly) {
	   u_int32_t operation = HAN_IOCTL_DCM_LBD_DELMAC;
	   if (!setParams->enable) {
		   operation = HAN_IOCTL_DCM_LBD_ADDMAC;
		   return LBD_OK; //pengdecai added.
	
	   }

//	   printf("\nwlanifBSteerControlNonCandidateSetCB  ");
	   
   
	   if(operation == HAN_IOCTL_DCM_LBD_DELMAC){
	   	return LBD_OK; //pengdecai added.
	
//		   printf("operation =HAN_IOCTL_DCM_LBD_DELMAC \n");
	   }else{
//		   printf("operation =HAN_IOCTL_DCM_LBD_ADDMAC \n");
	   
	   }


	   if(han_dcm_ioctl(vap->radio->ifname,\
	   	             operation,\
	   	             setParams->staAddr->ether_addr_octet,\
	   	             vap->radio->channel,0)){
			   dbgf(state->dbgModule, DBGERR,
					"%s: ioctl to change state to %d for " lbMACAddFmt(":")
					"on interface %s failed with errno %u",
					__func__, setParams->enable, 
					lbMACAddData(setParams->staAddr->ether_addr_octet),
					vap->ifname,
					errno);
			   return LBD_NOK;

	   }
   }
    // Only need to disable probe response witholding,
    // or enable if in probe only mode - it is enabled automatically when
    // enabling the VAP
    if ((!setParams->enable) || setParams->probeOnly) {
        u_int8_t bsteering_withhold;
        bsteering_withhold = setParams->enable ? 0 : 1;

        if (wlanifBSteerControlSetSendVAP(
            state, vap->ifname,
            IEEE80211_DBGREQ_BSTEERING_SET_PROBE_RESP_WH,
            setParams->staAddr, (void *) &bsteering_withhold,
            sizeof(bsteering_withhold)) != LBD_OK) {
            dbgf(state->dbgModule, DBGERR,
                 "%s: ioctl to set probe response status to %d for candidate "
                 " failed with errno %u",
                 __func__, setParams->enable, errno);
            return LBD_NOK;
        }
    }

    return LBD_OK;
}

#if 0
static LBD_STATUS wlanifBSteerControlNonCandidateSetCB(
    wlanifBSteerControlHandle_t state,
    struct wlanifBSteerControlVapInfo *vap,
    void *cookie) {

    wlanifBSteerControlNonCandidateSet_t *setParams = 
        (wlanifBSteerControlNonCandidateSet_t *)cookie;

    if (!setParams->probeOnly) {
	   #if 0
        // Set association state
        u_int32_t operation = IEEE80211_IOCTL_DELMAC;
        if (!setParams->enable) {
            operation = IEEE80211_IOCTL_ADDMAC;
        }
       #endif
	   
	   u_int32_t operation = IEEE80211_IOCTL_DELMAC;
	   if (!setParams->enable) {
		   operation = IEEE80211_IOCTL_ADDMAC;
	   }
	   
        if (wlanifBSteerControlPerformIoctlWithMAC(
            state, operation, vap, setParams->staAddr) != LBD_OK) {
            dbgf(state->dbgModule, DBGERR,
                 "%s: ioctl to change state to %d for " lbMACAddFmt(":")
                 "on interface %s failed with errno %u",
                 __func__, setParams->enable, 
                 lbMACAddData(setParams->staAddr->ether_addr_octet),
                 vap->ifname,
                 errno);
            return LBD_NOK;
        }
    }
    // Only need to disable probe response witholding,
    // or enable if in probe only mode - it is enabled automatically when
    // enabling the VAP
    if ((!setParams->enable) || setParams->probeOnly) {
        u_int8_t bsteering_withhold;
        bsteering_withhold = setParams->enable ? 0 : 1;

        if (wlanifBSteerControlSetSendVAP(
            state, vap->ifname,
            IEEE80211_DBGREQ_BSTEERING_SET_PROBE_RESP_WH,
            setParams->staAddr, (void *) &bsteering_withhold,
            sizeof(bsteering_withhold)) != LBD_OK) {
            dbgf(state->dbgModule, DBGERR,
                 "%s: ioctl to set probe response status to %d for candidate "
                 " failed with errno %u",
                 __func__, setParams->enable, errno);
            return LBD_NOK;
        }
    }

    return LBD_OK;
}
#endif
/**
 * @brief Callback function to use when finding VAPs that match 
 *        the ESS but aren't on the candidate list.
 * 
 * @param [in] state  BSteerControl state
 * @param [in] vap  VAP found
 * @param [inout] cookie contains 
 *                       wlanifBSteerControlNonCandidateGet_t
 * 
 * @return Always returns LBD_OK
 */
static LBD_STATUS wlanifBSteerControlNonCandidateGetCB(
    wlanifBSteerControlHandle_t state,
    struct wlanifBSteerControlVapInfo *vap,
    void *cookie) {

    wlanifBSteerControlNonCandidateGet_t *getParams = 
        (wlanifBSteerControlNonCandidateGet_t *)cookie;

    if (getParams->outCandidateCount >= getParams->maxCandidateCount) {
        return LBD_OK;
    }

    getParams->outCandidateList[getParams->outCandidateCount].apId = 
        LBD_APID_SELF;
    getParams->outCandidateList[getParams->outCandidateCount].channelId = 
        vap->radio->channel;
    getParams->outCandidateList[getParams->outCandidateCount].essId = 
        vap->essId;
    getParams->outCandidateList[getParams->outCandidateCount].vap = 
        vap;

    getParams->outCandidateCount++;

    return LBD_OK;
}

/**
 * @brief Find the set of VAPs on the same ESS as the candidate 
 *        list but not matching the candidate list.
 *  
 *        Will take action dependant on the callback function
 *        provided.
 * 
 * @param [in] handle  the handle returned from
 *                     wlanifBSteerControlCreate()
 * @param [in] candidateCount number of candidates in
 *                            candidateList
 * @param [in] candidateList set of candidate BSSes 
 * @param [in] callback  callback function to call when an 
 *                       appropriate VAP is found
 * @param [in] cookie cookie provided to callback function
 * 
 * @return LBD_OK on success; LBD_NOK otherwise
 */
static LBD_STATUS wlanifBSteerControlNonCandidateMatch(
    wlanifBSteerControlHandle_t state,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    wlanifBSteerControlNonCandidateCB callback,
    void *cookie) {

    if (!state || !candidateCount || candidateCount > ieee80211_bstm_req_max_candidates ||
        !candidateList) {
        return LBD_NOK;
    }

    wlanif_band_e band;

    // Disable or enable for all VAPs on the same ESS but not on the candidate list
    for (band = wlanif_band_24g; band < wlanif_band_invalid; band++) {
        int vap;
        for (vap = 0; vap < MAX_VAP_PER_BAND; ++vap) {
            if (!state->bandInfo[band].vaps[vap].valid) {
                // No more valid VAPs on this band
               // break;
               continue;
            }

            // Check if this VAP is on the same ESS as the candidates
            if (state->bandInfo[band].vaps[vap].essId == candidateList[0].essId) {
                // Is this a candidate VAP?
                LBD_BOOL match = LBD_FALSE;
                int i;
                for (i = 0; i < candidateCount; i++) {
                    if (!candidateList[i].vap) {
                        return LBD_NOK;
                    }
                    if (candidateList[i].vap == &state->bandInfo[band].vaps[vap]) {
                        // Candidate VAP
                        match = LBD_TRUE;
                        break;
                    }
                }

                if (!match) {
                    if (callback(state, &state->bandInfo[band].vaps[vap],
                                 cookie) != LBD_OK) {
                        return LBD_NOK;
                    }
                }
            }
        }
    }

    return LBD_OK;
}

/*modefied by pengdecai for dcm*/
LBD_STATUS	wlanif_han_dcm_balance_ioctl_done(
			wlanifBSteerControlHandle_t state,
			 char * ifname,
			unsigned char option,
	        const unsigned char * mac, 
	        unsigned char channel,
	        unsigned char denycnt){

	int i;
	int radioid = 0xff;
//	printf("lbd_4\n");
	

	for (i = 0;i < 3; i ++){
		if(state->radioInfo[i].channel == channel){
			radioid = i;
			break;			
		}
	}
	
//	printf("lbd_5\n");
		
	if(radioid == 0xff){
	   printf("radioid == 0xff\n");
	   return LBD_NOK;
	}
	
	if(option == HAN_IOCTL_DCM_LBD_DELMAC ||\
	   option == HAN_IOCTL_DCM_LBD_ADDMAC){
             if(han_dcm_ioctl(ifname,option,mac,channel,denycnt)){
		          return LBD_NOK;
	      }
	      	return LBD_OK;
	}
	
	if(han_dcm_ioctl(state->radioInfo[radioid].ifname\
	                 ,option,mac,channel,denycnt)){
		return LBD_NOK;
	}
	return LBD_OK;
}




LBD_STATUS wlanifBSteerControlSetNonCandidateStateForSTA(
    wlanifBSteerControlHandle_t state,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    const struct ether_addr *staAddr,
    LBD_BOOL enable,
    LBD_BOOL probeOnly) {

    // Other parameters checked inside the function call
    if (!staAddr) {
        return LBD_NOK;
    }

    wlanifBSteerControlNonCandidateSet_t setParams = {
        staAddr,
        enable,
        probeOnly
    };

    return wlanifBSteerControlNonCandidateMatch(
        state, candidateCount, candidateList,
        wlanifBSteerControlNonCandidateSetCB,
        (void *)&setParams);
}

u_int8_t wlanifBSteerControlGetNonCandidateStateForSTA(
    wlanifBSteerControlHandle_t state,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    u_int8_t maxCandidateCount,
    lbd_bssInfo_t *outCandidateList) {

    // Other parameters checked inside the function call
    if (!outCandidateList || !maxCandidateCount) {
        return 0;
    }

    wlanifBSteerControlNonCandidateGet_t getParams = {
        maxCandidateCount,
        0,
        outCandidateList
    };

    if (wlanifBSteerControlNonCandidateMatch(
            state, candidateCount, candidateList,
            wlanifBSteerControlNonCandidateGetCB,
            (void *)&getParams) != LBD_OK) {
        return 0;
    }

    return getParams.outCandidateCount;
}

/*modified by pengdecai for lbd blacklist*/
LBD_STATUS wlanifBSteerControlSetCandidateStateForSTA(
    wlanifBSteerControlHandle_t state,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    const struct ether_addr *staAddr,
    LBD_BOOL enable) {

    size_t i,k;

    if (!state || !candidateCount || candidateCount > ieee80211_bstm_req_max_candidates ||
        !candidateList || !staAddr) {
        return LBD_NOK;
    }

    // Set association state
    u_int32_t operation = HAN_IOCTL_DCM_LBD_DELMAC;
    if (!enable) {
        operation = HAN_IOCTL_DCM_LBD_ADDMAC;
		return LBD_OK; //pengdecai added.
	
    }
	
	printf("wlanifBSteerControlSetCandidateStateForSTA\n");
	
	if(operation == HAN_IOCTL_DCM_LBD_DELMAC){
		return LBD_OK; //pengdecai added.
	
		printf("operation =HAN_IOCTL_DCM_LBD_DELMAC \n");
	}else{
		printf("operation =HAN_IOCTL_DCM_LBD_ADDMAC \n");
	}

    int radio_num = 0;
	struct wlanifBSteerControlRadioInfo * radio[3]={NULL};

    for (i = 0; i < candidateCount; i++) {
		struct wlanifBSteerControlVapInfo *vap =
            (struct wlanifBSteerControlVapInfo *)candidateList[i].vap;
        if (vap) {
			for(k = 0; k < 3; k ++){
				if(radio[k] == NULL){
					radio[k] = vap->radio;
					radio_num ++;
					break;
				}else if(radio[k] && HAN_DCM_STRING_EQ(radio[k]->ifname,vap->radio->ifname)){
					break;
				}
				else if(radio[k] && (!HAN_DCM_STRING_EQ(radio[k]->ifname,vap->radio->ifname))){
					continue;
				}
			}
        } else {
            return LBD_NOK;
		}
	}

    for (i = 0; i < radio_num; i++) {
		if(han_dcm_ioctl(radio[i]->ifname,operation,staAddr->ether_addr_octet,radio[i]->channel,0)){
            dbgf(state->dbgModule, DBGERR,
                 "%s: ioctl to set %s state to %d for candidate failed with errno %u",
                 __func__, radio[i]->ifname,enable, errno);
            return LBD_NOK;
		}
	}	
	
    for (i = 0; i < candidateCount; i++) {
        struct wlanifBSteerControlVapInfo *vap =
            (struct wlanifBSteerControlVapInfo *)candidateList[i].vap;
        if (!vap) {
            return LBD_NOK;
        }

        // Only need to disable probe response witholding - it is enabled automatically when
        // enabling the VAP
        if (!enable) {
            u_int8_t bsteering_withhold = 1;

            if (wlanifBSteerControlSetSendVAP(
                        state, vap->ifname,
                        IEEE80211_DBGREQ_BSTEERING_SET_PROBE_RESP_WH,
                        staAddr, (void *) &bsteering_withhold,
                        sizeof(bsteering_withhold)) != LBD_OK) {
                dbgf(state->dbgModule, DBGERR,
                     "%s: ioctl to start probe response witholding for candidate "
                     lbBSSInfoAddFmt() " failed with errno %u",
                     __func__, lbBSSInfoAddData(&candidateList[i]), errno);
                return LBD_NOK;
            }
        }
    }

    return LBD_OK;
}

#if 0
LBD_STATUS wlanifBSteerControlSetCandidateStateForSTA(
    wlanifBSteerControlHandle_t state,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    const struct ether_addr *staAddr,
    LBD_BOOL enable) {

    if (!state || !candidateCount || candidateCount > ieee80211_bstm_req_max_candidates ||
        !candidateList || !staAddr) {
        return LBD_NOK;
    }

    struct iwreq iwr;
    struct sockaddr addr;

    memset(&addr, 0, sizeof(addr));
    addr.sa_family = ARPHRD_ETHER;
    lbCopyMACAddr(staAddr->ether_addr_octet, addr.sa_data);

    memset(&iwr, 0, sizeof(iwr));

    // This parameter is small enough that it can fit in the name union
    // member.
    memcpy(iwr.u.name, &addr, sizeof(addr));

    // Set association state
    u_int32_t operation = IEEE80211_IOCTL_DELMAC;
    if (!enable) {
        operation = IEEE80211_IOCTL_ADDMAC;
    }

    size_t i;

    for (i = 0; i < candidateCount; i++) {
        struct wlanifBSteerControlVapInfo *vap =
            (struct wlanifBSteerControlVapInfo *)candidateList[i].vap;
        if (!vap) {
            return LBD_NOK;
        }
        strncpy(iwr.ifr_name, vap->ifname, IFNAMSIZ);

        if (ioctl(state->controlSock, operation, &iwr) < 0) {
            dbgf(state->dbgModule, DBGERR,
                 "%s: ioctl to set VAP state to %d for candidate " lbBSSInfoAddFmt() " failed with errno %u",
                 __func__, enable, lbBSSInfoAddData(&candidateList[i]), errno);
            return LBD_NOK;
        }

        // Only need to disable probe response witholding - it is enabled automatically when
        // enabling the VAP
        if (!enable) {
            u_int8_t bsteering_withhold = 1;

            if (wlanifBSteerControlSetSendVAP(
                        state, vap->ifname,
                        IEEE80211_DBGREQ_BSTEERING_SET_PROBE_RESP_WH,
                        staAddr, (void *) &bsteering_withhold,
                        sizeof(bsteering_withhold)) != LBD_OK) {
                dbgf(state->dbgModule, DBGERR,
                     "%s: ioctl to start probe response witholding for candidate "
                     lbBSSInfoAddFmt() " failed with errno %u",
                     __func__, lbBSSInfoAddData(&candidateList[i]), errno);
                return LBD_NOK;
            }
        }
    }

    return LBD_OK;
}
#endif
LBD_BOOL wlanifBSteerControlIsBSSIDInList(
    wlanifBSteerControlHandle_t state,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    const struct ether_addr *bssid) {

    if (!state || !candidateCount || !candidateList || !bssid) {
        return LBD_FALSE;
    }

    size_t i;

    for (i = 0; i < candidateCount; i++) {
        struct wlanifBSteerControlVapInfo *vap =
            wlanifBSteerControlExtractVapHandle(&candidateList[i]);
        
        if (!vap) {
            dbgf(state->dbgModule, DBGERR,
                 "%s: BSS " lbBSSInfoAddFmt() " does not have a VAP handle",
                 __func__, lbBSSInfoAddData(&candidateList[i]));
            continue;
        }

        lbDbgAssertExit(state->dbgModule, vap->valid);

        if (lbAreEqualMACAddrs(&bssid->ether_addr_octet, 
                               &vap->macaddr.ether_addr_octet)) {
            return LBD_TRUE;
        }
    }

    // No match found
    return LBD_FALSE;
}

u_int8_t wlanifBSteerControlGetChannelList(wlanifBSteerControlHandle_t state,
                                           lbd_channelId_t *channelList,
                                           u_int8_t maxSize) {
    if (!state || !channelList) {
        return 0;
    }

    u_int8_t channelCount = 0;
    size_t i;

    for (i = 0; i < WLANIF_MAX_RADIOS; ++i) {
        if (state->radioInfo[i].valid) {
            channelList[channelCount] = state->radioInfo[i].channel;
            channelCount++;

            if (channelCount >= maxSize) {
                // Have reached the maximum number of channels
                break;
            }
        }
    }

    return channelCount;
}

LBD_STATUS wlanifBSteerControlDisassociateSTA(
        wlanifBSteerControlHandle_t state, const lbd_bssInfo_t *assocBSS,
        const struct ether_addr *staAddr) {
    if (!state || !assocBSS || !assocBSS->vap || !staAddr) {
        return LBD_NOK;
    }

    return wlanifBSteerControlPerformIoctlWithMAC(
            state, IEEE80211_IOCTL_KICKMAC, assocBSS->vap, staAddr);
}

LBD_STATUS wlanifBSteerControlSendBTMRequest(wlanifBSteerControlHandle_t state,
                                             const lbd_bssInfo_t *assocBSS,
                                             const struct ether_addr *staAddr,
                                             u_int8_t dialogToken,
                                             u_int8_t candidateCount,
                                             const lbd_bssInfo_t *candidateList) {
    int i;
    struct ieee80211_bstm_reqinfo_target reqinfo;

    // Sanity check
    if (!state || !assocBSS || !assocBSS->vap ||
        !staAddr || !candidateCount || !candidateList ||
        candidateCount > ieee80211_bstm_req_max_candidates) {
        return LBD_NOK;
    }

    reqinfo.dialogtoken = dialogToken;
    reqinfo.num_candidates = candidateCount;

    // Copy the candidates
    // Candidates are in preference order - first candidate is most preferred
    for (i = 0; i < candidateCount; i++) {
        struct wlanifBSteerControlVapInfo *vap =
            (struct wlanifBSteerControlVapInfo *)candidateList[i].vap;
        if (!vap) {
            return LBD_NOK;
        }

        lbCopyMACAddr(&vap->macaddr.ether_addr_octet,
                      &reqinfo.candidates[i].bssid);
        reqinfo.candidates[i].channel_number = candidateList[i].channelId;
        reqinfo.candidates[i].preference = UCHAR_MAX - i;
    }

    // Send on the VAP this STA is associated on
    struct wlanifBSteerControlVapInfo *vap =
        (struct wlanifBSteerControlVapInfo *)assocBSS->vap;
    return wlanifBSteerControlSetSendVAP(state,
                                         vap->ifname,
                                         IEEE80211_DBGREQ_SENDBSTMREQ_TARGET, staAddr,
                                         (void *)&reqinfo, sizeof(reqinfo));
}

LBD_STATUS wlanifBSteerControlRestartChannelUtilizationMonitoring(
        wlanifBSteerControlHandle_t state) {
    // Sanity check
    if (!state) {
        return LBD_NOK;
    }

    // If band steering is not currently enabled, we do not want to try to
    // disable it, as otherwise we might get a false failure (since the driver
    // checks for a double disable).
    if (state->bandSteeringEnabled) {
        if (wlanifBSteerControlDisable(state) == LBD_NOK) {
            dbgf(state->dbgModule, DBGERR,
                 "%s: Temporarily disabling on both bands failed",
                 __func__);
            return LBD_NOK;
        }else {
            dbgf(state->dbgModule, DBGERR,
                 "%s:  disabling on both bands successfull\n",
                 __func__);

	}
    }

    // Flush the ACLs as we could be disabled for a while if the new channel
    // is a DFS one.
    wlanifBSteerControlFlushACLs(state, wlanif_band_24g);
    wlanifBSteerControlFlushACLs(state, wlanif_band_5g);

    LBD_BOOL enabled = LBD_FALSE;
    if (wlanifBSteerControlEnableWhenReady(state, &enabled) == LBD_NOK) {
        dbgf(state->dbgModule, DBGERR,
             "%s: Re-enabling on both bands failed", __func__);
        return LBD_NOK;
    }else{
        dbgf(state->dbgModule, DBGERR,
             "%s: Re-enabling on both bands successfull", __func__);
    }

    if (enabled) {
        dbgf(state->dbgModule, DBGINFO, "%s: Restart complete", __func__);
        evloopTimeoutUnregister(&state->vapReadyTimeout);
    }
    return LBD_OK;
}

void wlanifBSteerControlHandleRSSIMeasurement(
        wlanifBSteerControlHandle_t state,
        const lbd_bssInfo_t *bss,
        const struct ether_addr *staAddr) {
    struct wlanifBSteerControlVapInfo *vap =
        wlanifBSteerControlExtractVapHandle(bss);
    if (!state || !vap || !staAddr) {
        return;
    }

    struct wlanifBSteerControlRadioInfo *radio = vap->radio;
    lbDbgAssertExit(state->dbgModule, radio);
    if (list_is_empty(&radio->rssiWaitingList)) {
        dbgf(state->dbgModule, DBGERR, "%s: No RSSI measurement is pending (received one from "
                                       lbMACAddFmt(":")").",
             __func__, lbMACAddData(staAddr->ether_addr_octet));
        return;
    }

    wlanifBSteerControlRSSIRequestEntry_t *head =
        list_first_entry(&radio->rssiWaitingList,
                         wlanifBSteerControlRSSIRequestEntry_t,
                         listChain);

    if (!lbAreEqualMACAddrs(head->addr.ether_addr_octet,
                            staAddr->ether_addr_octet)) {
        dbgf(state->dbgModule, DBGERR, "%s: Expecting RSSI measurement from "
                                       lbMACAddFmt(":")", received one from "
                                       lbMACAddFmt(":")".",
             __func__, lbMACAddData(head->addr.ether_addr_octet),
             lbMACAddData(staAddr->ether_addr_octet));
        return;
    }

    list_remove_entry(&head->listChain);
    free(head);

    if (list_is_empty(&radio->rssiWaitingList)) {
        return;
    }

    list_head_t *iter = radio->rssiWaitingList.next;
    while (iter != &radio->rssiWaitingList) {
        wlanifBSteerControlRSSIRequestEntry_t *curEntry =
            list_entry(iter, wlanifBSteerControlRSSIRequestEntry_t, listChain);

        iter = iter->next;

        if (LBD_NOK == wlanifBSteerControlSendRequestRSSI(state, curEntry->vap, &curEntry->addr,
                                                          curEntry->numSamples)) {
            // If request RSSI fails, do not retry, rely on RSSI xing event to update RSSI
            dbgf(state->dbgModule, DBGERR, "%s: Failed to request RSSI measurement for "
                                           lbMACAddFmt(":")".",
                 __func__, lbMACAddData(curEntry->addr.ether_addr_octet));
            list_remove_entry(&curEntry->listChain);
            free(curEntry);
        } else {
            dbgf(state->dbgModule, DBGDEBUG, "%s: RSSI measurement request for STA "
                                         lbMACAddFmt(":")" is dequeued and sent.",
                 __func__, lbMACAddData(curEntry->addr.ether_addr_octet));
            break;
        }
    }
}

LBD_STATUS wlanifBSteerControlGetBSSInfo(wlanifBSteerControlHandle_t state,
                                         u_int32_t sysIndex, lbd_bssInfo_t *bss) {
    if (!state || !bss) {
        return LBD_NOK;
    }

    struct wlanifBSteerControlVapInfo *vap =
            wlanifBSteerControlGetVAPFromSysIndex(state, sysIndex, wlanif_band_invalid);

    if (vap) {
        bss->apId = LBD_APID_SELF;
        bss->essId = vap->essId;
        bss->channelId = vap->radio->channel;
        bss->vap = vap;

        return LBD_OK;
    }

    // No match found
    return LBD_NOK;
}

LBD_STATUS wlanifBSteerControlGetBSSInfoFromBSSID(
    wlanifBSteerControlHandle_t state,
    const u_int8_t *bssid,
    lbd_bssInfo_t *bss) {

    wlanif_band_e band;
    int i;

    if (!state || !bss || !bssid) {
        return LBD_NOK;
    }

    for (band = wlanif_band_24g ; band < wlanif_band_invalid; ++band) {
        for (i = 0; i < MAX_VAP_PER_BAND; ++i) {
            if (!state->bandInfo[band].vaps[i].valid) {
                break;
            }
            if (lbAreEqualMACAddrs(bssid,
                                   state->bandInfo[band].vaps[i].macaddr.ether_addr_octet)) {
                // Found match
                bss->apId = LBD_APID_SELF;
                bss->essId = state->bandInfo[band].vaps[i].essId;
                bss->channelId = state->bandInfo[band].vaps[i].radio->channel;
                bss->vap = &state->bandInfo[band].vaps[i];

                return LBD_OK;
            }
        }
    }

    // No match found
    return LBD_NOK;
}

/**
 * @brief Enable stats collection for direct attach
 *
 * @param [in] state the handle returned from
 *                   wlanifBSteerControlCreate()
 * @param [in] bss To obtain vap and subsequently the radio
 *                 for which stats collection needs to be enabled
 */
static LBD_STATUS wlanifBSteerControlEnableNoDebug(wlanifBSteerControlHandle_t state,
                                            const lbd_bssInfo_t *bss) {
    struct wlanifBSteerControlVapInfo *vap =
        wlanifBSteerControlExtractVapHandle(bss);
    LBD_STATUS result = LBD_OK;
    if (0 == vap->radio->numEnableStats) {
        result =
            wlanifBSteerControlPrivIoctlSetParam(state, vap->radio,
                                                 vap->radio->enableNoDebug,
                                                 0); /*its a -ve ioctl so 0 means enable */
    }
    return result;
}

LBD_STATUS wlanifBSteerControlEnableSTAStats(wlanifBSteerControlHandle_t state,
                                             const lbd_bssInfo_t *bss) {
    struct wlanifBSteerControlVapInfo *vap =
        wlanifBSteerControlExtractVapHandle(bss);
    if (!state || !vap) {
        return LBD_NOK;
    }

    LBD_STATUS result = LBD_OK;
    if (vap->radio->enableNoDebug) {
        result = wlanifBSteerControlEnableNoDebug( state,bss );
    }
    else if (vap->radio->enableOLStatsIoctl) {
        if (0 == vap->radio->numEnableStats) {
            result =
                wlanifBSteerControlPrivIoctlSetParam(state, vap->radio,
                                                     vap->radio->enableOLStatsIoctl,
                                                     1);
        }
    }
    // Otherwise, must be a radio that does not require stats to be
    // enabled. Succeed without doing anything.

    // Keep track of the number of enables so that when an equivalent number
    // of disables is done, we can set the driver back into no stats mode.
    //
    // Note that this bookkeeping is done even when the ioctl was not resolved
    // so that we can enforce that an enable has to be done prior to sampling
    // the STA stats.
    if (LBD_OK == result) {
        vap->radio->numEnableStats++;
    }
    return result;
}

/**
 * @brief Get STA stats from the driver 
 * 
 * @param [in] state  the handle returned from 
 *                    wlanifBSteerControlCreate()
 * @param [in] vap  VAP to fetch STA stats on
 * @param [in] staAddr  STA to collect stats for
 * @param [out] stats  stats returned from driver 
 * 
 * @return LBD_OK if the STA stats could be fetched; LBD_NOK 
 *         otherwise
 */
static LBD_STATUS wlanifBSteerControlGetSTAStats(wlanifBSteerControlHandle_t state,
                                                 const struct wlanifBSteerControlVapInfo *vap,
                                                 const struct ether_addr *staAddr,
                                                 struct ieee80211req_sta_stats *stats) {
    struct iwreq iwr;
    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, vap->ifname, IFNAMSIZ);

    lbCopyMACAddr(staAddr->ether_addr_octet, stats->is_u.macaddr);
    iwr.u.data.pointer = stats;
    iwr.u.data.length = sizeof(*stats);

    if (ioctl(state->controlSock, IEEE80211_IOCTL_STA_STATS, &iwr) < 0) {
        return LBD_NOK;
    }

    return LBD_OK;
}

LBD_STATUS wlanifBSteerControlSampleSTAStats(wlanifBSteerControlHandle_t state,
                                             const lbd_bssInfo_t *bss,
                                             const struct ether_addr *staAddr,
                                             LBD_BOOL rateOnly,
                                             wlanif_staStatsSnapshot_t *staStats) {
    struct wlanifBSteerControlVapInfo *vap =
        wlanifBSteerControlExtractVapHandle(bss);
    if (!state || !vap || !staAddr || !staStats) {
        return LBD_NOK;
    }

    if (vap->radio->numEnableStats || rateOnly) {
        struct ieee80211req_sta_stats stats;
        
        if (wlanifBSteerControlGetSTAStats(state, vap, staAddr, &stats) != LBD_OK) {
            dbgf(state->dbgModule, DBGERR,
                 "%s: Failed to retrieve STA stats for " lbMACAddFmt(":") " on %s",
                 __func__, lbMACAddData(staAddr->ether_addr_octet),
                 vap->ifname);
            return LBD_NOK;
        }

        // Success, so fill in the out parameter.
        if (!rateOnly) {
            // Tx and Rx byte counts will only be valid if called with
            // stats enabled.
            staStats->txBytes = stats.is_stats.ns_tx_bytes_success;
            staStats->rxBytes = stats.is_stats.ns_rx_bytes;
        } else {
            staStats->txBytes = 0;
            staStats->rxBytes = 0;
        }

        // Rates are reported in Kbps, so convert them to Mbps.
        staStats->lastTxRate = stats.is_stats.ns_last_tx_rate / 1000;
        staStats->lastRxRate = stats.is_stats.ns_last_rx_rate / 1000;
        return LBD_OK;
    } else {   // stats are not enabled
        dbgf(state->dbgModule, DBGERR,
             "%s: Cannot sample STA stats for " lbMACAddFmt(":") " on %s "
             "as stats collection is not enabled",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             vap->ifname);
        return LBD_NOK;
    }
}

LBD_STATUS wlanifBSteerControlDisableSTAStats(wlanifBSteerControlHandle_t state,
                                              const lbd_bssInfo_t *bss) {
    struct wlanifBSteerControlVapInfo *vap =
        wlanifBSteerControlExtractVapHandle(bss);
    if (!state || !vap) {
        return LBD_NOK;
    }

    LBD_STATUS result = LBD_OK;
    if (vap->radio->enableNoDebug) {
        result = wlanifBSteerControlDisableNoDebug( state, bss );
    }
    else if (vap->radio->enableOLStatsIoctl) {
        if (1 == vap->radio->numEnableStats) {
            result =
                wlanifBSteerControlPrivIoctlSetParam(state, vap->radio,
                                                     vap->radio->enableOLStatsIoctl,
                                                     0);
        }
    }
    // Otherwise, must be a radio that does not require stats to be
    // disabled. Succeed without doing anything.
    if (LBD_OK == result && vap->radio->numEnableStats) {
        vap->radio->numEnableStats--;
    }

    return result;
}

/**
 * @brief Disable stats collection
 *
 * @param [in] state the handle returned from
 *                    wlanifBSteerControlCreate()
 * @param [in] bss Used to obtain vap and subsequently
 *                radio for which stats collection needs to be disabled
 */
static LBD_STATUS wlanifBSteerControlDisableNoDebug(wlanifBSteerControlHandle_t state,
                                             const lbd_bssInfo_t *bss) {
    struct wlanifBSteerControlVapInfo *vap =
        wlanifBSteerControlExtractVapHandle(bss);

    LBD_STATUS result = LBD_OK;
    if (1 == vap->radio->numEnableStats) {
        result = wlanifBSteerControlPrivIoctlSetParam(state, vap->radio,
                                                      vap->radio->enableNoDebug,
                                                      1); /*-ve ioctl 1 mean disable here */
    }
    return result;
}

const wlanif_phyCapInfo_t *wlanifBSteerControlGetBSSPHYCapInfo(
        wlanifBSteerControlHandle_t state, const lbd_bssInfo_t *bss) {
    struct wlanifBSteerControlVapInfo *vap =
        wlanifBSteerControlExtractVapHandle(bss);
    if (!state || !vap) {
        return NULL;
    }

    return &vap->phyCapInfo;
}

LBD_STATUS wlanifBSteerControlUpdateChannel(wlanifBSteerControlHandle_t state,
                                            wlanif_band_e band,
                                            u_int32_t sysIndex,
                                            u_int32_t frequency) {
    if (!state || band >= wlanif_band_invalid) {
        return LBD_NOK;
    }

    int i;

    // Find the VAP which has changed channel.
    struct wlanifBSteerControlVapInfo *vap =
            wlanifBSteerControlGetVAPFromSysIndex(state, sysIndex, band);
    if (vap) {
        // Found match - get the frequency for the VAP
        if (frequency <= 1000) {
            // This is a channel - need to resolve the regclass
            vap->radio->channel = frequency;

            if (wlanifResolveRegclass(
                frequency,
                &vap->radio->regClass) != LBD_OK) {
                dbgf(state->dbgModule, DBGERR,
                     "%s: Invalid regulatory class for radio %s, channel is %d",
                     __func__, vap->radio->ifname, frequency);
                return LBD_NOK;
            }
        } else {
            // This is a frequency - resolve channel and regclass
            if (wlanifResolveRegclassAndChannum(
                frequency, &vap->radio->channel, &vap->radio->regClass) != LBD_OK) {
                dbgf(state->dbgModule, DBGERR,
                     "%s: Invalid channel / regulatory class for radio %s, frequency is %d",
                     __func__, vap->radio->ifname, frequency);
                return LBD_NOK;
            }
        }

        wlanifBSteerControlNotifyChanChangeObserver(state, vap);

        // Log the updated interface
        wlanifBSteerControlLogInterfaceInfo(state, vap);

	  for(i = 0; i < WLANIF_MAX_RADIOS;i ++){
		if(strcmp(g_own_ap_state.radio[i].ifname,vap->radio->ifname)==0){
                  g_own_ap_state.radio[i].channelID =  vap->radio->channel ;
		     g_own_ap_state.radio[i].bandtype = wlanifMapFreqToBand(g_own_ap_state.radio[i].channelID);
		     break;
		}
	  }


        return LBD_OK;
    }

    // No match found
    return LBD_NOK;
}

/**
 * @brief Get the VAP corresponding to sysIndex
 *
 * @param [in] state the 'this' pointer
 * @param [in] sysIndex sysIndex for the VAP to search for
 * @param [in] indexBand band on which sysIndex is found (if
 *                       known).  If set to wlanif_band_invalid,
 *                       will search all bands.
 *
 * @return struct wlanifBSteerControlVapInfo*
 *     pointer to the VAP corresponding to sysIndex if found,
 *     otherwise NULL
 */
static
struct wlanifBSteerControlVapInfo *wlanifBSteerControlGetVAPFromSysIndex(
        wlanifBSteerControlHandle_t state, int sysIndex,
        wlanif_band_e indexBand) {
    lbDbgAssertExit(state->dbgModule, state);

    wlanif_band_e band;
    wlanif_band_e startingBand = wlanif_band_24g;
    wlanif_band_e endingBand = wlanif_band_5g;
    int i;

    if (indexBand != wlanif_band_invalid) {
        startingBand = indexBand;
        endingBand = indexBand;
    }
	
     char ifname[IFNAMSIZ]={0};
     if_indextoname(sysIndex,ifname);
	
 //   printf("%s sysIndex = %d,ifname = %s \n ",__func__,sysIndex,ifname);
	
    for (band = startingBand; band <= endingBand; ++band) {
        for (i = 0; i < MAX_VAP_PER_BAND; ++i) {
            if (!state->bandInfo[band].vaps[i].valid) {
              //  break;
              continue;
            }
		#if 0	
	       printf("%s band = %d, vap_ifname = %s,sysindex = %d \n ",__func__,band,\
		   	state->bandInfo[band].vaps[i].ifname,\
			state->bandInfo[band].vaps[i].sysIndex);
            #endif
            if (state->bandInfo[band].vaps[i].sysIndex == sysIndex) {
                return &state->bandInfo[band].vaps[i];
            }
        }
    }

    // Not found
    return NULL;
}

/**
 * @brief Get the VAP with a matching channel
 *
 * @param [in] state the 'this' pointer
 * @param [in] channelId  the channel to search for
 *
 * @pre state must be valid
 * @pre channelId must be valid
 *
 * @return pointer to the first VAP with a matching channel; otherwise NULL
 */
static struct wlanifBSteerControlVapInfo *
wlanifBSteerControlGetFirstVAPByChannel(
        wlanifBSteerControlHandle_t state, lbd_channelId_t channelId) {
    wlanif_band_e band = wlanif_resolveBandFromChannelNumber(channelId);
    lbDbgAssertExit(state->dbgModule, band != wlanif_band_invalid);

    size_t i;

    for (i = 0; i < MAX_VAP_PER_BAND; ++i) {
        if (!state->bandInfo[band].vaps[i].valid) {
            //break;
            continue;
        }
        if (channelId == state->bandInfo[band].vaps[i].radio->channel) {
	//	printf(" print  channel = %d bandInfo[%d].vaps[%d] = %s\n",channelId,band,i,state->bandInfo[band].vaps[i].ifname);
        }
    }
	
	/*pengdecai for dcm because of app exit as the first vap is athscan.
	* get the not scan vap.
	*/
    for (i = 0; i < MAX_VAP_PER_BAND; ++i) {
        if (!state->bandInfo[band].vaps[i].valid) {
          //  break;
          continue;
        }
        if (channelId == state->bandInfo[band].vaps[i].radio->channel) {
			if(!strstr(state->bandInfo[band].vaps[i].ifname,"athscan")){
           	   return &state->bandInfo[band].vaps[i];
			}
        }
    }
	/*pengdecai end*/

	printf("There is no vaps except athscan vap!\n");
	
    for (i = 0; i < MAX_VAP_PER_BAND; ++i) {
        if (!state->bandInfo[band].vaps[i].valid) {
          //  break;
          continue;
        }
        if (channelId == state->bandInfo[band].vaps[i].radio->channel) {
            return &state->bandInfo[band].vaps[i];
        }
    }

    // Not found
    return NULL;
}

LBD_STATUS wlanifBSteerControlDumpATFTable(wlanifBSteerControlHandle_t state,
                                           wlanif_reservedAirtimeCB callback,
                                           void *cookie) {
    size_t i;
    for (i = 0; i < wlanif_band_invalid; ++i) {
        size_t j;
        for (j = 0; j < MAX_VAP_PER_BAND; ++j) {
            if (state->bandInfo[i].vaps[j].valid) {
                if (wlanifBSteerControlDumpATFTableOneIface(state,
                            &state->bandInfo[i].vaps[j],
                            callback, cookie) != LBD_OK) {
                    return LBD_NOK;
                }
            } else {
                // No more valid VAPs on this band
                break;
            }
        }
    }

    return LBD_OK;
}

LBD_BOOL wlanifBSteerControlIsSTAAssociated(wlanifBSteerControlHandle_t state,
                                            const lbd_bssInfo_t *bss,
                                            const struct ether_addr *staAddr) {
    struct wlanifBSteerControlVapInfo *vap =
        wlanifBSteerControlExtractVapHandle(bss);
    if (!state || !staAddr || !vap) {
        return LBD_FALSE;
    }

    struct ieee80211req_sta_stats stats;
    if (wlanifBSteerControlGetSTAStats(state, vap, 
                                       staAddr, &stats) == LBD_OK) {
        // STA is associated on bss
        return LBD_TRUE;
    }

    // STA is not associated on bss
    return LBD_FALSE;
}

/**
 * @brief Dump the ATF table for a single interface
 *
 * @param [in] state the 'this' pointer
 * @param [in] vap  the vap to dump associated STAs for
 * @param [in] callback  the callback function to invoke for each reserved
 *                       airtime STA entry
 * @param [in] cookie  the parameter to provide back in the callback
 *
 * @return LBD_OK if the dump succeeded on this interface; otherwise LBD_NOK
 */
static LBD_STATUS wlanifBSteerControlDumpATFTableOneIface(
        wlanifBSteerControlHandle_t state,
        struct wlanifBSteerControlVapInfo *vap,
        wlanif_reservedAirtimeCB callback, void *cookie) {
    struct atftable atfInfo;
    memset(&atfInfo, 0, sizeof(atfInfo));
    atfInfo.id_type = IEEE80211_IOCTL_ATF_SHOWATFTBL;

    struct iwreq iwr;
    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, vap->ifname, sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *) &atfInfo;
    iwr.u.data.length = sizeof(atfInfo);

    if (ioctl(state->controlSock, IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        if (errno == EOPNOTSUPP) {
            dbgf(state->dbgModule, DBGINFO,
                 "%s: WARNING: ATF is not enabled by driver for iface %s",
                 __func__, vap->ifname);
            return LBD_OK;
        } else {
            dbgf(state->dbgModule, DBGERR,
                 "%s: Failed to perform ioctl for iface %s [errno %d]",
                 __func__, vap->ifname, errno);
            return LBD_NOK;
        }
    }

    lbd_bssInfo_t bss = {
        LBD_APID_SELF, vap->radio->channel,
        vap->essId, vap
    };

    size_t i;
    for (i = 0; i < atfInfo.info_cnt; ++i) {
        struct atfcntbl *entry = &atfInfo.atf_info[i];
        if (entry->info_mark) {
            lbd_airtime_t airtime = wlanifMapToAirtime(state->dbgModule, entry->cfg_value);
            if (airtime != LBD_INVALID_AIRTIME) {
                struct ether_addr staAddr;
                lbCopyMACAddr(entry->sta_mac, staAddr.ether_addr_octet);
                callback(&staAddr, &bss, airtime, cookie);
            }
        }
    }

    return LBD_OK;
}

LBD_STATUS wlanifBSteerControlRegisterChanChangeObserver(
        wlanifBSteerControlHandle_t state, wlanif_chanChangeObserverCB callback,
        void *cookie) {
    if (!callback) {
        return LBD_NOK;
    }

    struct wlanifBSteerControlChanChangeObserver *freeSlot = NULL;
    size_t i;
    for (i = 0; i < MAX_CHAN_CHANGE_OBSERVERS; ++i) {
        struct wlanifBSteerControlChanChangeObserver *curSlot = &state->chanChangeObserver[i];
        if (curSlot->isValid && curSlot->callback == callback &&
            curSlot->cookie == cookie) {
            dbgf(state->dbgModule, DBGERR, "%s: Duplicate registration "
                                               "(func %p, cookie %p)",
                 __func__, callback, cookie);
           return LBD_NOK;
        }

        if (!freeSlot && !curSlot->isValid) {
            freeSlot = curSlot;
        }

    }

    if (freeSlot) {
        freeSlot->isValid = LBD_TRUE;
        freeSlot->callback = callback;
        freeSlot->cookie = cookie;
        return LBD_OK;
    }

    // No free entry found
    return LBD_NOK;
}

LBD_STATUS wlanifBSteerControlUnregisterChanChangeObserver(
        wlanifBSteerControlHandle_t state, wlanif_chanChangeObserverCB callback,
        void *cookie) {
    if (!callback) {
        return LBD_NOK;
    }

    size_t i;
    for (i = 0; i < MAX_CHAN_CHANGE_OBSERVERS; ++i) {
        struct wlanifBSteerControlChanChangeObserver *curSlot = &state->chanChangeObserver[i];
        if (curSlot->isValid && curSlot->callback == callback &&
            curSlot->cookie == cookie) {
            curSlot->isValid = LBD_FALSE;
            curSlot->callback = NULL;
            curSlot->cookie = NULL;
            return LBD_OK;
        }
    }

    // No match found
    return LBD_NOK;
}

/**
 * @brief Notify all observers about a channel change
 *
 * @param [in] state the 'this' pointer
 * @param [in] vap  the VAP on which channel change happens
 */
static void wlanifBSteerControlNotifyChanChangeObserver(
        wlanifBSteerControlHandle_t state,
        struct wlanifBSteerControlVapInfo *vap) {
    size_t i;
    for (i = 0; i < MAX_CHAN_CHANGE_OBSERVERS; ++i) {
        if (state->chanChangeObserver[i].isValid) {
            state->chanChangeObserver[i].callback(
                    vap, vap->radio->channel, state->chanChangeObserver[i].cookie);
        }
    }
}

void wlanifBSteerControlUpdateMaxTxPower(wlanifBSteerControlHandle_t state,
                                         const lbd_bssInfo_t *bss,
                                         u_int16_t maxTxPower) {
    struct wlanifBSteerControlVapInfo *vap = wlanifBSteerControlExtractVapHandle(bss);
    if (!state || !vap || !maxTxPower) { return; }

    vap->phyCapInfo.maxTxPower = maxTxPower;
    dbgf(state->dbgModule, DBGINFO,
         "%s: Max Tx power changed to %d dBm on " lbBSSInfoAddFmt(),
         __func__, maxTxPower, lbBSSInfoAddData(bss));
    // When there is Tx power change on one VAP, we assume it also changes
    // on all other VAPs on the same radio.
    if (maxTxPower != vap->radio->maxTxPower) {
        vap->radio->maxTxPower = maxTxPower;
        wlanifBSteerControlFindStrongestRadioOnBand(
            state, wlanif_resolveBandFromChannelNumber(vap->radio->channel));
    }
}

LBD_STATUS wlanifBSteerControlIsStrongestChannel(
        wlanifBSteerControlHandle_t state, lbd_channelId_t channelId,
        LBD_BOOL *isStrongest) {
    if (!state || channelId == LBD_CHANNEL_INVALID || !isStrongest) {
        return LBD_NOK;
    }

    size_t i;
    for (i = 0; i < WLANIF_MAX_RADIOS; ++i) {
        if (state->radioInfo[i].valid &&
            state->radioInfo[i].channel == channelId) {
            *isStrongest = state->radioInfo[i].strongestRadio;
            return LBD_OK;
        }
    }

    return LBD_NOK;
}

LBD_STATUS wlanifBSteerControlIsBSSOnStrongestChannel(
        wlanifBSteerControlHandle_t state, const lbd_bssInfo_t *bss,
        LBD_BOOL *isStrongest) {
    struct wlanifBSteerControlVapInfo *vap = wlanifBSteerControlExtractVapHandle(bss);
    if (!state || !vap || !isStrongest) { return LBD_NOK; }

    *isStrongest = vap->radio->strongestRadio;

    return LBD_OK;
}

/**
 * @brief Compare all radios on a given band to determine which
 *        radio(s) has the strongest Tx power
 *
 * @param [in] state  the 'this' pointer
 * @param [in] band  the given band
 */
static void wlanifBSteerControlFindStrongestRadioOnBand(
        wlanifBSteerControlHandle_t state, wlanif_band_e band) {
    size_t i;
    u_int8_t strongestTxPower = 0;
    for (i = 0; i < WLANIF_MAX_RADIOS; ++i) {
        if (!state->radioInfo[i].valid ||
            wlanif_resolveBandFromChannelNumber(state->radioInfo[i].channel) != band) {
            // Only compare same band radios
            continue;
        }
        if(state->radioInfo[i].maxTxPower > strongestTxPower) {
            strongestTxPower = state->radioInfo[i].maxTxPower;
        }
    }
    // Mark all radios with highest Tx power as strongest radio, since
    // we want to keep 11ac clients on any of them.
    for (i = 0; i < WLANIF_MAX_RADIOS; ++i) {
        if (!state->radioInfo[i].valid ||
            wlanif_resolveBandFromChannelNumber(state->radioInfo[i].channel) != band) {
            // Only compare same band radios
            continue;
        }
        if (state->radioInfo[i].maxTxPower == strongestTxPower) {
            state->radioInfo[i].strongestRadio = LBD_TRUE;
        } else {
            state->radioInfo[i].strongestRadio = LBD_FALSE;
        }
    }
}

LBD_STATUS wlanifBSteerControlGetBSSesSameESS(
        wlanifBSteerControlHandle_t state, const lbd_bssInfo_t *bss,
        LBD_BOOL sameBand, size_t* maxNumBSSes, lbd_bssInfo_t *bssList) {
    struct wlanifBSteerControlVapInfo *vap = wlanifBSteerControlExtractVapHandle(bss);
    if (!state || !vap || !bssList || !maxNumBSSes || !(*maxNumBSSes)) { return LBD_NOK; }

    size_t i, numBSSes = 0, numBands = wlanif_band_invalid;
    struct wlanifBSteerControlVapInfo *vapEntry = NULL;

    // Find same band BSSes first
    wlanif_band_e band = wlanif_resolveBandFromChannelNumber(bss->channelId);
    lbDbgAssertExit(state->dbgModule, band != wlanif_band_invalid);
    while (numBands--) {
        for (i = 0; i < MAX_VAP_PER_BAND; ++i) {
            vapEntry = &state->bandInfo[band].vaps[i];
            if (!vapEntry->valid) {
                break;
            } else if (vapEntry == vap) {
                // Ignore current BSS
                continue;
            } else if (vapEntry->essId != vap->essId) {
                // Ignore BSS on other ESS
                continue;
            }
            if (numBSSes < *maxNumBSSes) {
                bssList[numBSSes].apId = LBD_APID_SELF;
                bssList[numBSSes].essId = vapEntry->essId;
                bssList[numBSSes].channelId = vapEntry->radio->channel;
                bssList[numBSSes].vap = vapEntry;
                ++numBSSes;
            } else {
                // Reach maximum BSSes requested, return here
                return LBD_OK;
            }
        }

        if (sameBand) {
            // Only request same band BSSes, return
            *maxNumBSSes = numBSSes;
            return LBD_OK;
        }

        // Find BSSes on the other band
        band = band == wlanif_band_24g ? wlanif_band_5g : wlanif_band_24g;
    }

    *maxNumBSSes = numBSSes;
    return LBD_OK;
}
