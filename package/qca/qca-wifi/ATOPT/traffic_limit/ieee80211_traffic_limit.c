/* ***************************************************************
 * Filename: ieee80211_traffic_limit.c
 * Description: a module for traffic limit.
 * Project: Autelan ap 2012
 * Author: Jia Wang
 * Date: 2012-10-25
 ****************************************************************/
#include <ieee80211_var.h>
#include <linux/ip.h>
#include <linux/timer.h>
#include <ath_internal.h>
#include <if_athvar.h>
#include <osif_private.h>

#include "han_ioctl.h"
//#include "ol_txrx_api.h"
#include "ieee80211_traffic_limit.h"
struct tasklet_struct tl_dequeue_cache_tx_tasklet;

struct tasklet_struct tl_dequeue_cache_rx_tasklet;

struct timer_list tl_dequeue_cache_timer;

struct ieee80211com *ic_specific[3]; //zhaoyang1 modified for 11ac traffic limit 2014-03-31
EXPORT_SYMBOL(ic_specific);


extern uint32_t
ol_tx_ll_fast(ol_txrx_vdev_handle vdev,
        adf_nbuf_t *nbuf_arr,
        uint32_t num_msdus);

extern void
ol_rx_deliver(
		struct ol_txrx_vdev_t *vdev,
		struct ol_txrx_peer_t *peer,
		unsigned tid,
		adf_nbuf_t head_msdu);

//extern u_int64_t ath_rx_tasklet_tick;
//extern u_int64_t ath_rx_tasklet_time_slice;
//extern u_int64_t ath_tx_tasklet_tick;
//extern u_int64_t ath_tx_tasklet_time_slice;

u_int32_t tl_tasklet_timeslice = 1000;
u_int32_t tl_dequeue_threshold = 50;
u_int32_t tl_debug_flag = 0x00;

u_int64_t ath_rx_tasklet_tick = 0;
EXPORT_SYMBOL(ath_rx_tasklet_tick);
u_int64_t ath_rx_tasklet_time_slice = 0;
EXPORT_SYMBOL(ath_rx_tasklet_time_slice);
u_int64_t ath_tx_tasklet_tick = 0;
EXPORT_SYMBOL(ath_tx_tasklet_tick);
u_int64_t ath_tx_tasklet_time_slice = 0;
EXPORT_SYMBOL(ath_tx_tasklet_time_slice);


void ieee80211_input_data_for_tl(struct ieee80211_node *ni, wbuf_t wbuf, 
        struct ieee80211_rx_status *rs, int subtype, int dir);

void ieee80211_input_data_aponly_for_tl(struct ieee80211_node *ni, wbuf_t wbuf, 
        struct ieee80211_rx_status *rs, int subtype, int dir);

void ieee80211_tl_cacheq_detach(struct ieee80211_node *ni)
{ 
	wbuf_t wbuf;
    struct ieee80211_tl_srtcm *ni_srtcm = NULL;
    struct ieee80211_tl_cache_queue_rx *ni_cq_up = NULL;
    struct ieee80211_tl_cache_queue_tx *ni_cq_down = NULL;
	struct ieee80211com *ic = ni->ni_ic; //zhaoyang1 modified for 11ac traffic limit 2014-03-31
	
    if(NULL == ni)
    {
        return ;
    }

    ni_cq_up = &(ni->ni_tl_up_cacheq);
	while(ni_cq_up->cq_len > 0)
	{						 
		IEEE80211_TL_CACHEQ_LOCK(ni_cq_up);				
		IEEE80211_TL_CACHEQ_DEQUEUE(ni_cq_up, wbuf);
		IEEE80211_TL_CACHEQ_UNLOCK(ni_cq_up);
		wbuf_free(wbuf);   
	}
    IEEE80211_TL_CACHEQ_DESTROY(ni_cq_up);

    ni_srtcm = &(ni->ni_tl_up_srtcm_sp);
    IEEE80211_TL_SRTCM_DESTORY(ni_srtcm);   
    ni_srtcm = &(ni->ni_tl_up_srtcm_ev);
    IEEE80211_TL_SRTCM_DESTORY(ni_srtcm); 

    ni_cq_down = &(ni->ni_tl_down_cacheq);
	while(ni_cq_down->cq_len > 0)
	{						 
		IEEE80211_TL_CACHEQ_LOCK(ni_cq_down);				
		IEEE80211_TL_CACHEQ_DEQUEUE(ni_cq_down, wbuf);
		IEEE80211_TL_CACHEQ_UNLOCK(ni_cq_down);
		wbuf_set_status(wbuf, WB_STATUS_TX_ERROR);
		/*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
		if (ic->ic_is_mode_offload(ic)) {
			adf_nbuf_unmap_single(
	        ic->ic_adf_dev, (adf_nbuf_t) wbuf, ADF_OS_DMA_TO_DEVICE);
		}
		/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
		wbuf_complete(wbuf);
	}	
    IEEE80211_TL_CACHEQ_DESTROY(ni_cq_down);
    
    ni_srtcm = &(ni->ni_tl_down_srtcm_sp);
    IEEE80211_TL_SRTCM_DESTORY(ni_srtcm);   
    ni_srtcm = &(ni->ni_tl_down_srtcm_ev);
    IEEE80211_TL_SRTCM_DESTORY(ni_srtcm); 

}

/*
 * Clear any frames queued on a node's cache queue.
 */
void ieee80211_tl_node_cacheq_drain(struct ieee80211_node *ni)
{
    wbuf_t wbuf;
    struct ieee80211_tl_cache_queue_rx *ni_cq_up = NULL;
    struct ieee80211_tl_cache_queue_tx *ni_cq_down = NULL;

    if(NULL == ni)
    {
        return ;
    }


    ni_cq_up = &(ni->ni_tl_up_cacheq);
    while(ni_cq_up->cq_len > 0) {
        IEEE80211_TL_CACHEQ_LOCK(ni_cq_up);
        IEEE80211_TL_CACHEQ_DEQUEUE(ni_cq_up, wbuf);
        IEEE80211_TL_CACHEQ_UNLOCK(ni_cq_up);
        wbuf_free(wbuf);   
    }
    IEEE80211_TL_CACHEQ_INIT_RX(ni_cq_up);
    
    ni_cq_down = &(ni->ni_tl_down_cacheq);
    while(ni_cq_down->cq_len > 0) {
        IEEE80211_TL_CACHEQ_LOCK(ni_cq_down);
        IEEE80211_TL_CACHEQ_DEQUEUE(ni_cq_down, wbuf);
        IEEE80211_TL_CACHEQ_UNLOCK(ni_cq_down);
        wbuf_free(wbuf);
    } 
    IEEE80211_TL_CACHEQ_INIT_TX(ni_cq_down);
}

/**
 * When Sta leaves or using kickmac etc. Those buffers cached in Vap's cache queue
 * which belong to this Sta should be freed.
 */
void ieee80211_tl_cleanup_vap_cache_of_node(struct ieee80211_node *ni)
{  
    wbuf_t next_wbuf = NULL;
    wbuf_t current_wbuf = NULL;

    struct ieee80211vap *vap = NULL;
    
    struct ieee80211_tl_cache_rx_extra *last_rx_extra = NULL;
    struct ieee80211_tl_cache_rx_extra *next_rx_extra = NULL;
    struct ieee80211_tl_cache_rx_extra *current_rx_extra = NULL;
    
    struct ieee80211_node *wbuf_node = NULL;
    struct ieee80211_tl_cache_queue_tx *vap_cq_down = NULL;
    struct ieee80211_tl_cache_queue_rx *vap_cq_up   = NULL;

    if(NULL == ni)
    {
        return ;
    }

    vap = ni->ni_vap;
    vap_cq_up = &(vap->vap_tl_up_cacheq);
    vap_cq_down = &(vap->vap_tl_down_cacheq);
    
    traffic_limit_debug_print(IEEE80211_TL_LOG_INFO,
        "[%s]: Entering...[%02X:%02X:%02X:%02X:%02X:%02X]! UP - %d, DOWN - %d!\r\n", __func__, 
        ni->ni_macaddr[0], ni->ni_macaddr[1], ni->ni_macaddr[2],
        ni->ni_macaddr[3], ni->ni_macaddr[4], ni->ni_macaddr[5],
        vap_cq_up->cq_len, vap_cq_down->cq_len); 
    
    /*Down Flow */   
    IEEE80211_TL_CACHEQ_LOCK(vap_cq_down);
    if(vap_cq_down->cq_len > 0)
    {
        IEEE80211_TL_CACHEQ_POLL(vap_cq_down, current_wbuf);
        /**
         * Just like to reconstruct a wbuf link, wbufs belongs to node ni will be freed.
         */
        vap_cq_down->cq_whead = NULL;
        vap_cq_down->cq_wtail = NULL;
        while(NULL != current_wbuf)
        {   
            next_wbuf = wbuf_next(current_wbuf);
            wbuf_node = wbuf_get_node(current_wbuf);
            if(wbuf_node == ni)
            {
                wbuf_set_next(current_wbuf, NULL);
                wbuf_set_status(current_wbuf, WB_STATUS_TX_ERROR);
        		wbuf_complete(current_wbuf);

                vap_cq_down->cq_len--;
                vap_cq_down->cq_drop_count++;
            } 
            else
            {
                wbuf_set_next(current_wbuf, NULL);
                if (vap_cq_down->cq_wtail != NULL) {
                    wbuf_set_next(vap_cq_down->cq_wtail, current_wbuf);
                    vap_cq_down->cq_wtail = current_wbuf;
                } else {
                    vap_cq_down->cq_whead = vap_cq_down->cq_wtail = current_wbuf;
                }  
            }
            current_wbuf = next_wbuf;        
        }
    }
    IEEE80211_TL_CACHEQ_UNLOCK(vap_cq_down);

    /*Up Flow */
    next_wbuf = NULL;
    current_wbuf = NULL;    
    IEEE80211_TL_CACHEQ_LOCK(vap_cq_up);
    if(vap_cq_up->cq_len > 0)
    {
        IEEE80211_TL_CACHEQ_POLL(vap_cq_up, current_wbuf);
        vap_cq_up->cq_whead = NULL;
        vap_cq_up->cq_wtail = NULL;
        last_rx_extra = vap_cq_up->cq_rx_tail;
        current_rx_extra = vap_cq_up->cq_rx_head;
        while(NULL != current_wbuf)
        {   
            next_wbuf = wbuf_next(current_wbuf);
            next_rx_extra = current_rx_extra->ex_next;
            
            wbuf_node = wbuf_get_node(current_wbuf);
            if(wbuf_node == ni)
            {
                wbuf_set_next(current_wbuf, NULL);
                wbuf_set_status(current_wbuf, WB_STATUS_TX_ERROR);
                wbuf_complete(current_wbuf);

                if(current_rx_extra == vap_cq_up->cq_rx_head)
                {
                    vap_cq_up->cq_rx_head = next_rx_extra;
                }
                /**
                 * "Free" current rx_extra node(Move it to the tail, so it will be reused.). 
                 */
                current_rx_extra->ex_next = vap_cq_up->cq_rx_tail->ex_next;
                last_rx_extra->ex_next = next_rx_extra;
                vap_cq_up->cq_rx_tail->ex_next = current_rx_extra;
                current_rx_extra = next_rx_extra;
                
                vap_cq_up->cq_len--;
                vap_cq_up->cq_drop_count++;
            } 
            else
            {
                wbuf_set_next(current_wbuf, NULL);
                if (vap_cq_up->cq_wtail != NULL) {
                    wbuf_set_next(vap_cq_up->cq_wtail, current_wbuf);
                    vap_cq_up->cq_wtail = current_wbuf;
                } else {
                    vap_cq_up->cq_whead = vap_cq_up->cq_wtail = current_wbuf;
                }  
            }
            current_wbuf = next_wbuf;

            last_rx_extra = current_rx_extra;
            current_rx_extra = next_rx_extra;
        }
    }
    IEEE80211_TL_CACHEQ_UNLOCK(vap_cq_up);

    traffic_limit_debug_print(IEEE80211_TL_LOG_INFO,
        "[%s]: Exit...!UP - %d, DOWN - %d!\r\n", __func__, 
        vap_cq_up->cq_len, vap_cq_down->cq_len);
}

void ieee80211_tl_vap_init(struct ieee80211vap *vap)
{
    if(NULL == vap)
    {
        return ;
    }

    vap->vap_tl_ev_enable  = IEEE80211_TL_DISABLE;
    vap->vap_tl_vap_enable = IEEE80211_TL_DISABLE;

    IEEE80211_TL_SRTCM_INIT(&(vap->vap_tl_down_srtcm_ev));
    IEEE80211_TL_SRTCM_INIT(&(vap->vap_tl_down_srtcm_vap));

    IEEE80211_TL_SRTCM_INIT(&(vap->vap_tl_up_srtcm_ev));
    IEEE80211_TL_SRTCM_INIT(&(vap->vap_tl_up_srtcm_vap));

    IEEE80211_TL_CACHEQ_INIT_TX(&(vap->vap_tl_down_cacheq));
    IEEE80211_TL_CACHEQ_INIT_RX(&(vap->vap_tl_up_cacheq));
    
    ieee80211_tl_node_init(vap, vap->iv_bss);
}

void ieee80211_tl_node_init(struct ieee80211vap *vap, 
    struct ieee80211_node *ni)
{
    if(NULL == vap || NULL == ni)
    {
        return ;
    }

    ni->ni_tl_sp_enable = IEEE80211_TL_DISABLE;
    ni->ni_tl_ev_enable = vap->vap_tl_ev_enable;
    
    IEEE80211_TL_SRTCM_INIT_FROM(&(ni->ni_tl_down_srtcm_ev), &(vap->vap_tl_down_srtcm_ev));
    IEEE80211_TL_SRTCM_INIT_FROM(&(ni->ni_tl_up_srtcm_ev), &(vap->vap_tl_up_srtcm_ev));

    IEEE80211_TL_SRTCM_INIT(&(ni->ni_tl_down_srtcm_sp));
    IEEE80211_TL_SRTCM_INIT(&(ni->ni_tl_up_srtcm_sp));

    IEEE80211_TL_CACHEQ_INIT_TX(&(ni->ni_tl_down_cacheq));
    IEEE80211_TL_CACHEQ_INIT_RX(&(ni->ni_tl_up_cacheq));
}

/**
 *  Implementation of Single Rate Three Color Marker algorithm.
 *  If GREEN then can dequeue next wbuf, if RED then can not. 
 *  Color YELLOW has not been used.
 */
int ieee80211_tl_srtcm_meter(struct ieee80211_tl_srtcm *srtcm, wbuf_t wbuf)
{
    u_int64_t uiCBS = 0;
	u_int64_t uiEBS = 0;
	u_int64_t uiCIR = 0;
    u_int64_t burst_refill_bucket = 0;

    u_int64_t interval_time = 0;
    struct timeval tv_current_time;
    
	u_int64_t temp_val = 0;

    if(NULL == srtcm)
	{
        traffic_limit_debug_print(IEEE80211_TL_LOG_ERROR,
            "[%s]: Warning srtcm pointer is Null!\r\n", __func__);

		return IEEE80211_TL_COLOR_MARK_INVALID;
	}
	if(NULL == wbuf)
	{
        traffic_limit_debug_print(IEEE80211_TL_LOG_ERROR,
            "[%s]: Warning wbuf pointer is Null!\r\n", __func__);
        
		return IEEE80211_TL_COLOR_MARK_INVALID;
	}
    
    IEEE80211_TL_SRTCM_LOCK(srtcm);
    /**
     *  If a node's tl_enable is ENABLE, but its sr_cir is 0(zero), 
     *  we just regard it as unlimit.
     */
    if(0 == srtcm->sr_cir)
    {
        IEEE80211_TL_SRTCM_UNLOCK(srtcm);
        srtcm->sr_green_packet_count++;
        return IEEE80211_TL_COLOR_MARK_GREEN;
    }
    
	uiCBS = srtcm->sr_cbs;
    uiEBS = srtcm->sr_ebs;
    uiCIR = srtcm->sr_cir;

    /* 
     * IntervalTime = CurrentTime - Last Send(Receive) Time
	 * BurstUpdate = CIR * IntervalTime; 
	 * TC = TC + BurstUpdate 
	 */
    do_gettimeofday(&tv_current_time);
    
    if(tv_current_time.tv_usec < srtcm->sr_timeval.tv_usec)
    {
        interval_time = 1000000 - srtcm->sr_timeval.tv_usec + tv_current_time.tv_usec;
    } else {
        interval_time = tv_current_time.tv_usec - srtcm->sr_timeval.tv_usec;
    }

    srtcm->sr_timeval.tv_usec = tv_current_time.tv_usec;
    srtcm->sr_timeval.tv_sec  = tv_current_time.tv_sec;
        
    temp_val = interval_time * uiCIR;
	do_div(temp_val, 1000000);
	burst_refill_bucket = temp_val;

    /* Adjust the max value of sr_current_tc_num and sr_current_te_num. */
    srtcm->sr_current_tc_num += burst_refill_bucket;
    if(srtcm->sr_current_tc_num > srtcm->sr_cbs)
    {
        srtcm->sr_current_te_num += (srtcm->sr_current_tc_num - srtcm->sr_cbs);
        srtcm->sr_current_tc_num  = srtcm->sr_cbs;

        if(srtcm->sr_current_te_num > srtcm->sr_ebs)
        {
            srtcm->sr_current_te_num = srtcm->sr_ebs;
        }
    }

    /* Has enough token for this wbuf? */
    if(srtcm->sr_current_tc_num >= wbuf->len)
    {
        srtcm->sr_current_tc_num -= wbuf->len;
        srtcm->sr_green_packet_count++;
        IEEE80211_TL_SRTCM_UNLOCK(srtcm);
        return IEEE80211_TL_COLOR_MARK_GREEN;
    }

    srtcm->sr_red_packet_count++;

    IEEE80211_TL_SRTCM_UNLOCK(srtcm);
    return IEEE80211_TL_COLOR_MARK_RED;
}


/**
 *  AP to Sta.
 */
int ieee80211_tl_vap_cache_enqueue_tx(struct ieee80211vap *vap, 
    wbuf_t wbuf, struct ieee80211com *ic)
{
    u_int32_t maxlen = 0;

	struct ieee80211_tl_cache_queue_tx *vap_cq = NULL;
 
    if(NULL == vap || NULL == wbuf)
    {
        traffic_limit_debug_print(IEEE80211_TL_LOG_ERROR, 
            "%s vap or wbuf is null\n", __func__);
        return IEEE80211_TL_ENQUEUE_IC_IS_NULL;
    }

	if(ic == NULL)
	{
		traffic_limit_debug_print(IEEE80211_TL_LOG_ERROR, 
            "%s ic is null\n",__func__);
        return IEEE80211_TL_ENQUEUE_IC_IS_NULL;
	}

    vap_cq = &(vap->vap_tl_down_cacheq);

    IEEE80211_TL_CACHEQ_LOCK(vap_cq);
    maxlen = vap_cq->cq_max_len;
    
	if(vap_cq->cq_len < maxlen)
	{	
		if((wbuf->len > IEEE80211_TL_CACHE_MIN_SIZE && wbuf->len < IEEE80211_TL_CACHE_MAX_SIZE)) 
		{
			IEEE80211_TL_CACHEQ_ENQUEUE(vap_cq, wbuf);
			IEEE80211_TL_CACHEQ_UNLOCK(vap_cq);

            vap_cq->cq_enqueue_count++;

	        tasklet_schedule(&tl_dequeue_cache_tx_tasklet);
			return IEEE80211_TL_ENQUEUE_OK;
		}
		else
		{
			traffic_limit_debug_print(IEEE80211_TL_LOG_WARNING,
                "cache_wrong_size wbuf->len = %d\n",wbuf->len);
			/**
			 * the size of packet is too small or too large, 
			 * we send it right away! need to change, because there is no couter
			 */
			IEEE80211_TL_CACHEQ_UNLOCK(vap_cq);
            return IEEE80211_TL_ENQUEUE_PACKET_LEN;
        }
	}
	else
	{
		vap_cq->cq_drop_count++;
        IEEE80211_TL_CACHEQ_UNLOCK(vap_cq);
		return IEEE80211_TL_ENQUEUE_IS_FULL;
	}

    IEEE80211_TL_CACHEQ_UNLOCK(vap_cq);
    return IEEE80211_TL_ENQUEUE_CACHE_IS_DISABLE;
}

/**
 *  AP to Sta.
 */
int ieee80211_tl_node_cache_enqueue_tx(struct ieee80211_node *ni, 
    wbuf_t wbuf, struct ieee80211com *ic)
{
    u_int32_t maxlen = 0;

	struct ieee80211_tl_cache_queue_tx *ncq = NULL;
 
    if(NULL == ni || NULL == wbuf)
    {
		traffic_limit_debug_print(IEEE80211_TL_LOG_ERROR, "%s ni or wbuf is null\n",__func__);
        return IEEE80211_TL_ENQUEUE_IC_IS_NULL;
    }

	if(ic == NULL)
	{
		traffic_limit_debug_print(IEEE80211_TL_LOG_ERROR, "%s ic is null\n",__func__);
        return IEEE80211_TL_ENQUEUE_IC_IS_NULL;
	}

    ncq = &(ni->ni_tl_down_cacheq);

    IEEE80211_TL_CACHEQ_LOCK(ncq);
    maxlen = ncq->cq_max_len;
    
	if(ncq->cq_len < maxlen)
	{	
		// if((wbuf->len > cache_min_size && wbuf->len < cache_max_size)) 
		if((wbuf->len > IEEE80211_TL_CACHE_MIN_SIZE && wbuf->len < IEEE80211_TL_CACHE_MAX_SIZE)) 
		{
			IEEE80211_TL_CACHEQ_ENQUEUE(ncq, wbuf);
            ncq->cq_enqueue_count++;

	        tasklet_schedule(&tl_dequeue_cache_tx_tasklet);

            IEEE80211_TL_CACHEQ_UNLOCK(ncq);
			return IEEE80211_TL_ENQUEUE_OK;
		}
		else
		{
			traffic_limit_debug_print(IEEE80211_TL_LOG_WARNING,
                "cache_wrong_size wbuf->len = %d\n",wbuf->len);
			/**
			 * the size of packet is too small or too large, 
			 * we send it right away! need to change, because there is no couter
			 */
			IEEE80211_TL_CACHEQ_UNLOCK(ncq);
            return IEEE80211_TL_ENQUEUE_PACKET_LEN;
        }
	}
	else
	{
		ncq->cq_drop_count++;
        IEEE80211_TL_CACHEQ_UNLOCK(ncq);
		return IEEE80211_TL_ENQUEUE_IS_FULL;
	}

    IEEE80211_TL_CACHEQ_UNLOCK(ncq);
    return IEEE80211_TL_ENQUEUE_CACHE_IS_DISABLE;
}

int ieee80211_tl_vap_cache_enqueue_rx(struct ieee80211vap *vap, wbuf_t wbuf, 
    struct ieee80211_rx_status *rs, int subtype, int dir, struct ieee80211com *ic)
{
    u_int32_t maxlen = 0;
    
    struct ieee80211_tl_cache_queue_rx *vap_cq = NULL;

    if(NULL == vap || NULL == wbuf || NULL == rs)
    {
        traffic_limit_debug_print(IEEE80211_TL_LOG_ERROR,
            "[%s]: Warning vap or wbuf or rs pointer is Null!\r\n", __func__);
        return IEEE80211_TL_ENQUEUE_IC_IS_NULL;
    }
    
    if(ic == NULL)
    {
        traffic_limit_debug_print(IEEE80211_TL_LOG_ERROR, "[%s]: ic is null\n",__func__);
        return IEEE80211_TL_ENQUEUE_IC_IS_NULL;
    }

    vap_cq = &(vap->vap_tl_up_cacheq);

    IEEE80211_TL_CACHEQ_LOCK(vap_cq);
    maxlen = vap_cq->cq_max_len;
    
    if(vap_cq->cq_len < maxlen)
    {   
        if((wbuf->len > IEEE80211_TL_CACHE_MIN_SIZE && wbuf->len < IEEE80211_TL_CACHE_MAX_SIZE)) 
        {
            IEEE80211_TL_RX_ENQUEUE(vap_cq, wbuf, rs, subtype, dir);
            vap_cq->cq_enqueue_count++;
            IEEE80211_TL_CACHEQ_UNLOCK(vap_cq);
            
            tasklet_schedule(&tl_dequeue_cache_rx_tasklet);

            return IEEE80211_TL_ENQUEUE_OK;
        }
        else
        {
            traffic_limit_debug_print(IEEE80211_TL_LOG_WARNING, "cache_wrong_size wbuf->len = %d\n",wbuf->len);
			/**
			 * the size of packet is too small or too large, 
			 * we send it right away! need to change, because there is no couter
			 */
            IEEE80211_TL_CACHEQ_UNLOCK(vap_cq);
            return IEEE80211_TL_ENQUEUE_PACKET_LEN;
        }
    }
    else
    {
        vap_cq->cq_drop_count++;
        IEEE80211_TL_CACHEQ_UNLOCK(vap_cq);
        return IEEE80211_TL_ENQUEUE_IS_FULL;
    }

    IEEE80211_TL_CACHEQ_UNLOCK(vap_cq);
    return IEEE80211_TL_ENQUEUE_CACHE_IS_DISABLE;

}

/*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
int ol_ieee80211_tl_vap_cache_enqueue_rx(struct ieee80211vap *vap, wbuf_t wbuf, 
    void* peer, unsigned tid)
{
    u_int32_t maxlen = 0;
    
    struct ieee80211_tl_cache_queue_rx *vap_cq = NULL;

    if(NULL == vap || NULL == wbuf || NULL == peer)
    {
        traffic_limit_debug_print(IEEE80211_TL_LOG_ERROR,
            "[%s]: Warning vap or wbuf or rs pointer is Null!\r\n", __func__);
        return IEEE80211_TL_ENQUEUE_IC_IS_NULL;
    }
    

    vap_cq = &(vap->vap_tl_up_cacheq);

    IEEE80211_TL_CACHEQ_LOCK(vap_cq);
    maxlen = vap_cq->cq_max_len;
    
    if(vap_cq->cq_len < maxlen)
    {   
        if((wbuf->len > IEEE80211_TL_CACHE_MIN_SIZE && wbuf->len < IEEE80211_TL_CACHE_MAX_SIZE)) 
        {
			IEEE80211_TL_CACHEQ_ENQUEUE(vap_cq, wbuf);
        	OL_IEEE80211_TL_ENQUEUE_RX_EXTRA(vap_cq, peer, tid); 
            vap_cq->cq_enqueue_count++;
            IEEE80211_TL_CACHEQ_UNLOCK(vap_cq);
            
            tasklet_schedule(&tl_dequeue_cache_rx_tasklet);

            return IEEE80211_TL_ENQUEUE_OK;
        }
        else
        {
            traffic_limit_debug_print(IEEE80211_TL_LOG_WARNING, "cache_wrong_size wbuf->len = %d\n",wbuf->len);
			/**
			 * the size of packet is too small or too large, 
			 * we send it right away! need to change, because there is no couter
			 */
            IEEE80211_TL_CACHEQ_UNLOCK(vap_cq);
            return IEEE80211_TL_ENQUEUE_PACKET_LEN;
        }
    }
    else
    {
        vap_cq->cq_drop_count++;
        IEEE80211_TL_CACHEQ_UNLOCK(vap_cq);
        return IEEE80211_TL_ENQUEUE_IS_FULL;
    }

    IEEE80211_TL_CACHEQ_UNLOCK(vap_cq);
    return IEEE80211_TL_ENQUEUE_CACHE_IS_DISABLE;

}


int ol_ieee80211_tl_node_cache_enqueue_rx(struct ieee80211_node *ni, wbuf_t wbuf, 
    void* peer, unsigned tid)
{
    u_int32_t maxlen = 0;

	struct ieee80211_tl_cache_queue_rx *ncq = NULL;

    if(NULL == ni || NULL == wbuf || NULL == peer)
    {
        traffic_limit_debug_print(IEEE80211_TL_LOG_ERROR, 
            "%s ni or wbuf or rs pointer is null\n",__func__);
        return IEEE80211_TL_ENQUEUE_IC_IS_NULL;
    }
    
    ncq = &(ni->ni_tl_up_cacheq);

    IEEE80211_TL_CACHEQ_LOCK(ncq);
    maxlen = ncq->cq_max_len;
   
	if(ncq->cq_len < maxlen)
	{	
		if((wbuf->len > IEEE80211_TL_CACHE_MIN_SIZE && wbuf->len < IEEE80211_TL_CACHE_MAX_SIZE)) 
		{
			IEEE80211_TL_CACHEQ_ENQUEUE(ncq, wbuf);
        	OL_IEEE80211_TL_ENQUEUE_RX_EXTRA(ncq, peer, tid); 
			IEEE80211_TL_CACHEQ_UNLOCK(ncq);

            ncq->cq_enqueue_count++;

            tasklet_schedule(&tl_dequeue_cache_rx_tasklet);
            
			return IEEE80211_TL_ENQUEUE_OK;
		}
		else
		{
			traffic_limit_debug_print(IEEE80211_TL_LOG_WARNING,
                "cache_wrong_size wbuf->len = %d\n",wbuf->len);
			/**
			 * the size of packet is too small or too large, 
			 * we send it right away! need to change, because there is no couter
			 */
			IEEE80211_TL_CACHEQ_UNLOCK(ncq);
            return IEEE80211_TL_ENQUEUE_PACKET_LEN;
        }
	}
	else
	{
		ncq->cq_drop_count++;
        IEEE80211_TL_CACHEQ_UNLOCK(ncq);
		return IEEE80211_TL_ENQUEUE_IS_FULL;
	}

    IEEE80211_TL_CACHEQ_UNLOCK(ncq);
    return IEEE80211_TL_ENQUEUE_CACHE_IS_DISABLE;
}

/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/


/**
 *  Sta to AP.
 */
int ieee80211_tl_node_cache_enqueue_rx(struct ieee80211_node *ni, wbuf_t wbuf, 
    struct ieee80211_rx_status *rs, int subtype, int dir, struct ieee80211com *ic)
{
    u_int32_t maxlen = 0;

	struct ieee80211_tl_cache_queue_rx *ncq = NULL;

    if(NULL == ni || NULL == wbuf || NULL == rs)
    {
        traffic_limit_debug_print(IEEE80211_TL_LOG_ERROR, 
            "%s ni or wbuf or rs pointer is null\n",__func__);
        return IEEE80211_TL_ENQUEUE_IC_IS_NULL;
    }
    
    if(ic == NULL)
	{
		traffic_limit_debug_print(IEEE80211_TL_LOG_ERROR, "%s ic pointer is null\n",__func__);
		return IEEE80211_TL_ENQUEUE_IC_IS_NULL;
	}

    ncq = &(ni->ni_tl_up_cacheq);

    IEEE80211_TL_CACHEQ_LOCK(ncq);
    maxlen = ncq->cq_max_len;
   
	if(ncq->cq_len < maxlen)
	{	
		if((wbuf->len > IEEE80211_TL_CACHE_MIN_SIZE && wbuf->len < IEEE80211_TL_CACHE_MAX_SIZE)) 
		{
            IEEE80211_TL_RX_ENQUEUE(ncq, wbuf, rs, subtype, dir);
			IEEE80211_TL_CACHEQ_UNLOCK(ncq);

            ncq->cq_enqueue_count++;

            tasklet_schedule(&tl_dequeue_cache_rx_tasklet);
            
			return IEEE80211_TL_ENQUEUE_OK;
		}
		else
		{
			traffic_limit_debug_print(IEEE80211_TL_LOG_WARNING,
                "cache_wrong_size wbuf->len = %d\n",wbuf->len);
			/**
			 * the size of packet is too small or too large, 
			 * we send it right away! need to change, because there is no couter
			 */
			IEEE80211_TL_CACHEQ_UNLOCK(ncq);
            return IEEE80211_TL_ENQUEUE_PACKET_LEN;
        }
	}
	else
	{
		ncq->cq_drop_count++;
        IEEE80211_TL_CACHEQ_UNLOCK(ncq);
		return IEEE80211_TL_ENQUEUE_IS_FULL;
	}

    IEEE80211_TL_CACHEQ_UNLOCK(ncq);
    return IEEE80211_TL_ENQUEUE_CACHE_IS_DISABLE;
}

/**
 *  AP to Sta.
 */
void ieee80211_tl_vap_dequeue_cache_tx(struct ieee80211vap *vap)
{
    int count = 0;
    int send_weight = 0;
	int color = IEEE80211_TL_COLOR_MARK_INVALID;

    wbuf_t send_wbuf = NULL;

    struct ieee80211_node *ni = NULL;
    
    struct ieee80211_tl_srtcm *vap_srtcm = NULL;
    struct ieee80211_tl_cache_queue_tx *vap_cq = NULL;

	/*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
	struct ieee80211com *ic = vap->iv_ic;
	//u_int32_t free_buff = 0;
	/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
	
    if(NULL == vap)
    { 
        traffic_limit_debug_print(IEEE80211_TL_LOG_ERROR, 
            "[%s]: vap pointer is null!\r\n", __func__);
        return ;
    }

    vap_srtcm = &(vap->vap_tl_down_srtcm_vap);
    vap_cq = &(vap->vap_tl_down_cacheq); 
    send_weight = vap_cq->cq_weighted; 
    
    IEEE80211_TL_CACHEQ_LOCK(vap_cq);	
	while(vap_cq->cq_len > 0)
	{		
		if(count >= tl_dequeue_threshold) // send_weight)
		{
			break;
		}
		
        if(IEEE80211_TL_ENABLE == vap->vap_tl_vap_enable)
        {
            IEEE80211_TL_CACHEQ_POLL(vap_cq, send_wbuf);
            color = ieee80211_tl_srtcm_meter(vap_srtcm, send_wbuf);
            
            /* Exceed Vap's limitation */
            if(IEEE80211_TL_COLOR_MARK_GREEN == color)
            {
    			IEEE80211_TL_CACHEQ_DEQUEUE(vap_cq, send_wbuf);
            }
            else if(IEEE80211_TL_COLOR_MARK_YELLOW == color)
    		{
    			traffic_limit_debug_print(IEEE80211_TL_LOG_INFO,
                    "[%s]Dequeue: the color marked yellow!\r\n", __func__);
    			if(vap_cq->cq_len < vap_cq->cq_threshold_low)
    			{
    				vap_cq->cq_pre_depth = IEEE80211_TL_CACHEQ_DEPTH_LOW;
    				IEEE80211_TL_CACHEQ_DEQUEUE(vap_cq, send_wbuf);
    			}
    			else if(vap_cq->cq_len > vap_cq->cq_threshold_high)
    			{
    				vap_cq->cq_pre_depth = IEEE80211_TL_CACHEQ_DEPTH_HIGH;
    				break;
    			}
    			else
    			{
    				/* from low->high, yellow packet pass */
    				if(vap_cq->cq_pre_depth == IEEE80211_TL_CACHEQ_DEPTH_LOW)
    				{
    					IEEE80211_TL_CACHEQ_DEQUEUE(vap_cq, send_wbuf);
    				}
    				else /* from high -> low, yellow packet not pass */
    				{
    					break;
    				}
    			}
    		}
            /* Exceed Node's limitation */
    		else if(IEEE80211_TL_COLOR_MARK_RED == color)
    		{	
    			traffic_limit_debug_print(IEEE80211_TL_LOG_INFO, 
                    "[%s]Dequeue: the color marked red!\r\n", __func__);
    			break;
    		}
    		else
    		{
    			traffic_limit_debug_print(IEEE80211_TL_LOG_INFO,
                    "[%s]Dequeue error: the color marked invalid!\r\n", __func__);
    			break;
    		}
        }
        else
        {
            IEEE80211_TL_CACHEQ_DEQUEUE(vap_cq, send_wbuf);
        }
        
		count++;
        ni = wbuf_get_node(send_wbuf);
		/*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
		if (ic->ic_is_mode_offload(ic)) {
			osif_dev  *osdev = ath_netdev_priv(send_wbuf->dev);
#if 1
            OL_TX_LL_WRAPPER(osdev->iv_txrx_handle, send_wbuf, vap->iv_ic->ic_adf_dev);
#else
            if (adf_os_unlikely(ol_tx_ll_fast(osdev->iv_txrx_handle, &send_wbuf, 1))) {
				while (send_wbuf) {
					adf_nbuf_t next = adf_nbuf_next(send_wbuf);
					adf_nbuf_unmap_single(vap->iv_ic->ic_adf_dev, send_wbuf, ADF_OS_DMA_TO_DEVICE);
					adf_nbuf_free(send_wbuf);
					send_wbuf = next;
				}
			}
#endif
		} else {
			ieee80211_send_wbuf(vap, ni, send_wbuf); 
		}
		/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
	}  

    IEEE80211_TL_CACHEQ_UNLOCK(vap_cq);
    return ;
}


/**
 *  AP to Sta.
 */
void ieee80211_tl_node_dequeue_cache_tx(struct ieee80211_node *ni)
{
    int count = 0;
    int send_weight = 0;
	int color = IEEE80211_TL_COLOR_MARK_INVALID;

    wbuf_t send_wbuf = NULL;

    struct ieee80211_tl_srtcm *nsrtcm = NULL;
	struct ieee80211_tl_cache_queue_tx *ncq = NULL;

    struct ieee80211vap *vap = NULL;
    struct ieee80211_tl_srtcm *vap_srtcm = NULL;
	/*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
	struct ieee80211com *ic = ni->ni_ic;
	//u_int32_t free_buff = 0;
	/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
	
    if(NULL == ni)
    { 
        traffic_limit_debug_print(IEEE80211_TL_LOG_ERROR, 
            "[%s] ni pointer is null!\r\n", __func__);
        return ;
    }
    
    vap = ni->ni_vap;
    vap_srtcm = &(vap->vap_tl_down_srtcm_vap);

    ncq = &(ni->ni_tl_down_cacheq);     // Always use node's cache queue

    // Specific Node has a higher priority with Everynode.
    if(IEEE80211_TL_ENABLE == ni->ni_tl_sp_enable)  // Specific Node
    {
        nsrtcm = &(ni->ni_tl_down_srtcm_sp);
    }
    else if(IEEE80211_TL_ENABLE == ni->ni_tl_ev_enable) // Everynode
    {
        nsrtcm = &(ni->ni_tl_down_srtcm_ev);
    }

    send_weight = ncq->cq_weighted; 
    
    IEEE80211_TL_CACHEQ_LOCK(ncq);	
	while(ncq->cq_len > 0)
	{		
		if(count >= tl_dequeue_threshold) // send_weight)
		{
			break;
		}
		
		IEEE80211_TL_CACHEQ_POLL(ncq, send_wbuf);

        if(IEEE80211_TL_ENABLE == vap->vap_tl_vap_enable)
        {
            color = ieee80211_tl_srtcm_meter(vap_srtcm, send_wbuf);
            /* Exceed Vap's limitation */
            if(IEEE80211_TL_COLOR_MARK_RED == color)
            {
                break;
            }
        }

        if((ni != vap->iv_bss) &&
           ((IEEE80211_TL_ENABLE == ni->ni_tl_sp_enable) ||
            (IEEE80211_TL_ENABLE == ni->ni_tl_ev_enable)))
        {
    		color = ieee80211_tl_srtcm_meter(nsrtcm, send_wbuf);
    		
    		if(color == IEEE80211_TL_COLOR_MARK_GREEN)
    		{
    			IEEE80211_TL_CACHEQ_DEQUEUE(ncq, send_wbuf);
    		}
    		else if(color == IEEE80211_TL_COLOR_MARK_YELLOW)
    		{
    			traffic_limit_debug_print(IEEE80211_TL_LOG_INFO,
                    "[%s]Dequeue: the color marked yellow!\r\n", __func__);
    			if(ncq->cq_len < ncq->cq_threshold_low)
    			{
    				ncq->cq_pre_depth = IEEE80211_TL_CACHEQ_DEPTH_LOW;
    				IEEE80211_TL_CACHEQ_DEQUEUE(ncq, send_wbuf);
    			}
    			else if(ncq->cq_len > ncq->cq_threshold_high)
    			{
    				ncq->cq_pre_depth = IEEE80211_TL_CACHEQ_DEPTH_HIGH;
    				break;
    			}
    			else
    			{
    				/* from low->high, yellow packet pass */
    				if(ncq->cq_pre_depth == IEEE80211_TL_CACHEQ_DEPTH_LOW)
    				{
    					IEEE80211_TL_CACHEQ_DEQUEUE(ncq, send_wbuf);
    				}
    				else /* from high -> low, yellow packet not pass */
    				{
    					break;
    				}
    			}
    		}
            /* Exceed Node's limitation */
    		else if(color == IEEE80211_TL_COLOR_MARK_RED)
    		{	   			
    			traffic_limit_debug_print(IEEE80211_TL_LOG_INFO, 
                    "[%s]Dequeue: the color marked red!\r\n", __func__);
    			break;
    		}
    		else
    		{
    			traffic_limit_debug_print(IEEE80211_TL_LOG_INFO,
                    "[%s]Dequeue error: the color marked invalid!\r\n", __func__);
    			break;
    		}
        }
        else
        { 
            IEEE80211_TL_CACHEQ_DEQUEUE(ncq, send_wbuf); 
        }
        
		count++;
		/*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
		if (ic->ic_is_mode_offload(ic)) {
			osif_dev  *osdev = ath_netdev_priv(send_wbuf->dev);
#if 1
            OL_TX_LL_WRAPPER(osdev->iv_txrx_handle, send_wbuf, vap->iv_ic->ic_adf_dev);
#else
			if (adf_os_unlikely(ol_tx_ll_fast(osdev->iv_txrx_handle, &send_wbuf, 1))) {
				while (send_wbuf) {
					adf_nbuf_t next = adf_nbuf_next(send_wbuf);
					adf_nbuf_unmap_single(vap->iv_ic->ic_adf_dev, send_wbuf, ADF_OS_DMA_TO_DEVICE);
					adf_nbuf_free(send_wbuf);
					send_wbuf = next;
				}
			}
#endif
		} else {
			ieee80211_send_wbuf(vap, ni, send_wbuf); 
		}
		/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
	}  

    IEEE80211_TL_CACHEQ_UNLOCK(ncq);
    return ;
}

void ieee80211_tl_vap_dequeue_cache_rx(struct ieee80211vap *vap)
{
    int dir;
    int subtype;
    u_int32_t count = 0;
    int receive_weight = 0;
	int color = IEEE80211_TL_COLOR_MARK_INVALID;
    
    wbuf_t receive_wbuf = NULL;
    struct ieee80211_node *ni = NULL;
    struct ieee80211_rx_status *rs = NULL;

    struct ieee80211_tl_srtcm *vap_srtcm = NULL;
	struct ieee80211_tl_cache_queue_rx *vap_cq = NULL;
	
	/*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
	struct ieee80211com *ic = vap->iv_ic;
	unsigned tid;
	void *peer = NULL;
	/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/

	if(NULL == vap)
    {
        traffic_limit_debug_print(IEEE80211_TL_LOG_ERROR,
                    "[%s] vap pointer is null!\r\n", __func__);
        return ;
    }

    vap_cq = &(vap->vap_tl_up_cacheq);
    vap_srtcm = &(vap->vap_tl_up_srtcm_vap);

    receive_weight = vap_cq->cq_weighted;

    IEEE80211_TL_CACHEQ_LOCK(vap_cq);
    while(vap_cq->cq_len > 0)
	{		
		if(count >= tl_dequeue_threshold) // receive_weight)
		{
			break;
		}
        
        if(IEEE80211_TL_ENABLE == vap->vap_tl_vap_enable)
        {
            IEEE80211_TL_CACHEQ_POLL(vap_cq, receive_wbuf);
            color = ieee80211_tl_srtcm_meter(vap_srtcm, receive_wbuf);
            
            if(color == IEEE80211_TL_COLOR_MARK_GREEN)
    		{
                
                /*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
				//IEEE80211_TL_RX_DEQUEUE(vap_cq, receive_wbuf, rs, subtype, dir);
                IEEE80211_TL_CACHEQ_DEQUEUE(vap_cq, receive_wbuf);
        		if (FALSE == ic->ic_is_mode_offload(ic))
	            	IEEE80211_TL_DEQUEUE_RX_EXTRA(vap_cq, rs, subtype, dir); 
				else 
					OL_IEEE80211_TL_DEQUEUE_RX_EXTRA(vap_cq, peer, tid);
				/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
    		}
    		else if(color == IEEE80211_TL_COLOR_MARK_YELLOW)
    		{
    			traffic_limit_debug_print(IEEE80211_TL_LOG_INFO,
                    "[%s]Dequeue: the color marked yellow!\r\n", __func__);

    			if(vap_cq->cq_len < vap_cq->cq_threshold_low)
    			{
    				vap_cq->cq_pre_depth = IEEE80211_TL_CACHEQ_DEPTH_LOW;
    				
	                /*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
					//IEEE80211_TL_RX_DEQUEUE(vap_cq, receive_wbuf, rs, subtype, dir);
	                IEEE80211_TL_CACHEQ_DEQUEUE(vap_cq, receive_wbuf);
	        		if (FALSE == ic->ic_is_mode_offload(ic))
		            	IEEE80211_TL_DEQUEUE_RX_EXTRA(vap_cq, rs, subtype, dir); 
					else 
						OL_IEEE80211_TL_DEQUEUE_RX_EXTRA(vap_cq, peer, tid);
					/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
    			}
    			else if(vap_cq->cq_len > vap_cq->cq_threshold_high)
    			{
    				vap_cq->cq_pre_depth = IEEE80211_TL_CACHEQ_DEPTH_HIGH;
    				break;
    			}
    			else
    			{
    				/*from low->high, yellow packet pass*/
    				if(vap_cq->cq_pre_depth == IEEE80211_TL_CACHEQ_DEPTH_LOW)
    				{
    					/*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
						//IEEE80211_TL_RX_DEQUEUE(vap_cq, receive_wbuf, rs, subtype, dir);
		                IEEE80211_TL_CACHEQ_DEQUEUE(vap_cq, receive_wbuf);
		        		if (FALSE == ic->ic_is_mode_offload(ic))
			            	IEEE80211_TL_DEQUEUE_RX_EXTRA(vap_cq, rs, subtype, dir); 
						else 
							OL_IEEE80211_TL_DEQUEUE_RX_EXTRA(vap_cq, peer, tid);
						/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
    				}
    				else /*from high -> low, yellow packet not pass*/
    				{
    					IEEE80211_TL_CACHEQ_UNLOCK(vap_cq);
    					break;
    				}
    			}
    		}
            /* Exceed Node's limitation */
    		else if(color == IEEE80211_TL_COLOR_MARK_RED)
    		{	
    			traffic_limit_debug_print(IEEE80211_TL_LOG_INFO, 
                    "[%s]Dequeue: the color marked red!\r\n", __func__);
    			break;
    		}
    		else
    		{
    			traffic_limit_debug_print(IEEE80211_TL_LOG_INFO,
                    "[%s]Dequeue error: the color marked invilaid!\r\n", __func__);
    			break;
    		}
        }
        else 
        {
            /*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
			//IEEE80211_TL_RX_DEQUEUE(vap_cq, receive_wbuf, rs, subtype, dir);
		    IEEE80211_TL_CACHEQ_DEQUEUE(vap_cq, receive_wbuf);
		    if (FALSE == ic->ic_is_mode_offload(ic))
				IEEE80211_TL_DEQUEUE_RX_EXTRA(vap_cq, rs, subtype, dir); 
			else 
				OL_IEEE80211_TL_DEQUEUE_RX_EXTRA(vap_cq, peer, tid);
			/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
        }
    	
		count++;
        ni = wbuf_get_node(receive_wbuf);
        if(NULL != ni && NULL != receive_wbuf)
		{
			/*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
			if (FALSE == ic->ic_is_mode_offload(ic))
#if UMAC_SUPPORT_APONLY            
            	ieee80211_input_data_aponly_for_tl(ni, receive_wbuf, rs, subtype, dir);
#else
            	ieee80211_input_data_for_tl(ni, receive_wbuf, rs, subtype, dir);
#endif
			else 
				ol_rx_deliver(vap->iv_txrx_handle, peer, tid, receive_wbuf);
			/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
        }
        else
        {
            traffic_limit_debug_print(IEEE80211_TL_LOG_ERROR,
                    "[%s]ni - %p, receive_wbuf - %p \r\n", __func__, ni, receive_wbuf);
        }
	}  
 
    IEEE80211_TL_CACHEQ_UNLOCK(vap_cq);
    return ;
}

/**
 * Sta to AP.
 */
void ieee80211_tl_node_dequeue_cache_rx(struct ieee80211_node *ni) 
{
    int dir;
    int subtype;
    u_int32_t count = 0;
    int receive_weight = 0;
	int color = IEEE80211_TL_COLOR_MARK_INVALID;

    wbuf_t receive_wbuf = NULL;
    struct ieee80211_rx_status *rs = NULL;

    struct ieee80211_tl_srtcm *nsrtcm = NULL;
	struct ieee80211_tl_cache_queue_rx *ncq = NULL;

    struct ieee80211vap *vap = NULL;
    struct ieee80211_tl_srtcm *vap_srtcm = NULL;
	
	/*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
	struct ieee80211com *ic = NULL;
	void *peer = NULL;
	unsigned tid;
	/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/

    if(NULL == ni)
    {
        return ;
    }
    
    vap = ni->ni_vap;
	ic = vap->iv_ic; //zhaoyang1 modified for 11ac traffic limit 2014-03-31
    vap_srtcm = &(vap->vap_tl_up_srtcm_vap);

    ncq = &(ni->ni_tl_up_cacheq);     // Always use node's cache queue

    // Specific Node has a higher priority with Everynode.
    if(IEEE80211_TL_ENABLE == ni->ni_tl_sp_enable)  // Specific Node
    {
        nsrtcm = &(ni->ni_tl_up_srtcm_sp);
    }
    else if(IEEE80211_TL_ENABLE == ni->ni_tl_ev_enable) // Everynode
    {
        nsrtcm = &(ni->ni_tl_up_srtcm_ev);
    }

    receive_weight = ncq->cq_weighted;
    
    IEEE80211_TL_CACHEQ_LOCK(ncq);
    while(ncq->cq_len > 0)
	{		
		if(count >= tl_dequeue_threshold) // receive_weight)
		{
			break;
		}
				
		IEEE80211_TL_CACHEQ_POLL(ncq, receive_wbuf);

        if(IEEE80211_TL_ENABLE == vap->vap_tl_vap_enable)
        {
            color = ieee80211_tl_srtcm_meter(vap_srtcm, receive_wbuf);
            /* Exceed Vap's limitation */
            if(IEEE80211_TL_COLOR_MARK_RED == color)
            {
                break;
            }
        }

        if((ni != vap->iv_bss) &&
           ((IEEE80211_TL_ENABLE == ni->ni_tl_sp_enable) ||
            (IEEE80211_TL_ENABLE == ni->ni_tl_ev_enable)))
        {
    		color = ieee80211_tl_srtcm_meter(nsrtcm, receive_wbuf);
    		
    		if(color == IEEE80211_TL_COLOR_MARK_GREEN)
    		{
				/*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
				//IEEE80211_TL_RX_DEQUEUE(ncq, receive_wbuf, rs, subtype, dir);
                IEEE80211_TL_CACHEQ_DEQUEUE(ncq, receive_wbuf);   
				if (FALSE == ic->ic_is_mode_offload(ic))
        			IEEE80211_TL_DEQUEUE_RX_EXTRA(ncq, rs, subtype, dir); 
				else 
					OL_IEEE80211_TL_DEQUEUE_RX_EXTRA(ncq, peer, tid);
				/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
    		}
    		else if(color == IEEE80211_TL_COLOR_MARK_YELLOW)
    		{
    			traffic_limit_debug_print(IEEE80211_TL_LOG_INFO,
                    "[%s]Dequeue: the color marked yellow!\r\n", __func__);

    			if(ncq->cq_len < ncq->cq_threshold_low)
    			{
    				ncq->cq_pre_depth = IEEE80211_TL_CACHEQ_DEPTH_LOW;
					/*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
    				//IEEE80211_TL_RX_DEQUEUE(ncq, receive_wbuf, rs, subtype, dir);
	                IEEE80211_TL_CACHEQ_DEQUEUE(ncq, receive_wbuf);   
					if (FALSE == ic->ic_is_mode_offload(ic))
	        			IEEE80211_TL_DEQUEUE_RX_EXTRA(ncq, rs, subtype, dir); 
					else 
						OL_IEEE80211_TL_DEQUEUE_RX_EXTRA(ncq, peer, tid);
					/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
    			}
    			else if(ncq->cq_len > ncq->cq_threshold_high)
    			{
    				ncq->cq_pre_depth = IEEE80211_TL_CACHEQ_DEPTH_HIGH;
    				break;
    			}
    			else
    			{
    				/*from low->high, yellow packet pass*/
    				if(ncq->cq_pre_depth == IEEE80211_TL_CACHEQ_DEPTH_LOW)
    				{
						/*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
    					//IEEE80211_TL_RX_DEQUEUE(ncq, receive_wbuf, rs, subtype, dir);
		                IEEE80211_TL_CACHEQ_DEQUEUE(ncq, receive_wbuf);   
						if (FALSE == ic->ic_is_mode_offload(ic))
		        			IEEE80211_TL_DEQUEUE_RX_EXTRA(ncq, rs, subtype, dir); 
						else 
							OL_IEEE80211_TL_DEQUEUE_RX_EXTRA(ncq, peer, tid);
						/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
    				}
    				else /*from high -> low, yellow packet not pass*/
    				{
    					break;
    				}
    			}
    		}
            /* Exceed Node's limitation */
    		else if(color == IEEE80211_TL_COLOR_MARK_RED)
    		{	   			
    			traffic_limit_debug_print(IEEE80211_TL_LOG_INFO, 
                    "[%s]Dequeue: the color marked red!\r\n", __func__);
    			break;
    		}
    		else
    		{
    			traffic_limit_debug_print(IEEE80211_TL_LOG_INFO,
                    "[%s]Dequeue error: the color marked invilaid!\r\n", __func__);
    			break;
    		}
        }
        else
        {
         	/*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
		    //IEEE80211_TL_RX_DEQUEUE(ncq, receive_wbuf, rs, subtype, dir);
			IEEE80211_TL_CACHEQ_DEQUEUE(ncq, receive_wbuf);   
			if (FALSE == ic->ic_is_mode_offload(ic))
				IEEE80211_TL_DEQUEUE_RX_EXTRA(ncq, rs, subtype, dir); 
			else 
				OL_IEEE80211_TL_DEQUEUE_RX_EXTRA(ncq, peer, tid);
			/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
        }
    	
		count++;
		/*Begin: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
		if (FALSE == ic->ic_is_mode_offload(ic))
#if UMAC_SUPPORT_APONLY            
        	ieee80211_input_data_aponly_for_tl(ni, receive_wbuf, rs, subtype, dir);
#else
        	ieee80211_input_data_for_tl(ni, receive_wbuf, rs, subtype, dir);
#endif
		else
			ol_rx_deliver(vap->iv_txrx_handle, peer, tid, receive_wbuf);
		/*End: zhaoyang1 modified for 11ac traffic limit 2014-03-31*/
	} 

    IEEE80211_TL_CACHEQ_UNLOCK(ncq);
    return ;
}


void ieee80211_tl_dequeue_cache_tx_tasklet_fn(struct ieee80211com *ic)
{
    u_int8_t wifi_num = 0;
    u_int32_t cq_len = 0;
    struct timeval time_point;

    struct ieee80211com *ic_tmp = NULL;
    struct ieee80211_node   *ni = NULL;	
	struct ieee80211_node_table *nt = NULL; 

    struct ieee80211vap *vap = NULL;
    
    if(NULL == ic)
    {
        return ;
    }
    
    // for the time slice between tasklets
	do_gettimeofday(&time_point);
	if(time_point.tv_usec < ath_tx_tasklet_tick)
	{
		ath_tx_tasklet_time_slice = 1000000 - ath_tx_tasklet_tick + time_point.tv_usec;
	}
	else
	{
		ath_tx_tasklet_time_slice = time_point.tv_usec - ath_tx_tasklet_tick;
	}

	ath_tx_tasklet_tick = time_point.tv_usec;
    
    if(ath_tx_tasklet_time_slice >= tl_tasklet_timeslice) 
    {
		for (wifi_num = 0; wifi_num < 3; wifi_num++) {

			ic_tmp = ic_specific[wifi_num];
			if(ic_tmp) {
				nt = &ic_tmp->ic_sta; 
				if(nt == NULL)
				{
					traffic_limit_debug_print(IEEE80211_TL_LOG_INFO,
                            "[%s] nt is NULL\n",__func__);
					continue ;
				}
			}
			else {
				continue ;
			}

            TAILQ_FOREACH(vap, &ic_tmp->ic_vaps, iv_next)
            {
                IEEE80211_TL_CACHEQ_LOCK(&(vap->vap_tl_down_cacheq));
                cq_len = vap->vap_tl_down_cacheq.cq_len;
                IEEE80211_TL_CACHEQ_UNLOCK(&(vap->vap_tl_down_cacheq));
                if(cq_len > 0)
				{   
                    ieee80211_tl_vap_dequeue_cache_tx(vap);
				}
            }
            
			TAILQ_FOREACH(ni, &nt->nt_node, ni_list)
			{   
                IEEE80211_TL_CACHEQ_LOCK(&(ni->ni_tl_down_cacheq));
                cq_len = ni->ni_tl_down_cacheq.cq_len;
                IEEE80211_TL_CACHEQ_UNLOCK(&(ni->ni_tl_down_cacheq));
                if(cq_len > 0)
				{   
                    ieee80211_tl_node_dequeue_cache_tx(ni);
				}
			}
		}
	}
}

void ieee80211_tl_dequeue_cache_rx_tasklet_fn(struct ieee80211com *ic)
{
    u_int8_t wifi_num = 0;
    u_int32_t cq_len = 0;
    struct timeval time_point;

    struct ieee80211com *ic_tmp = NULL ;
    struct ieee80211_node   *ni = NULL;	
	struct ieee80211_node_table *nt = NULL; 

    struct ieee80211vap *vap = NULL;
    
    if(NULL == ic)
    {
        return ;
    }
        
    // for the time slice between tasklets
	do_gettimeofday(&time_point);
	if(time_point.tv_usec < ath_rx_tasklet_tick)
	{
		ath_rx_tasklet_time_slice = 1000000 - ath_rx_tasklet_tick + time_point.tv_usec;
	}
	else
	{
		ath_rx_tasklet_time_slice = time_point.tv_usec - ath_rx_tasklet_tick;
	}

	ath_rx_tasklet_tick = time_point.tv_usec;
    
    if(ath_rx_tasklet_time_slice >= tl_tasklet_timeslice) 
    {
		for (wifi_num = 0; wifi_num < 3; wifi_num++) {

			ic_tmp = ic_specific[wifi_num];
			if(ic_tmp) {
				nt = &ic_tmp->ic_sta; 
				if(nt == NULL)
				{
					traffic_limit_debug_print(IEEE80211_TL_LOG_INFO,
                            "[%s] nt is NULL\n",__func__);
					continue ;
				}
			}
			else {
				continue ;
			}
            
            TAILQ_FOREACH(vap, &ic_tmp->ic_vaps, iv_next)
            {
                IEEE80211_TL_CACHEQ_LOCK(&(vap->vap_tl_up_cacheq));
                cq_len = vap->vap_tl_up_cacheq.cq_len;
                IEEE80211_TL_CACHEQ_UNLOCK(&(vap->vap_tl_up_cacheq));
                if(cq_len > 0)
				{   
                    ieee80211_tl_vap_dequeue_cache_rx(vap);
				}
            }
                        
			TAILQ_FOREACH(ni, &nt->nt_node, ni_list)
			{                
                IEEE80211_TL_CACHEQ_LOCK(&(ni->ni_tl_up_cacheq));
                cq_len = ni->ni_tl_up_cacheq.cq_len;
                IEEE80211_TL_CACHEQ_UNLOCK(&(ni->ni_tl_up_cacheq));
                if(cq_len > 0)
				{
                    ieee80211_tl_node_dequeue_cache_rx(ni);
				}
			}
		}
	}
}

void ieee80211_tl_dequeue_cache_timer_fn(void)
{
	
	tasklet_schedule(&tl_dequeue_cache_tx_tasklet);

    tasklet_schedule(&tl_dequeue_cache_rx_tasklet);

	mod_timer(&tl_dequeue_cache_timer, jiffies + 1);
}

EXPORT_SYMBOL(ieee80211_tl_dequeue_cache_tx_tasklet_fn);

EXPORT_SYMBOL(ieee80211_tl_dequeue_cache_rx_tasklet_fn);

EXPORT_SYMBOL(ieee80211_tl_dequeue_cache_timer_fn);


void ieee80211_traffic_limit_init(struct net_device *dev,struct ieee80211com *ic)
{

	if (memcmp(dev->name, "wifi0", 5) == 0) {
		printk("####### wifi0 ic = 0x%p ######\n",ic);
		ic_specific[0] = ic;

    	tasklet_init(&tl_dequeue_cache_tx_tasklet,
    			(void *)ieee80211_tl_dequeue_cache_tx_tasklet_fn,
    			(unsigned long)ic_specific);
    	
    	tasklet_init(&tl_dequeue_cache_rx_tasklet,
    			(void *)ieee80211_tl_dequeue_cache_rx_tasklet_fn,
    			(unsigned long)ic_specific);
    	
    	init_timer(&tl_dequeue_cache_timer);
    	tl_dequeue_cache_timer.function = (void *)ieee80211_tl_dequeue_cache_timer_fn;
    	tl_dequeue_cache_timer.data = (unsigned long)0;
    	tl_dequeue_cache_timer.expires	= jiffies + 1;
    	add_timer(&tl_dequeue_cache_timer);
    }

	if (memcmp(dev->name, "wifi1", 5) == 0) {
		printk("####### wifi1 ic = 0x%p ######\n",ic);
		ic_specific[1] = ic;
	}
	else if (memcmp(dev->name, "wifi2", 5) == 0) {
		printk("####### wifi2 ic = 0x%p ######\n",ic);
		ic_specific[2] = ic;
	}
    
    return;
}


void ieee80211_traffic_limit_deinit(struct net_device *dev)
{

    del_timer(&tl_dequeue_cache_timer);
    
    return;
}

extern u_int32_t tl_tasklet_timeslice;
extern u_int32_t tl_dequeue_threshold;
extern u_int32_t tl_debug_flag;

#define NETDEV_TO_VAP(_dev) (((osif_dev *)netdev_priv(_dev))->os_if)

int
ieee80211_ioctl_han_traffic_limit(struct net_device *dev, struct iwreq *iwr)
{
    /*xiaruixin modify for traffic limit reset*/
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    /*xiaruixin modify end*/
    struct ieee80211com   *ic = vap->iv_ic;
    struct ieee80211_node *ni = NULL ;
    struct ieee80211_han_traffic_limit ik;
	struct han_ioctl_priv_args tmp_args;
    struct ieee80211_node_table *nt = &ic->ic_sta; 

    u_int32_t rate = 0;
    u_int64_t cir = 0;

    u_int32_t loop = 0;
    u_int32_t flag = 0;
    
    struct ieee80211_tl_srtcm *ni_tl_up = NULL;
    struct ieee80211_tl_srtcm *ni_tl_down = NULL;
    struct ieee80211_tl_srtcm *vap_tl_up = NULL;
    struct ieee80211_tl_srtcm *vap_tl_down = NULL;
    struct ieee80211_tl_srtcm *vap_tl_ev_up = NULL;
    struct ieee80211_tl_srtcm *vap_tl_ev_down = NULL;    

    vap_tl_up = &(vap->vap_tl_up_srtcm_vap);
    vap_tl_down = &(vap->vap_tl_down_srtcm_vap);

    vap_tl_ev_up = &(vap->vap_tl_up_srtcm_ev);
    vap_tl_ev_down = &(vap->vap_tl_down_srtcm_ev);
    
    memset(&ik, 0x00, sizeof(ik));

    if (copy_from_user(&tmp_args, iwr->u.data.pointer, sizeof(ik))) {
        return -EFAULT;
    }
	memcpy(&ik, &tmp_args.u.traffic_limit, sizeof(struct ieee80211_han_traffic_limit));
    
    switch (ik.type) { 
        case SET_VAP_TRAFFIC_LIMIT_FLAG:
            if(1 == ik.arg1) {
                vap->vap_tl_vap_enable = IEEE80211_TL_ENABLE;
            } else if(0 == ik.arg1) {
                vap->vap_tl_vap_enable = IEEE80211_TL_DISABLE;
            } else {
                return -EINVAL;
            }
            break;

        case GET_VAP_TRAFFIC_LIMIT_FLAG:
            flag = vap->vap_tl_vap_enable;
            copy_to_user(iwr->u.data.pointer, &(flag), sizeof(flag));
            break;

        case SET_VAP_TRAFFIC_LIMIT:
            rate = ik.arg1;
            IEEE80211_TL_SRTCM_SET_CIR(vap_tl_up, rate);
            break;

        case GET_VAP_TRAFFIC_LIMIT :
            cir = vap_tl_up->sr_cir;
            rate = IEEE80211_TL_CIR_TO_RATE(cir);
            copy_to_user(iwr->u.data.pointer, &rate, sizeof(rate));
            break;

        case SET_EVERY_NODE_TRAFFIC_LIMIT_FLAG:
            if(1 == ik.arg1) {
                vap->vap_tl_ev_enable = IEEE80211_TL_ENABLE;
            } else if(0 == ik.arg1) {
                vap->vap_tl_ev_enable = IEEE80211_TL_DISABLE;
            } else {
                return -EINVAL;
            }
                
            TAILQ_FOREACH(ni, &nt->nt_node, ni_list){
                if((ni->ni_vap != vap) || (ni == ni->ni_vap->iv_bss))
                {
                    continue;
                }

                ni->ni_tl_ev_enable = vap->vap_tl_ev_enable;
                /**
                 *  when EVERY node is set, whenever is turn ON/OFF, 
                 *  turn OFF every node's SPECIFIC flag;
                 */
                ni->ni_tl_sp_enable = IEEE80211_TL_DISABLE;
            }
            break;

        case GET_EVERY_NODE_TRAFFIC_LIMIT_FLAG:
            flag = vap->vap_tl_ev_enable;
            copy_to_user(iwr->u.data.pointer, &flag, sizeof(flag));
            break;

        case SET_EVERY_NODE_TRAFFIC_LIMIT:
            rate = ik.arg1;   
            IEEE80211_TL_SRTCM_SET_CIR(vap_tl_ev_up, rate);
            TAILQ_FOREACH(ni, &nt->nt_node, ni_list){
                if((ni->ni_vap != vap) || (ni == ni->ni_vap->iv_bss))
                {
                    continue;
                }
                ni_tl_up = &(ni->ni_tl_up_srtcm_ev);
                IEEE80211_TL_SRTCM_SET_CIR(ni_tl_up, rate);
            }
            break;

        case GET_EVERY_NODE_TRAFFIC_LIMIT :
            cir = vap_tl_ev_up->sr_cir;
            rate = IEEE80211_TL_CIR_TO_RATE(cir);
            copy_to_user(iwr->u.data.pointer, &rate, sizeof(rate));

            break;

        case SET_SPECIFIC_NODE_TRAFFIC_LIMIT_FLAG:
            ni = ieee80211_find_node(&ic->ic_sta, ik.macaddr);
            if (ni == NULL)
                return -EINVAL;

            ni_tl_up = &(ni->ni_tl_up_srtcm_sp);
            if(1 == ik.arg1) {
                ni->ni_tl_sp_enable = IEEE80211_TL_ENABLE;
            } else if(0 == ik.arg1) {
                ni->ni_tl_sp_enable = IEEE80211_TL_DISABLE;
            } else {
                ieee80211_free_node(ni);
                return -EINVAL;
            }
            ieee80211_free_node(ni);
            break;

        case GET_SPECIFIC_NODE_TRAFFIC_LIMIT_FLAG:
            ni = ieee80211_find_node(&ic->ic_sta, ik.macaddr);
            if (ni == NULL)
                return -EINVAL;

            flag = ni->ni_tl_sp_enable;
            copy_to_user(iwr->u.data.pointer, &flag, sizeof(flag));

            ieee80211_free_node(ni);
            break;
            
        case SET_SPECIFIC_NODE_TRAFFIC_LIMIT:
            ni = ieee80211_find_node(&ic->ic_sta, ik.macaddr);

            if (ni == NULL)
                return -EINVAL; 
            rate = ik.arg1;
            ni_tl_up = &(ni->ni_tl_up_srtcm_sp);
            IEEE80211_TL_SRTCM_SET_CIR(ni_tl_up, rate);
            
            ieee80211_free_node(ni);
            break;

        case GET_SPECIFIC_NODE_TRAFFIC_LIMIT :
            ni = ieee80211_find_node(&ic->ic_sta, ik.macaddr);
            
            if (ni == NULL)
                return -EINVAL; 

            ni_tl_up = &(ni->ni_tl_up_srtcm_sp);
            cir = ni_tl_up->sr_cir;
            rate = IEEE80211_TL_CIR_TO_RATE(cir);
            copy_to_user(iwr->u.data.pointer, &rate, sizeof(rate));
            
            ieee80211_free_node(ni);
            break;

        case SET_VAP_TRAFFIC_LIMIT_SEND:
            rate = ik.arg1;
            IEEE80211_TL_SRTCM_SET_CIR(vap_tl_down, rate);

            break;

        case GET_VAP_TRAFFIC_LIMIT_SEND:
            cir = vap_tl_down->sr_cir;
            rate = IEEE80211_TL_CIR_TO_RATE(cir);
            copy_to_user(iwr->u.data.pointer, &rate, sizeof(rate));
            break;
            
        case SET_EVERY_NODE_TRAFFIC_LIMIT_SEND:
            rate = ik.arg1;
            IEEE80211_TL_SRTCM_SET_CIR(vap_tl_ev_down, rate);
            
            TAILQ_FOREACH(ni, &nt->nt_node, ni_list){
                if((ni->ni_vap != vap) || (ni == ni->ni_vap->iv_bss))
                {
                    continue;
                }
                ni_tl_down = &(ni->ni_tl_down_srtcm_ev);
                IEEE80211_TL_SRTCM_SET_CIR(ni_tl_down, rate);
            }            
            break;

        case GET_EVERY_NODE_TRAFFIC_LIMIT_SEND:
            cir = vap_tl_ev_down->sr_cir;
            rate = IEEE80211_TL_CIR_TO_RATE(cir);
            copy_to_user(iwr->u.data.pointer, &rate, sizeof(rate));
            break;

        case SET_SPECIFIC_NODE_TRAFFIC_LIMIT_SEND:
            ni = ieee80211_find_node(&ic->ic_sta, ik.macaddr);

            if (ni == NULL)
                return -EINVAL;

            rate = ik.arg1;
            ni_tl_down = &(ni->ni_tl_down_srtcm_sp);
            IEEE80211_TL_SRTCM_SET_CIR(ni_tl_down, rate);
            
            ieee80211_free_node(ni);
            break;

            case GET_SPECIFIC_NODE_TRAFFIC_LIMIT_SEND:
            ni = ieee80211_find_node(&ic->ic_sta, ik.macaddr);

            if (ni == NULL)
                return -EINVAL;

            ni_tl_down = &(ni->ni_tl_down_srtcm_sp);
            cir = ni_tl_down->sr_cir;
            rate = IEEE80211_TL_CIR_TO_RATE(cir);
            copy_to_user(iwr->u.data.pointer, &rate, sizeof(rate));
            
            ieee80211_free_node(ni);

            break;
        /*AUTELAN-Added-Begin: Added by WangJia, for traffic limit. 2012-11-02.*/
        case TL_GET_TRAFFIC_LIMIT_STATUS:
            printf("Vap  Sum           :     %s, Down - %llukbps, Up - %llukbps\r\n", 
                   (IEEE80211_TL_ENABLE == vap->vap_tl_vap_enable) ? " ON" : "OFF", 
                   IEEE80211_TL_CIR_TO_RATE(vap_tl_down->sr_cir), 
                   IEEE80211_TL_CIR_TO_RATE(vap_tl_up->sr_cir));
            
            printf("Node List          : ");
            TAILQ_FOREACH(ni, &nt->nt_node, ni_list){
                if((ni->ni_vap != vap) || (ni == ni->ni_vap->iv_bss))
                {
                    continue;
                }
                ni_tl_up = &(ni->ni_tl_up_srtcm_ev);
                ni_tl_down = &(ni->ni_tl_down_srtcm_ev);
                if(IEEE80211_TL_ENABLE == ni->ni_tl_sp_enable)
                {
                    ni_tl_up = &(ni->ni_tl_up_srtcm_sp);
                    ni_tl_down = &(ni->ni_tl_down_srtcm_sp);
                }

                flag = 1;
                printf("\r\n[%02X:", ni->ni_macaddr[0]);
                for(loop = 1; loop < 5; loop++)
                {
                    printf("%02X:", ni->ni_macaddr[loop]);
                }
                printf("%02X]: ", ni->ni_macaddr[5]);
                printf("%s, ", (IEEE80211_TL_ENABLE == ni->ni_tl_sp_enable) ? "SP NODE ON" :
                               (IEEE80211_TL_ENABLE == ni->ni_tl_ev_enable) ? "EV NODE ON" : "    OFF");

                printf("Down - %llukbps, Up - %llukbps", 
                    IEEE80211_TL_CIR_TO_RATE(ni_tl_down->sr_cir),
                    IEEE80211_TL_CIR_TO_RATE(ni_tl_up->sr_cir));
            }
            if(flag == 0)
            {
                printf("No Stations.");
            }
            printf("\r\n");
            break;
        case TL_SET_TASKLET_TIMESLICE:
            tl_tasklet_timeslice = ik.arg1;
            break;

        case TL_GET_TASKLET_TIMESLICE:
            printf("tl_tasklet_timeslice = %d\r\n", tl_tasklet_timeslice);
            break;

        case TL_SET_DEQUEUE_THRESHOLD:
            tl_dequeue_threshold = ik.arg1;
            break;
            
        case TL_GET_DEQUEUE_THRESHOLD:
            printf("tl_dequeue_threshold = %d\r\n", tl_dequeue_threshold);
            break;
            
        case TL_GET_EVERYNODE_QUEUE_LEN:
            printf("VAP                 : UP - %u, DOWN - %u\r\n", 
                    vap->vap_tl_up_cacheq.cq_len, 
                    vap->vap_tl_down_cacheq.cq_len);
            TAILQ_FOREACH(ni, &nt->nt_node, ni_list){
                if((ni->ni_vap != vap) || (ni == ni->ni_vap->iv_bss))
                {
                    continue;
                }
                printf("[");
                for(loop = 0; loop < 5; loop++)
                {
                    printf("%02X:", ni->ni_macaddr[loop]);
                }
                printf("%02X] : UP - %u, DOWN - %u\r\n", ni->ni_macaddr[5],
                    ni->ni_tl_up_cacheq.cq_len, ni->ni_tl_down_cacheq.cq_len);
                flag = 1;
            }
            if(flag == 0)
            {
                printf("No Stations.\r\n");
            }
            break;
        case TL_SET_DEBUG_FLAG:
            if(ik.arg1 & IEEE80211_TL_LOG_INFO || ik.arg1 & IEEE80211_TL_LOG_WARNING || 
               ik.arg1 & IEEE80211_TL_LOG_ERROR) 
            {
                tl_debug_flag = (ik.arg1 & IEEE80211_TL_LOG_INFO) | 
                                (ik.arg1 & IEEE80211_TL_LOG_WARNING) | 
                                (ik.arg1 & IEEE80211_TL_LOG_ERROR);
            }
            break;
        case TL_GET_DEBUG_FLAG:
            printf("Current traffic limit debug switch: 0X%02X [ ", tl_debug_flag);
            if(tl_debug_flag & IEEE80211_TL_LOG_INFO)
                printf(" INFO ");
            if(tl_debug_flag & IEEE80211_TL_LOG_WARNING)
                printf(" WARNING ");
            if(tl_debug_flag & IEEE80211_TL_LOG_ERROR)
                printf(" ERROR ");
            printf("]\r\n");
            break;
        /*AUTELAN-Added-End: Added by WangJia, for traffic limit. 2012-11-02.*/
        default :
            return -EFAULT;
    }
    return 0;
}

