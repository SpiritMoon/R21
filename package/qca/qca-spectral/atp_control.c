/*
 * Copyright (c) 2015 HAN-networks, Inc..
 * All Rights Reserved.
 *
 * =====================================================================================
 *
 *    Filename:  atp_control.c
 *
 *    Description:  auto txpower control
 *
 *    Version:  1.0
 *    Created:  04/22/2016 10:01:01
 *    Revision:  none
 *    Compiler:  gcc
 *
 *    Author:  Mingzhe Duan
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "icm.h"
#include "drm.h"
#include "atp_control.h"

                              /*{distance,best txpower, {{txpower,rssi},{txpower,rssi},...}}*/
distance_estimate g_aptoap[7] = {{3,3,  {{3,40},{5,43},{8,45},{11,49},{14,52},{17,56},{20,59},{23,63}}},
                               {6,3,  {{3,39},{5,42},{8,45},{11,48},{14,52},{17,55},{20,59},{23,62}}},
                               {9,3,  {{3,39},{5,42},{8,45},{11,48},{14,50},{17,53},{20,57},{23,60}}},
                               {12,5, {{3,37},{5,39},{8,42},{11,45},{14,47},{17,50},{20,53},{23,56}}},
                               {15,8, {{3,33},{5,35},{8,38},{11,41},{14,43},{17,45},{20,48},{23,51}}},
                               {18,11,{{3,31},{5,33},{8,36},{11,39},{14,41},{17,43},{20,46},{23,50}}},
                               {21,14,{{3,28},{5,31},{8,34},{11,37},{14,39},{17,41},{20,44},{23,48}}},
                              };    
                               /*distance,best txpower*/
distance_estimate g_aptosta[7]={3,5,  {},
                                6,8,  {},
                                9,8,  {},
                                12,11,{},
                                15,11,{},
                                18,14,{},
                                21,14,{}};

int g_atp_waiting_time = 30;
time_t g_atp_check_time;

static inline int OS_MACCMP(const void *_mac1, const void *_mac2)
{
    const char *mac1 = _mac1;
    const char *mac2 = _mac2;
    return ((mac1[0] ^ mac2[0]) | (mac1[1] ^ mac2[1]) | (mac1[2] ^ mac2[2]) | (mac1[3] ^ mac2[3]) | (mac1[4] ^ mac2[4]) | (mac1[5] ^ mac2[5])); 
}

static inline void * OS_MACCPY(void *_mac1, const void *_mac2)
{
    char *mac1 = _mac1;
    const char *mac2 = _mac2;
    mac1[0] = mac2[0];
    mac1[1] = mac2[1];
    mac1[2] = mac2[2];
    mac1[3] = mac2[3];
    mac1[4] = mac2[4];
    mac1[5] = mac2[5];
    return mac1;
}

void print_buf(char * data,int len)
{
     int i =0;
     while (i <= len)
     {
          if ((0 != (i%8)) || (0 == i))
          {
                 printf("%02x ",data[i]);
                 i++;
                 continue;
           }

            printf("\n");
           printf("%02x ",data[i]);
           i++;
      }
     printf("\n\n");
}

int atp_get_distance(int cur_txpower, int neighbor_rssi)
{
    int distance_cnt = 0, txpower_cnt = 0;
    int txpower_cur_cnt = 0;
    int cur_distance = 0;
    for(distance_cnt = 0; distance_cnt < 7; distance_cnt++){
        for(txpower_cnt = 0; txpower_cnt < 8; txpower_cnt++){
            //printf("distance_cnt %d txpower_cnt %d (%d %d)\n",distance_cnt,txpower_cnt,aptoap[distance_cnt].txpower_and_rssi[txpower_cnt].txpower,cur_txpower);
            if(g_aptoap[distance_cnt].txpower_and_rssi[txpower_cnt].txpower < cur_txpower){
                continue;
            }else{
                txpower_cur_cnt = txpower_cnt;
                break;
            }
        }
    }
    
    cur_distance = g_aptoap[0].meter; //default is distance 3
    for(distance_cnt = 0; distance_cnt < 7; distance_cnt++){
        if(g_aptoap[distance_cnt].txpower_and_rssi[txpower_cur_cnt].rssi >= neighbor_rssi)
            cur_distance = g_aptoap[distance_cnt].meter;
    }
    return cur_distance;
}

int atp_get_best_txpower_by_sta(int distance)
{
    int distance_cnt = 0, txpower_cnt = 0;
    for(distance_cnt = 0; distance_cnt < 7; distance_cnt++){
      if(g_aptosta[distance_cnt].meter == distance){
        return g_aptosta[distance_cnt].best_txpower;
      }
    }
    return 0;
}

int atp_get_best_txpower_by_distance(int distance)
{
    int distance_cnt = 0, txpower_cnt = 0;
    for(distance_cnt = 0; distance_cnt < 7; distance_cnt++){
      if(g_aptoap[distance_cnt].meter == distance){
        return g_aptoap[distance_cnt].best_txpower;
      }
    }
    return 0;
}

int atp_recalculate_txpower(int current_txpower, int best_txpower)
{
    int adjuest_txpower = 0;
    if(current_txpower < best_txpower)
    {
      adjuest_txpower = current_txpower + 3;
      if(adjuest_txpower > best_txpower){
        adjuest_txpower = best_txpower;
      }

    }else if(current_txpower > best_txpower){
      adjuest_txpower = current_txpower - 3;
      if(adjuest_txpower < best_txpower){
        adjuest_txpower = best_txpower;
      }
    }else{
      adjuest_txpower = best_txpower;
    }
    return adjuest_txpower;
}

int atp_txpower_selector(int current_txpower, int neighbor_txpower, int neighbor_rssi)
{
    int distance = 0;
    int best_txpower = 0;
    int best_txpower_by_sta = 0;
    int adjuest_txpower = 0;
    /*get coverage by txpower*/
    distance = atp_get_distance(neighbor_txpower,neighbor_rssi);
    /*get best txpower by distance*/
    best_txpower = atp_get_best_txpower_by_distance(distance);
    /*get best txpower by sta*/
    best_txpower_by_sta = atp_get_best_txpower_by_sta(distance);
    /*get adjuest txpower*/
    adjuest_txpower = atp_recalculate_txpower(current_txpower,(best_txpower < best_txpower_by_sta?best_txpower_by_sta:best_txpower));
    if(current_txpower != adjuest_txpower){
        drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ATP_CONTROL: current distance is %d, current_txpower %d, best_txpower is %d, best_txpower_by_sta is %d (%d), adjuest_txpower is %d \n",
                distance,current_txpower,best_txpower,best_txpower_by_sta,
                (best_txpower < best_txpower_by_sta?best_txpower_by_sta:best_txpower),adjuest_txpower);
    }
    
    return adjuest_txpower;
}

void atp_set_txpower(ICM_INFO_T* picm,int best_txpower)
{
    int ret;
    int i = 0;
    
    if (best_txpower > 0) {
        for (i = 0; i < picm->numdevs; i++) {
            char cmd[128] = {0};      
            sprintf(cmd,"iwconfig %s txpower %d",picm->dev_ifnames_list[i],best_txpower);
            ret = system(cmd);
            if (ret == -1) {
                perror("ATP_CONTROL : set txpower");
            }
        }
    }
}

void atp_control_timer()
{
    int i = 0;
    ICM_INFO_T *picm = NULL;
    ICM_DEV_INFO_T* pdev = get_pdev();
    Clusterlist * node = NULL;
    time_t now_time;
    
    time(&now_time);
    
    if(g_atp_check_time == NULL){
		printf("Get first check time\n");
		time(&g_atp_check_time);
        return;
	}else if((now_time - g_atp_check_time) < g_atp_waiting_time){
	    return;
	}
    
    time(&g_atp_check_time);

	/*
	 *drm_get_clustr_list();
	 */

	drm_log(DRM_LOG_NORMAL,"ATP_CONTROL:Find max rssi\n");

	for(i = 0; i < MAX_DEV_NUM; i++){
        picm = NULL;
        picm = get_picm(i);
        if(picm == NULL)
            continue;
        /* check switch*/
        if(picm->numdevs == 0)
            continue;
		if(!picm->atp_enable){
			continue;
		}
		drm_get_channel_txpower(picm,picm->dev_ifname);
		/*get max rssi & txpower of ap from this channel*/
        if(os_strcmp(picm->radio_ifname, "wifi0") == 0){ 
            int best_txpower = picm->current_txpower;
            drm_log(DRM_LOG_NORMAL,"ATP_CONTROL:Trying recalculate txpower for wifi0, current channel is %d current txpower is %d\n",picm->current_channel,picm->current_txpower);
            node = atp_find_max_rssi_cluster_member(0,picm->current_channel);
            if(node != NULL){
                drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ATP_CONTROL:Max rssi neighbor MAC %s radio[0] txpower %d rssi %d \n",macaddr_to_str(node->mac),node->radio[0].txpower,node->radio[0].rssi);
                /*call txpowe selector*/
                best_txpower = atp_txpower_selector(picm->current_txpower,(node->radio[0].txpower?node->radio[0].txpower:WIFI0_MAX_TXPOWER),node->radio[0].rssi);
                if(picm->current_txpower != best_txpower){
                    picm->current_txpower = best_txpower;
                    drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ATP_CONTROL: %s change txpower to %d\n",picm->radio_ifname,best_txpower);
                    atp_set_txpower(picm,best_txpower);
				}
            }else{
                 drm_log(DRM_LOG_NORMAL,"ATP_CONTROL:wifi0 can't found match neighbor, current txpower is %d\n",picm->current_txpower);
                 drm_print_cluster_list(DRM_LOG_NORMAL);
                 best_txpower = atp_recalculate_txpower(picm->current_txpower,WIFI0_MAX_TXPOWER);
                 if(picm->current_txpower != best_txpower){
                    picm->current_txpower = best_txpower;
                    drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ATP_CONTROL: %s can't found match neighbor, trying to change the txpower to %d\n",picm->radio_ifname,best_txpower);
                    atp_set_txpower(picm,best_txpower);
				}
            }
        }
        else if(os_strcmp(picm->radio_ifname, "wifi1") == 0){            
            int best_txpower = picm->current_txpower;
            drm_log(DRM_LOG_NORMAL,"ATP_CONTROL:Trying recalculate txpower for wifi1, current channel is %d current txpower is %d\n",picm->current_channel,picm->current_txpower);
            node = atp_find_max_rssi_cluster_member(1,picm->current_channel);
            if(node != NULL){                
                drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ATP_CONTROL:Max rssi neighbor MAC %s radio[1] txpower %d rssi %d\n",macaddr_to_str(node->mac),node->radio[1].txpower,node->radio[1].rssi);
                /*call txpowe selector*/
                best_txpower = atp_txpower_selector(picm->current_txpower,(node->radio[1].txpower?node->radio[1].txpower:WIFI1_MAX_TXPOWER),node->radio[1].rssi);
                
                /*if txpower change, call driver modifiy txpower*/
                if(picm->current_txpower != best_txpower){
                    picm->current_txpower = best_txpower;
                    drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ATP_CONTROL: %s change txpower to %d\n",picm->radio_ifname,best_txpower);
                    atp_set_txpower(picm,best_txpower);
                }
            }else{
                 drm_log(DRM_LOG_NORMAL,"ATP_CONTROL:wifi1 can't found match neighbor, current txpower is %d\n",picm->current_txpower);
                 drm_print_cluster_list(DRM_LOG_NORMAL);
                 best_txpower = atp_recalculate_txpower(picm->current_txpower,WIFI1_MAX_TXPOWER);
                 if(picm->current_txpower != best_txpower){
                    picm->current_txpower = best_txpower;
                    drm_log(DRM_LOG_WRITE_TO_SYSLOG,"ATP_CONTROL: %s can't found match neighbor, trying to change the txpower to %d\n",picm->radio_ifname,best_txpower);
                    atp_set_txpower(picm,best_txpower);
				}
            }
        }      
        
	}
}
