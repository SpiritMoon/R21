#!/bin/sh
# test :all deltele 
# Copyright (c) 2014, The Linux Foundation. All rights reserved.
#
#  Permission to use, copy, modify, and/or distribute this software for any
#  purpose with or without fee is hereby granted, provided that the above
#  copyright notice and this permission notice appear in all copies.
#
#  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
#  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
#  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
#  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
#  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

append DRIVERS "qcawifi"

wlanconfig() {
	[ -n "${DEBUG}" ] && echo wlanconfig "$@"
	/usr/sbin/wlanconfig "$@"
}

iwconfig() {
	[ -n "${DEBUG}" ] && echo iwconfig "$@"
	/usr/sbin/iwconfig "$@"
}

iwpriv() {
	[ -n "${DEBUG}" ] && echo iwpriv "$@"
	/usr/sbin/iwpriv "$@"
}

xtod() {
        xnum="$1"
        bit1=`echo $xnum | cut -b 2`
        bit2=`echo $xnum | cut -b 1`
        if [ "$bit1" = "a" -o "$bit1" = "A" ];then
                dnum=10
        elif [ "$bit1" = "b" -o "$bit1" = "B" ];then
                dnum=11
        elif [ "$bit1" = "c" -o "$bit1" = "C" ];then
                dnum=12
        elif [ "$bit1" = "d" -o "$bit1" = "D" ];then
                dnum=13
        elif [ "$bit1" = "e" -o "$bit1" = "E" ];then
                dnum=14
        elif [ "$bit1" = "f" -o "$bit1" = "F" ];then
                dnum=15
        else
                dnum=$bit1
        fi
        if [ "$bit2" = "a" -o "$bit2" = "A" ];then
                dnum=`expr $dnum + 160`
        elif [ "$bit2" = "b" -o "$bit2" = "B" ];then
                dnum=`expr $dnum + 176`
        elif [ "$bit2" = "c" -o "$bit2" = "C" ];then
                dnum=`expr $dnum + 192`
        elif [ "$bit2" = "d" -o "$bit2" = "D" ];then
                dnum=`expr $dnum + 208`
        elif [ "$bit2" = "e" -o "$bit2" = "E" ];then
                dnum=`expr $dnum + 224`
        elif [ "$bit2" = "f" -o "$bit2" = "F" ];then
                dnum=`expr $dnum + 240`
        else
                tmp=`expr $bit2 \* 16`
                dnum=`expr $dnum + $tmp`
        fi
        return $dnum
}

find_qcawifi_phy() {
	local device="$1"

	local macaddr="$(config_get "$device" macaddr | tr 'A-Z' 'a-z')"
	local mac="$(/usr/sbin/showsysinfo|/bin/grep 'MAC:'|/usr/bin/cut -d: -f2-7)"
	config_get phy "$device" phy
	[ -z "$phy" -a -n "$macaddr" ] && {
		cd /sys/class/net
		for phy in $(ls -d wifi* 2>&-); do
			[ "$macaddr" = "$(cat /sys/class/net/${phy}/address)" ] || continue
			config_set "$device" phy "$phy"
			break
		done
		config_get phy "$device" phy
	}
	[ -n "$phy" -a -d "/sys/class/net/$phy" ] || {
		echo "phy for wifi device $1 not found"
		return 1
	}
	[ -z "$macaddr" ] && {
		config_set "$device" macaddr "$(cat /sys/class/net/${phy}/address)"
	}
	[ "$phy" = "wifi0" ] && {                                       
                ifconfig wifi0 down                                     
                #mac=`partool -part mtd8 -show product.mac`              
                ifconfig wifi0 hw ether $mac                            
                ifconfig wifi0 up          
        }                                         
        [ "$phy" = "wifi1" ] && {                                                          
                ifconfig wifi1 down                                                        
                #mac=`partool -part mtd8 -show product.mac`                                 
                byte1=`echo $mac | cut -b 16-17`                                             
		xtod $byte1
		byte1=$?
                byte2=`echo $mac | cut -b 13-14`                                             
		xtod $byte2
		byte2=$?
                byte3=`echo $mac | cut -b 10-11`                                             
		xtod $byte3
		byte3=$?
		if [ -f /jffs/.mac-policy ];then
                byte1=`expr $byte1 + 1`                       
                else
		byte1=`expr $byte1 + 8`                       
		fi
		if [ $byte1 -gt 255 ];then
			byte1=`expr $byte1 - 256`
			byte2=`expr $byte2 + 1`
			if [ $byte2 -gt 255 ];then
				byte2=`expr $byte2 - 256`
				byte3=`expr $byte3 + 1`
			fi
			echo "waring:basemac incorrect"
		fi
		if [ $byte3 -gt 255 ];then
			byte3=`expr $byte3 - 256`
		fi
                byte1=`echo $byte1 |awk '{printf("%x",$0)}'`
                byte2=`echo $byte2 |awk '{printf("%x",$0)}'`
                byte3=`echo $byte3 |awk '{printf("%x",$0)}'`
                mac=`echo $mac | cut -b 1-9`          
                mac=`echo ${mac}${byte3}":"${byte2}":"${byte1}`                
                ifconfig wifi1 hw ether $mac           
                ifconfig wifi1 up                         
        } 
	return 0
}

scan_qcawifi() {
	local device="$1"
	local wds
	local adhoc sta ap monitor disabled

	[ ${device%[0-9]} = "wifi" ] && config_set "$device" phy "$device"

	local ifidx=0
	local radioidx=${device#wifi}

	config_get vifs "$device" vifs
	for vif in $vifs; do
		config_get_bool disabled "$vif" disabled 0
		[ $disabled = 0 ] || continue

		local vifname
		[ $ifidx -gt 0 ] && vifname="ath${radioidx}$ifidx" || vifname="ath${radioidx}"

		config_get ifname "$vif" ifname
		config_set "$vif" ifname "${ifname:-$vifname}"
		
		config_get mode "$vif" mode
		case "$mode" in
			adhoc|sta|ap|monitor|wrap)
				append "$mode" "$vif"
			;;
			wds)
				config_get ssid "$vif" ssid
				[ -z "$ssid" ] && continue

				config_set "$vif" wds 1
				config_set "$vif" mode sta
				mode="sta"
				addr="$ssid"
				${addr:+append "$mode" "$vif"}
			;;
			*) echo "$device($vif): Invalid mode, ignored."; continue;;
		esac

		ifidx=$(($ifidx + 1))
	done

	case "${adhoc:+1}:${sta:+1}:${ap:+1}" in
		# valid mode combinations
		1::) wds="";;
		1::1);;
		:1:1)config_set "$device" nosbeacon 1;; # AP+STA, can't use beacon timers for STA
		:1:);;
		::1);;
		::);;
		*) echo "$device: Invalid mode combination in config"; return 1;;
	esac

	config_set "$device" vifs "${wrap:+$wrap }${sta:+$sta }${ap:+$ap }${adhoc:+$adhoc }${wds:+$wds }${monitor:+$monitor}"
}


load_qcawifi() {
	local umac_args

	config_get_bool testmode qcawifi testmode
	[ -n "$testmode" ] && append umac_args "testmode=$testmode"

	config_get vow_config qcawifi vow_config
	[ -n "$vow_config" ] && append umac_args "vow_config=$vow_config"

	config_get ol_bk_min_free qcawifi ol_bk_min_free
	[ -n "$ol_bk_min_free" ] && append umac_args "OL_ACBKMinfree=$ol_bk_min_free"

	config_get ol_be_min_free qcawifi ol_be_min_free
	[ -n "$ol_be_min_free" ] && append umac_args "OL_ACBEMinfree=$ol_be_min_free"

	config_get ol_vi_min_free qcawifi ol_vi_min_free
	[ -n "$ol_vi_min_free" ] && append umac_args "OL_ACVIMinfree=$ol_vi_min_free"

	config_get ol_vo_min_free qcawifi ol_vo_min_free
	[ -n "$ol_vo_min_free" ] && append umac_args "OL_ACVOMinfree=$ol_vo_min_free"

	config_get enable_max_clients qcawifi enable_max_clients
	[ -n "$enable_max_clients" ] && append umac_args "enable_max_clients=$enable_max_clients"

	config_get atf_mode qcawifi atf_mode
	[ -n "$atf_mode" ] && append umac_args "atf_mode=$atf_mode"

        config_get atf_msdu_desc qcawifi atf_msdu_desc
        [ -n "$atf_msdu_desc" ] && append umac_args "atf_msdu_desc=$atf_msdu_desc"
	
	config_get atf_peers qcawifi atf_peers
        [ -n "$atf_peers" ] && append umac_args "atf_peers=$atf_peers"

	config_get atf_max_vdevs qcawifi atf_max_vdevs
        [ -n "$atf_max_vdevs" ] && append umac_args "atf_max_vdevs=$atf_max_vdevs"

	config_get lteu_support qcawifi lteu_support
	[ -n "$lteu_support" ] && append umac_args "lteu_support=$lteu_support"

	config_get max_peers qcawifi max_peers
	[ -n "$max_peers" ] && append umac_args "max_peers=$max_peers"

	for mod in $(cat /etc/modules.d/33-qca-wifi*); do

		case ${mod} in
			umac) [ -d /sys/module/${mod} ] || { \
				insmod ${mod} ${umac_args} || { \
					unload_qcawifi
					return 1
				}
			};;

			*) [ -d /sys/module/${mod} ] || { \
				insmod ${mod} || { \
					unload_qcawifi
					return 1
				}
			};;

		esac
	done
}


unload_qcawifi() {
#duanmingzhe added, unload lbd moudle
        /etc/init.d/lbd stop
#duanmingzhe delete, don't remove dirver
#	for mod in $(cat /etc/modules.d/33-qca-wifi* | sed '1!G;h;$!d'); do
#		[ -d /sys/module/${mod} ] && rmmod ${mod}
#	done
}


disable_qcawifi() {
	local device="$1"
	local parent

	find_qcawifi_phy "$device" || return 1
	config_get phy "$device" phy

	set_wifi_down "$device"

	include /lib/network
	cd /sys/class/net
	for dev in *; do
		[ -f /sys/class/net/${dev}/parent ] && { \
			local parent=$(cat /sys/class/net/${dev}/parent)
			[ -n "$parent" -a "$parent" = "$device" ] && { \
				hostapd_remove_vif "$dev"
				dhcp_snp_remove_vif "$dev"
				ifconfig "$dev" down
				unbridge "$dev"
			}
		}
	done

	for dev in *; do
		[ -f /sys/class/net/${dev}/parent ] && { \
			local parent=$(cat /sys/class/net/${dev}/parent)
			[ -n "$parent" -a "$parent" = "$device" ] && { \
				wlanconfig "$dev" destroy
			}
		}
	done

	nrvaps=$(find /sys/class/net/ -name 'ath*'|wc -l)
	[ ${nrvaps} -gt 0 ] || unload_qcawifi

	return 0
}

create_mgt_ssid() {
        #duanmingzhe: create management ssid
        wlanconfig ath99 destroy 2> /dev/null
        bit1=`getrevnumber`
        if [ "$bit1" = "0" ];then               
                #clusterid=`uci get cluster.cluster.cluster_id`
                ssid_prefix=`showsysinfo | grep Prefix | awk -F : '{print$2}' | awk -F " " '{print $1}'`
                mac_suffix=`showsysinfo | grep MAC | awk -F ":" '{print $6$7}'`
                mgt_ssid=$ssid_prefix"-"$mac_suffix
                echo 'create cluster manger ssid ' $mgt_ssid
                wlanconfig ath99 create wlanmode ap wlandev wifi0
                iwconfig ath99 essid $mgt_ssid
                #brctl addif br-wan ath99
		ubus call network.interface.wan add_device '{"name":"ath99","link-ext":"ture"}'
                ifconfig ath99 up
        fi

}

# Function: _global_settings(void)
# Description: It's not take immediate action, also called from 'power on', 'create new vap'
# Author: Yuyaowen
_global_settings() {
	local macfilter=
	config_get macfilter global macfilter
	[ ! "$macfilter" ] && return
	case "$macfilter" in
		allow)
			iwpriv "$ifname" maccmd 1
			;;
		deny)
			iwpriv "$ifname" maccmd 2
			;;
		*)
			[ -n "$maclist" ] && iwpriv "$ifname" maccmd 2
			;;
	esac

	iwpriv "$ifname" maccmd 3              
	set_han_maclist_start global
}

enable_qcawifi() {
	local device="$1"

	create_mgt_ssid	

	load_qcawifi || return 1

	find_qcawifi_phy "$device" || return 1
	config_get phy "$device" phy

	# If the country parameter is number (either hex or decimal), we
	# assume it's a regulatory domain - i.e. we use iwpriv setCountryID.
	# Else we assume it's a country code - i.e. we use iwpriv setCountry.
	config_get country "$device" country
	if [ `expr "$country" : '[0-9].*'` -ne 0 ]; then
		iwpriv "$phy" setCountryID "$country"
	elif [ -n "$country" ]; then
		iwpriv "$phy" setCountry "$country"
	fi

	config_get channel "$device" channel
	config_get vifs "$device" vifs
	config_get txpower "$device" txpower
	#modified by duanmingzhe & yuyaowen for auto channel & auto txpower
	#[ auto = "$channel" ] && channel=0
	if [ "auto" == "$channel" ]
	then
        	[ "$device" = "wifi0" ] && {
            		sed -i "s/wifi0_acs_enable=0/wifi0_acs_enable=1/g" /etc/ath/drm.conf
                        if [ -f /tmp/channel ] ;then
                                ret=`cat /tmp/channel | grep wifi0_channel | awk -F '=' '{print $2}'`
                                if [ "" != "$ret" ] ;then
                              		channel=$ret
                                else
                              		channel=1
                                fi
                        else
                                channel=1
                        fi
        	}
        	[ "$device" = "wifi1" ] && {
            		sed -i "s/wifi1_acs_enable=0/wifi1_acs_enable=1/g" /etc/ath/drm.conf
                        if [ -f /tmp/channel ] ;then
                                ret=`cat /tmp/channel | grep wifi1_channel | awk -F '=' '{print $2}'`
                                if [ "" != "$ret" ] ;then
                              		channel=$ret
                                else
                              		channel=36
                                fi
                        else
                                channel=36
                        fi
        	}
    	else
        	[ "$device" = "wifi0" ] && {
            		sed -i "s/wifi0_acs_enable=1/wifi0_acs_enable=0/g" /etc/ath/drm.conf
        	}
        	[ "$device" = "wifi1" ] && {
         	   	sed -i "s/wifi1_acs_enable=1/wifi1_acs_enable=0/g" /etc/ath/drm.conf
        	}
	fi

	if [ "auto" == "$txpower" ]
    then
            [ "$device" = "wifi0" ] && {
                    sed -i "s/wifi0_atp_enable=0/wifi0_atp_enable=1/g" /etc/ath/drm.conf
                    txpower=21
            }
            [ "$device" = "wifi1" ] && {
                    sed -i "s/wifi1_atp_enable=0/wifi1_atp_enable=1/g" /etc/ath/drm.conf
                    txpower=23
            }
    else
            [ "$device" = "wifi0" ] && {
                    sed -i "s/wifi0_atp_enable=1/wifi0_atp_enable=0/g" /etc/ath/drm.conf
            }
            [ "$device" = "wifi1" ] && {
                    sed -i "s/wifi1_atp_enable=1/wifi1_atp_enable=0/g" /etc/ath/drm.conf
            }
    fi
	

	config_get_bool antdiv "$device" diversity
	config_get antrx "$device" rxantenna
	config_get anttx "$device" txantenna
	config_get_bool softled "$device" softled
	config_get antenna "$device" antenna
	config_get distance "$device" distance

	[ -n "$antdiv" ] && echo "antdiv option not supported on this driver"
	[ -n "$antrx" ] && echo "antrx option not supported on this driver"
	[ -n "$anttx" ] && echo "anttx option not supported on this driver"
	[ -n "$softled" ] && echo "softled option not supported on this driver"
	[ -n "$antenna" ] && echo "antenna option not supported on this driver"
	[ -n "$distance" ] && echo "distance option not supported on this driver"

	# Advanced QCA wifi per-radio parameters configuration
	config_get txchainmask "$device" txchainmask
	[ -n "$txchainmask" ] && iwpriv "$phy" txchainmask "$txchainmask"

	config_get rxchainmask "$device" rxchainmask
	[ -n "$rxchainmask" ] && iwpriv "$phy" rxchainmask "$rxchainmask"

	config_get AMPDU "$device" AMPDU
	[ -n "$AMPDU" ] && iwpriv "$phy" AMPDU "$AMPDU"

	config_get ampdudensity "$device" ampdudensity
	[ -n "$ampdudensity" ] && iwpriv "$phy" ampdudensity "$ampdudensity"

	config_get_bool AMSDU "$device" AMSDU
	[ -n "$AMSDU" ] && iwpriv "$phy" AMSDU "$AMSDU"

	config_get AMPDULim "$device" AMPDULim
	[ -n "$AMPDULim" ] && iwpriv "$phy" AMPDULim "$AMPDULim"

	config_get AMPDUFrames "$device" AMPDUFrames
	[ -n "$AMPDUFrames" ] && iwpriv "$phy" AMPDUFrames "$AMPDUFrames"

	config_get AMPDURxBsize "$device" AMPDURxBsize
	[ -n "$AMPDURxBsize" ] && iwpriv "$phy" AMPDURxBsize "$AMPDURxBsize"

	config_get_bool bcnburst "$device" bcnburst 0
	[ "$bcnburst" -gt 0 ] && iwpriv "$phy" set_bcnburst "$bcnburst"

	config_get set_smart_antenna "$device" set_smart_antenna
	[ -n "$set_smart_antenna" ] && iwpriv "$phy" setSmartAntenna "$set_smart_antenna"

	config_get current_ant "$device" current_ant
	[ -n  "$current_ant" ] && iwpriv "$phy" current_ant "$current_ant"

	config_get default_ant "$device" default_ant
	[ -n "$default_ant" ] && iwpriv "$phy" default_ant "$default_ant"

	config_get ant_retrain "$device" ant_retrain
	[ -n "$ant_retrain" ] && iwpriv "$phy" ant_retrain "$ant_retrain"

	config_get retrain_interval "$device" retrain_interval
	[ -n "$retrain_interval" ] && iwpriv "$phy" ret_interval "$retrain_interval"

	config_get retrain_drop "$device" retrain_drop
	[ -n "$retrain_drop" ] && iwpriv "$phy" retrain_drop "$retrain_drop"

	config_get ant_train "$device" ant_train
	[ -n "$ant_train" ] && iwpriv "$phy" ant_train "$ant_train"

	config_get ant_trainmode "$device" ant_trainmode
	[ -n "$ant_trainmode" ] && iwpriv "$phy" ant_trainmode "$ant_trainmode"

	config_get ant_traintype "$device" ant_traintype
	[ -n "$ant_traintype" ] && iwpriv "$phy" ant_traintype "$ant_traintype"

	config_get ant_pktlen "$device" ant_pktlen
	[ -n "$ant_pktlen" ] && iwpriv "$phy" ant_pktlen "$ant_pktlen"

	config_get ant_numpkts "$device" ant_numpkts
	[ -n "$ant_numpkts" ] && iwpriv "$phy" ant_numpkts "$ant_numpkts"

	config_get ant_numitr "$device" ant_numitr
	[ -n "$ant_numitr" ] && iwpriv "$phy" ant_numitr "$ant_numitr"

	config_get ant_train_thres "$device" ant_train_thres
	[ -n "$ant_train_thres" ] && iwpriv "$phy" train_threshold "$ant_train_thres"

	config_get ant_train_min_thres "$device" ant_train_min_thres
	[ -n "$ant_train_min_thres" ] && iwpriv "$phy" train_threshold "$ant_train_min_thres"

	config_get ant_traffic_timer "$device" ant_traffic_timer
	[ -n "$ant_traffic_timer" ] && iwpriv "$phy" traffic_timer "$ant_traffic_timer"

	config_get dcs_enable "$device" dcs_enable
	[ -n "$dcs_enable" ] && iwpriv "$phy" dcs_enable "$dcs_enable"

	config_get dcs_coch_int "$device" dcs_coch_int
	[ -n "$dcs_coch_int" ] && iwpriv "$phy" set_dcs_coch_int "$dcs_coch_int"

	config_get dcs_errth "$device" dcs_errth
	[ -n "$dcs_errth" ] && iwpriv "$phy" set_dcs_errth "$dcs_errth"

	config_get dcs_phyerrth "$device" dcs_phyerrth
	[ -n "$dcs_phyerrth" ] && iwpriv "$phy" s_dcs_phyerrth "$dcs_phyerrth"

	config_get dcs_usermaxc "$device" dcs_usermaxc
	[ -n "$dcs_usermaxc" ] && iwpriv "$phy" set_dcs_usermaxc "$dcs_usermaxc"

	config_get dcs_debug "$device" dcs_debug
	[ -n "$dcs_debug" ] && iwpriv "$phy" set_dcs_debug "$dcs_debug"

	config_get set_ch_144 "$device" set_ch_144
	[ -n "$set_ch_144" ] && iwpriv "$phy" setCH144 "$set_ch_144"

	config_get_bool ani_enable "$device" ani_enable
	[ -n "$ani_enable" ] && iwpriv "$phy" ani_enable "$ani_enable"

	config_get_bool acs_bkscanen "$device" acs_bkscanen
	[ -n "$acs_bkscanen" ] && iwpriv "$phy" acs_bkscanen "$acs_bkscanen"

	config_get acs_scanintvl "$device" acs_scanintvl
	[ -n "$acs_scanintvl" ] && iwpriv "$phy" acs_scanintvl "$acs_scanintvl"

	config_get acs_rssivar "$device" acs_rssivar
	[ -n "$acs_rssivar" ] && iwpriv "$phy" acs_rssivar "$acs_rssivar"

	config_get acs_chloadvar "$device" acs_chloadvar
	[ -n "$acs_chloadvar" ] && iwpriv "$phy" acs_chloadvar "$acs_chloadvar"

	config_get acs_lmtobss "$device" acs_lmtobss
	[ -n "$acs_lmtobss" ] && iwpriv "$phy" acs_lmtobss "$acs_lmtobss"

	config_get acs_ctrlflags "$device" acs_ctrlflags
	[ -n "$acs_ctrlflags" ] && iwpriv "$phy" acs_ctrlflags "$acs_ctrlflags"

	config_get acs_dbgtrace "$device" acs_dbgtrace
	[ -n "$acs_dbgtrace" ] && iwpriv "$phy" acs_dbgtrace "$acs_dbgtrace"

	config_get_bool dscp_ovride "$device" dscp_ovride
	[ -n "$dscp_ovride" ] && iwpriv "$phy" set_dscp_ovride "$dscp_ovride"

	config_get reset_dscp_map "$device" reset_dscp_map
	[ -n "$reset_dscp_map" ] && iwpriv "$phy" reset_dscp_map "$reset_dscp_map"

	config_get dscp_tid_map "$device" dscp_tid_map
	[ -n "$dscp_tid_map" ] && iwpriv "$phy" s_dscp_tid_map $dscp_tid_map

	config_get_bool igmp_dscp_ovride "$device" igmp_dscp_ovride
	[ -n "$igmp_dscp_ovride" ] && iwpriv "$phy" sIgmpDscpOvrid "$igmp_dscp_ovride"

	config_get igmp_dscp_tid_map "$device" igmp_dscp_tid_map
	[ -n "$igmp_dscp_tid_map" ] && iwpriv "$phy" sIgmpDscpTidMap "$igmp_dscp_tid_map"

	config_get_bool hmmc_dscp_ovride "$device" hmmc_dscp_ovride
	[ -n "$hmmc_dscp_ovride" ] && iwpriv "$phy" sHmmcDscpOvrid "$hmmc_dscp_ovride"

	config_get hmmc_dscp_tid_map "$device" hmmc_dscp_tid_map
	[ -n "$hmmc_dscp_tid_map" ] && iwpriv "$phy" sHmmcDscpTidMap "$hmmc_dscp_tid_map"

	config_get_bool blk_report_fld "$device" blk_report_fld
	[ -n "$blk_report_fld" ] && iwpriv "$phy" setBlkReportFld "$blk_report_fld"

	config_get_bool drop_sta_query "$device" drop_sta_query
	[ -n "$drop_sta_query" ] && iwpriv "$phy" setDropSTAQuery "$drop_sta_query"

	config_get_bool burst "$device" burst
	[ -n "$burst" ] && iwpriv "$phy" burst "$burst"

	config_get burst_dur "$device" burst_dur
	[ -n "$burst_dur" ] && iwpriv "$phy" burst_dur "$burst_dur"

	config_get TXPowLim2G "$device" TXPowLim2G
	[ -n "$TXPowLim2G" ] && iwpriv "$phy" TXPowLim2G "$TXPowLim2G"

	config_get TXPowLim5G "$device" TXPowLim5G
	[ -n "$TXPowLim5G" ] && iwpriv "$phy" TXPowLim5G "$TXPowLim5G"

	config_get_bool enable_ol_stats "$device" enable_ol_stats
	[ -n "$enable_ol_stats" ] && iwpriv "$phy" enable_ol_stats "$enable_ol_stats"

	config_get_bool set_fw_recovery "$device" set_fw_recovery
	[ -n "$set_fw_recovery" ] && iwpriv "$phy" set_fw_recovery "$set_fw_recovery"

	config_get_bool allowpromisc "$device" allowpromisc
	[ -n "$allowpromisc" ] && iwpriv "$phy" allowpromisc "$allowpromisc"

	config_get set_sa_param "$device" set_sa_param
	[ -n "$set_sa_param" ] && iwpriv "$phy" set_sa_param $set_sa_param

	config_get_bool aldstats "$device" aldstats
	[ -n "$aldstats" ] && iwpriv "$phy" aldstats "$aldstats"

	config_get setHwaddr "$device" setHwaddr
	[ -n "$setHwaddr" ] && iwpriv "$phy" setHwaddr "$setHwaddr"

	config_get mcast_echo "$device" mcast_echo
	[ -n "$mcast_echo" ] && iwpriv "$phy" mcast_echo "${mcast_echo}"

	config_get staDFSEn "$device" staDFSEn
	[ -n "$staDFSEn" ] && iwpriv "$phy" staDFSEn "${staDFSEn}"


	for vif in $vifs; do
		local vif_txpower= nosbeacon= wlanaddr=""

		config_get enable "$vif" enable
		if [ "$enable" = "0" ]; then
			continue;
		fi

		radio_idx=${device#wifi}
		existed_ifnames=`iwconfig 2>/dev/null |egrep -o "ath$radio_idx." |sort`
		v_ifname=
		if_idx=1
		for exist_ifname in $existed_ifnames
		do
			v_ifname="ath${radio_idx}$if_idx"
			[ "$v_ifname" = "$exist_ifname" ] && if_idx=`expr $if_idx + 1`
		done
		v_ifname="ath${radio_idx}$if_idx"
		vifname=$v_ifname
		config_get ifname "$vif" ifname
		config_set "$vif" ifname "${ifname:=$vifname}"
		config_get mode "$vif" mode

		case "$mode" in
			sta)
				config_get_bool nosbeacon "$device" nosbeacon
				config_get qwrap_enable "$device" qwrap_enable 0
				[ $qwrap_enable -gt 0 ] && wlanaddr="00:00:00:00:00:00"
				;;
			adhoc)
				config_get_bool nosbeacon "$vif" sw_merge 1
				;;
		esac

		[ "$nosbeacon" = 1 ] || nosbeacon=""
		[ -n "${DEBUG}" ] && echo wlanconfig "$ifname" create wlandev "$phy" wlanmode "$mode" ${wlanaddr:+wlanaddr "$wlanaddr"} ${nosbeacon:+nosbeacon}
		ifname=$(/usr/sbin/wlanconfig "$ifname" create wlandev "$phy" wlanmode "$mode" ${wlanaddr:+wlanaddr "$wlanaddr"} ${nosbeacon:+nosbeacon})
		[ $? -ne 0 ] && {
			echo "enable_qcawifi($device): Failed to set up $mode vif $ifname" >&2
			continue
		}
		config_set "$vif" ifname "$ifname"

		config_get hwmode "$device" hwmode auto
		config_get htmode "$device" htmode auto

#		# For fix hwmode. Yuyaowen added.
#		if [ "$device" = "wifi1" ]; then
#			[ "$hwmode" = "auto" ] && hwmode=11ac
#			[ "$htmode" = "auto" ] && htmode=HT20
#		fi
#		# End for fix hwmode. Yuyaowen added.

		pureg=0
		case "$hwmode:$htmode" in
		# The parsing stops at the first match so we need to make sure
		# these are in the right orders (most generic at the end)
			*ng:HT20) hwmode=11NGHT20;;
			*ng:HT40-) hwmode=11NGHT40MINUS;;
			*ng:HT40+) hwmode=11NGHT40PLUS;;
			*ng:HT40) hwmode=11NGHT40;;
			*ng:*) hwmode=11NGHT20;;
			*na:HT20) hwmode=11NAHT20;;
			*na:HT40-) hwmode=11NAHT40MINUS;;
			*na:HT40+) hwmode=11NAHT40PLUS;;
			*na:HT40) hwmode=11NAHT40;;
			*na:*) hwmode=11NAHT40;;
			*ac:HT20) hwmode=11ACVHT20;;
			*ac:HT40+) hwmode=11ACVHT40PLUS;;
			*ac:HT40-) hwmode=11ACVHT40MINUS;;
			*ac:HT40) hwmode=11ACVHT40;;
			*ac:HT80) hwmode=11ACVHT80;;
			*ac:*) hwmode=11ACVHT80;;
			*b:*) hwmode=11B;;
			*bg:*) hwmode=11G;;
			*g:*) hwmode=11G; pureg=1;;
			*a:*) hwmode=11A;;
			*) hwmode=AUTO;;
		esac
		iwpriv "$ifname" mode "$hwmode"
		[ $pureg -gt 0 ] && iwpriv "$ifname" pureg "$pureg"

		config_get puren "$vif" puren
		[ -n "$puren" ] && iwpriv "$ifname" puren "$puren"

		iwconfig "$ifname" channel "$channel" >/dev/null 2>/dev/null 

		config_get_bool hidden "$vif" hidden 0
		iwpriv "$ifname" hide_ssid "$hidden"

		config_get_bool shortgi "$vif" shortgi 1
		[ -n "$shortgi" ] && iwpriv "$ifname" shortgi "${shortgi}"

		config_get_bool disablecoext "$vif" disablecoext
		[ -n "$disablecoext" ] && iwpriv "$ifname" disablecoext "${disablecoext}"

		config_get chwidth "$vif" chwidth
		[ -n "$chwidth" ] && iwpriv "$ifname" chwidth "${chwidth}"

		config_get wds "$vif" wds
		case "$wds" in
			1|on|enabled) wds=1;;
			*) wds=0;;
		esac
		iwpriv "$ifname" wds "$wds" >/dev/null 2>&1

		config_get TxBFCTL "$vif" TxBFCTL
		[ -n "$TxBFCTL" ] && iwpriv "$ifname" TxBFCTL "$TxBFCTL"

		config_get bintval "$vif" bintval
		[ -n "$bintval" ] && iwpriv "$ifname" bintval "$bintval"

		config_get_bool countryie "$vif" countryie
		[ -n "$countryie" ] && iwpriv "$ifname" countryie "$countryie"


		case "$mode" in
			sta|adhoc)
				config_get addr "$vif" bssid
				[ -z "$addr" ] || { 
					iwconfig "$ifname" ap "$addr"
				}
			;;
		esac

		config_get_bool uapsd "$vif" uapsd
		[ -n "$uapsd" ] && iwpriv "$ifname" uapsd "$uapsd"

		config_get mcast_rate "$vif" mcast_rate
		[ -n "$mcast_rate" ] && iwpriv "$ifname" mcast_rate "${mcast_rate%%.*}"

		config_get powersave "$vif" powersave
		[ -n "$powersave" ] && iwpriv "$ifname" powersave "${powersave}"

		config_get_bool ant_ps_on "$vif" ant_ps_on
		[ -n "$ant_ps_on" ] && iwpriv "$ifname" ant_ps_on "${ant_ps_on}"

		config_get ps_timeout "$vif" ps_timeout
		[ -n "$ps_timeout" ] && iwpriv "$ifname" ps_timeout "${ps_timeout}"

		config_get_bool mcastenhance "$vif" mcastenhance
		[ -n "$mcastenhance" ] && iwpriv "$ifname" mcastenhance "${mcastenhance}"

		config_get metimer "$vif" metimer
		[ -n "$metimer" ] && iwpriv "$ifname" metimer "${metimer}"

		config_get metimeout "$vif" metimeout
		[ -n "$metimeout" ] && iwpriv "$ifname" metimeout "${metimeout}"

		config_get_bool medropmcast "$vif" medropmcast
		[ -n "$medropmcast" ] && iwpriv "$ifname" medropmcast "${medropmcast}"

		config_get me_adddeny "$vif" me_adddeny
		[ -n "$me_adddeny" ] && iwpriv "$ifname" me_adddeny ${me_adddeny}

		#support independent repeater mode
		config_get vap_ind "$vif" vap_ind
		[ -n "$vap_ind" ] && iwpriv "$ifname" vap_ind "${vap_ind}"

		#support extender ap & STA
		config_get extap "$vif" extap
		[ -n "$extap" ] && iwpriv "$ifname" extap "${extap}"

		config_get scanband "$vif" scanband
		[ -n "$scanband" ] && iwpriv "$ifname" scanband "${scanband}"

		config_get periodicScan "$vif" periodicScan
		[ -n "$periodicScan" ] && iwpriv "$ifname" periodicScan "${periodicScan}"

		config_get frag "$vif" frag
		[ -n "$frag" ] && iwconfig "$ifname" frag "${frag%%.*}"

		config_get rts "$vif" rts
		[ -n "$rts" ] && iwconfig "$ifname" rts "${rts%%.*}"

		config_get cwmin "$vif" cwmin
		[ -n "$cwmin" ] && iwpriv "$ifname" cwmin ${cwmin}

		config_get cwmax "$vif" cwmax
		[ -n "$cwmax" ] && iwpriv "$ifname" cwmax ${cwmax}

		config_get aifs "$vif" aifs
		[ -n "$aifs" ] && iwpriv "$ifname" aifs ${aifs}

		config_get txoplimit "$vif" txoplimit
		[ -n "$txoplimit" ] && iwpriv "$ifname" txoplimit ${txoplimit}

		config_get noackpolicy "$vif" noackpolicy
		[ -n "$noackpolicy" ] && iwpriv "$ifname" noackpolicy ${noackpolicy}

		config_get_bool wmm "$vif" wmm
		[ -n "$wmm" ] && iwpriv "$ifname" wmm "$wmm"

		config_get_bool doth "$vif" doth
		[ -n "$doth" ] && iwpriv "$ifname" doth "$doth"

		config_get doth_chanswitch "$vif" doth_chanswitch
		[ -n "$doth_chanswitch" ] && iwpriv "$ifname" doth_chanswitch ${doth_chanswitch}

		config_get quiet "$vif" quiet
		[ -n "$quiet" ] && iwpriv "$ifname" quiet "$quiet"

		config_get mfptest "$vif" mfptest
		[ -n "$mfptest" ] && iwpriv "$ifname" mfptest "$mfptest"

		config_get dtim_period "$vif" dtim_period
		[ -n "$dtim_period" ] && iwpriv "$ifname" dtim_period "$dtim_period"

		config_get noedgech "$vif" noedgech
		[ -n "$noedgech" ] && iwpriv "$ifname" noedgech "$noedgech"

		config_get ps_on_time "$vif" ps_on_time
		[ -n "$ps_on_time" ] && iwpriv "$ifname" ps_on_time "$ps_on_time"

		config_get inact "$vif" inact
		[ -n "$inact" ] && iwpriv "$ifname" inact "$inact"

		config_get wnm "$vif" wnm
		[ -n "$wnm" ] && iwpriv "$ifname" wnm "$wnm"

		config_get ampdu "$vif" ampdu
		[ -n "$ampdu" ] && iwpriv "$ifname" ampdu "$ampdu"

		config_get amsdu "$vif" amsdu
		[ -n "$amsdu" ] && iwpriv "$ifname" amsdu "$amsdu"

		config_get maxampdu "$vif" maxampdu
		[ -n "$maxampdu" ] && iwpriv "$ifname" maxampdu "$maxampdu"

		config_get vhtmaxampdu "$vif" vhtmaxampdu
		[ -n "$vhtmaxampdu" ] && iwpriv "$ifname" vhtmaxampdu "$vhtmaxampdu"

		config_get setaddbaoper "$vif" setaddbaoper
		[ -n "$setaddbaoper" ] && iwpriv "$ifname" setaddbaoper "$setaddbaoper"

		config_get addbaresp "$vif" addbaresp
		[ -n "$addbaresp" ] && iwpriv "$ifname" $addbaresp

		config_get addba "$vif" addba
		[ -n "$addba" ] && iwpriv "$ifname" addba $addba

		config_get delba "$vif" delba
		[ -n "$delba" ] && iwpriv "$ifname" delba $delba

# Yuyaowen removed, the driver is not implemented this ioctl.
#		config_get_bool stafwd "$vif" stafwd 0
#		[ -n "$stafwd" ] && iwpriv "$ifname" stafwd "$stafwd"
# Yuyaowen removed end, the driver is not implemented this ioctl.

#		config_get maclist "$vif" maclist
#		[ -n "$maclist" ] && {
#			# flush MAC list
#			iwpriv "$ifname" maccmd 3
#			for mac in $maclist; do
#				iwpriv "$ifname" addmac "$mac"
#			done
#		}

		config_get macfilter "$vif" macfilter
		case "$macfilter" in
			allow)
				iwpriv "$ifname" maccmd 1
			;;
			deny)
				iwpriv "$ifname" maccmd 2
			;;
			*)
				# default deny policy if mac list exists
				[ -n "$maclist" ] && iwpriv "$ifname" maccmd 2
			;;
		esac

		config_get nss "$vif" nss
		[ -n "$nss" ] && iwpriv "$ifname" nss "$nss"

		config_get vht_mcsmap "$vif" vht_mcsmap
		[ -n "$vht_mcsmap" ] && iwpriv "$ifname" vht_mcsmap "$vht_mcsmap"

		config_get chwidth "$vif" chwidth
		[ -n "$chwidth" ] && iwpriv "$ifname" chwidth "$chwidth"

		config_get chbwmode "$vif" chbwmode
		[ -n "$chbwmode" ] && iwpriv "$ifname" chbwmode "$chbwmode"

		config_get ldpc "$vif" ldpc
		[ -n "$ldpc" ] && iwpriv "$ifname" ldpc "$ldpc"

		config_get rx_stbc "$vif" rx_stbc
		[ -n "$rx_stbc" ] && iwpriv "$ifname" rx_stbc "$rx_stbc"

		config_get tx_stbc "$vif" tx_stbc
		[ -n "$tx_stbc" ] && iwpriv "$ifname" tx_stbc "$tx_stbc"

		config_get cca_thresh "$vif" cca_thresh
		[ -n "$cca_thresh" ] && iwpriv "$ifname" cca_thresh "$cca_thresh"

		config_get set11NRetries "$vif" set11NRetries
		[ -n "$set11NRetries" ] && iwpriv "$ifname" set11NRetries "$set11NRetries"

		config_get chanbw "$vif" chanbw
		[ -n "$chanbw" ] && iwpriv "$ifname" chanbw "$chanbw"

		config_get maxsta "$vif" maxsta
		[ -n "$maxsta" ] && iwpriv "$ifname" maxsta "$maxsta"

		config_get sko_max_xretries "$vif" sko_max_xretries
		[ -n "$sko_max_xretries" ] && iwpriv "$ifname" sko "$sko_max_xretries"

		config_get extprotmode "$vif" extprotmode
		[ -n "$extprotmode" ] && iwpriv "$ifname" extprotmode "$extprotmode"

		config_get extprotspac "$vif" extprotspac
		[ -n "$extprotspac" ] && iwpriv "$ifname" extprotspac "$extprotspac"

		config_get_bool cwmenable "$vif" cwmenable
		[ -n "$cwmenable" ] && iwpriv "$ifname" cwmenable "$cwmenable"

		config_get_bool protmode "$vif" protmode
		[ -n "$protmode" ] && iwpriv "$ifname" protmode "$protmode"

		config_get enablertscts "$vif" enablertscts
		[ -n "$enablertscts" ] && iwpriv "$ifname" enablertscts "$enablertscts"

		config_get txcorrection "$vif" txcorrection
		[ -n "$txcorrection" ] && iwpriv "$ifname" txcorrection "$txcorrection"

		config_get rxcorrection "$vif" rxcorrection
		[ -n "$rxcorrection" ] && iwpriv "$ifname" rxcorrection "$rxcorrection"

		config_get ssid "$vif" ssid
                [ -n "$ssid" ] && {
                        iwconfig "$ifname" essid on
                        iwconfig "$ifname" essid "$ssid"
                }

		config_get txqueuelen "$vif" txqueuelen
		[ -n "$txqueuelen" ] && ifconfig "$ifname" txqueuelen "$txqueuelen"

                config_load network
                net_cfg="$(find_net_config "$vif")"

                config_get mtu $net_cfg mtu

                [ -n "$mtu" ] && {
                        config_set "$vif" mtu $mtu
                        ifconfig "$ifname" mtu $mtu
		}

		config_get tdls "$vif" tdls
		[ -n "$tdls" ] && iwpriv "$ifname" tdls "$tdls"

		config_get set_tdls_rmac "$vif" set_tdls_rmac
		[ -n "$set_tdls_rmac" ] && iwpriv "$ifname" set_tdls_rmac "$set_tdls_rmac"

		config_get tdls_qosnull "$vif" tdls_qosnull
		[ -n "$tdls_qosnull" ] && iwpriv "$ifname" tdls_qosnull "$tdls_qosnull"

		config_get tdls_uapsd "$vif" tdls_uapsd
		[ -n "$tdls_uapsd" ] && iwpriv "$ifname" tdls_uapsd "$tdls_uapsd"

		config_get tdls_set_rcpi "$vif" tdls_set_rcpi
		[ -n "$tdls_set_rcpi" ] && iwpriv "$ifname" set_rcpi "$tdls_set_rcpi"

		config_get tdls_set_rcpi_hi "$vif" tdls_set_rcpi_hi
		[ -n "$tdls_set_rcpi_hi" ] && iwpriv "$ifname" set_rcpihi "$tdls_set_rcpi_hi"

		config_get tdls_set_rcpi_lo "$vif" tdls_set_rcpi_lo
		[ -n "$tdls_set_rcpi_lo" ] && iwpriv "$ifname" set_rcpilo "$tdls_set_rcpi_lo"

		config_get tdls_set_rcpi_margin "$vif" tdls_set_rcpi_margin
		[ -n "$tdls_set_rcpi_margin" ] && iwpriv "$ifname" set_rcpimargin "$tdls_set_rcpi_margin"

		config_get tdls_dtoken "$vif" tdls_dtoken
		[ -n "$tdls_dtoken" ] && iwpriv "$ifname" tdls_dtoken "$tdls_dtoken"

		config_get do_tdls_dc_req "$vif" do_tdls_dc_req
		[ -n "$do_tdls_dc_req" ] && iwpriv "$ifname" do_tdls_dc_req "$do_tdls_dc_req"

		config_get tdls_auto "$vif" tdls_auto
		[ -n "$tdls_auto" ] && iwpriv "$ifname" tdls_auto "$tdls_auto"

		config_get tdls_off_timeout "$vif" tdls_off_timeout
		[ -n "$tdls_off_timeout" ] && iwpriv "$ifname" off_timeout "$tdls_off_timeout"

		config_get tdls_tdb_timeout "$vif" tdls_tdb_timeout
		[ -n "$tdls_tdb_timeout" ] && iwpriv "$ifname" tdb_timeout "$tdls_tdb_timeout"

		config_get tdls_weak_timeout "$vif" tdls_weak_timeout
		[ -n "$tdls_weak_timeout" ] && iwpriv "$ifname" weak_timeout "$tdls_weak_timeout"

		config_get tdls_margin "$vif" tdls_margin
		[ -n "$tdls_margin" ] && iwpriv "$ifname" tdls_margin "$tdls_margin"

		config_get tdls_rssi_ub "$vif" tdls_rssi_ub
		[ -n "$tdls_rssi_ub" ] && iwpriv "$ifname" tdls_rssi_ub "$tdls_rssi_ub"

		config_get tdls_rssi_lb "$vif" tdls_rssi_lb
		[ -n "$tdls_rssi_lb" ] && iwpriv "$ifname" tdls_rssi_lb "$tdls_rssi_lb"

		config_get tdls_path_sel "$vif" tdls_path_sel
		[ -n "$tdls_path_sel" ] && iwpriv "$ifname" tdls_pathSel "$tdls_path_sel"

		config_get tdls_rssi_offset "$vif" tdls_rssi_offset
		[ -n "$tdls_rssi_offset" ] && iwpriv "$ifname" tdls_rssi_o "$tdls_rssi_offset"

		config_get tdls_path_sel_period "$vif" tdls_path_sel_period
		[ -n "$tdls_path_sel_period" ] && iwpriv "$ifname" tdls_pathSel_p "$tdls_path_sel_period"

		config_get tdlsmacaddr1 "$vif" tdlsmacaddr1
		[ -n "$tdlsmacaddr1" ] && iwpriv "$ifname" tdlsmacaddr1 "$tdlsmacaddr1"

		config_get tdlsmacaddr2 "$vif" tdlsmacaddr2
		[ -n "$tdlsmacaddr2" ] && iwpriv "$ifname" tdlsmacaddr2 "$tdlsmacaddr2"

		config_get tdlsaction "$vif" tdlsaction
		[ -n "$tdlsaction" ] && iwpriv "$ifname" tdlsaction "$tdlsaction"

		config_get tdlsoffchan "$vif" tdlsoffchan
		[ -n "$tdlsoffchan" ] && iwpriv "$ifname" tdlsoffchan "$tdlsoffchan"

		config_get tdlsswitchtime "$vif" tdlsswitchtime
		[ -n "$tdlsswitchtime" ] && iwpriv "$ifname" tdlsswitchtime "$tdlsswitchtime"

		config_get tdlstimeout "$vif" tdlstimeout
		[ -n "$tdlstimeout" ] && iwpriv "$ifname" tdlstimeout "$tdlstimeout"

		config_get tdlsecchnoffst "$vif" tdlsecchnoffst
		[ -n "$tdlsecchnoffst" ] && iwpriv "$ifname" tdlsecchnoffst "$tdlsecchnoffst"

		config_get tdlsoffchnmode "$vif" tdlsoffchnmode
		[ -n "$tdlsoffchnmode" ] && iwpriv "$ifname" tdlsoffchnmode "$tdlsoffchnmode"

		config_get_bool blockdfschan "$vif" blockdfschan
		[ -n "$blockdfschan" ] && iwpriv "$ifname" blockdfschan "$blockdfschan"

		config_get dbgLVL "$vif" dbgLVL
		[ -n "$dbgLVL" ] && iwpriv "$ifname" dbgLVL "$dbgLVL"

		config_get acsmindwell "$vif" acsmindwell
		[ -n "$acsmindwell" ] && iwpriv "$ifname" acsmindwell "$acsmindwell"

		config_get acsmaxdwell "$vif" acsmaxdwell
		[ -n "$acsmaxdwell" ] && iwpriv "$ifname" acsmaxdwell "$acsmaxdwell"

		config_get acsreport "$vif" acsreport
		[ -n "$acsreport" ] && iwpriv "$ifname" acsreport "$acsreport"

		config_get ch_hop_en "$vif" ch_hop_en
		[ -n "$ch_hop_en" ] && iwpriv "$ifname" ch_hop_en "$ch_hop_en"

		config_get ch_long_dur "$vif" ch_long_dur
		[ -n "$ch_long_dur" ] && iwpriv "$ifname" ch_long_dur "$ch_long_dur"

		config_get ch_nhop_dur "$vif" ch_nhop_dur
		[ -n "$ch_nhop_dur" ] && iwpriv "$ifname" ch_nhop_dur "$ch_nhop_dur"

		config_get ch_cntwn_dur "$vif" ch_cntwn_dur
		[ -n "$ch_cntwn_dur" ] && iwpriv "$ifname" ch_cntwn_dur "$ch_cntwn_dur"

		config_get ch_noise_th "$vif" ch_noise_th
		[ -n "$ch_noise_th" ] && iwpriv "$ifname" ch_noise_th "$ch_noise_th"

		config_get ch_cnt_th "$vif" ch_cnt_th
		[ -n "$ch_cnt_th" ] && iwpriv "$ifname" ch_cnt_th "$ch_cnt_th"

		config_get_bool scanchevent "$vif" scanchevent
		[ -n "$scanchevent" ] && iwpriv "$ifname" scanchevent "$scanchevent"

		config_get_bool send_add_ies "$vif" send_add_ies
		[ -n "$send_add_ies" ] && iwpriv "$ifname" send_add_ies "$send_add_ies"

		config_get_bool ext_ifu_acs "$vif" ext_ifu_acs
		[ -n "$ext_ifu_acs" ] && iwpriv "$ifname" ext_ifu_acs "$ext_ifu_acs"

		config_get_bool rrm "$vif" rrm
		[ -n "$rrm" ] && iwpriv "$ifname" rrm "$rrm"

		config_get_bool rrmslwin "$vif" rrmslwin
		[ -n "$rrmslwin" ] && iwpriv "$ifname" rrmslwin "$rrmslwin"

		config_get_bool rrmstats "$vif" rrmsstats
		[ -n "$rrmstats" ] && iwpriv "$ifname" rrmstats "$rrmstats"

		config_get rrmdbg "$vif" rrmdbg
		[ -n "$rrmdbg" ] && iwpriv "$ifname" rrmdbg "$rrmdbg"

		config_get acparams "$vif" acparams
		[ -n "$acparams" ] && iwpriv "$ifname" acparams $acparams

		config_get setwmmparams "$vif" setwmmparams
		[ -n "$setwmmparams" ] && iwpriv "$ifname" setwmmparams $setwmmparams

		config_get_bool qbssload "$vif" qbssload
		[ -n "$qbssload" ] && iwpriv "$ifname" qbssload "$qbssload"

		config_get_bool proxyarp "$vif" proxyarp
		[ -n "$proxyarp" ] && iwpriv "$ifname" proxyarp "$proxyarp"

		config_get_bool dgaf_disable "$vif" dgaf_disable
		[ -n "$dgaf_disable" ] && iwpriv "$ifname" dgaf_disable "$dgaf_disable"

		config_get setibssdfsparam "$vif" setibssdfsparam
		[ -n "$setibssdfsparam" ] && iwpriv "$ifname" setibssdfsparam "$setibssdfsparam"

		config_get startibssrssimon "$vif" startibssrssimon
		[ -n "$startibssrssimon" ] && iwpriv "$ifname" strtibssrssimon "$startibssrssimon"

		config_get setibssrssihyst "$vif" setibssrssihyst
		[ -n "$setibssrssihyst" ] && iwpriv "$ifname" setibssrssihyst "$setibssrssihyst"

		config_get noIBSSCreate "$vif" noIBSSCreate
		[ -n "$noIBSSCreate" ] && iwpriv "$ifname" noIBSSCreate "$noIBSSCreate"

		config_get setibssrssiclass "$vif" setibssrssiclass
		[ -n "$setibssrssiclass" ] && iwpriv "$ifname" s_ibssrssiclass $setibssrssiclass

		config_get offchan_tx_test "$vif" offchan_tx_test
		[ -n "$offchan_tx_test" ] && iwpriv "$ifname" offchan_tx_test $offchan_tx_test

		handle_vow_dbg_cfg() {
			local value="$1"
			iwpriv "$ifname" vow_dbg_cfg $value
		}

		config_list_foreach "$vif" vow_dbg_cfg handle_vow_dbg_cfg

		config_get_bool vow_dbg "$vif" vow_dbg
		[ -n "$vow_dbg" ] && iwpriv "$ifname" vow_dbg "$vow_dbg"

		handle_set_max_rate() {
			local value="$1"
			wlanconfig "$ifname" set_max_rate $value
		}
		config_list_foreach "$vif" set_max_rate handle_set_max_rate

		config_get dscp_tid_map "$vif" dscp_tid_map
		[ -n "$dscp_tid_map" ] && iwpriv "$ifname" set_dscp_tidmap $dscp_tid_map

		config_get athnewind "$vif" athnewind
		[ -n "$athnewind" ] && iwpriv "$ifname" athnewind "$athnewind"
		#Added by zhaoyang for bg-scan
                config_get vif_monitor "$vif" vif_monitor
#                [ -n "$vif_monitor" ] && iwpriv "$ifname" vif_monitor "$vif_monitor"
		# For 8 WLan. Yuyaowen modified.
		if [ -n "$vif_monitor" ]; then
			iwpriv "$ifname" vif_monitor "$vif_monitor"
			local dev=
			local wifi_index="1"
			config_get dev "$vif" device
			[ "$dev" = "wifi0" ] && wifi_index="0"
			cluster-cfg set "bg-s.bs.scan_iface$wifi_index=$ifname"
			
			cluster-cfg -c "/etc/cfm/config/config-pub" set "bg-s.bs.scan_iface$wifi_index=$ifname"
			cluster-cfg -c "/etc/cfm/config/config-pub" commit "bg-s"
			bg-s "-x" "scan-iface$wifi_index=$ifname"
		fi
		# End for 8 WLan. Yuyaowen modified.
		config_get_bool commitatf "$vif" commitatf
		[ -n "$commitatf" ] && iwpriv "$ifname" commitatf "${commitatf}"

		config_get perunit "$vif" perunit
		[ -n "$perunit" ] && iwpriv "$ifname" perunit "${perunit}"

		config_get enh_ind "$vif" enh_ind
		[ -n "$enh_ind" ] && iwpriv "$ifname" enh-ind "$enh_ind"

		config_get osen "$vif" osen
		[ -n "$osen" ] && iwpriv "$ifname" osen "$osen"
	done

	for vif in $vifs; do
		config_get enable "$vif" enable "1"
		[ "$enable" = "0" ] && continue

		_global_settings

		local start_hostapd= start_wapid=

		config_get ifname "$vif" ifname
		config_get enc "$vif" encryption "none"

		#ifconfig "$ifname" up

		case "$enc" in
			none)
				start_hostapd=1
				# If we're in open mode and want to use WPS, we
				# must start hostapd
				config_get_bool wps_pbc "$vif" wps_pbc 0
				config_get config_methods "$vif" wps_config
				[ "$wps_pbc" -gt 0 ] && append config_methods push_button
				[ -n "$config_methods" ] && start_hostapd=1
			;;
			wep*)
				case "$enc" in
					*mixed*)  iwpriv "$ifname" authmode 4;;
					*shared*) iwpriv "$ifname" authmode 2;;
					*)        iwpriv "$ifname" authmode 1;;
				esac
				for idx in 1 2 3 4; do
					config_get key "$vif" "key${idx}"
					iwconfig "$ifname" enc "[$idx]" "${key:-off}"
				done
				config_get key "$vif" key
				key="${key:-1}"
				case "$key" in
					[1234]) iwconfig "$ifname" enc "[$key]";;
					*) iwconfig "$ifname" enc "$key";;
				esac
			;;
			mixed*|psk*|wpa*|8021x)
				start_hostapd=1
				config_get key "$vif" key
			;;
			wapi*)
				start_wapid=1
				config_get key "$vif" key
			;;
		esac

		config_get set11NRates "$vif" set11NRates
		[ -n "$set11NRates" ] && iwpriv "$ifname" set11NRates "$set11NRates"

		# 256 QAM capability needs to be parsed first, since
		# vhtmcs enables/disable rate indices 8, 9 for 2G
		# only if vht_11ng is set or not
		config_get_bool vht_11ng "$vif" vht_11ng
		[ -n "$vht_11ng" ] && iwpriv "$ifname" vht_11ng "$vht_11ng"

		config_get vhtmcs "$vif" vhtmcs
		[ -n "$vhtmcs" ] && iwpriv "$ifname" vhtmcs "$vhtmcs"

		#support nawds
		config_get nawds_mode "$vif" nawds_mode
		[ -n "$nawds_mode" ] && wlanconfig "$ifname" nawds mode "${nawds_mode}"

		handle_nawds() {
			local value="$1"
			wlanconfig "$ifname" nawds add-repeater $value
		}
		config_list_foreach "$vif" nawds_add_repeater handle_nawds

		handle_hmwds() {
			local value="$1"
			wlanconfig "$ifname" hmwds add_addr $value
		}
		config_list_foreach "$vif" hmwds_add_addr handle_hmwds

		config_get nawds_override "$vif" nawds_override
		[ -n "$nawds_override" ] && wlanconfig "$ifname" nawds override "${nawds_override}"

		config_get nawds_defcaps "$vif" nawds_defcaps
		[ -n "$nawds_defcaps" ] && wlanconfig "$ifname" nawds defcaps "${nawds_defcaps}"

		handle_hmmc_add() {
			local value="$1"
			wlanconfig "$ifname" hmmc add $value
		}
		config_list_foreach "$vif" hmmc_add handle_hmmc_add

		config_get mode "$vif" mode

		config_get_bool ap_isolation_enabled $device ap_isolation_enabled 0
		config_get_bool isolate "$vif" isolate 0

		if [ $ap_isolation_enabled -ne 0 ]; then
			[ "$mode" = "wrap" ] && isolate=1
		fi

		local net_cfg bridge
		net_cfg="$(find_net_config "$vif")"
		[ -z "$net_cfg" -o "$isolate" = 1 -a "$mode" = "wrap" ] || {
			bridge="$(bridge_interface "$net_cfg")"
			config_set "$vif" bridge "$bridge"
			start_net "$ifname" "$net_cfg"
		}

		set_wifi_up "$vif" "$ifname"

		# TXPower settings only work if device is up already
		# while atheros hardware theoretically is capable of per-vif (even per-packet) txpower
		# adjustment it does not work with the current atheros hal/madwifi driver

		config_get vif_txpower "$vif" txpower
		# use vif_txpower (from wifi-iface) instead of txpower (from wifi-device) if
		# the latter doesn't exist
		txpower="${txpower:-$vif_txpower}"
		[ -z "$txpower" ] || iwconfig "$ifname" txpower "${txpower%%.*}"

		case "$mode" in
			ap|wrap)

				iwpriv "$ifname" ap_bridge "$((isolate^1))"
				
				[ "$mode" = "ap" ] && iwpriv "$ifname" ap_bridge $isolate #pengdecai for phone roaming

				config_get_bool l2tif "$vif" l2tif
				[ -n "$l2tif" ] && iwpriv "$ifname" l2tif "$l2tif"

				if [ -n "$start_wapid" ]; then
					wapid_setup_vif "$vif" || {
						echo "enable_qcawifi($device): Failed to set up wapid for interface $ifname" >&2
						ifconfig "$ifname" down
						wlanconfig "$ifname" destroy
						continue
					}
				fi

				if [ -n "$start_hostapd" ] && eval "type hostapd_setup_vif" 2>/dev/null >/dev/null; then

					dhcp_snp_setup_vif "$vif"

					hostapd_setup_vif "$ifname" "$vif" atheros no_nconfig || {
						echo "enable_qcawifi($device): Failed to set up hostapd for interface $ifname" >&2
						# make sure this wifi interface won't accidentally stay open without encryption
						ifconfig "$ifname" down
						wlanconfig "$ifname" destroy
						continue
					}
				fi
			;;
			wds|sta)
				if eval "type wpa_supplicant_setup_vif" 2>/dev/null >/dev/null; then

					wpa_supplicant_setup_vif "$vif" athr || {
						echo "enable_qcawifi($device): Failed to set up wpa_supplicant for interface $ifname" >&2
						ifconfig "$ifname" down
						wlanconfig "$ifname" destroy
						continue
					}
				fi
			;;
			adhoc)
				if eval "type wpa_supplicant_setup_vif" 2>/dev/null >/dev/null; then
					wpa_supplicant_setup_vif "$vif" athr || {
						echo "enable_qcawifi($device): Failed to set up wpa"
						ifconfig "$ifname" down
						wlanconfig "$ifname" destroy
						continue
					}
				fi
		esac
		#ifconfig "$ifname" up

		#Begin:traffic limit(yuyaowen)
		config_get stream_limit_sw "$vif" stream_limit_sw
		[ -n "$stream_limit_sw" ] && wlanset traffic_limit "$ifname" set_every_node_flag "$stream_limit_sw"
	
		config_get upstream_limit "$vif" upstream_limit
		[ -n "$upstream_limit" ] && wlanset traffic_limit "$ifname" set_every_node "$upstream_limit"
		
		config_get downstream_limit "$vif" downstream_limit
		[ -n "$downstream_limit" ] && wlanset traffic_limit "$ifname" set_every_node_send "$downstream_limit"
		#End:traffic limit(yuyaowen)
	
		#Begin:maclist add(yuyaowen)
		set_han_maclist_start $vif
		#End:maclist add(yuyaowen)
	done
	
	set_igmpsnp_start
	#Begin:pengdecai for han private wmm
	set_han_wmm_start
	set_prio_8021p_start
	#End:pengdecai for han private wmm
	#duanmingzhe added, start lbd moudle
	/etc/init.d/lbd start
}

#Begin:pengdecai for han igmpsnp
set_igmp() {   	
local cfg="$1"
local ifname="$2"

[ ! "$ifname" ] && return
[ $ifname = "athscan0" ] && return
[ $ifname = "athscan1" ] && return

config_get switch "$cfg" switch "0"
config_get multounicast "$cfg"  multounicast "0"


wlanset igmp  "$ifname" set_snoop_enable $switch  > /dev/null 2>&1 
if [ $multounicast -gt 0 ];then 
	wlanset igmp  "$ifname" set_mutoun_enable 2  > /dev/null 2>&1 
	else 
	wlanset igmp  "$ifname" set_mutoun_enable 0  > /dev/null 2>&1 
fi
} 

set_igmpsnp() {
    local ifname=
    local cfg="$1"
 	config_get ifname "$cfg" ifname
    config_load igmp
	config_foreach set_igmp igmp "$ifname"
}

set_igmpsnp_start() {
#echo set_igmpsnp_start 
config_load wireless 
config_foreach set_igmpsnp wifi-iface
}
#endf pengdecai for han igmpsnp

#Begin:pengdecai for han private wmm
set_wmm() {    
	local ifname=
	local cfg="$1"
	config_get ifname "$cfg" ifname
	config_get dscp_enable "$cfg" dscp_enable  
	config_get dot1p_enable "$cfg" dot1p_enable 	
	config_get dscp_to_bk "$cfg" dscp_to_bk
	config_get dscp_to_be "$cfg" dscp_to_be 
	config_get dscp_to_vi "$cfg" dscp_to_vi
	config_get dscp_to_vo "$cfg" dscp_to_vo 		
	config_get bk_to_dscp "$cfg" bk_to_dscp                                                                                    
	config_get be_to_dscp "$cfg" be_to_dscp                                                          
	config_get vi_to_dscp "$cfg" vi_to_dscp     
	config_get vo_to_dscp "$cfg" vo_to_dscp  
	config_get dot1p_to_bk "$cfg" dot1p_to_bk
	config_get dot1p_to_be "$cfg" dot1p_to_be
	config_get dot1p_to_vi "$cfg" dot1p_to_vi 
	config_get dot1p_to_vo "$cfg" dot1p_to_vo 
	config_get bk_to_dot1p "$cfg" bk_to_dot1p 
	config_get be_to_dot1p "$cfg" be_to_dot1p 
	config_get vi_to_dot1p "$cfg" vi_to_dot1p
	config_get vo_to_dot1p "$cfg" vo_to_dot1p 
	
	[ -n "$dscp_enable" ] && wlanset wmm  "$ifname" set_dscp_enable $dscp_enable > /dev/null 2>&1 
	[ -n "$dot1p_enable" ] && wlanset wmm  "$ifname" set_8021p_enable $dot1p_enable > /dev/null 2>&1 

	if [  "$dscp_enable" = "1" ];then 
		[ -n "$dscp_to_bk" ] && wlanset wmm  "$ifname" set_dscp_to_background $dscp_to_bk > /dev/null 2>&1 
		[ -n "$dscp_to_be" ] && wlanset wmm  "$ifname" set_dscp_to_besteffort $dscp_to_be > /dev/null 2>&1 
		[ -n "$dscp_to_vi" ] && wlanset wmm  "$ifname" set_dscp_to_video $dscp_to_vi > /dev/null 2>&1 
		[ -n "$dscp_to_vo" ] && wlanset wmm  "$ifname" set_dscp_to_voice $dscp_to_vo > /dev/null 2>&1 
		[ -n "$bk_to_dscp" ] && wlanset wmm  "$ifname" set_background_to_dscp $bk_to_dscp > /dev/null 2>&1 
		[ -n "$be_to_dscp" ] && wlanset wmm  "$ifname" set_besteffort_to_dscp $be_to_dscp > /dev/null 2>&1 
		[ -n "$vi_to_dscp" ] && wlanset wmm  "$ifname" set_video_to_dscp $vi_to_dscp > /dev/null 2>&1 
		[ -n "$vo_to_dscp" ] && wlanset wmm  "$ifname" set_voice_to_dscp $vo_to_dscp > /dev/null 2>&1 
	fi

	if [  "$dot1p_enable" = "1" ];then 
		[ -n "$dot1p_to_bk" ] && wlanset wmm  "$ifname" set_8021p_to_background $dot1p_to_bk > /dev/null 2>&1 
		[ -n "$dot1p_to_be" ] && wlanset wmm  "$ifname" set_8021p_to_besteffort $dot1p_to_be > /dev/null 2>&1 
		[ -n "$dot1p_to_vi" ] && wlanset wmm  "$ifname" set_8021p_to_video $dot1p_to_vi > /dev/null 2>&1 
		[ -n "$dot1p_to_vo" ] && wlanset wmm  "$ifname" set_8021p_to_voice $dot1p_to_vo > /dev/null 2>&1 
		[ -n "$bk_to_dot1p" ] && wlanset wmm  "$ifname" set_background_to_8021p $bk_to_dot1p > /dev/null 2>&1 
		[ -n "$be_to_dot1p" ] && wlanset wmm  "$ifname" set_besteffort_to_8021p $be_to_dot1p > /dev/null 2>&1 
		[ -n "$vi_to_dot1p" ] && wlanset wmm  "$ifname" set_video_to_8021p $vi_to_dot1p > /dev/null 2>&1 
		[ -n "$vo_to_dot1p" ] && wlanset wmm  "$ifname" set_voice_to_8021p $vo_to_dot1p > /dev/null 2>&1  
	fi                                            
} 

set_han_wmm_start() {
    config_load wireless
	config_foreach set_wmm wifi-iface
}

# for maclist(yuyaowen)
set_han_maclist_start() {                                         
	config_load wireless                     
	config_get maclist "$1" maclist
	[ -n "$maclist" ] && {           
	#	iwpriv "$ifname" maccmd 3              
		for mac in $maclist; do                                          
			# flush MAC list        
			iwpriv "$ifname" addmac "$mac"
			iwpriv "$ifname" kickmac "$mac"
		done                            
	}  
}
# end: for maclist(yuyaowen)

set_prio_8021p() {

    local ifname=
    local cfg="$1"
    config_get name  "$cfg" name "0"                                      
    config_get vid  "$cfg"  vid  "0" 
        if [ $vid -gt 0 ];then     

        vconfig  set_egress_map  "$name" 0  0   > /dev/null 2>&1 
        vconfig  set_egress_map  "$name" 1  1   > /dev/null 2>&1 
        vconfig  set_egress_map  "$name" 2  2   > /dev/null 2>&1 
        vconfig  set_egress_map  "$name" 3  3   > /dev/null 2>&1 
        vconfig  set_egress_map  "$name" 4  4   > /dev/null 2>&1 
        vconfig  set_egress_map  "$name" 5  5   > /dev/null 2>&1 
        vconfig  set_egress_map  "$name" 6  6   > /dev/null 2>&1 
        vconfig  set_egress_map  "$name" 7  7   > /dev/null 2>&1 

        vconfig set_ingress_map "$name"  0  0  > /dev/null 2>&1 
        vconfig set_ingress_map "$name"  1  1  > /dev/null 2>&1 
        vconfig set_ingress_map "$name"  2  2  > /dev/null 2>&1 
        vconfig set_ingress_map "$name"  3  3  > /dev/null 2>&1 
        vconfig set_ingress_map "$name"  4  4  > /dev/null 2>&1 
        vconfig set_ingress_map "$name"  5  5  > /dev/null 2>&1 
        vconfig set_ingress_map "$name"  6  6  > /dev/null 2>&1 
        vconfig set_ingress_map "$name"  7  7  > /dev/null 2>&1 
     fi
}

set_prio_8021p_start() {
    config_load network
    config_foreach set_prio_8021p device
}
#End:pengdecai for han private wmm
pre_qcawifi() {
	local action=${1}

	config_load wireless

	case "${action}" in
		disable)
			config_get_bool wps_vap_tie_dbdc qcawifi wps_vap_tie_dbdc 0

			if [ $wps_vap_tie_dbdc -ne 0 ]; then
				kill "$(cat "/var/run/hostapd.pid")"
				[ -f "/tmp/hostapd_conf_filename" ] &&
					rm /tmp/hostapd_conf_filename

			fi

			eval "type qwrap_teardown" >/dev/null 2>&1 && qwrap_teardown
			eval "type icm_teardown" >/dev/null 2>&1 && icm_teardown
			eval "type wpc_teardown" >/dev/null 2>&1 && wpc_teardown
			[ ! -f /etc/init.d/lbd ] || /etc/init.d/lbd stop
		;;
	esac
}

qcawifi_start_hostapd_cli() {
	local device=$1
	local ifidx=0
	local radioidx=${device#wifi}

	config_get vifs $device vifs

	for vif in $vifs; do
		local config_methods vifname

		config_get vifname "$vif" ifname

		if [ -n $vifname ]; then
			[ $ifidx -gt 0 ] && vifname="ath${radioidx}$ifidx" || vifname="ath${radioidx}"
		fi

		config_get_bool wps_pbc "$vif" wps_pbc 0
		config_get config_methods "$vif" wps_config
		[ "$wps_pbc" -gt 0 ] && append config_methods push_button

		if [ -n "$config_methods" ]; then
			pid=/var/run/hostapd_cli-$vifname.pid
			hostapd_cli -i $vifname -P $pid -a /lib/wifi/wps-hostapd-update-uci -p /var/run/hostapd-$device -B
		fi

		ifidx=$(($ifidx + 1))
	done
}

post_qcawifi() {
	local action=${1}

	case "${action}" in
		enable)
			local icm_enable wpc_enable

			# Run a single hostapd instance for all the radio's
			# Enables WPS VAP TIE feature

			config_get_bool wps_vap_tie_dbdc qcawifi wps_vap_tie_dbdc 0

			if [ $wps_vap_tie_dbdc -ne 0 ]; then
				hostapd_conf_file=$(cat "/tmp/hostapd_conf_filename")
				hostapd -P /var/run/hostapd.pid $hostapd_conf_file -B
				config_foreach qcawifi_start_hostapd_cli wifi-device
			fi

			config_get_bool icm_enable icm enable 0
			[ ${icm_enable} -gt 0 ] && \
					eval "type icm_setup" >/dev/null 2>&1 && {
				icm_setup
			}

			config_get_bool wpc_enable wpc enable 0
			[ ${wpc_enable} -gt 0 ] && \
					eval "type wpc_setup" >/dev/null 2>&1 && {
				wpc_setup
			}

			eval "type qwrap_setup" >/dev/null 2>&1 && qwrap_setup

			# The init script will check whether lbd is actually
			# enabled
			[ ! -f /etc/init.d/lbd ] || /etc/init.d/lbd start

		;;
	esac
}

check_qcawifi_device() {
	[ ${1%[0-9]} = "wifi" ] && config_set "$1" phy "$1"
	config_get phy "$1" phy
	[ -z "$phy" ] && {
		find_qcawifi_phy "$1" >/dev/null || return 1
		config_get phy "$1" phy
	}
	[ "$phy" = "$dev" ] && found=1
}


detect_qcawifi() {
	devidx=0
	load_qcawifi
	config_load wireless
	while :; do
		config_get type "radio$devidx" type
		[ -n "$type" ] || break
		devidx=$(($devidx + 1))
	done
	cd /sys/class/net
	[ -d wifi0 ] || return
	for dev in $(ls -d wifi* 2>&-); do
		found=0
		config_foreach check_qcawifi_device wifi-device
		[ "$found" -gt 0 ] && continue

		hwcaps=$(cat ${dev}/hwcaps)
		case "${hwcaps}" in
			*11bgn) mode_11=ng;;
			*11abgn) mode_11=ng;;
			*11an) mode_11=na;;
			*11an/ac) mode_11=ac;;
			*11abgn/ac) mode_11=ac;;
		esac

		cat <<EOF
config wifi-device  wifi$devidx
	option type	qcawifi
	option channel	auto
	option macaddr	$(cat /sys/class/net/${dev}/address)
	option hwmode	11${mode_11}
	# REMOVE THIS LINE TO ENABLE WIFI:
	option disabled 1

config wifi-iface
	option device	wifi$devidx
	option network	lan
	option mode	ap
	option ssid	OpenWrt
	option encryption none

EOF
	devidx=$(($devidx + 1))
	done
}

# Function: flush_qcawifi(wifi-iface, old-ifname)
# Description: Only change one virtual iface, don't bother other wlans.
# Author: Yuyaowen
flush_qcawifi() {
	create_mgt_ssid
	vif=$1	#wifi-iface
	old_ifname=$2	#athxxx
	if [ "$vif" -a "$old_ifname" ]; then
		hostapd_remove_vif "$old_ifname"
		dhcp_snp_remove_vif "$old_ifname"
	fi
	[ "$old_ifname" ] && wlanconfig "$old_ifname" destroy 2> /dev/null
	config_get enable "$vif" enable
	if [ "$enable" = "0" ]; then
		return;
	fi
	config_get device "$vif" device
	[ ! "$device" ] && return

	local vif_txpower= nosbeacon= wlanaddr=""

	radio_idx=${device#wifi}
	existed_ifnames=`iwconfig 2>/dev/null |egrep -o "ath$radio_idx." |sort`
	v_ifname=
	if_idx=1
	for exist_ifname in $existed_ifnames
	do
		v_ifname="ath${radio_idx}$if_idx"
		[ "$v_ifname" = "$exist_ifname" ] && if_idx=`expr $if_idx + 1`
	done
	v_ifname="ath${radio_idx}$if_idx"
	vifname=$v_ifname

	config_get ifname "$vif" ifname
	config_set "$vif" ifname "${ifname:=$vifname}"
	cluster-cfg set wireless."$vif".ifname="$ifname"
	config_get mode "$vif" mode

	case "$mode" in
		sta)
			config_get_bool nosbeacon "$device" nosbeacon
			config_get qwrap_enable "$device" qwrap_enable 0
			[ $qwrap_enable -gt 0 ] && wlanaddr="00:00:00:00:00:00"
			;;
		adhoc)
			config_get_bool nosbeacon "$vif" sw_merge 1
			;;
	esac

	[ "$nosbeacon" = 1 ] || nosbeacon=""
	ifname=$(/usr/sbin/wlanconfig "$ifname" create wlandev "$device" wlanmode "$mode" ${wlanaddr:+wlanaddr "$wlanaddr"} ${nosbeacon:+nosbeacon})
	[ $? -ne 0 ] && {
		echo "enable_qcawifi($device): Failed to set up $mode vif $ifname" >&2
		return
	}
	config_set "$vif" ifname "$ifname"

	_global_settings

	config_get hwmode "$device" hwmode auto
	config_get htmode "$device" htmode auto

#	# For fix hwmode. Yuyaowen added.
#	if [ "$device" = "wifi1" ]; then
#		[ "$hwmode" = "auto" ] && hwmode=11ac
#		[ "$htmode" = "auto" ] && htmode=HT20
#	fi
#	# End for fix hwmode. Yuyaowen added.

	pureg=0
	case "$hwmode:$htmode" in
		*ng:HT20) hwmode=11NGHT20;;
		*ng:HT40-) hwmode=11NGHT40MINUS;;
		*ng:HT40+) hwmode=11NGHT40PLUS;;
		*ng:HT40) hwmode=11NGHT40;;
		*ng:*) hwmode=11NGHT20;;
		*na:HT20) hwmode=11NAHT20;;
		*na:HT40-) hwmode=11NAHT40MINUS;;
		*na:HT40+) hwmode=11NAHT40PLUS;;
		*na:HT40) hwmode=11NAHT40;;
		*na:*) hwmode=11NAHT40;;
		*ac:HT20) hwmode=11ACVHT20;;
		*ac:HT40+) hwmode=11ACVHT40PLUS;;
		*ac:HT40-) hwmode=11ACVHT40MINUS;;
		*ac:HT40) hwmode=11ACVHT40;;
		*ac:HT80) hwmode=11ACVHT80;;
		*ac:*) hwmode=11ACVHT80;;
		*b:*) hwmode=11B;;
		*bg:*) hwmode=11G;;
		*g:*) hwmode=11G; pureg=1;;
		*a:*) hwmode=11A;;
		*) hwmode=AUTO;;
	esac
	[ "$device" = "wifi0" ] && {
		if [ -f /tmp/channel ] ;then
			ret=`cat /tmp/channel | grep wifi0_mode | awk -F '=' '{print $2}'`
			if [ "" != "$ret" ] ;then
				hwmode=$ret
			fi
		fi
	}
	[ "$device" = "wifi1" ] && {
		if [ -f /tmp/channel ] ;then
			ret=`cat /tmp/channel | grep wifi1_mode | awk -F '=' '{print $2}'`
			if [ "" != "$ret" ] ;then
				hwmode=$ret
			fi
		fi
	}
	iwpriv "$ifname" mode "$hwmode"
	[ $pureg -gt 0 ] && iwpriv "$ifname" pureg "$pureg"

	config_get puren "$vif" puren
	[ -n "$puren" ] && iwpriv "$ifname" puren "$puren"

	# Avoid creating a new WLAN lead to other WLAN briefly dropped. Yuyaowen added.
	dont_set_channel=`iwconfig 2>/dev/null |grep "${ifname%?}" |sed -n 1p |awk '{print $1}'`
	if [ ! "$dont_set_channel" ]; then
		config_get channel "$device" channel
	        #modified by duanmingzhe & yuyaowen for auto channel & auto txpower
	        if [ "auto" == "$channel" ]
	        then
	                [ "$device" = "wifi0" ] && {
	                        if [ -f /tmp/channel ] ;then
	                                ret=`cat /tmp/channel | grep wifi0_channel | awk -F '=' '{print $2}'`
	                                if [ "" != "$ret" ] ;then
	                                        channel=$ret
	                                else
	                                        channel=1
	                                fi
	                        else
	                                channel=1
	                        fi
	                }
	                [ "$device" = "wifi1" ] && {
	                        if [ -f /tmp/channel ] ;then
	                                ret=`cat /tmp/channel | grep wifi1_channel | awk -F '=' '{print $2}'`
	                                if [ "" != "$ret" ] ;then
	                                        channel=$ret
	                                else
	                                        channel=36
	                                fi
	                        else
	                                channel=36
	                        fi
	                }
	        fi
		iwconfig "$ifname" channel "$channel" >/dev/null 2>/dev/null 
	fi

	config_get_bool hidden "$vif" hidden 0
	iwpriv "$ifname" hide_ssid "$hidden"

	config_get_bool shortgi "$vif" shortgi 1
	[ -n "$shortgi" ] && iwpriv "$ifname" shortgi "${shortgi}"

	config_get_bool disablecoext "$vif" disablecoext
	[ -n "$disablecoext" ] && iwpriv "$ifname" disablecoext "${disablecoext}"

	config_get chwidth "$vif" chwidth
	[ -n "$chwidth" ] && iwpriv "$ifname" chwidth "${chwidth}"

	config_get wds "$vif" wds

	case "$wds" in
		1|on|enabled) wds=1;;
		*) wds=0;;
	esac

	iwpriv "$ifname" wds "$wds" >/dev/null 2>&1

	config_get TxBFCTL "$vif" TxBFCTL
	[ -n "$TxBFCTL" ] && iwpriv "$ifname" TxBFCTL "$TxBFCTL"

	config_get bintval "$vif" bintval
	[ -n "$bintval" ] && iwpriv "$ifname" bintval "$bintval"

	config_get_bool countryie "$vif" countryie
	[ -n "$countryie" ] && iwpriv "$ifname" countryie "$countryie"

	case "$mode" in
		sta|adhoc)
		        config_get addr "$vif" bssid
		        [ -z "$addr" ] || { 
		  	      iwconfig "$ifname" ap "$addr"
		        }
		;;
	esac

	config_get_bool uapsd "$vif" uapsd
	[ -n "$uapsd" ] && iwpriv "$ifname" uapsd "$uapsd"

	config_get mcast_rate "$vif" mcast_rate
	[ -n "$mcast_rate" ] && iwpriv "$ifname" mcast_rate "${mcast_rate%%.*}"

	config_get powersave "$vif" powersave
	[ -n "$powersave" ] && iwpriv "$ifname" powersave "${powersave}"

	config_get_bool ant_ps_on "$vif" ant_ps_on
	[ -n "$ant_ps_on" ] && iwpriv "$ifname" ant_ps_on "${ant_ps_on}"

	config_get ps_timeout "$vif" ps_timeout
	[ -n "$ps_timeout" ] && iwpriv "$ifname" ps_timeout "${ps_timeout}"

	config_get_bool mcastenhance "$vif" mcastenhance
	[ -n "$mcastenhance" ] && iwpriv "$ifname" mcastenhance "${mcastenhance}"

	config_get metimer "$vif" metimer
	[ -n "$metimer" ] && iwpriv "$ifname" metimer "${metimer}"

	config_get metimeout "$vif" metimeout
	[ -n "$metimeout" ] && iwpriv "$ifname" metimeout "${metimeout}"

	config_get_bool medropmcast "$vif" medropmcast
	[ -n "$medropmcast" ] && iwpriv "$ifname" medropmcast "${medropmcast}"

	config_get me_adddeny "$vif" me_adddeny
	[ -n "$me_adddeny" ] && iwpriv "$ifname" me_adddeny ${me_adddeny}

	config_get vap_ind "$vif" vap_ind
	[ -n "$vap_ind" ] && iwpriv "$ifname" vap_ind "${vap_ind}"

	config_get extap "$vif" extap
	[ -n "$extap" ] && iwpriv "$ifname" extap "${extap}"

	config_get scanband "$vif" scanband
	[ -n "$scanband" ] && iwpriv "$ifname" scanband "${scanband}"

	config_get periodicScan "$vif" periodicScan
	[ -n "$periodicScan" ] && iwpriv "$ifname" periodicScan "${periodicScan}"

	config_get frag "$vif" frag
	[ -n "$frag" ] && iwconfig "$ifname" frag "${frag%%.*}"

	config_get rts "$vif" rts
	[ -n "$rts" ] && iwconfig "$ifname" rts "${rts%%.*}"

	config_get cwmin "$vif" cwmin
	[ -n "$cwmin" ] && iwpriv "$ifname" cwmin ${cwmin}

	config_get cwmax "$vif" cwmax
	[ -n "$cwmax" ] && iwpriv "$ifname" cwmax ${cwmax}

	config_get aifs "$vif" aifs
	[ -n "$aifs" ] && iwpriv "$ifname" aifs ${aifs}

	config_get txoplimit "$vif" txoplimit
	[ -n "$txoplimit" ] && iwpriv "$ifname" txoplimit ${txoplimit}

	config_get noackpolicy "$vif" noackpolicy
	[ -n "$noackpolicy" ] && iwpriv "$ifname" noackpolicy ${noackpolicy}

	config_get_bool wmm "$vif" wmm
	[ -n "$wmm" ] && iwpriv "$ifname" wmm "$wmm"

	config_get_bool doth "$vif" doth
	[ -n "$doth" ] && iwpriv "$ifname" doth "$doth"

	config_get doth_chanswitch "$vif" doth_chanswitch
	[ -n "$doth_chanswitch" ] && iwpriv "$ifname" doth_chanswitch ${doth_chanswitch}

	config_get quiet "$vif" quiet
	[ -n "$quiet" ] && iwpriv "$ifname" quiet "$quiet"

	config_get mfptest "$vif" mfptest
	[ -n "$mfptest" ] && iwpriv "$ifname" mfptest "$mfptest"

	config_get dtim_period "$vif" dtim_period
	[ -n "$dtim_period" ] && iwpriv "$ifname" dtim_period "$dtim_period"

	config_get noedgech "$vif" noedgech
	[ -n "$noedgech" ] && iwpriv "$ifname" noedgech "$noedgech"

	config_get ps_on_time "$vif" ps_on_time
	[ -n "$ps_on_time" ] && iwpriv "$ifname" ps_on_time "$ps_on_time"

	config_get inact "$vif" inact
	[ -n "$inact" ] && iwpriv "$ifname" inact "$inact"

	config_get wnm "$vif" wnm
	[ -n "$wnm" ] && iwpriv "$ifname" wnm "$wnm"

	config_get ampdu "$vif" ampdu
	[ -n "$ampdu" ] && iwpriv "$ifname" ampdu "$ampdu"

	config_get amsdu "$vif" amsdu
	[ -n "$amsdu" ] && iwpriv "$ifname" amsdu "$amsdu"

	config_get maxampdu "$vif" maxampdu
	[ -n "$maxampdu" ] && iwpriv "$ifname" maxampdu "$maxampdu"

	config_get vhtmaxampdu "$vif" vhtmaxampdu
	[ -n "$vhtmaxampdu" ] && iwpriv "$ifname" vhtmaxampdu "$vhtmaxampdu"

	config_get setaddbaoper "$vif" setaddbaoper
	[ -n "$setaddbaoper" ] && iwpriv "$ifname" setaddbaoper "$setaddbaoper"

	config_get addbaresp "$vif" addbaresp
	[ -n "$addbaresp" ] && iwpriv "$ifname" $addbaresp

	config_get addba "$vif" addba
	[ -n "$addba" ] && iwpriv "$ifname" addba $addba

	config_get delba "$vif" delba
	[ -n "$delba" ] && iwpriv "$ifname" delba $delba

	config_get_bool stafwd "$vif" stafwd 0
	[ -n "$stafwd" ] && iwpriv "$ifname" stafwd "$stafwd"

	config_get macfilter "$vif" macfilter
	case "$macfilter" in
		allow)
	        	iwpriv "$ifname" maccmd 1
	        	;;
		deny)
	        	iwpriv "$ifname" maccmd 2
	        	;;
		*)
	        	[ -n "$maclist" ] && iwpriv "$ifname" maccmd 2
	        	;;
	esac

	config_get nss "$vif" nss
	[ -n "$nss" ] && iwpriv "$ifname" nss "$nss"

	config_get vht_mcsmap "$vif" vht_mcsmap
	[ -n "$vht_mcsmap" ] && iwpriv "$ifname" vht_mcsmap "$vht_mcsmap"

	config_get chwidth "$vif" chwidth
	[ -n "$chwidth" ] && iwpriv "$ifname" chwidth "$chwidth"

	config_get chbwmode "$vif" chbwmode
	[ -n "$chbwmode" ] && iwpriv "$ifname" chbwmode "$chbwmode"

	config_get ldpc "$vif" ldpc
	[ -n "$ldpc" ] && iwpriv "$ifname" ldpc "$ldpc"

	config_get rx_stbc "$vif" rx_stbc
	[ -n "$rx_stbc" ] && iwpriv "$ifname" rx_stbc "$rx_stbc"

	config_get tx_stbc "$vif" tx_stbc
	[ -n "$tx_stbc" ] && iwpriv "$ifname" tx_stbc "$tx_stbc"

	config_get cca_thresh "$vif" cca_thresh
	[ -n "$cca_thresh" ] && iwpriv "$ifname" cca_thresh "$cca_thresh"

	config_get set11NRetries "$vif" set11NRetries
	[ -n "$set11NRetries" ] && iwpriv "$ifname" set11NRetries "$set11NRetries"

	config_get chanbw "$vif" chanbw
	[ -n "$chanbw" ] && iwpriv "$ifname" chanbw "$chanbw"

	config_get maxsta "$vif" maxsta
	[ -n "$maxsta" ] && iwpriv "$ifname" maxsta "$maxsta"

	config_get sko_max_xretries "$vif" sko_max_xretries
	[ -n "$sko_max_xretries" ] && iwpriv "$ifname" sko "$sko_max_xretries"

	config_get extprotmode "$vif" extprotmode
	[ -n "$extprotmode" ] && iwpriv "$ifname" extprotmode "$extprotmode"

	config_get extprotspac "$vif" extprotspac
	[ -n "$extprotspac" ] && iwpriv "$ifname" extprotspac "$extprotspac"

	config_get_bool cwmenable "$vif" cwmenable
	[ -n "$cwmenable" ] && iwpriv "$ifname" cwmenable "$cwmenable"

	config_get_bool protmode "$vif" protmode
	[ -n "$protmode" ] && iwpriv "$ifname" protmode "$protmode"

	config_get enablertscts "$vif" enablertscts
	[ -n "$enablertscts" ] && iwpriv "$ifname" enablertscts "$enablertscts"

	config_get txcorrection "$vif" txcorrection
	[ -n "$txcorrection" ] && iwpriv "$ifname" txcorrection "$txcorrection"

	config_get rxcorrection "$vif" rxcorrection
	[ -n "$rxcorrection" ] && iwpriv "$ifname" rxcorrection "$rxcorrection"

	config_get ssid "$vif" ssid
	[ -n "$ssid" ] && {
		iwconfig "$ifname" essid on
		iwconfig "$ifname" essid "$ssid"
	}

	config_get txqueuelen "$vif" txqueuelen
	[ -n "$txqueuelen" ] && ifconfig "$ifname" txqueuelen "$txqueuelen"

	config_load network
	net_cfg="$(find_net_config "$vif")"

	config_get mtu $net_cfg mtu

	[ -n "$mtu" ] && {
		config_set "$vif" mtu $mtu
		ifconfig "$ifname" mtu $mtu
	}

	config_get tdls "$vif" tdls
	[ -n "$tdls" ] && iwpriv "$ifname" tdls "$tdls"

	config_get set_tdls_rmac "$vif" set_tdls_rmac
	[ -n "$set_tdls_rmac" ] && iwpriv "$ifname" set_tdls_rmac "$set_tdls_rmac"

	config_get tdls_qosnull "$vif" tdls_qosnull
	[ -n "$tdls_qosnull" ] && iwpriv "$ifname" tdls_qosnull "$tdls_qosnull"

	config_get tdls_uapsd "$vif" tdls_uapsd
	[ -n "$tdls_uapsd" ] && iwpriv "$ifname" tdls_uapsd "$tdls_uapsd"

	config_get tdls_set_rcpi "$vif" tdls_set_rcpi
	[ -n "$tdls_set_rcpi" ] && iwpriv "$ifname" set_rcpi "$tdls_set_rcpi"

	config_get tdls_set_rcpi_hi "$vif" tdls_set_rcpi_hi
	[ -n "$tdls_set_rcpi_hi" ] && iwpriv "$ifname" set_rcpihi "$tdls_set_rcpi_hi"

	config_get tdls_set_rcpi_lo "$vif" tdls_set_rcpi_lo
	[ -n "$tdls_set_rcpi_lo" ] && iwpriv "$ifname" set_rcpilo "$tdls_set_rcpi_lo"

	config_get tdls_set_rcpi_margin "$vif" tdls_set_rcpi_margin
	[ -n "$tdls_set_rcpi_margin" ] && iwpriv "$ifname" set_rcpimargin "$tdls_set_rcpi_margin"

	config_get tdls_dtoken "$vif" tdls_dtoken
	[ -n "$tdls_dtoken" ] && iwpriv "$ifname" tdls_dtoken "$tdls_dtoken"

	config_get do_tdls_dc_req "$vif" do_tdls_dc_req
	[ -n "$do_tdls_dc_req" ] && iwpriv "$ifname" do_tdls_dc_req "$do_tdls_dc_req"

	config_get tdls_auto "$vif" tdls_auto
	[ -n "$tdls_auto" ] && iwpriv "$ifname" tdls_auto "$tdls_auto"

	config_get tdls_off_timeout "$vif" tdls_off_timeout
	[ -n "$tdls_off_timeout" ] && iwpriv "$ifname" off_timeout "$tdls_off_timeout"

	config_get tdls_tdb_timeout "$vif" tdls_tdb_timeout
	[ -n "$tdls_tdb_timeout" ] && iwpriv "$ifname" tdb_timeout "$tdls_tdb_timeout"

	config_get tdls_weak_timeout "$vif" tdls_weak_timeout
	[ -n "$tdls_weak_timeout" ] && iwpriv "$ifname" weak_timeout "$tdls_weak_timeout"

	config_get tdls_margin "$vif" tdls_margin
	[ -n "$tdls_margin" ] && iwpriv "$ifname" tdls_margin "$tdls_margin"

	config_get tdls_rssi_ub "$vif" tdls_rssi_ub
	[ -n "$tdls_rssi_ub" ] && iwpriv "$ifname" tdls_rssi_ub "$tdls_rssi_ub"

	config_get tdls_rssi_lb "$vif" tdls_rssi_lb
	[ -n "$tdls_rssi_lb" ] && iwpriv "$ifname" tdls_rssi_lb "$tdls_rssi_lb"

	config_get tdls_path_sel "$vif" tdls_path_sel
	[ -n "$tdls_path_sel" ] && iwpriv "$ifname" tdls_pathSel "$tdls_path_sel"

	config_get tdls_rssi_offset "$vif" tdls_rssi_offset
	[ -n "$tdls_rssi_offset" ] && iwpriv "$ifname" tdls_rssi_o "$tdls_rssi_offset"

	config_get tdls_path_sel_period "$vif" tdls_path_sel_period
	[ -n "$tdls_path_sel_period" ] && iwpriv "$ifname" tdls_pathSel_p "$tdls_path_sel_period"

	config_get tdlsmacaddr1 "$vif" tdlsmacaddr1
	[ -n "$tdlsmacaddr1" ] && iwpriv "$ifname" tdlsmacaddr1 "$tdlsmacaddr1"

	config_get tdlsmacaddr2 "$vif" tdlsmacaddr2
	[ -n "$tdlsmacaddr2" ] && iwpriv "$ifname" tdlsmacaddr2 "$tdlsmacaddr2"

	config_get tdlsaction "$vif" tdlsaction
	[ -n "$tdlsaction" ] && iwpriv "$ifname" tdlsaction "$tdlsaction"

	config_get tdlsoffchan "$vif" tdlsoffchan
	[ -n "$tdlsoffchan" ] && iwpriv "$ifname" tdlsoffchan "$tdlsoffchan"

	config_get tdlsswitchtime "$vif" tdlsswitchtime
	[ -n "$tdlsswitchtime" ] && iwpriv "$ifname" tdlsswitchtime "$tdlsswitchtime"

	config_get tdlstimeout "$vif" tdlstimeout
	[ -n "$tdlstimeout" ] && iwpriv "$ifname" tdlstimeout "$tdlstimeout"

	config_get tdlsecchnoffst "$vif" tdlsecchnoffst
	[ -n "$tdlsecchnoffst" ] && iwpriv "$ifname" tdlsecchnoffst "$tdlsecchnoffst"

	config_get tdlsoffchnmode "$vif" tdlsoffchnmode
	[ -n "$tdlsoffchnmode" ] && iwpriv "$ifname" tdlsoffchnmode "$tdlsoffchnmode"

	config_get_bool blockdfschan "$vif" blockdfschan
	[ -n "$blockdfschan" ] && iwpriv "$ifname" blockdfschan "$blockdfschan"

	config_get dbgLVL "$vif" dbgLVL
	[ -n "$dbgLVL" ] && iwpriv "$ifname" dbgLVL "$dbgLVL"

	config_get acsmindwell "$vif" acsmindwell
	[ -n "$acsmindwell" ] && iwpriv "$ifname" acsmindwell "$acsmindwell"

	config_get acsmaxdwell "$vif" acsmaxdwell
	[ -n "$acsmaxdwell" ] && iwpriv "$ifname" acsmaxdwell "$acsmaxdwell"

	config_get acsreport "$vif" acsreport
	[ -n "$acsreport" ] && iwpriv "$ifname" acsreport "$acsreport"

	config_get ch_hop_en "$vif" ch_hop_en
	[ -n "$ch_hop_en" ] && iwpriv "$ifname" ch_hop_en "$ch_hop_en"

	config_get ch_long_dur "$vif" ch_long_dur
	[ -n "$ch_long_dur" ] && iwpriv "$ifname" ch_long_dur "$ch_long_dur"

	config_get ch_nhop_dur "$vif" ch_nhop_dur
	[ -n "$ch_nhop_dur" ] && iwpriv "$ifname" ch_nhop_dur "$ch_nhop_dur"

	config_get ch_cntwn_dur "$vif" ch_cntwn_dur
	[ -n "$ch_cntwn_dur" ] && iwpriv "$ifname" ch_cntwn_dur "$ch_cntwn_dur"

	config_get ch_noise_th "$vif" ch_noise_th
	[ -n "$ch_noise_th" ] && iwpriv "$ifname" ch_noise_th "$ch_noise_th"

	config_get ch_cnt_th "$vif" ch_cnt_th
	[ -n "$ch_cnt_th" ] && iwpriv "$ifname" ch_cnt_th "$ch_cnt_th"

	config_get_bool scanchevent "$vif" scanchevent
	[ -n "$scanchevent" ] && iwpriv "$ifname" scanchevent "$scanchevent"

	config_get_bool send_add_ies "$vif" send_add_ies
	[ -n "$send_add_ies" ] && iwpriv "$ifname" send_add_ies "$send_add_ies"

	config_get_bool ext_ifu_acs "$vif" ext_ifu_acs
	[ -n "$ext_ifu_acs" ] && iwpriv "$ifname" ext_ifu_acs "$ext_ifu_acs"

	config_get_bool rrm "$vif" rrm
	[ -n "$rrm" ] && iwpriv "$ifname" rrm "$rrm"

	config_get_bool rrmslwin "$vif" rrmslwin
	[ -n "$rrmslwin" ] && iwpriv "$ifname" rrmslwin "$rrmslwin"

	config_get_bool rrmstats "$vif" rrmsstats
	[ -n "$rrmstats" ] && iwpriv "$ifname" rrmstats "$rrmstats"

	config_get rrmdbg "$vif" rrmdbg
	[ -n "$rrmdbg" ] && iwpriv "$ifname" rrmdbg "$rrmdbg"

	config_get acparams "$vif" acparams
	[ -n "$acparams" ] && iwpriv "$ifname" acparams $acparams

	config_get setwmmparams "$vif" setwmmparams
	[ -n "$setwmmparams" ] && iwpriv "$ifname" setwmmparams $setwmmparams

	config_get_bool qbssload "$vif" qbssload
	[ -n "$qbssload" ] && iwpriv "$ifname" qbssload "$qbssload"

	config_get_bool proxyarp "$vif" proxyarp
	[ -n "$proxyarp" ] && iwpriv "$ifname" proxyarp "$proxyarp"

	config_get_bool dgaf_disable "$vif" dgaf_disable
	[ -n "$dgaf_disable" ] && iwpriv "$ifname" dgaf_disable "$dgaf_disable"

	config_get setibssdfsparam "$vif" setibssdfsparam
	[ -n "$setibssdfsparam" ] && iwpriv "$ifname" setibssdfsparam "$setibssdfsparam"

	config_get startibssrssimon "$vif" startibssrssimon
	[ -n "$startibssrssimon" ] && iwpriv "$ifname" strtibssrssimon "$startibssrssimon"

	config_get setibssrssihyst "$vif" setibssrssihyst
	[ -n "$setibssrssihyst" ] && iwpriv "$ifname" setibssrssihyst "$setibssrssihyst"

	config_get noIBSSCreate "$vif" noIBSSCreate
	[ -n "$noIBSSCreate" ] && iwpriv "$ifname" noIBSSCreate "$noIBSSCreate"

	config_get setibssrssiclass "$vif" setibssrssiclass
	[ -n "$setibssrssiclass" ] && iwpriv "$ifname" s_ibssrssiclass $setibssrssiclass

	config_get offchan_tx_test "$vif" offchan_tx_test
	[ -n "$offchan_tx_test" ] && iwpriv "$ifname" offchan_tx_test $offchan_tx_test

	handle_vow_dbg_cfg() {
		local value="$1"
		iwpriv "$ifname" vow_dbg_cfg $value
	}

	config_list_foreach "$vif" vow_dbg_cfg handle_vow_dbg_cfg

	config_get_bool vow_dbg "$vif" vow_dbg
	[ -n "$vow_dbg" ] && iwpriv "$ifname" vow_dbg "$vow_dbg"

	handle_set_max_rate() {
		local value="$1"
		wlanconfig "$ifname" set_max_rate $value
	}
	config_list_foreach "$vif" set_max_rate handle_set_max_rate

	config_get dscp_tid_map "$vif" dscp_tid_map
	[ -n "$dscp_tid_map" ] && iwpriv "$ifname" set_dscp_tidmap $dscp_tid_map

	config_get athnewind "$vif" athnewind
	[ -n "$athnewind" ] && iwpriv "$ifname" athnewind "$athnewind"

	config_get vif_monitor "$vif" vif_monitor
	# For 8 WLan. Yuyaowen modified.
	if [ -n "$vif_monitor" ]; then
		iwpriv "$ifname" vif_monitor "$vif_monitor"
		local dev=
		local wifi_index="1"
		config_get dev "$vif" device
		[ "$dev" = "wifi0" ] && wifi_index="0"
		cluster-cfg set "bg-s.bs.scan_iface$wifi_index=$ifname"
		cluster-cfg -c "/etc/cfm/config/config-pub" set "bg-s.bs.scan_iface$wifi_index=$ifname"
		cluster-cfg -c "/etc/cfm/config/config-pub" commit "bg-s"
		bg-s "-x" "scan-iface$wifi_index=$ifname"
	fi
	# End for 8 WLan. Yuyaowen modified.

	config_get_bool commitatf "$vif" commitatf
	[ -n "$commitatf" ] && iwpriv "$ifname" commitatf "${commitatf}"

	config_get perunit "$vif" perunit
	[ -n "$perunit" ] && iwpriv "$ifname" perunit "${perunit}"

	config_get enh_ind "$vif" enh_ind
	[ -n "$enh_ind" ] && iwpriv "$ifname" enh-ind "$enh_ind"

	config_get osen "$vif" osen
	[ -n "$osen" ] && iwpriv "$ifname" osen "$osen"


	local start_hostapd= start_wapid=

	config_get ifname "$vif" ifname
	config_get enc "$vif" encryption "none"

	#ifconfig "$ifname" up

	
	case "$enc" in
		none)
		start_hostapd=1
			config_get_bool wps_pbc "$vif" wps_pbc 0
			config_get config_methods "$vif" wps_config
			[ "$wps_pbc" -gt 0 ] && append config_methods push_button
			[ -n "$config_methods" ] && start_hostapd=1
			;;
		wep*)
		case "$enc" in
			*mixed*)  iwpriv "$ifname" authmode 4;;
			*shared*) iwpriv "$ifname" authmode 2;;
			*)        iwpriv "$ifname" authmode 1;;
		esac

		for idx in 1 2 3 4; do
			config_get key "$vif" "key${idx}"
			iwconfig "$ifname" enc "[$idx]" "${key:-off}"
		done

		config_get key "$vif" key
		key="${key:-1}"
		case "$key" in
			[1234]) iwconfig "$ifname" enc "[$key]";;
			*) iwconfig "$ifname" enc "$key";;
		esac
		;;
		mixed*|psk*|wpa*|8021x)
		start_hostapd=1
		config_get key "$vif" key
		;;
		wapi*)
			start_wapid=1
			config_get key "$vif" key
			;;
		esac

		config_get set11NRates "$vif" set11NRates
		[ -n "$set11NRates" ] && iwpriv "$ifname" set11NRates "$set11NRates"

		config_get_bool vht_11ng "$vif" vht_11ng
		[ -n "$vht_11ng" ] && iwpriv "$ifname" vht_11ng "$vht_11ng"

		config_get vhtmcs "$vif" vhtmcs
		[ -n "$vhtmcs" ] && iwpriv "$ifname" vhtmcs "$vhtmcs"

		config_get nawds_mode "$vif" nawds_mode
		[ -n "$nawds_mode" ] && wlanconfig "$ifname" nawds mode "${nawds_mode}"

		handle_nawds() {
			local value="$1"
			wlanconfig "$ifname" nawds add-repeater $value
		}
		config_list_foreach "$vif" nawds_add_repeater handle_nawds

		handle_hmwds() {
			local value="$1"
			wlanconfig "$ifname" hmwds add_addr $value
		}
		config_list_foreach "$vif" hmwds_add_addr handle_hmwds

		config_get nawds_override "$vif" nawds_override
		[ -n "$nawds_override" ] && wlanconfig "$ifname" nawds override "${nawds_override}"

		config_get nawds_defcaps "$vif" nawds_defcaps
		[ -n "$nawds_defcaps" ] && wlanconfig "$ifname" nawds defcaps "${nawds_defcaps}"

		handle_hmmc_add() {
			local value="$1"
			wlanconfig "$ifname" hmmc add $value
		}
		config_list_foreach "$vif" hmmc_add handle_hmmc_add

		config_get mode "$vif" mode

		config_get_bool ap_isolation_enabled $device ap_isolation_enabled 0
		config_get_bool isolate "$vif" isolate 0

		if [ $ap_isolation_enabled -ne 0 ]; then
			[ "$mode" = "wrap" ] && isolate=1
		fi

		local net_cfg bridge
		net_cfg="$(find_net_config "$vif")"
		[ -z "$net_cfg" -o "$isolate" = 1 -a "$mode" = "wrap" ] || {
			bridge="$(bridge_interface "$net_cfg")"
			config_set "$vif" bridge "$bridge"
			start_net "$ifname" "$net_cfg"
		}

		set_wifi_up "$vif" "$ifname"

		config_get vif_txpower "$vif" txpower
		txpower="${txpower:-$vif_txpower}"
		[ -z "$txpower" ] || iwconfig "$ifname" txpower "${txpower%%.*}"

		case "$mode" in
			ap|wrap)

			iwpriv "$ifname" ap_bridge "$((isolate^1))"

			[ "$mode" = "ap" ] && iwpriv "$ifname" ap_bridge $isolate #pengdecai for phone roaming
			config_get_bool l2tif "$vif" l2tif
			[ -n "$l2tif" ] && iwpriv "$ifname" l2tif "$l2tif"

			if [ -n "$start_wapid" ]; then
				wapid_setup_vif "$vif" || {
					echo "enable_qcawifi($device): Failed to set up wapid for interface $ifname" >&2
					ifconfig "$ifname" down
					wlanconfig "$ifname" destroy
					continue
				}
			fi

			if [ -n "$start_hostapd" ] && eval "type hostapd_setup_vif" 2>/dev/null >/dev/null; then
				
				dhcp_snp_setup_vif "$vif"

				hostapd_setup_vif "$ifname" "$vif" atheros no_nconfig || {
					echo "enable_qcawifi($device): Failed to set up hostapd for interface $ifname" >&2
					ifconfig "$ifname" down
					wlanconfig "$ifname" destroy
					continue
				}
			fi
		;;
		wds|sta)
			if eval "type wpa_supplicant_setup_vif" 2>/dev/null >/dev/null; then
				wpa_supplicant_setup_vif "$vif" athr || {
					echo "enable_qcawifi($device): Failed to set up wpa_supplicant for interface $ifname" >&2
					ifconfig "$ifname" down
					wlanconfig "$ifname" destroy
					continue
				}
			fi
		;;
		adhoc)
			if eval "type wpa_supplicant_setup_vif" 2>/dev/null >/dev/null; then
				wpa_supplicant_setup_vif "$vif" athr || {
					echo "enable_qcawifi($device): Failed to set up wpa"
					ifconfig "$ifname" down
					wlanconfig "$ifname" destroy
					continue
				}
			fi
	esac
	#ifconfig "$ifname" up

	set_igmpsnp_start
	set_han_wmm_start
	set_prio_8021p_start

	config_get stream_limit_sw "$vif" stream_limit_sw
	[ -n "$stream_limit_sw" ] && wlanset traffic_limit "$ifname" set_every_node_flag "$stream_limit_sw"

	config_get upstream_limit "$vif" upstream_limit
	[ -n "$upstream_limit" ] && wlanset traffic_limit "$ifname" set_every_node "$upstream_limit"

	config_get downstream_limit "$vif" downstream_limit
	[ -n "$downstream_limit" ] && wlanset traffic_limit "$ifname" set_every_node_send "$downstream_limit"

	set_han_maclist_start $vif
}

# Function: _change_encryption(ifname, wifi-iface)
# Descryption: Restart hostapd and reload password, it can down/up vap automatically.
# Author: Yuyaowen
_change_encryption() {
	rm -r /var/run/wam_cluster/$ifname 2>/dev/null
	rm -r /var/run/wam-eag/$ifname 2>/dev/null
	rm -r /var/run/wam-wifi0/$ifname 2>/dev/null
	rm -r /var/run/wam-wifi1/$ifname 2>/dev/null

	ifname=$1
	vif=$2
	
	hostapd_remove_vif "$ifname"
	config_get enc $vif encryption
	case "$enc" in
		none)
		start_hostapd=1
			config_get_bool wps_pbc "$vif" wps_pbc 0
			config_get config_methods "$vif" wps_config
			[ "$wps_pbc" -gt 0 ] && append config_methods push_button
			[ -n "$config_methods" ] && start_hostapd=1
			;;
		wep*)
		case "$enc" in
			*mixed*)  iwpriv "$ifname" authmode 4;;
			*shared*) iwpriv "$ifname" authmode 2;;
			*)        iwpriv "$ifname" authmode 1;;
		esac

		for idx in 1 2 3 4; do
			config_get key "$vif" "key${idx}"
			iwconfig "$ifname" enc "[$idx]" "${key:-off}"
		done

		config_get key "$vif" key
		key="${key:-1}"
		case "$key" in
			[1234]) iwconfig "$ifname" enc "[$key]";;
			*) iwconfig "$ifname" enc "$key";;
		esac
		;;
		mixed*|psk*|wpa*|8021x)
		start_hostapd=1
		config_get key "$vif" key
		;;
		wapi*)
			start_wapid=1
			config_get key "$vif" key
			;;
		esac

		config_get set11NRates "$vif" set11NRates
		[ -n "$set11NRates" ] && iwpriv "$ifname" set11NRates "$set11NRates"

		config_get_bool vht_11ng "$vif" vht_11ng
		[ -n "$vht_11ng" ] && iwpriv "$ifname" vht_11ng "$vht_11ng"

		config_get vhtmcs "$vif" vhtmcs
		[ -n "$vhtmcs" ] && iwpriv "$ifname" vhtmcs "$vhtmcs"

		config_get nawds_mode "$vif" nawds_mode
		[ -n "$nawds_mode" ] && wlanconfig "$ifname" nawds mode "${nawds_mode}"

		handle_nawds() {
			local value="$1"
			wlanconfig "$ifname" nawds add-repeater $value
		}
		config_list_foreach "$vif" nawds_add_repeater handle_nawds

		handle_hmwds() {
			local value="$1"
			wlanconfig "$ifname" hmwds add_addr $value
		}
		config_list_foreach "$vif" hmwds_add_addr handle_hmwds

		config_get nawds_override "$vif" nawds_override
		[ -n "$nawds_override" ] && wlanconfig "$ifname" nawds override "${nawds_override}"

		config_get nawds_defcaps "$vif" nawds_defcaps
		[ -n "$nawds_defcaps" ] && wlanconfig "$ifname" nawds defcaps "${nawds_defcaps}"

		handle_hmmc_add() {
			local value="$1"
			wlanconfig "$ifname" hmmc add $value
		}
		config_list_foreach "$vif" hmmc_add handle_hmmc_add

		config_get mode "$vif" mode

		config_get_bool ap_isolation_enabled $device ap_isolation_enabled 0
		config_get_bool isolate "$vif" isolate 0

		if [ $ap_isolation_enabled -ne 0 ]; then
			[ "$mode" = "wrap" ] && isolate=1
		fi

		local net_cfg bridge
		net_cfg="$(find_net_config "$vif")"
		[ -z "$net_cfg" -o "$isolate" = 1 -a "$mode" = "wrap" ] || {
			bridge="$(bridge_interface "$net_cfg")"
			config_set "$vif" bridge "$bridge"
			start_net "$ifname" "$net_cfg"
		}

		set_wifi_up "$vif" "$ifname"

		case "$mode" in
			ap|wrap)

			iwpriv "$ifname" ap_bridge "$((isolate^1))"

			[ "$mode" = "ap" ] && iwpriv "$ifname" ap_bridge $isolate #pengdecai for phone roaming
			config_get_bool l2tif "$vif" l2tif
			[ -n "$l2tif" ] && iwpriv "$ifname" l2tif "$l2tif"

			if [ -n "$start_wapid" ]; then
				wapid_setup_vif "$vif" || {
					echo "enable_qcawifi($device): Failed to set up wapid for interface $ifname" >&2
					ifconfig "$ifname" down
					wlanconfig "$ifname" destroy
					continue
				}
			fi

			if [ -n "$start_hostapd" ] && eval "type hostapd_setup_vif" 2>/dev/null >/dev/null; then

				hostapd_setup_vif "$ifname" "$vif" atheros no_nconfig || {
					echo "enable_qcawifi($device): Failed to set up hostapd for interface $ifname" >&2
					ifconfig "$ifname" down
					wlanconfig "$ifname" destroy
					continue
				}
			fi
		;;
		wds|sta)
			if eval "type wpa_supplicant_setup_vif" 2>/dev/null >/dev/null; then
				wpa_supplicant_setup_vif "$vif" athr || {
					echo "enable_qcawifi($device): Failed to set up wpa_supplicant for interface $ifname" >&2
					ifconfig "$ifname" down
					wlanconfig "$ifname" destroy
					continue
				}
			fi
		;;
		adhoc)
			if eval "type wpa_supplicant_setup_vif" 2>/dev/null >/dev/null; then
				wpa_supplicant_setup_vif "$vif" athr || {
					echo "enable_qcawifi($device): Failed to set up wpa"
					ifconfig "$ifname" down
					wlanconfig "$ifname" destroy
					continue
				}
			fi
	esac
}

# Function: update_qcawifi(ifname, option, val, wifi-iface)
# Description: Only change one option, insteadof recreate the wlan.
# Author: Yuyaowen
# FIXME: It doesn't support 'list' suspensory.
update_qcawifi() {
	local ifname="$1"
	local option="$2"
	local val="$3"
	local wifi_iface="$4"

	if [ "$option" = "ssid" ]; then
		iwconfig "$ifname" essid "$val"
#		_change_encryption "$ifname" "$wifi_iface"
	elif [ "$option" = "channel" ]; then
		iwconfig "$ifname" channel "$val"
	elif [ "$option" = "txpower" ]; then
		iwconfig "$ifname" txpower "$val"
#	elif [ "$option" = "encryption" -o "$option" = "key" -o "$option" = "ieee80211r" -o "$option" = "okc" -o "$option" = "auth_server" -o "$option" = "acct_server" -o "$option" = "auth_port" -o "$option" = "acct_port" -o "$option" = "auth_secret" -o "$option" = "acct_secret" ]; then
	elif [ "$option" = "encr" -a "$val" = "1" ]; then
		_change_encryption "$ifname" "$wifi_iface"
	elif [ "$option" = "hidden" ]; then
		iwpriv "$ifname" hide_ssid "$val"
	elif [ "$option" = "macfilter" ]; then
		case "$macfilter" in
			allow) iwpriv "$ifname" maccmd 1 ;;
			deny) iwpriv "$ifname" maccmd 2 ;;
			*) [ -n "$maclist" ] && iwpriv "$ifname" maccmd 2 ;;
		esac
	elif [ "$option" = "maclist" ]; then
		iwpriv "$ifname" addmac "$val"
	elif [ "$option" = "_maclist" ]; then
		iwpriv "$ifname" delmac "$val"
	elif [ "$option" = "upstream_limit" ]; then
		wlanset traffic_limit "$ifname" set_every_node "$val"
	elif [ "$option" = "downstream_limit" ]; then
		wlanset traffic_limit "$ifname" set_every_node_send "$val"
	elif [ "$option" = "enable" -o "$option" = "vlan" ]; then
		flush_qcawifi "$wifi_iface" "$ifname"
	elif [ "$option" = "probe_threshold" ]; then
		return  # FIXME
	else
		iwpriv "$ifname" "$option" "$val"
	fi
}

# Function: _get_hwmode(wifix)
# Description: Only for hwmode
# Author: Yuyaowen
_get_hwmode() {
	local device=$1
	local hwmode=
	local htmode=
	config_get hwmode "$device" hwmode auto
	config_get htmode "$device" htmode auto

	case "$hwmode:$htmode" in
		*ng:HT20) hwmode=11NGHT20;;
		*ng:HT40-) hwmode=11NGHT40MINUS;;
		*ng:HT40+) hwmode=11NGHT40PLUS;;
		*ng:HT40) hwmode=11NGHT40;;
		*ng:*) hwmode=11NGHT20;;
		*na:HT20) hwmode=11NAHT20;;
		*na:HT40-) hwmode=11NAHT40MINUS;;
		*na:HT40+) hwmode=11NAHT40PLUS;;
		*na:HT40) hwmode=11NAHT40;;
		*na:*) hwmode=11NAHT40;;
		*ac:HT20) hwmode=11ACVHT20;;
		*ac:HT40+) hwmode=11ACVHT40PLUS;;
		*ac:HT40-) hwmode=11ACVHT40MINUS;;
		*ac:HT40) hwmode=11ACVHT40;;
		*ac:HT80) hwmode=11ACVHT80;;
		*ac:*) hwmode=11ACVHT80;;
		*b:*) hwmode=11B;;
		*bg:*) hwmode=11G;;
		*g:*) hwmode=11G; pureg=1;;
		*a:*) hwmode=11A;;
		*) hwmode=AUTO;;
	esac
	
	echo $hwmode
}

# Function: radio_updat_qcawifi(wifix, option1, val1, option2, val2, ...)
# Description: Only config changed options instead of wifi reload.
# Author: Yuyaowen
radio_update_qcawifi() {
	local DOL='$'
	radio=$1
	radio_id=${radio#wifi}
	all_exist_vap=`iwconfig 2>/dev/null |grep -E "ath$radio_id|athscan$radio_id" |awk '{print $1}' |sort -u`

	shift
	args=$@
	arg_num=$#

	for ifname in $all_exist_vap
	do
		i=1
		hwmod="0"
		while [ $i -le $# ]
		do
			opt=$(eval echo "$DOL$i")
			i=`expr $i + 1`
			val=$(eval echo "$DOL$i")
			i=`expr $i + 1`

			if [ "$opt" = "txpower" -o "$opt" = "channel" ]; then
				bin_cmd='iwconfig'
				if [ "$opt" = "txpower" ]; then
					if [ "$val" = "auto" ]; then
						[ "$radio" = "wifi0" ] && {
						        sed -i "s/wifi0_atp_enable=0/wifi0_atp_enable=1/g" /etc/ath/drm.conf
						}
						[ "$radio" = "wifi1" ] && {
						        sed -i "s/wifi1_atp_enable=0/wifi1_atp_enable=1/g" /etc/ath/drm.conf
						}
						bin_cmd=
					else
						[ "$radio" = "wifi0" ] && {
						        sed -i "s/wifi0_atp_enable=1/wifi0_atp_enable=0/g" /etc/ath/drm.conf
						}
						[ "$radio" = "wifi1" ] && {
						        sed -i "s/wifi1_atp_enable=1/wifi1_atp_enable=0/g" /etc/ath/drm.conf
						}
					fi
				elif [ "$opt" = "channel" ]; then
					if [ "$val" = "auto" ]; then
						[ "$radio" = "wifi0" ] && {
							sed -i "s/wifi0_acs_enable=0/wifi0_acs_enable=1/g" /etc/ath/drm.conf
						}
						[ "$radio" = "wifi1" ] && {
							sed -i "s/wifi1_acs_enable=0/wifi1_acs_enable=1/g" /etc/ath/drm.conf
						}
						bin_cmd=
					else
						[ "$radio" = "wifi0" ] && {
							sed -i "s/wifi0_acs_enable=1/wifi0_acs_enable=0/g" /etc/ath/drm.conf
						}
						[ "$radio" = "wifi1" ] && {
							sed -i "s/wifi1_acs_enable=1/wifi1_acs_enable=0/g" /etc/ath/drm.conf
						}
					fi
				fi
			elif [ "$opt" = "hwmode" -o "$opt" = "htmode" -o "$opt" = "bcnburst" -o "$opt" = "bintval" -o "$opt" = "shortgi" ]; then
				bin_cmd='iwpriv'

				[ "$hwmod" = "1" ] && continue
				if [ "$opt" = "hwmode" -o "$opt" = "htmode" ]; then
					hwmod="1"
					val=`_get_hwmode $radio`
					opt="mode"
				fi
			elif [ "$opt" = "fixme" ]; then
				bin_cmd='wlanconfig'
			else
				continue
			fi
			[ -n "$bin_cmd" ] && `$bin_cmd "$ifname" "$opt" "$val"`
		done
	done
}

# Function: global_qcawifi(attribute, name, val, active)
# Description: This function will take immediate action, attr: option/list, name: such as maclist/hidden, active: add/del
# Author: Yuyaowen
global_qcawifi() {
	attr=$1
	name=$2
	val=$3
	active=$4

	local all_ifname=`iwconfig 2>/dev/null |egrep ath |awk '{print $1}'`
#	config_load wireless
	
	for ifname in $all_ifname
	do
		if [ "$attr" = "option" ]; then
			if [ "$name" = "macfilter" ]; then
				case "$val" in
					allow) val=1 ;;
					deny) val=2 ;;
					*) [ -n "$maclist" ] && val=2 ;;
				esac
				bin_cmd="iwpriv"
				name="maccmd"
			fi
			`$bin_cmd "$ifname" "$name" "$val"`
		elif [ "$attr" = "list" ]; then
			if [ "$active" = "add" ]; then
				[ "$name" = "maclist" ] && iwpriv $ifname addmac $val
			elif [ "$active" = "del" ]; then
				[ "$name" = "maclist" ] && iwpriv $ifname delmac $val
			fi
		fi
	done
}
