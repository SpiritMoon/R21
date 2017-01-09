#!/bin/sh

IFACE_ID=1

. /lib/functions.sh
. /lib/functions/procd.sh

SETPRODUCT="/usr/sbin/setproductinfo"
SYSUPGRADE="/sbin/osupgrade"
CLUSTERCFG="/usr/bin/cluster-cfg"
CLUSTERCLI="/usr/bin/cluster_cli"
CONFIG_WLAN="config_wlan"
MD5="/usr/bin/md5sum"

IFACESSID=""
IFACETYPE=""

set_ap_config()
{
	local countrycode
	local password

	config_get countrycode $1 countrycode
	config_get password $1 password
	config_get clustervip $1 clustervip
	
	
	ztp_log "country: $countrycode"
	ztp_log "password: $password"
	ztp_log "cluster.ip: $clustervip"
	
	if [ ! -z "$password" ]; then
		value=`echo -n "$password"|$MD5|cut -d ' ' -f1`
		$CLUSTERCFG set system.Administrator.password=$value
	fi
	
	if [ ! -z "$countrycode" ]; then
		$CLUSTERCFG set wireless.wifi0.country=$countrycode
		$CLUSTERCFG set wireless.wifi1.country=$countrycode
	fi
	
	if [ ! -z "$clustervip" ]; then
		$CLUSTERCFG set cluster.cluster.cluster_vip=$clustervip
	fi
	
}

set_network_config_extension()
{
	local network=$1
	
	vlan=`echo ${network#*vlan}`
	vlan_id=`echo $vlan | sed -e 's/[0-9]//g'`
	
	#create vlan interface
	if [ -z "$vlan_id" ]; then
		ztp_log "create network vlan[$vlan] interface"
		
		if [ "$vlan" -gt 4094 ] || [ "$vlan" -lt 1 ]; then
			ztp_log "vland id is invalid or out of range [$vlan]"
			return                                      
		fi
		
		$CONFIG_WLAN edit_wlan ssid "$IFACESSID" "vlan" "$vlan" noflush
	fi
	
}

set_firmware_config()
{
	local version
	local filename
	local md5
	local file_ver
	
	ztp_log "MODEL: $MODEL   $1"
	
	if [ $MODEL != $1 ]; then
		return
	fi
	
	config_get version $1 version
	config_get filename  $1 filename
	config_get md5 $1 md5

	ztp_log "firmware.version:    $version" 
	ztp_log "firmware.filename:   $filename"
	ztp_log "firmware.md5:        $md5"
	
	if [ -z $filename ] || [ "$filename" = "None" ]; then
		ztp_log "image name is empty"
		return
	fi
	
	if [ "$version" = "$VER_ID" ]; then
		ztp_log "current system version is : $VER_ID, not need to sysupgrade"
		return
	fi
	
	if [ "$FIRMWARE_PATH" = "None" ] || [ "$FIRMWARE_PATH" = "" ]; then
		file_location=$filename
	else
		file_location=$FIRMWARE_PATH$filename
	fi
	
	download_url_file $file_location
	
	if [ $? -eq 1 ]; then
		ztp_log "downloading firmware image file failed!"
		return
	fi
	
	file_ver=`firmware-hd "$filename" | grep version | awk -F ':' '{print $2}'`
	
	ztp_log "fw version is $file_ver"
	
	if [ "$file_ver" = "$VER_ID" ]; then
		ztp_log "current system version is : $VER_ID, fw version is $file_ver, it does not need to sysupgrade and del fw"
		rm -rf $filename
		return
	fi
	
	ztp_log "sysupgrade firmware ..."
	
	$SYSUPGRADE $filename
}


configuration_file_management()
{
	if [ "$CONFIG_FILE" = "None" ]; then
		return $SYSUPGRADE_MANAGEMENT
	fi
	
	#remove file path 
	local file_location=`echo $CONFIG_FILE|sed 's/.*\///'`
	
	download_url_file $CONFIG_FILE
	
	if [ $? -eq 1 ]; then
		ztp_log "downloading configuration file $file_location failed!"
		return $SYSUPGRADE_MANAGEMENT
	fi
	
	# Once again to confirm whether the configuration changes
	check_config_enable
	if [ "$?" = "$ZTP_QUIT" ]; then
		ztp_log "configuration changes, exit configuration management"
		return $ZTP_QUIT
	fi
	
	ztp_log "interpret confiuration file $file_location"
	
	#copy uci file format
	cp $file_location $UCI_CONFIG_FILE
	
	config_cb() {
		option_cb() {
			return 0
		}
		
		IFACETYPE=$2
		case "$1" in
			wifi-iface)
				option_cb() {
					case "$1" in
						ssid)
							IFACESSID="$2"
							$CONFIG_WLAN add_wlan ssid "$IFACESSID" freq "2G" device "wifi0"
							$CONFIG_WLAN add_wlan ssid "$IFACESSID" freq "5G" device "wifi1"
							$CONFIG_WLAN edit_wlan ssid "$IFACESSID" network_type "$IFACETYPE" noflush
						;;
						key)
							local key_scvt=`scvt enc "$2"`
							$CONFIG_WLAN edit_wlan ssid "$IFACESSID" encryption psk2+ccmp noflush
							$CONFIG_WLAN edit_wlan ssid "$IFACESSID" "key" "$key_scvt" noflush
						;;
					esac
					
					ztp_log "	$IFACESSID  $1 $2"
					
					case "$1" in
						network)
							set_network_config_extension "$2"
						;;
						key)
							local key_scvt=`scvt enc "$2"`
							$CONFIG_WLAN edit_wlan ssid "$IFACESSID" "key" "$key_scvt" noflush
						;;
						*)
							$CONFIG_WLAN edit_wlan ssid "$IFACESSID" "$1" "$2" noflush
						;;
					esac
				}
			;;
			*)
				option_cb() { return 0; }
			;;
		esac
	}
	
	config_load "$UCI_CONFIG_FILE"
	config_foreach set_ap_config ap
	
	# final confirm whether the configuration changes
	check_firstboot
	if [ "$?" = "$ZTP_QUIT" ]; then
		ztp_log "configuration complete, restart later"
		REBOOT_FLAG=1
	else
		ztp_log "configuration fail or no complete, enter sysupgrade management"
		REBOOT_FLAG=0
	fi

	`$SET_CONF_UNLOCK` > /dev/null 2>&1

	return $SYSUPGRADE_MANAGEMENT
}


firmware_file_management()
{
	if [ "$FIRMWARE_DESC_FILE" = "None" ]; then
		return $ZTP_QUIT
	fi
	
	#remove file path
	local file_location=`echo $FIRMWARE_DESC_FILE|sed 's/.*\///'`

	download_url_file $FIRMWARE_DESC_FILE
	
	if [ $? -eq 1 ]; then
		ztp_log "downloading firmware file $file_location failed!"
		return $ZTP_QUIT
	fi

	ztp_log "interpret firmware desc file $file_location"
	
	#copy uci file format
	cp $file_location $UCI_FIRMWARE_FILE
	
	config_load "$UCI_FIRMWARE_FILE"
	config_foreach set_firmware_config model

	return $ZTP_QUIT
}
