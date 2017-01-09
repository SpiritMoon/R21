#!/bin/sh

. /usr/sbin/ztp_get_instruction_file.sh
. /usr/sbin/ztp_configuration_management.sh

ZTP_PATH="/tmp"

GET_REV_NUM="/usr/bin/getrevnumber"
GET_CONF_LOCK="/usr/bin/cfglock"
SET_CONF_UNLOCK="/usr/bin/cfgunlock"

CONFIGURATION_STATE="/tmp/configuration_state"

ZTP_LOG="/tmp/ztp_log"

ZTP_QUIT=0
CHECK_FIRSTBOOT=1
GET_DHCP_INFO=2
GET_LLDP_VLAN=3
DOWN_INSTRUCTION_FILE=4
INTERPRET_INSTRUCTION_FILE=5
SCRIPT_MANAGEMENT=6
CONFIGURATION_MANAGEMENT=7
SYSUPGRADE_MANAGEMENT=8

REBOOT_FLAG=0

INSTRUCTION_FILE_NAME=""
SERVER_ADDRESS=""
SERVER_IDENTIFIER=""

WAITIONG_TIME=2
DOWNLOAD_TIME=10

DEVICE_MODEL=`/usr/sbin/showsysinfo|/bin/grep 'Device Model:'|/usr/bin/cut -d: -f2`
MODEL=`echo ${DEVICE_MODEL#*-}`

VER_ID=`/usr/sbin/showver`

UCI_FIRMWARE_FILE="/tmp/hap_imgdesc"
UCI_CONFIG_FILE="/tmp/hap_conf"

CERTHAN="/etc/cert/Certhan.crt"
KEYHAN="/etc/cert/Certhan.key"
CACERT="/etc/cert/CAoxo.crt"

ztp_log()
{
	#echo "$1" >>  "$ZTP_LOG"
	/usr/bin/logger -t ztp $1
}

ztp_write_config_state()
{
	echo "$1" >  "$CONFIGURATION_STATE"
	ztp_log "config state :  $1" 
}

check_firstboot()
{
	local is_firstboot

	is_firstboot="`$GET_REV_NUM`" > /dev/null 2>&1
	
	if [ -z "$is_firstboot" ]; then
		ztp_log "read revsion number is error!"
		return $ZTP_QUIT
	fi

	#check factory state
	if [ "$is_firstboot" -ne 0 ]; then
		ztp_log "[$is_firstboot] Equipment is not in factory condition"
		return $ZTP_QUIT
	fi

	return $GET_DHCP_INFO
}

check_config_enable()
{
	local is_firstboot

	is_firstboot="`$GET_REV_NUM`" > /dev/null 2>&1
	is_lock="`$GET_CONF_LOCK`" > /dev/null 2>&1
	
	if [ -z "$is_firstboot" ]; then
		ztp_log "read revsion number is error!"
		return $ZTP_QUIT
	fi

	#check factory state
	if [ "$is_firstboot" -ne 0 ]; then
		ztp_log "[$is_firstboot] Equipment is not in factory condition"
		return $ZTP_QUIT
	fi
	
	#check configuration lock
	if [ "$is_lock" = "busy" ]; then
		ztp_log "[$is_lock] Equipment is not in configuration condition"
		return $ZTP_QUIT
	fi
	
	return $GET_DHCP_INFO
}

https_download_file()
{
	local file_name=$1
	
	if [ -z "$file_name" ]; then
		ztp_log "HTTPs file name:$file_name error!"
		return 1
	fi
	
	/usr/bin/curl --cert "$CERTHAN" --key "$KEYHAN" --cacert "$CACERT" -O $file_name
	
	if [ $? -eq 0 ]; then
		stat=`/usr/bin/curl --cert "$CERTHAN" --key "$KEYHAN" --cacert "$CACERT" -I -s $file_name |grep OK`
		if [ -z "$stat" ]; then
			ztp_log "HTTPs download file $file_name Not Found"
			return 1
		else
			ztp_log "HTTPs download file $file_name success"
			return 0
		fi
	else
		ztp_log "HTTPs download file $file_name failed"
		return 1
	fi
}

tftp_download_file()
{
	local file_name=$1
	
	if [ -z "$file_name" ]; then
		ztp_log "TFTP file name:$file_name error!"
		return 1
	fi

	#tftp -gr $file_name $server_addr
	/usr/bin/curl -O $file_name
	if [ $? -eq 0 ]; then
		ztp_log "TFTP download file $file_name success"
		return 0
	else
		ztp_log "TFTP download file $file_name failed"
		return 1
	fi
}

http_download_file()
{
	local file_name=$1
	
	if [ -z "$file_name" ]; then
		ztp_log "HTTP file name:$file_name error!"
		return 1
	fi
	
	/usr/bin/curl -O $file_name
	if [ $? -eq 0 ]; then
		stat=`/usr/bin/curl -I -s $file_name |grep OK`
		if [ -z "$stat" ]; then
			ztp_log "HTTP download file $file_name Not Found"
			return 1
		else
			ztp_log "HTTP download file $file_name success"
			return 0
		fi
	else
		ztp_log "HTTP download file $file_name failed"
		return 1
	fi
}

download_url_file()
{
	local file_path=$1
	local download_retries=0
	local ret=0
	
	if [ -z $file_path ]; then
		ztp_log "downloading file name $file_path is error"
		return 1
	fi
	
	#analysis URL 
	local download_proto=`echo $file_path | awk -F':' '{print$1}'`
	local server_addr=`echo $file_path | awk -F'[/:]' '{print$4}'`
	local file_name=`echo $file_path | cut -d/ -f4-` 
	
	ztp_log "download file name:    $file_path"
	ztp_log "download file proto:   $download_proto"
	ztp_log "download file server:  $server_addr"
	ztp_log "download file patch:   $file_name"
	
	if [ -z $server_addr ] || [ -z $file_name ]; then
		ztp_log "server addr $server_addr or file name $file_name is error"
		return 1
	fi
	
	while [ $download_retries -lt $DOWNLOAD_TIME ]
	do
		case "$download_proto" in
			"tftp")
				tftp_download_file $file_path
			;;
			"https")
				https_download_file $file_path
			;;
			"http")
				http_download_file $file_path
			;;
			*)
				ztp_log "use default download proto : tftp"
				tftp_download_file $file_path
			;;
		esac
		ret=$?
		download_retries=$(( $download_retries + 1 ))
		if [ "$ret" -eq 0 ]; then
			break
		fi
		sleep $WAITIONG_TIME
	done
	
	return $ret
}


if [ -f $ZTP_LOG ]; then
	rm -rf $ZTP_LOG
fi

cd /tmp
#touch  "$ZTP_LOG"
touch  "&CONFIGURATION_STATE"

ztp_write_config_state "NONE"

NextState="$CHECK_FIRSTBOOT"
ztp_log "STATE:  WAITING TO GET THE INSTRUCTIONG FILE ..."

while true
do
	case  "$NextState"  in   
	"$CHECK_FIRSTBOOT")
		sleep $WAITIONG_TIME
		check_firstboot
	;;
	"$GET_DHCP_INFO")
		#ztp_log "STATE:  GET_DHCP_INFO"
		check_ztp_dhcp_info
	;;
	"$GET_LLDP_VLAN")
		#ztp_log "STATE:  GET_LLDP_VLAN"
		check_ztp_lldp_info
	;;
	"$DOWN_INSTRUCTION_FILE")
		ztp_log "STATE:  DOWNLOAD INSTRUCTION FILE"
		ztp_write_config_state "ZTP"
		download_instruction_file
	;;
	"$INTERPRET_INSTRUCTION_FILE")
		ztp_log "STATE:  INTERPRET INSTRUCTION FILE"
		interpret_instruction_file
	;;
	"$SCRIPT_MANAGEMENT")
		ztp_log "STATE:  SCRIPT FILE MANAGEMENT"
		script_file_management
	;;
	"$CONFIGURATION_MANAGEMENT")
		ztp_log "STATE:  CONFIGURATION FILE MANAGEMENT"
		configuration_file_management
	;;
	"$SYSUPGRADE_MANAGEMENT")
		ztp_log "STATE:  FIRMWARE FILE MANAGEMENT"
		firmware_file_management
	;;
	"$ZTP_QUIT")
		ztp_log "STATE:  ZTP QUIT"
		ztp_write_config_state "NONE"
		del_ztp_interface
		`$SET_CONF_UNLOCK` > /dev/null 2>&1
		if [ "$REBOOT_FLAG" -eq 1 ]; then
			ztp_log "STATE:  ZTP HAP REBOOT"
			/usr/sbin/reset_reason add 07
			reboot
		fi
		exit
	;;
	esac
	NextState=$?
done