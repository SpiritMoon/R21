#!/bin/sh

DHCP_VENDOR_CLASS="/tmp/ztp_server_indentifer"
DHCP_TFTP_SERVER_NAME="/tmp/ztp_server_addr"
DHCP_BOOT_FILE="/tmp/ztp_instruction_name"

LLDPCTL="/usr/sbin/lldpctl"

DEFAULT_VLAN_INFO=1
CURRENT_VLAN_INFO=$DEFAULT_VLAN_INFO
BEFORE_VLAN_INFO=0

FIRMWARE_DESC_FILE=""
FIRMWARE_PATH=""
CONFIG_FILE=""

version=0
country=`/usr/sbin/showsysinfo |grep Country|awk -F ':' '{print$2}'`
model=`/usr/sbin/showsysinfo |grep 'Device Model'|awk -F ':' '{print$2}'`
vendorclass="HAP.$version-$model-$country"

check_ztp_dhcp_info()
{
	if [ ! -f "$DHCP_TFTP_SERVER_NAME" ] || [ ! -f "$DHCP_BOOT_FILE" ]; then
		return $GET_LLDP_VLAN
	fi
	
	if [ -f "$DHCP_VENDOR_CLASS" ]; then
		local server_indent="`cat $DHCP_VENDOR_CLASS`" > /dev/null 2>&1
	fi
	
	local server_url="`cat $DHCP_TFTP_SERVER_NAME`" > /dev/null 2>&1
	local file_name="`cat $DHCP_BOOT_FILE`" > /dev/null 2>&1

	if [ -z "$server_url" ] || [ -z "$file_name" ]; then
		ztp_log "get dhcp info error,remove dhcp info files,try again!"
		rm -rf $DHCP_VENDOR_CLASS
		rm -rf $DHCP_TFTP_SERVER_NAME
		rm -rf $DHCP_BOOT_FILE
		return $GET_LLDP_VLAN
	fi
	
	INSTRUCTION_FILE_NAME=$file_name
	SERVER_ADDRESS=$server_url
	SERVER_IDENTIFIER=$server_indent
	
	ztp_log "get_ztp_dhcp_info:"
	ztp_log "Instruct file name:   $INSTRUCTION_FILE_NAME"
	ztp_log "Server indentifer:    $SERVER_IDENTIFIER"
	ztp_log "Server addr:          $SERVER_ADDRESS"
	
	return $DOWN_INSTRUCTION_FILE
}

check_ztp_lldp_info()
{

	local lldp_vlan=`$LLDPCTL |grep VLAN| awk -F'[/:]' '{print$2}'|head -1`
	
	if [ -z "$lldp_vlan" ]; then
		#before no create vlan iface
		if [ "$BEFORE_VLAN_INFO" -eq 0 ]; then
			del_ztp_interface
			create_ztp_interface
		fi
		return $CHECK_FIRSTBOOT
	fi
		
	CURRENT_VLAN_INFO="`echo $lldp_vlan |sed s/[[:space:]]//g`"
	vlan=`echo $CURRENT_VLAN_INFO | sed -e 's/[0-9]//g'`

	if [ -n "$vlan" ] || [ "$CURRENT_VLAN_INFO" -gt 4096 ]; then
		#before no create vlan iface
		ztp_log "get error vlan [$CURRENT_VLAN_INFO], use default vlan $DEFAULT_VLAN_INFO"
		CURRENT_VLAN_INFO=$DEFAULT_VLAN_INFO
		if [ "$BEFORE_VLAN_INFO" -eq 0 ]; then
			del_ztp_interface
			create_ztp_interface
		fi
		return $CHECK_FIRSTBOOT
	fi

	if [ "$CURRENT_VLAN_INFO" != "$BEFORE_VLAN_INFO" ]; then
		ztp_log "get new vlan [$CURRENT_VLAN_INFO]"
		del_ztp_interface
		create_ztp_interface
	fi
	
	return $CHECK_FIRSTBOOT
}

create_ztp_interface()
{
	if [ -z "$CURRENT_VLAN_INFO" ] || [ "$CURRENT_VLAN_INFO" -eq 0 ] || [ "$CURRENT_VLAN_INFO" -eq "$BEFORE_VLAN_INFO" ]; then
		return
	fi
	
	local vlan_interface="eth0.$CURRENT_VLAN_INFO"
	local br_vlan_interface="br-vlan$CURRENT_VLAN_INFO"
	
	ztp_log "create ztp interface $br_vlan_interface"
	
	vconfig add eth0 $CURRENT_VLAN_INFO
	#vconfig set_flag $vlan_interface 1 1
	brctl addbr $br_vlan_interface
	brctl addif $br_vlan_interface $vlan_interface
	ifconfig $vlan_interface up
	ifconfig $br_vlan_interface up
	#udhcpc -p /var/run/udhcpc-$br_vlan_interface.pid -s /usr/share//udhcpc/default.script -V ale.han-ap.$MODEL -f -t 0 -i $br_vlan_interface -C &  > /dev/null 2>&1
	/sbin/udhcpc -p /var/run/udhcpc-$br_vlan_interface.pid -s /lib/netifd/dhcp.script -V $vendorclass -f -t 0 -i $br_vlan_interface -C &  > /dev/null 2>&1
	
	BEFORE_VLAN_INFO=$CURRENT_VLAN_INFO
}

del_ztp_interface()
{
	if [ -z "$BEFORE_VLAN_INFO" ] || [ "$BEFORE_VLAN_INFO" -eq 0 ]; then
		return
	fi
	
	local vlan_interface="eth0.$BEFORE_VLAN_INFO"
	local br_vlan_interface="br-vlan$BEFORE_VLAN_INFO"
	
	ztp_log "del ztp vlan[$CURRENT_VLAN_INFO] interface $br_vlan_interface"
	
	pid=`cat /var/run/udhcpc-$br_vlan_interface.pid`
	
	if [ -n "$pid" ]; then
		kill $pid
	fi
	ifconfig $vlan_interface down
	ifconfig $br_vlan_interface down
	brctl delif $br_vlan_interface $vlan_interface
	brctl delbr $br_vlan_interface
	vconfig rem $vlan_interface

	BEFORE_VLAN_INFO=0
}

download_instruction_file()
{
	if [ -z "$INSTRUCTION_FILE_NAME" ] || [ -z "$SERVER_ADDRESS" ]; then
		ztp_log "get dhcp info error,exit ztp!"
		return $ZTP_QUIT
	fi
	
	echo "$SERVER_ADDRESS" | grep -q ":"
	if [ $? -eq 0 ]; then
		echo "$SERVER_ADDRESS$INSTRUCTION_FILE_NAME" | grep -q "/"
		if [ $? -eq 0 ]; then
			url_file="https://$SERVER_ADDRESS$INSTRUCTION_FILE_NAME"
		else
			url_file="https://$SERVER_ADDRESS/$INSTRUCTION_FILE_NAME"
		fi
	else
		echo "$SERVER_ADDRESS/$INSTRUCTION_FILE_NAME" | grep -q "/tpcfg/"
		if [ $? -eq 0 ]; then
			url_file="http://$SERVER_ADDRESS$INSTRUCTION_FILE_NAME"
		else
			url_file="tftp://$SERVER_ADDRESS/$INSTRUCTION_FILE_NAME"
		fi
	fi
	
	download_url_file $url_file
	
	if [ $? -eq 0 ]; then
		return $INTERPRET_INSTRUCTION_FILE
	else
		return $ZTP_QUIT
	fi
}

interpret_instruction_file()
{
	INSTRUCTION_FILE_NAME=`echo $INSTRUCTION_FILE_NAME|sed 's/.*\///'`

	if [ ! -f "$INSTRUCTION_FILE_NAME" ]; then
		ztp_log "the instruction file $INSTRUCTION_FILE_NAME cannot be found"
		return $ZTP_QUIT
	fi
	
	ztp_log "interpret instruction file $INSTRUCTION_FILE_NAME"

	SAVEIFS=$IFS  
	#assign new separator to IFS
	IFS=[:\"]
	while read name value
        do
		if [ "$name" = "" ] || [ "$value" = "" ]; then
			continue;
		fi
		case  "$name"  in   
		"imgdesc")
			#FIRMWARE_DESC_FILE="`echo $value |sed s/[[:space:]]//g`"
			firmware_desc_file=$value
			continue
			;;
		"imgurlhead")
			#FIRMWARE_PATH="`echo $value |sed s/[[:space:]]//g`"
			firmware_path=$value
			continue
			;;
		"conf")
			#CONFIG_FILE="`echo $value |sed s/[[:space:]]//g`"
			config_file=$value
			continue
			;;
		*)
			continue
			;;
		esac
	done < $INSTRUCTION_FILE_NAME
	IFS=$SAVEIFS

	#Remove the semicolon and Quotes
	FIRMWARE_DESC_FILE="`echo $firmware_desc_file |awk -F '\"' '{print$2}'|sed s/[[:space:]]//g`"
	FIRMWARE_PATH="`echo $firmware_path |awk -F '\"' '{print$2}'|sed s/[[:space:]]//g`"
	CONFIG_FILE="`echo $config_file |awk -F '\"' '{print$2}'|sed s/[[:space:]]//g`"
	
	ztp_log "Firmware desc file:   $FIRMWARE_DESC_FILE"
	ztp_log "Firmware url head:    $FIRMWARE_PATH"
	ztp_log "Config filename:      $CONFIG_FILE"

	return $CONFIGURATION_MANAGEMENT
}
