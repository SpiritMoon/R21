#!/bin/sh
IPTABLES="iptables"
CP_NAT_DEFAULT="CP_N_DEFAULT"

case $1 in
	add)
		$IPTABLES -nL $CP_NAT_DEFAULT -t nat > /dev/null 2>&1
		if [  $? -eq 0 ];then
			$IPTABLES -t nat -I $CP_NAT_DEFAULT -p udp --dport 53 -m string --hex-string "|$2|" --algo bm -j ACCEPT
		fi
		;;
	del)
		$IPTABLES -nL $CP_NAT_DEFAULT -t nat > /dev/null 2>&1
		if [  $? -eq 0 ];then
			$IPTABLES -t nat -D $CP_NAT_DEFAULT -p udp --dport 53 -m string --hex-string "|$2|" --algo bm -j ACCEPT
		fi
	  	;;
esac	
