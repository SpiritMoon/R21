#!/bin/sh
IPTABLES="iptables"
CP_DNAT="CP_DNAT"

if [ ! $# -eq 3 ] ; then
     echo "Usage: cp_dns_redirect.sh ADD/DEL PORTALIP  INTERFACE "
     exit 1;
fi


CP_IP=$2
CP_INTF=$3

CP_NAT_DEFAULT="CP_N_DEFAULT_"$CP_INTF

case $1 in
	add)	
		$IPTABLES -nL $CP_NAT_DEFAULT -t nat > /dev/null 2>&1
		if [  $? -eq 0 ];then
			count=` iptables -t nat -nL $CP_NAT_DEFAULT |wc -l`
			count=$(( $count - 4 ))
			iptables -t nat -I $CP_NAT_DEFAULT $count -p udp --dport 53 -j DNAT --to-destination ${CP_IP}:3993	
		fi
		;;
	del)
		$IPTABLES -nL $CP_NAT_DEFAULT -t nat > /dev/null 2>&1
		if [  $? -eq 0 ];then
			iptables -t nat -D $CP_NAT_DEFAULT -p udp --dport 53 -j DNAT --to-destination ${CP_IP}:3993
		fi
		;;
esac
