#!/bin/sh
if [ -d /var/run/cpp ] && [ `ls /var/run/cpp |wc -l` -eq 0 ];then
	exit 0;
fi

if [ ! -d /var/run/cpp ];then
	exit 0;
fi

CP_DNAT="CP_DNAT"
CP_FILTER="CP_FILTER"
CP_FILTER_DEFAULT="CP_F_DEFAULT"
CP_NAT_DEFAULT="CP_N_DEFAULT"

iptables -F $CP_FILTER_DEFAULT
iptables -D $CP_FILTER -j $CP_FILTER_DEFAULT
iptables -X $CP_FILTER_DEFAULT

iptables -t nat -F $CP_NAT_DEFAULT
iptables -t nat -D $CP_DNAT -j $CP_NAT_DEFAULT
iptables -t nat -X $CP_NAT_DEFAULT

iptables -F CP_FILTER
iptables -t nat -F CP_DNAT

intf=`ls /var/run/cpp/ |grep CP_IF_INFO |cut -d "_" -f 4`
for x in $intf;do
	CP_F_IF=CP_F_$x
	CP_F_IF_IN="$CP_F_IF"_IN
	iptables -F $CP_F_IF                        
	iptables -X $CP_F_IF                         
	iptables -F $CP_F_IF_IN
	iptables -X $CP_F_IF_IN
	iptables -t nat -F "CP_N_DEFAULT_$x"
	iptables -t nat -X "CP_N_DEFAULT_$x"
done

#iptables -F ${CP_FILTER_AUTH_IF}
#iptables -X ${CP_FILTER_AUTH_IF}

#iptables -F ${CP_FILTER_AUTH_IF_IN}
#iptables -X ${CP_FILTER_AUTH_IF_IN}

#iptables -t nat -F ${CP_NAT_DEFAULT_IF}
#iptables -t nat -X ${CP_NAT_DEFAULT_IF}

iptables -D FORWARD -j CP_FILTER
iptables -t nat -D PREROUTING -j CP_DNAT

iptables -X ${CP_FILTER}
iptables -t nat -X ${CP_DNAT}


rm -rf /var/run/cpp/CP_* 
