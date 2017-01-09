#!/bin/sh

 cd /www/internal_portal/

get_brwan_interface_ip()
{
	ifconfig br-wan | awk -F'addr:|Bcast' '/Bcast/{print $2}' | awk {'print $1'}
}

while [ 1 ]
do
	BRWAN_IP=$(get_brwan_interface_ip)
	tmp=`grep :8080 portal_account_login.html | cut -d / -f3 | awk -F ":8080" '{print $1}' | head -1`
#	echo "DEBUG: br-wan interface ip address is $BRWAN_IP"
#	echo "DEBUG: portal login url interface ip address is $tmp"
	if [  "$BRWAN_IP" = "" ];then
#		echo "DEBUG: br-wan interface ip address is null"
		sleep 5
		continue
	fi
	if [ "$BRWAN_IP" = "192.168.1.254" ];then
#		echo "DEBUG: br-wan interface ip address is 192.168.1.254"
		sleep 5
		continue
	fi
	if [ "$BRWAN_IP" = "0.0.0.0" ];then
#		echo "DEBUG: br-wan interface ip address is 192.168.1.254"
		sleep 5
		continue
	fi
	if [ $BRWAN_IP != $tmp ];then
#		sed -i "s/http:\/\/.*:8080.*\//http:\/\/$BRWAN_IP:8080\//g" *.html
		sed -i "s/$tmp/$BRWAN_IP/g" *.html
	fi
	
	sleep 30
done
