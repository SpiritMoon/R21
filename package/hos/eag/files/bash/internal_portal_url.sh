#!/bin/sh
INTF=$1
IP=$2
[ -d /www/internal_portal/$INTF ] || mkdir /www/internal_portal/$INTF

rm /www/internal_portal/$INTF/*.html
cp /www/internal_portal/*.html /www/internal_portal/$INTF

cd /www/internal_portal/$INTF

sed -i "s/instant.alcatel-lucentnetworks.com/$IP/g" *.html
sed -i "s/internal_portal/internal_portal\/$INTF/g" *.html
