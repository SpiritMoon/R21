#!/bin/sh
CONFIG_FILE=/etc/config/auth_local
DEL_LIST=/var/run/del_list
grep "list userinfo" $CONFIG_FILE |awk -F "'" '{print $2}'|awk -v d=$(date +%Y.%m.%d) '{if ($9 <= d){print $0}}' >$DEL_LIST
while read myline
do
#  echo "MYLINE:$myline"
   cluster-cfg del_list auth_local.accout.userinfo="$myline"
done <$DEL_LIST
rm $DEL_LIST
/etc/init.d/auth_local.init reload
