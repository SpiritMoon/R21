#!/bin/sh

CRONTAB_PATH=/etc/crontabs/root
crontab -l | grep account_expire_check.sh
if [ ! $? -eq 0 ];then
	echo "59  23  *  *  *  /usr/sbin/account_expire_check.sh" >> $CRONTAB_PATH
fi
