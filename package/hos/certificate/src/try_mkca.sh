#!/bin/ash

# note the lock, don't exit before unlock
MKCA=/etc/cert/mkca.sh
SERVER_PEM=/etc/cert/server.pem
MKCA_MARK=0
TIME_OUT=$(grep "TIME_OUT=" $MKCA |awk -F '=' '{print $2}')
LOCKFILE=/tmp/mkca_lock

if [ $(ps -w|grep '\/cert\/mkca.sh'|grep -v grep|wc -l) -ge 2 ]; then
	exit
fi

lock $LOCKFILE

if [ ! -f $SERVER_PEM ]; then
	MKCA_MARK=1
fi

if [ $MKCA_MARK = "0" ]; then

	# ip address check
	server_list=$(openssl x509 -in $SERVER_PEM -text -noout|awk '{if(flag == 1){print $0;exit 0}; if($1 == "X509v3" && $2 == "Subject" && $3 == "Alternative" && $4 == "Name:") flag=1}')

	DNS=$(showurlinfo)
	if [ ! -z $DNS ]; then
		echo $server_list | grep $DNS -q || MKCA_MARK=1
	fi

	IP=$(ifconfig br-wan|awk -F ':' '/inet addr:/ {print $2}'|awk '{print $1}');
	if [ ! -z $IP ]; then
		# usually, 192.168.1.254 is a intermediate address.
		if [ $IP = "192.168.1.254" ]; then
			sleep 7
			IP=$(ifconfig br-wan|awk -F ':' '/inet addr:/ {print $2}'|awk '{print $1}');
		fi
	fi

	if [ ! -z $IP ]; then
		echo $server_list | grep $IP -q || MKCA_MARK=1
	fi

	if [ $MKCA_MARK = "0" ]; then
		IP=$(ifconfig br-wan:0|awk -F ':' '/inet addr:/ {print $2}'|awk '{print $1}')
		if [ ! -z $IP ]; then
			echo $server_list | grep $IP -q || MKCA_MARK=1
		fi
	fi

	# timeout check
	YEAR=$(date +%Y)
	DAY=$(date +%j)
	PEM_YEAR=$(date -r $SERVER_PEM +%Y)
	PEM_DAY=$(date -r $SERVER_PEM +%j)

	if [ $((($YEAR-$PEM_YEAR)*365+$DAY-$PEM_DAY)) -gt $TIME_OUT ]; then
		MKCA_MARK=1
	fi

fi


if [ $MKCA_MARK = "1" ]; then
	$MKCA
fi

lock -u $LOCKFILE
exit 0
