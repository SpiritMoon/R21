#!/bin/sh
ipaddr=`ifconfig br-wan| awk -F'addr:|Bcast' '/Bcast/{print $2}'`
while true;
do
     if [ $ipaddr != `ifconfig br-wan| awk -F'addr:|Bcast' '/Bcast/{print $2}'` ];then
             /etc/init.d/eag restart
			 ipaddr=`ifconfig br-wan| awk -F'addr:|Bcast' '/Bcast/{print $2}'` 
	 fi      
     filenum=`ls -lt /var/log/eag.log  |awk '{print $5}'`
	 if [ $filenum -ge 65536 ];then
		 echo >/var/log/eag.log
	 fi
     
     logsize=`ls -lt /var/log/auth_local.log  |awk '{print $5}'`
	 if [ $logsize -ge 524288 ];then
		 echo >/var/log/auth_local.log
	 fi	 

	 sleep 30
done
