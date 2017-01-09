#!/bin/sh

if [ ! -f /var/run/wam_ifname_file ];then
	echo "wam_ifname_file do not exsit" >> /var/log/wam_err_log
	exit 1
fi

all_ifname=`cat /tmp/run/wam_ifname_file`

for ifname in $all_ifname

do
	i=1
	while true
	do
		ps | grep /sbin/wifi | grep -v grep
                
		if [ $? -eq 0 ];then        
                        break;
                fi		
	
		ps -w | grep wam-$ifname | grep -v grep > /dev/null

		if [ $? -eq 0 ];then
			break;
		else
			if [ $i -gt 6 ];then
				echo "WAM module cannot load, need reboot." >> /var/log/wam_err_log
				logger -t wam -p 2 "WAM module cannot load, need reboot."
				#touch /tmp/wam-crash
				break
			fi
			echo ======================================================== >> /var/log/wam_err_log
			date >> /var/log/wam_err_log
			echo  wam-$ifname is not running >> /var/log/wam_err_log
			iwconfig 2>/dev/null | grep $ifname
                        if [ $? -ne 0 ];then
                        echo $ifname don not be created >> /var/log/wam_err_log
                        iwconfig >> /var/log/wam_err_log
			fi
			brctl show | grep $ifname
                        if [ $? -ne 0 ];then
                        echo $ifname don not be add into br-wan >> /var/log/wam_err_log
                        brctl show >> /var/log/wam_err_log
						bridge=`cat /var/run/wam-$ifname.conf | grep bridge |sed 's/bridge=//g'`
						brctl addif $bridge $ifname
						brctl show >> /var/log/wam_err_log
                        fi
			[ -f /tmp/log/wam-$ifname.log ] && tail -n 100 /tmp/log/wam-$ifname.log >> /var/log/wam_err_log
			echo ======================================================== >> /var/log/wam_err_log
			wam -P /var/run/wifi-$ifname.pid -B /var/run/wam-$ifname.conf -d -f /var/log/wam-$ifname.log
			i=$(($i+1))
		fi
		
	done	

done
 



