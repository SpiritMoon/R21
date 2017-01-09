LF_MAXSIZE=28672
TMP_LOG_FILE=/var/log/tmp.log

for logfile in $(ls /var/log/wam-ath*.log 2>&-); do
	wam_log_size=`ls -l $logfile | awk '{print $5}'`
	if [ $wam_log_size -ge $LF_MAXSIZE ]; then
	cp $logfile TMP_LOG_FILE
	echo > $logfile
	tail -n 200 TMP_LOG_FILE > $logfile
	rm TMP_LOG_FILE 
	fi
done

wam_activity_log_size=`ls -l /tmp/log/wam_activity | awk '{print $5}'`
if [ $wam_activity_log_size -ge 10240 ]; then
	sed -i '1,100d' /tmp/log/wam_activity
fi

wam_err_log_size=`ls -l /var/log/wam_err_log | awk '{print $5}'`
if [ $wam_err_log_size -ge 40960 ]; then
	        sed -i '1,150d' /var/log/wam_err_log
fi
