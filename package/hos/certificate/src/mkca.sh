#!/bin/ash


ROOT_PASSWD=""
TIME_OUT=7300
CERT_DIR=/etc/cert
OPENSSL_CNF=$CERT_DIR/han-openssl.cnf
TMP_DIR=/tmp/openssl/
CERT_FILE=$CERT_DIR/server.pem
SERIAL_FILE=$CERT_DIR/serial

# for safety
mask_backup=`umask`
umask 0077
mkdir $TMP_DIR
umask $mask_backup

cd $TMP_DIR
cp $OPENSSL_CNF openssl.cnf -f

echo "DNS.1       = `showurlinfo`" >> openssl.cnf
IP=$(ifconfig br-wan|awk -F ':' '/inet addr:/ {print $2}'|awk '{print $1}')
echo "IP.1       =$IP" >> openssl.cnf
IP=$(ifconfig br-wan:0|awk -F ':' '/inet addr:/ {print $2}'|awk '{print $1}')
test -z $IP || echo "IP.2       =$IP" >> openssl.cnf
sed -i "s/default_days.*$/default_days  = $TIME_OUT/p" openssl.cnf

mkdir newcerts
touch index.txt
test -f $SERIAL_FILE || showsysinfo|fgrep MAC|awk -F : '{print $2 $3 $4 $5 $6 $7 "000000"}' > $SERIAL_FILE

cp $SERIAL_FILE .


openssl req -sha256 -new -newkey rsa:2048 -nodes -out ap.csr -keyout ap.key -subj "/C=US/ST=CA/L=Calabasas/O=ALE/CN=OmniAccess AP R2.1/OU=ALE Network Division" -config openssl.cnf


expect << EOF
set timeout 100
spawn openssl ca -config openssl.cnf -out final.crt -infiles ap.csr
expect "\[y/n\]"
send "y\r"
expect "\[y/n\]"
send "y\r"
expect eof
EOF

if [ $(wc -L $SERIAL_FILE|awk '{print $1}') -gt 6 ]; then
	cp serial $SERIAL_FILE -f
fi

/etc/init.d/lighttpd stop
LIGHTTPD_STOP_SUCCESS=$?


if [ -f ap.key -a -f final.crt ]; then
	chmod 600 $CERT_FILE
	cat ap.key final.crt > $CERT_FILE
	chmod 400 $CERT_FILE
fi

# when at boot stage, it's blocking here and lighttpd is not started, otherwise lighttped is stopped.
if [ $LIGHTTPD_STOP_SUCCESS -eq 0 ]; then
	/etc/init.d/lighttpd start
fi

cd /tmp
rm -rf $TMP_DIR

