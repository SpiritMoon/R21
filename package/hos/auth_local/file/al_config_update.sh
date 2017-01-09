#!/bin/sh

CONFIG_PATH=/etc/config/auth_local
PUB_CONFIG_PATH="/etc/cfm/config/config-pub/auth_local"
PUB_CFG_DIR="/etc/cfm/config/config-pub"

accout="config user 'accout'"         
grep "$accout" $CONFIG_PATH
if [ ! $? -eq 0 ];then
    uci set auth_local.accout=user
    uci commit auth_local
fi

grep "$accout" $PUB_CONFIG_PATH
if [ ! $? -eq 0 ];then
    uci -c $PUB_CFG_DIR set auth_local.accout=user
    uci -c $PUB_CFG_DIR commit auth_local
fi
