#!/bin/sh
#
###########################################################################
#
#              Copyright (C) Autelan Technology
#
#This software file is owned and distributed by Autelan Technology 
#
############################################################################
#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
#ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
#WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
#DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR 
#ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
#(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
#LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
#ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
#(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
#SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##############################################################################
#
# eag_init
#
# CREATOR:
# autelan.software.shaojunwu. team
# 
# DESCRIPTION: 
#    init $IPTABLES bash chain!!!
#    for firewall captive portal and asd prev auth
#  filter like!!!
#Chain INPUT (policy ACCEPT 5891 packets, 640047 bytes)
#    pkts      bytes target     prot opt in     out     source               destination         
#
#Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
#    pkts      bytes target     prot opt in     out     source               destination         
#       0        0 ASD_FILTER  0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#       0        0 CP_FILTER  0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#       0        0 FW_FILTER  0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain OUTPUT (policy ACCEPT 1777 packets, 940641 bytes)
#    pkts      bytes target     prot opt in     out     source               destination         
#
#Chain ASD_FILTER (1 references)
#    pkts      bytes target     prot opt in     out     source               destination         
#       0        0 RETURN     0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain CP_FILTER (1 references)
#    pkts      bytes target     prot opt in     out     source               destination         
#       0        0 RETURN     0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain FW_FILTER (1 references)
#    pkts      bytes target     prot opt in     out     source               destination         
#       0        0 TRAFFIC_CONTROL  0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#       0        0 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain TRAFFIC_CONTROL (1 references)
#    pkts      bytes target     prot opt in     out     source               destination
#       0        0 RETURN     0    --  *      *       0.0.0.0/0            0.0.0.0/0
#  nat like!!!
#sh-3.1# /opt/bin/$IPTABLES -t nat -nvxL
#Chain PREROUTING (policy ACCEPT 2 packets, 96 bytes)
#    pkts      bytes target     prot opt in     out     source               destination         
#    3877   330542 ASD_DNAT   0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#    3877   330542 CP_DNAT    0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#    4345   373105 FW_DNAT    0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain POSTROUTING (policy ACCEPT 1 packets, 69 bytes)
#    pkts      bytes target     prot opt in     out     source               destination         
#      11     2346 FW_SNAT    0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain OUTPUT (policy ACCEPT 12 packets, 2415 bytes)
#    pkts      bytes target     prot opt in     out     source               destination         
#
#Chain ASD_DNAT (1 references)
#    pkts      bytes target     prot opt in     out     source               destination         
#    3877   330542 RETURN     0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain CP_DNAT (1 references)
#    pkts      bytes target     prot opt in     out     source               destination         
#    3870   330178 RETURN     0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain FW_DNAT (1 references)
#    pkts      bytes target     prot opt in     out     source               destination         
#    4343   373009 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain FW_SNAT (1 references)
#    pkts      bytes target     prot opt in     out     source               destination         
#      11     2346 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#
#############################################################################
IPTABLES="iptables"
CP_DNAT="CP_DNAT"

if [ ! $# -eq 3 ] ; then
     echo "Usage: cp_create_profile.sh  PORTALIP PORTALPORT INTERFACE "
     exit 1;
fi


CP_IP=$1
CP_PORT=$2
CP_INTF=$3

CP_NAT_DEFAULT="CP_N_DEFAULT_"$CP_INTF
CP_ID_FILE="/var/run/cpp/CP_"$CP_INTF

[ -d /var/run/cpp ] || mkdir /var/run/cpp

if [ -e $CP_ID_FILE ] ; then 
    ip=$(cat $CP_ID_FILE)
    echo "Captive Portal Profile already exist with PORT ${ip}"
    exit 4;
fi
printf "${CP_PORT}" > $CP_ID_FILE

$IPTABLES -nL $CP_NAT_DEFAULT -t nat > /dev/null 2>&1
if [ ! $? -eq 0 ];then
	iptables -t nat -N $CP_NAT_DEFAULT
	iptables -t nat -I $CP_NAT_DEFAULT -j RETURN
	iptables -t nat -I $CP_NAT_DEFAULT -p tcp -m tcp --dport 80 -m physdev --physdev-in $CP_INTF -j DNAT --to-destination ${CP_IP}:${CP_PORT}
	iptables -t nat -I $CP_NAT_DEFAULT -p tcp -m tcp --dport 8080 -m physdev --physdev-in $CP_INTF -j DNAT --to-destination ${CP_IP}:${CP_PORT}
	#iptables -t nat -I $CP_NAT_DEFAULT -p udp --dport 53 -j DNAT --to-destination ${CP_IP}:3993	
	#iptables -t nat -I $CP_NAT_DEFAULT -p tcp -m tcp --dport 443 -j DNAT --to-destination ${CP_IP}:${CP_PORT}
fi


