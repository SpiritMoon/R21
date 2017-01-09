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
IPTABLES="iptables"
FW_DNAT="FW_DNAT"
CP_DNAT="CP_DNAT"
CP_FILTER="CP_FILTER"

CP_IP=$1

$IPTABLES -nL $CP_FILTER > /dev/null 2>&1
if [ ! $? -eq 0 ];then                        
    $IPTABLES -N $CP_FILTER
	$IPTABLES -nL dhcp_snp_rule > /dev/null 2>&1
	if [ $? -eq 0 ];then
		$IPTABLES -I FORWARD 2 -j $CP_FILTER
	else
    		$IPTABLES -I FORWARD -j $CP_FILTER
	fi
    $IPTABLES -A $CP_FILTER -j RETURN
fi

$IPTABLES -nL $CP_DNAT -t nat > /dev/null 2>&1
if [ ! $? -eq 0 ];then                        
    $IPTABLES -t nat -N $CP_DNAT
    $IPTABLES -t nat -I PREROUTING -j $CP_DNAT
    $IPTABLES -t nat -A $CP_DNAT -j RETURN
fi

CP_NAT_DEFAULT="CP_N_DEFAULT"

$IPTABLES -nL $CP_NAT_DEFAULT -t nat > /dev/null 2>&1
if [ ! $? -eq 0 ];then
    $IPTABLES -t nat -N $CP_NAT_DEFAULT
    $IPTABLES -t nat -I $CP_DNAT -j $CP_NAT_DEFAULT
	$IPTABLES -t nat -I $CP_NAT_DEFAULT -p udp --sport 68 --dport 67 -j ACCEPT
	$IPTABLES -t nat -I $CP_NAT_DEFAULT -p udp --sport 67 --dport 68 -j ACCEPT
	#$IPTABLES -t nat -I $CP_NAT_DEFAULT -p udp --dport 53 -m string --hex-string "|$2|" --algo bm -j ACCEPT
#	$IPTABLES -t nat -I $CP_NAT_DEFAULT -p tcp --dport 53 -j ACCEPT
#   $IPTABLES -t nat -I $CP_NAT_DEFAULT -p tcp --sport 53 -j ACCEPT
#   $IPTABLES -t nat -I $CP_NAT_DEFAULT -p udp --dport 53 -j ACCEPT
#   $IPTABLES -t nat -I $CP_NAT_DEFAULT -p udp --sport 53 -j ACCEPT
	$IPTABLES -t nat -I $CP_NAT_DEFAULT -m pkttype --pkt-type multicast -j ACCEPT
	$IPTABLES -t nat -I $CP_NAT_DEFAULT -d $CP_IP -j ACCEPT
    $IPTABLES -t nat -A $CP_NAT_DEFAULT -j RETURN
fi

CP_FILTER_DEFAULT="CP_F_DEFAULT"

$IPTABLES -nL $CP_FILTER_DEFAULT  > /dev/null 2>&1
if [ ! $? -eq 0 ];then
	iptables -N $CP_FILTER_DEFAULT
	iptables -I $CP_FILTER_DEFAULT -j RETURN
	iptables -I $CP_FILTER_DEFAULT -p udp --sport 68 --dport 67 -j ACCEPT
	iptables -I $CP_FILTER_DEFAULT -p udp --sport 67 --dport 68 -j ACCEPT
	iptables -I $CP_FILTER_DEFAULT -p tcp --dport 53 -j ACCEPT
	iptables -I $CP_FILTER_DEFAULT -p tcp --sport 53 -j ACCEPT
	iptables -I $CP_FILTER_DEFAULT -p udp --dport 53 -j ACCEPT
	iptables -I $CP_FILTER_DEFAULT -p udp --sport 53 -j ACCEPT
	iptables -I $CP_FILTER_DEFAULT -m pkttype --pkt-type multicast -j ACCEPT
	iptables -I $CP_FILTER_DEFAULT -d $CP_IP -j ACCEPT
	iptables -I $CP_FILTER -j $CP_FILTER_DEFAULT 
fi
#iptables -I $CP_FILTER_DEFAULT -d $CP_IP -j ACCEPT
#iptables -t nat -I $CP_NAT_DEFAULT -d $CP_IP -j ACCEPT
