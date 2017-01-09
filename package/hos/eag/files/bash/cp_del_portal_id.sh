#!/bin/sh


CP_DNAT="CP_DNAT"
CP_FILTER="CP_FILTER"
CP_FILTER_DEFAULT="CP_F_DEFAULT"
CP_NAT_DEFAULT="CP_N_DEFAULT"

iptables -F $CP_FILTER_DEFAULT
iptables -D $CP_FILTER -j $CP_FILTER_DEFAULT
iptables -X $CP_FILTER_DEFAULT

iptables -t nat -F $CP_NAT_DEFAULT
iptables -t nat -D $CP_DNAT -j $CP_NAT_DEFAULT
iptables -t nat -X $CP_NAT_DEFAULT

iptables -D FORWARD -j $CP_FILTER
iptables -F $CP_FILTER
iptables -X $CP_FILTER

iptables -t nat -D PREROUTING -j $CP_DNAT
iptables -t nat -F $CP_DNAT
iptables -t nat -X $CP_DNAT

rm -rf /var/run/cpp/*

