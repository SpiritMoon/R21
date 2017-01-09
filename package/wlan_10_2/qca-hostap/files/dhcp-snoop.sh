dhcp_snp_setup_vif() {
    local vif="$1" && shift
	local ifname
	
	config_get ifname "$vif" ifname
	if [[ "$ifname" = athscan0 ]] ||
		[[ "$ifname" = athscan1 ]]; then
		return
	fi
	echo dhcp_snp_setup_vif $ifname
	
	iptables -nL dhcp_snp_rule >/dev/null 2>&1
	if [ $? -eq 0 ];then
		iptables -I dhcp_snp_rule -p udp --dport 68 -m physdev --physdev-in $ifname --physdev-is-bridged -j DROP >/dev/null 2>&1
	else 
		iptables -N dhcp_snp_rule >/dev/null 2>&1
		iptables -I FORWARD -j dhcp_snp_rule >/dev/null 2>&1
		iptables -I dhcp_snp_rule -p udp --dport 68 -m physdev --physdev-in $ifname --physdev-is-bridged -j DROP >/dev/null 2>&1
	fi
}


dhcp_snp_remove_vif() {
    local ifname="$1" && shift

	if [[ "$ifname" = athscan0 ]] ||
		[[ "$ifname" = athscan1 ]]; then
		return
	fi

	echo dhcp_snp_remove_vif $ifname
	iptables -D dhcp_snp_rule -p udp --dport 68 -m physdev --physdev-in $ifname --physdev-is-bridged -j DROP >/dev/null 2>&1
}
