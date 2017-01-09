/*
 * arp-proxy
 * Copyright (c) 2016-2017, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <syslog.h>
#include <syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stddef.h>
#include <sys/wait.h>

#include <net/if.h>
#include <sys/ioctl.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include <linux/netlink.h>
#include <netinet/in.h>

#include "common.h"
#include "eloop.h"
#include "debug.h"
#include "arp_proxy.h"
#include "l2_packet.h"
#include "arpp_tbl.h"

struct sockaddr_nl arpp_src_addr, arpp_dest_addr;
struct nlmsghdr *arpp_nlh = NULL;
struct iovec arpp_iov;
struct msghdr arpp_nl_msghdr;


int linux_br_get(char *brname, const char *ifname)
{
	char path[128], brlink[128], *pos;
	os_snprintf(path, sizeof(path), "/sys/class/net/%s/brport/bridge",
		    ifname);
	os_memset(brlink, 0, sizeof(brlink));
	if (readlink(path, brlink, sizeof(brlink) - 1) < 0)
		return -1;
	pos = os_strrchr(brlink, '/');
	if (pos == NULL)
		return -1;
	pos++;
	os_strlcpy(brname, pos, IFNAMSIZ);
	return 0;
}

int arpp_netlink_send(struct arpp_interfaces *interfaces, struct arppm_nl_msg *nl_msg)
{
	memcpy(NLMSG_DATA(arpp_nlh), (char *)nl_msg, sizeof(struct arppm_nl_msg));

	arpp_printf(ARPP_DEBUG, "[arpp_netlink_send] start......\n");
	
	if(sendmsg(interfaces->nl_sock, &arpp_nl_msghdr, 0) < 0) {
		arpp_printf(ARPP_ERROR, "Failed to send netlink msg : %s\n", strerror(errno));
		return -1;
	}

	arpp_printf(ARPP_DEBUG, "[arpp_netlink_send] end......\n");

	return 0;
}



static void arpp_netlink_receive(int sock, void *eloop_ctx,
				       void *sock_ctx)
{
	socklen_t len = 0;
    int res;
    unsigned char buf[4096]= {0};
    struct sockaddr_nl addr;
	struct arppm_nl_msg *nl_msg;
	struct arpp_interfaces *arpp_iface = eloop_ctx;

    /* recv msg from kernel */
    res = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &len);
    if (res < 0) {
		perror("recvfrom(netlink)");
		return;
	}

	nl_msg = buf + sizeof(struct nlmsghdr);
	//printPacketBuffer(nl_msg, sizeof(struct arppm_nl_msg));

	if (handle_nl_arp(arpp_iface, nl_msg)) {
		arpp_netlink_send(arpp_iface, nl_msg);
	}
	
    return;
}

int arpp_netlink_iface_init(struct arpp_interfaces *interfaces)
{
	int  s = -1;
	struct sockaddr_nl addr;
	int ret = -1;

	/* creat socket */
    s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ARPPM);
	if (s < 0)
	{
	    arpp_printf(ARPP_DEBUG, "Failed to create netlink socket\n");
        return -1;
	}

	/* bind */
	memset(&arpp_src_addr, 0, sizeof(arpp_src_addr));
	arpp_src_addr.nl_family = AF_NETLINK;
	arpp_src_addr.nl_pid = getpid();
    arpp_src_addr.nl_groups = 1;
    ret = bind(s, (struct sockaddr*)&arpp_src_addr, sizeof(arpp_src_addr));
	if (ret < 0) 
	{
        arpp_printf(ARPP_DEBUG, "Failed to bind netlink\n");
		goto fail;
	}

	memset(&arpp_dest_addr, 0, sizeof(arpp_dest_addr));
	arpp_dest_addr.nl_family = AF_NETLINK;
	arpp_dest_addr.nl_pid = 0;
    arpp_dest_addr.nl_groups = 1;

	/* Initialize buffer */
	if((arpp_nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(MAX_PAYLOAD))) == NULL) {
		arpp_printf(ARPP_ERROR, "Failed malloc\n");
		goto fail;
	}

	memset(arpp_nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	arpp_nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	arpp_nlh->nlmsg_pid = getpid();
	arpp_nlh->nlmsg_flags = 0;
	memset(&arpp_iov, 0, sizeof(arpp_iov));
	arpp_iov.iov_base = (void *)arpp_nlh;
	arpp_iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
	memset(&arpp_nl_msghdr, 0, sizeof(arpp_nl_msghdr));
	arpp_nl_msghdr.msg_name = (void *)&arpp_dest_addr;
	arpp_nl_msghdr.msg_namelen = sizeof(arpp_dest_addr);
	arpp_nl_msghdr.msg_iov = &arpp_iov;
	arpp_nl_msghdr.msg_iovlen = 1;

	interfaces->nl_sock = s;
	eloop_register_read_sock(s, arpp_netlink_receive, interfaces, NULL);

	return 0;
fail:
	if (s)
		close(s);

	return -1;
	
}

static void arpp_database_iface_receive(int sock, void *eloop_ctx,
				       void *sock_ctx)
{
	struct arpp_interfaces *arpp_iface = eloop_ctx;
	WAM_MSG *wam_msg;
	arpp_item_t *item = NULL;
	char buf[512];
	int res, ret;
	struct sockaddr_un from;
	socklen_t fromlen = sizeof(from);
	char *reply;
	const int reply_size = 4096;
	int reply_len;
	u8 *tmp;

	res = recvfrom(sock, buf, sizeof(buf) - 1, 0,
			   (struct sockaddr *) &from, &fromlen);
	if (res < 0) {
		perror("recvfrom(ctrl_iface)");
		return;
	}

	printPacketBuffer(buf, res);

	wam_msg = (WAM_MSG *)&buf;
	tmp = (u8 *)&(wam_msg->ip_addr);

	arpp_printf(ARPP_DEBUG, "iface: %s\n", wam_msg->iface);
	arpp_printf(ARPP_DEBUG, "bridge: %s\n", wam_msg->bridge);
	arpp_printf(ARPP_DEBUG, "ssid: %s\n", wam_msg->ssid);
	arpp_printf(ARPP_DEBUG, "addr: " MACSTR "\n", MAC2STR(wam_msg->addr));
	arpp_printf(ARPP_DEBUG, "ip_addr: %d.%d.%d.%d\n", tmp[0], tmp[1], tmp[2], tmp[3]);

	if (wam_msg->op == STA_ADD) {
		item = arpp_tbl_item_new_from_msg(wam_msg);
		if (item != NULL) {
			arpp_printf(ARPP_DEBUG, "ip_addr: %d.%d.%d.%d\n", tmp[0], tmp[1], tmp[2], tmp[3]);
			if (arpp_tbl_item_insert(item)) {
				arpp_printf(ARPP_ERROR, "Failed to insert arpp_tbl_item!!!\n");
				return;
			}
		}else {
			arpp_printf(ARPP_ERROR, "Failed to create arpp_tbl_item!!!\n");
			return;
		}
	}
	else if (wam_msg->op == STA_DEL) {
		item = arpp_tbl_item_find_by_ip(wam_msg->addr);
		if (item != NULL) {
			if (arpp_tbl_item_remove(item)) {
				arpp_printf(ARPP_ERROR, "Failed to remove arpp_tbl_item!!!\n");
				return;
			}
		}
	}
	
	return;
}

int arpp_database_iface_init(struct arpp_interfaces *interfaces)
{
	struct sockaddr_un addr;
	int s = -1;

	interfaces->database_iface_path= os_strdup(ARPP_DATABASE_IFACE_PATH);
	if (interfaces->database_iface_path == NULL) {
		arpp_printf(ARPP_DEBUG, "ctrl_iface_path not configured!\n");
		return 0;
	}

	if (mkdir(ARPP_FILE_DIR, S_IRWXU | S_IRWXG) < 0) {
		if (errno == EEXIST) {
			arpp_printf(ARPP_DEBUG, "Using existing control "
				   "interface directory.\n");
		} else {
			perror("mkdir[ctrl_path]");
			goto fail;
		}
	}

	if (os_strlen(interfaces->database_iface_path) >= sizeof(addr.sun_path))
		goto fail;

	s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket(PF_UNIX)");
		goto fail;
	}

	os_memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	os_strlcpy(addr.sun_path, interfaces->database_iface_path, sizeof(addr.sun_path));
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		arpp_printf(ARPP_DEBUG, "ctrl_iface bind(PF_UNIX) failed: %s\n",
			   strerror(errno));
		if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			arpp_printf(ARPP_DEBUG, "ctrl_iface exists, but does not"
				   " allow connections - assuming it was left"
				   "over from forced program termination\n");
			if (unlink(interfaces->database_iface_path) < 0) {
				perror("unlink[ctrl_iface]");
				arpp_printf(ARPP_ERROR, "Could not unlink "
					   "existing ctrl_iface socket '%s'\n",
					   interfaces->database_iface_path);
				goto fail;
			}
			if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) <
			    0) {
				perror("bind(PF_UNIX)");
				goto fail;
			}
			arpp_printf(ARPP_DEBUG, "Successfully replaced leftover "
				   "ctrl_iface socket '%s'\n", interfaces->database_iface_path);
		} else {
			arpp_printf(ARPP_INFO, "ctrl_iface exists and seems to "
				   "be in use - cannot override it\n");
			arpp_printf(ARPP_INFO, "Delete '%s' manually if it is "
				   "not used anymore\n", interfaces->database_iface_path);
			os_free(interfaces->database_iface_path);
			interfaces->database_iface_path = NULL;
			goto fail;
		}
	}

	if (chmod(interfaces->database_iface_path, S_IRWXU | S_IRWXG) < 0) {
		perror("chmod[ctrl_interface/ifname]");
		goto fail;
	}
	os_free(interfaces->database_iface_path);

	interfaces->database_iface_sock = s;
	eloop_register_read_sock(s, arpp_database_iface_receive, interfaces, NULL);

	return 0;
fail:
	if (s >= 0)
		close(s);
	if (interfaces->database_iface_path) {
		unlink(interfaces->database_iface_path);
		os_free(interfaces->database_iface_path);
	}
	return -1;
}

int arpp_iface_init(struct arpp_interfaces *interfaces, struct arpp_iface *iface, char *ifname)
{
	struct ifreq ifr;
	int ifindex, i;
	struct sockaddr_in *addr = NULL;
	unsigned char mac[ETH_ALEN];
	u8 *tmp;
	
	memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(interfaces->ioctl_sock, SIOCGIFINDEX, &ifr) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		return -1;
	}
	ifindex = ifr.ifr_ifindex;

	memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(interfaces->ioctl_sock, SIOCGIFADDR, &ifr) != 0) {
		perror("ioctl(SIOCGIFADDR)");
		return -1;
	}
	addr = (struct sockaddr_in *)&(ifr.ifr_addr);

	memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(interfaces->ioctl_sock, SIOCGIFHWADDR, &ifr) != 0) {
		perror("ioctl(SIOCGIFADDR)");
		return -1;
	}
	memcpy(&mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	os_strlcpy(iface->ifname, ifname, sizeof(iface->ifname));
	iface->ifindex = ifindex;
	iface->ipaddr = htonl(addr->sin_addr.s_addr);
	for (i = 0; i < ETH_ALEN; i++) {
		iface->addr[i] = mac[i];
	}

	tmp = (u8 *)&(iface->ipaddr);
	arpp_printf(ARPP_DEBUG, "arpp_iface_init - ifname %s ifindex %d hwaddr "
			MACSTR " ipaddr %d.%d.%d.%d\n", iface->ifname, iface->ifindex, 
			MAC2STR(addr), tmp[0], tmp[1], tmp[2], tmp[3]);

	return 0;
}

void arpp_iface_free(struct arpp_iface *iface)
{	
	if (iface && iface->sock_arp) {
			l2_packet_deinit(iface->sock_arp);
	}

	if (iface)
		os_free(iface);
}


struct arpp_interfaces *arpp_iface_alloc(struct arpp_interfaces *interfaces)
{
	struct arpp_iface *arpp_if;

	if (interfaces->count == 0) {
		interfaces->iface = os_zalloc(sizeof(struct arpp_iface *));
		if (interfaces->iface == NULL) {
			arpp_printf(ARPP_ERROR, "malloc failed\n");
			return NULL;
		}
	} else {
		struct arpp_iface **iface;
		iface = os_realloc(interfaces->iface,
				   (interfaces->count + 1) *
				   sizeof(struct arpp_iface *));
		if (iface == NULL)
			return NULL;
		interfaces->iface = iface;
	}
	arpp_if = interfaces->iface[interfaces->count] =
		os_zalloc(sizeof(*arpp_if));
	if (arpp_if == NULL) {
		arpp_printf(ARPP_ERROR, "%s: Failed to allocate memory for "
			   "the interface\n", __func__);
		return NULL;
	}
	interfaces->count++;

	return arpp_if;
}


int arpp_add_iface(struct arpp_interfaces *interfaces, char *buf)
{
	struct arpp_iface *arpp_if = NULL;
	char brname[IFNAMSIZ], buffer[60], *ptr;
	size_t i, iface_count;

	os_strlcpy(brname, buf, sizeof(brname));

	for (i = 0; i < interfaces->count; i++) {
		if (!os_strcmp(interfaces->iface[i]->ifname, brname)) {
			arpp_printf(ARPP_ERROR, "BR-iface already exists!!\n");
			
			return -1;
		}
	}
	
	iface_count = i;
	if (iface_count == interfaces->count) {
		arpp_if = arpp_iface_alloc(interfaces);
		if (arpp_if == NULL) {
			arpp_printf(ARPP_ERROR, "%s: Failed to allocate memory "
				   "for interface\n", __func__);
			return -1;
		}
		if (arpp_iface_init(interfaces, arpp_if, buf)) {
			arpp_printf(ARPP_ERROR, "%s: Failed to init iface "
				   "for interface\n", __func__);
			arpp_iface_free(arpp_if);

			return -1;
		}
		
		return 0;
	}

	return -1;
}


int arpp_remove_iface(struct arpp_interfaces *interfaces, char *buf)
{
	struct arpp_iface *arpp_if;
	char brname[IFNAMSIZ];
	size_t i, k = 0;

	os_strlcpy(brname, buf, sizeof(brname));

	for (i = 0; i < interfaces->count; i++) {
		arpp_if = interfaces->iface[i];
		if (arpp_if == NULL)
			return -1;
		if (!os_strcmp(arpp_if->ifname, brname)) {
			arpp_iface_free(arpp_if);
			k = i;
			while (k < (interfaces->count - 1)) {
				interfaces->iface[k] =
					interfaces->iface[k + 1];
				k++;
			}
			interfaces->count--;
			return 0;
		}
	}
	arpp_printf(ARPP_ERROR, "%s: %s\n", __func__, buf);
	return 0;
}

int arpp_find_iface(struct arpp_interfaces *interfaces, char *buf, unsigned int *id)
{
	char brname[IFNAMSIZ], buffer[60], *ptr;
	size_t i, iface_count;

	os_strlcpy(brname, buf, sizeof(brname));
	
	for (i = 0; i < interfaces->count; i++) {
		if (!os_strcmp(interfaces->iface[i]->ifname, brname)) {
			arpp_printf(ARPP_DEBUG, "BR-iface already found!!\n");
			
			*id = i;
			return 0;
		}
	}
	
	iface_count = i;
	if (iface_count == interfaces->count) {
		arpp_printf(ARPP_DEBUG, "BR-iface not found!!\n");
		
		return 1;
	}
	
	return -1;
}

int arpp_ctrl_iface_add_if(struct arpp_interfaces *interfaces,
				      const char *ifname)
{
	struct ifreq ifr;
	int ifindex = 0;
	int ret, id;

        arpp_printf(ARPP_ERROR,"arpp_ctrl_iface_add_if: interfaces=%p, ifname=%s sock=%d\n" , interfaces, ifname, interfaces->ioctl_sock);
	if (interfaces->ioctl_sock <= 0){
		interfaces->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
		arpp_printf(ARPP_ERROR,"arpp_ctrl_iface_add_if: sock=%d\n" ,interfaces->ioctl_sock);
		if (interfaces->ioctl_sock < 0) {
			perror("socket[PF_INET,SOCK_DGRAM]");
			arpp_printf(ARPP_ERROR,"socket[PF_INET,SOCK_DGRAM] errno: %s\n" , strerror(errno));
			goto bad;
		}
	}

	memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(interfaces->ioctl_sock, SIOCGIFINDEX, &ifr) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		arpp_printf(ARPP_ERROR,"ioctl(SIOCGIFINDEX) errno: %s\n", strerror(errno));
		goto bad;
	}

	arpp_printf(ARPP_DEBUG, "CTRL_IFACE ADD_IF %s ifindex %d\n", ifname, ifr.ifr_ifindex);

	if (!arpp_find_iface(interfaces, ifname, &id)) {
		if (interfaces->iface[id]->sock_arp) {
			arpp_printf(ARPP_DEBUG, "interface %s already added\n", ifname);
			return 1;
		}else {
			if (arp_snoop_init(interfaces->iface[id])) {
				arpp_printf(ARPP_ERROR,
					   "interface %s ARP snooping initialization failed\n",
					   ifname);
				goto bad;
			}
		}
	}else {
		if (!arpp_add_iface(interfaces, ifname)) {
			if (arp_snoop_init(interfaces->iface[interfaces->count - 1])) {
				arpp_printf(ARPP_ERROR,
						"interface %s ARP snooping initialization failed\n",
						ifname);
				goto bad;
			}
		}else {
			arpp_printf(ARPP_ERROR, "ARPP_IFACE add failed\n");

			return -1;
		}
	}

	return 0;
bad:
	arpp_remove_iface(interfaces, ifname);

	return -1;
}

int arpp_ctrl_iface_del_if(struct arpp_interfaces *interfaces,
				      const char *ifname)
{
	struct ifreq ifr;
	int ifindex = 0;
	int ret, id;

	arpp_printf(ARPP_DEBUG, "CTRL_IFACE DEL_IF %s ifindex %d\n", ifname, ifr.ifr_ifindex);

	arpp_remove_iface(interfaces, ifname);

	return -1;
}
/* The rtrim() function removes trailing spaces from a string. */
char *rtrim(char *str)
{
        int n = strlen(str) - 1;
	while((*(str + n) == ' ') ||(*(str + n) == '\n') ||(*(str + n) == '\r'))
	{
                *(str+n--) = '\0';
	}
}

