/*
 * arp-proxy / main()
 * Copyright (c) 2016-2017, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stddef.h>

#include "common.h"
#include "os.h"
#include "eloop.h"
#include "debug.h"
#include "arp_proxy.h"
#include "arpp_tbl.h"


/**
 * handle_term - SIGINT and SIGTERM handler to terminate hostapd process
 */
 int golbal_arp_proxy_switch = 1;

static void handle_term(int sig, void *signal_ctx)
{
	arpp_printf(ARPP_DEBUG, "Signal %d received - terminating\n", sig);
	eloop_terminate();
}

int arpp_ctrl_config_reload(struct arpp_interfaces *interfaces)
{
	char cmd[128]="";
	char get_interface_name[128] = "";	
	int ret = 0;
	FILE *interface_file;
	char buf[128];

	interface_file= fopen(ARPP_INTERFACE_FILE, "r");
	if (!interface_file){
		arpp_printf(ARPP_ERROR,"open interface file %s failed.\n", ARPP_INTERFACE_FILE);
    	        return -1;
	}
	os_memset(buf,0,sizeof(buf));
	while(fgets(buf,16,interface_file) != NULL){
	arpp_printf(ARPP_DEBUG,"handle_pre: strlen(buf) = %d ,%s\n",(int)strlen(buf), buf);
            rtrim(buf);
	arpp_printf(ARPP_DEBUG,"handle_post: strlen(buf) = %d ,%s\n",(int)strlen(buf), buf);
	arpp_ctrl_iface_add_if(interfaces, buf);
	arpp_printf(ARPP_DEBUG,"get_interface_name:%s", buf);
#if 0
    	memset(cmd, 0, sizeof(cmd));
    	snprintf(cmd, sizeof(cmd) - 1, "arpp_cli add_if %s", buf);
    	
    	ret = system(cmd);
    	arpp_printf(ARPP_DEBUG,"add_interface cmd = %s  ret=%d\n", cmd, ret);
    	ret = WEXITSTATUS(ret); 
    	if( 0 != ret) {
    		return -1;
    	}
#endif
		os_memset(buf,0,sizeof(buf));
	}
	fclose(interface_file);
	
	return 0;
}

static void arpp_ctrl_iface_receive(int sock, void *eloop_ctx,
				       void *sock_ctx)
{
	struct arpp_interfaces *arpp_iface = eloop_ctx;
	char buf[512];
	int res;
	struct sockaddr_un from;
	socklen_t fromlen = sizeof(from);
	char *reply;
	const int reply_size = 4096;
	int reply_len;

	res = recvfrom(sock, buf, sizeof(buf) - 1, 0,
			   (struct sockaddr *) &from, &fromlen);
	if (res < 0) {
		perror("recvfrom(ctrl_iface)");
		return;
	}
	buf[res] = '\0';

	reply = os_malloc(reply_size);
	if (reply == NULL) {
		sendto(sock, "malloc FAIL\n", 5, 0, (struct sockaddr *) &from,
			   fromlen);
		return;
	}

	os_memcpy(reply, "OK\n", 3);
	reply_len = 3;

	if (os_strcmp(buf, "PING") == 0) {
		os_memcpy(reply, "PONG\n", 5);
		reply_len = 5;
	} 
	else if (os_strncmp(buf,"ADD_IF ", 7) == 0) {
		if (arpp_ctrl_iface_add_if(arpp_iface, buf + 7))
			reply_len = -1;
	}
	else if (os_strncmp(buf,"DEL_IF ", 7) == 0) {
		if (arpp_ctrl_iface_del_if(arpp_iface, buf + 7))
			reply_len = -1;
	}
	else if (os_strncmp(buf,"SHOW_ITEM", 9) == 0) {
		if (arpp_tbl_item_debug_show())
			reply_len = -1;
	}
	else if (os_strncmp(buf,"SERVICE ", 8) == 0) {
		arpp_printf(ARPP_DEBUG,"strlen(buf) = %d buf = %s\n",(int)strlen(buf) ,buf);
		if (os_strncmp(buf+8, "disable", 7)== 0){
			if( golbal_arp_proxy_switch == 1 ){
        			golbal_arp_proxy_switch = 0;
        			arpp_printf(ARPP_DEBUG,"golbal_arp_proxy_switch = %d\n",golbal_arp_proxy_switch);
			}
			else
				arpp_printf(ARPP_DEBUG,"switch already is disable\n");
/*			os_memcpy(reply, "disable\n", 5);
		        reply_len = 8;
*/

		}
		else{
			if( golbal_arp_proxy_switch == 0 ){
				golbal_arp_proxy_switch = 1;
				arpp_printf(ARPP_DEBUG, "golbal_arp_proxy_switch = %d\n",golbal_arp_proxy_switch);
/*				os_memcpy(reply, "enable\n", 5);
                		reply_len = 7;
*/
			}
			else
				arpp_printf(ARPP_DEBUG,"switch already is enable\n");
		}
	}
	else if (os_strncmp(buf,"RELOAD", 6) == 0) {
		arpp_printf(ARPP_ERROR, "*******11*****\n");
		if (arpp_ctrl_config_reload(arpp_iface)){
			reply_len = -1;
		arpp_printf(ARPP_ERROR, "*******22*****\n");
		}
	}
	else {
		os_memcpy(reply, "UNKNOWN COMMAND\n", 16);
		reply_len = 16;
	}

	if (reply_len < 0) {
		os_memcpy(reply, "FAIL\n", 5);
		reply_len = 5;
	}
	sendto(sock, reply, reply_len, 0, (struct sockaddr *) &from, fromlen);
	os_free(reply);
}


int arpp_global_ctrl_iface_init(struct arpp_interfaces *interfaces)
{
	struct sockaddr_un addr;
	int s = -1;

	interfaces->ctrl_iface_path = os_strdup(ARPP_CTRL_IFACE_PATH);
	if (interfaces->ctrl_iface_path == NULL) {
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

	if (os_strlen(interfaces->ctrl_iface_path) >= sizeof(addr.sun_path))
		goto fail;

	s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket(PF_UNIX)");
		goto fail;
	}

	os_memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	os_strlcpy(addr.sun_path, interfaces->ctrl_iface_path, sizeof(addr.sun_path));
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		arpp_printf(ARPP_DEBUG, "ctrl_iface bind(PF_UNIX) failed: %s\n",
			   strerror(errno));
		if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			arpp_printf(ARPP_DEBUG, "ctrl_iface exists, but does not"
				   " allow connections - assuming it was left"
				   "over from forced program termination\n");
			if (unlink(interfaces->ctrl_iface_path) < 0) {
				perror("unlink[ctrl_iface]");
				arpp_printf(ARPP_ERROR, "Could not unlink "
					   "existing ctrl_iface socket '%s'\n",
					   interfaces->ctrl_iface_path);
				goto fail;
			}
			if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) <
			    0) {
				perror("bind(PF_UNIX)");
				goto fail;
			}
			arpp_printf(ARPP_DEBUG, "Successfully replaced leftover "
				   "ctrl_iface socket '%s'\n", interfaces->ctrl_iface_path);
		} else {
			arpp_printf(ARPP_INFO, "ctrl_iface exists and seems to "
				   "be in use - cannot override it\n");
			arpp_printf(ARPP_INFO, "Delete '%s' manually if it is "
				   "not used anymore\n", interfaces->ctrl_iface_path);
			os_free(interfaces->ctrl_iface_path);
			interfaces->ctrl_iface_path = NULL;
			goto fail;
		}
	}

	if (chmod(interfaces->ctrl_iface_path, S_IRWXU | S_IRWXG) < 0) {
		perror("chmod[ctrl_interface/ifname]");
		goto fail;
	}
	os_free(interfaces->ctrl_iface_path);

	interfaces->ctrl_iface_sock = s;
	eloop_register_read_sock(s, arpp_ctrl_iface_receive, interfaces, NULL);

	return 0;
fail:
	if (s >= 0)
		close(s);
	if (interfaces->ctrl_iface_path) {
		unlink(interfaces->ctrl_iface_path);
		os_free(interfaces->ctrl_iface_path);
	}
		return -1;
}

int arpp_global_init(struct arpp_interfaces *interfaces)
{
	if (eloop_init()) {
		arpp_printf(ARPP_ERROR, "Failed to initialize event loop\n");
		return -1;
	}
	eloop_register_signal_terminate(handle_term, interfaces);
	
	if (arpp_global_ctrl_iface_init(interfaces)){
		arpp_printf(ARPP_ERROR, "Failed to setup control interface\n");
		return -1;
	}
	
	if (arpp_database_iface_init(interfaces)){
		arpp_printf(ARPP_ERROR, "Failed to setup database interface\n");
		return -1;
	}

	if (arpp_netlink_iface_init(interfaces)){
		arpp_printf(ARPP_ERROR, "Failed to setup database interface\n");
		return -1;
	}

	return 0;
}

static int arpp_global_run(struct hapd_interfaces *ifaces, int daemonize,
			      const char *pid_file)
{
	/*
	if (daemonize && os_daemonize(pid_file)) {
		perror("daemon");
		return -1;
	}
	*/

	eloop_run();

	return 0;
}


int main(int argc, char *argv[])
{
	struct arpp_interfaces interfaces;
	int ret = 0, daemonize = 1;
	char *pid_file = NULL;

	interfaces.count = 0;
	interfaces.ctrl_iface_path = NULL;
	interfaces.ctrl_iface_sock = 0;
	interfaces.database_iface_path = NULL;
	interfaces.database_iface_sock = 0;
	interfaces.ioctl_sock = 0;
	
	ret = arpp_debug_open_file(ARPP_OUT_FILE);

	if (arpp_global_init(&interfaces)){
		arpp_printf(ARPP_DEBUG, "arpp global init failed.\n");
		return -1;
	}

	memset(arpp_item_hash_table, 0, ARPP_ITEM_HASH_TABLE_SIZE * sizeof(arpp_item_t *));
	
	pid_file = os_strdup(ARPP_PID_FILE);
	if (arpp_global_run(&interfaces, daemonize, pid_file))
		return -1;

	return 0;
}
