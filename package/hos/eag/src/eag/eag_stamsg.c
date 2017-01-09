/* eag_stamsg.c */

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "nm_list.h"
#include "hashtable.h"
#include "eag_mem.h"
#include "eag_log.h"
#include "eag_blkmem.h"
#include "eag_thread.h"
#include "eag_conf.h"  //not need
#include "eag_time.h"
#include "eag_util.h"
#include "eag_stamsg.h"
#include "eag_ins.h"
#include "eag_portal.h"
#include "eag_captive.h"
#include "radius_packet.h"
#include "eag_wireless.h"
#include "eag_statistics.h"
#include "eag_macauth.h"
#include "eag_radius.h"
#include "eag_authorize.h"
#include "eag_sync.h"

extern int eag_macauth_type;

struct eag_stamsg {
	int sockfd;
	//uint8_t hansi_type;
	//uint8_t hansi_id;
	char sockpath[128];
	char ntf_asd_path[128];
	eag_thread_t *t_read;
	eag_thread_master_t *master;
	eag_ins_t *eagins;
	eag_portal_t *portal;
	eag_radius_t *radius;
	//eag_dbus_t *eagdbus;
	appconn_db_t *appdb;
	eag_captive_t *captive;
	eag_statistics_t *eagstat;
	eag_macauth_t *macauth;
	struct portal_conf *portalconf;
	struct nasid_conf *nasidconf;
	struct nasportid_conf *nasportidconf;
	//eag_hansi_t *eaghansi;
};

typedef enum {
	EAG_STAMSG_READ,
} eag_stamsg_event_t;

static void
eag_stamsg_event(eag_stamsg_event_t event,
		eag_stamsg_t *stamsg);

eag_stamsg_t *eag_stamsg_new()
{
	eag_stamsg_t *stamsg = NULL;
            char path[64]={0};
	stamsg = eag_malloc(sizeof(*stamsg));
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_new eag_malloc failed");
		return NULL;
	}
	/*if (mkdir(STAMSG_SOCK_PATH_FMT, S_IRWXU | S_IRWXG) < 0) {
		if (errno == EEXIST) {
			eag_log_err( "Using existing eag "
				   "interface directory.");
		} else {
			eag_log_err("mkdir[ctrl_interface]");
			return NULL;
		}
	}*/


	memset(stamsg, 0, sizeof(*stamsg));
	stamsg->sockfd = -1;
	//sprintf(path,STAMSG_SOCK_PATH_FMT"/%s",global_bridge);
	strcpy(stamsg->sockpath,STAMSG_SOCK_PATH_FMT);
	strcpy(stamsg->ntf_asd_path,STAMSG_ASD_SOCK_PATH_FMT);
	
	eag_log_debug("eag_stamsg", "stamsg new ok, sockpath=%s",
			stamsg->sockpath);
	return stamsg;
}

int
eag_stamsg_free(eag_stamsg_t *stamsg)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_free input error");
		return -1;
	}

	if (stamsg->sockfd >= 0) {
		close(stamsg->sockfd);
		stamsg->sockfd = -1;
	}
	eag_free(stamsg);

	eag_log_debug("eag_stamsg", "stamsg free ok");
	return 0;
}

int
eag_stamsg_start(eag_stamsg_t *stamsg)
{
	int ret = 0;
	int len = 0;
	struct sockaddr_un addr = {0};
	mode_t old_mask = 0;
  
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_start input error");
		return EAG_ERR_NULL_POINTER;
	}

	if (stamsg->sockfd >= 0) {
		eag_log_info("eag_stamsg_start already start fd(%d)", 
			stamsg->sockfd);
		return EAG_RETURN_OK;
	}

	stamsg->sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (stamsg->sockfd  < 0) {
		eag_log_err("Can't create stamsg unix dgram socket: %s",
			safe_strerror(errno));
		stamsg->sockfd = -1;
		return EAG_ERR_SOCKET_FAILED;
	}

	if (0 != set_nonblocking(stamsg->sockfd)){
		eag_log_err("eag_stamsg_start set socket nonblocking failed");
		close(stamsg->sockfd);
		stamsg->sockfd = -1;
		return EAG_ERR_SOCKET_OPT_FAILED;
	}
		
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, stamsg->sockpath, sizeof(addr.sun_path)-1);
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

	unlink(addr.sun_path);
	old_mask = umask(0111);
	ret  = bind(stamsg->sockfd, (struct sockaddr *)&addr, len);
	if (ret < 0) {
		eag_log_err("Can't bind to stamsg socket(%d): %s",
			stamsg->sockfd, safe_strerror(errno));
		close(stamsg->sockfd);
		stamsg->sockfd = -1;
		umask(old_mask);
		return EAG_ERR_SOCKET_BIND_FAILED;
	}
	umask(old_mask);
	
	eag_stamsg_event(EAG_STAMSG_READ, stamsg);
	
	eag_log_info("stamsg(%s) fd(%d) start ok",
			stamsg->sockpath,
			stamsg->sockfd);

	return EAG_RETURN_OK;
}

int
eag_stamsg_stop(eag_stamsg_t *stamsg)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_stop input error");
		return EAG_ERR_NULL_POINTER;
	}

	eag_log_info("stamsg(%s) fd(%d) stop ok",
			stamsg->sockpath,
			stamsg->sockfd);
		
	if (NULL != stamsg->t_read) {
		eag_thread_cancel(stamsg->t_read);
		stamsg->t_read = NULL;
	}
	if (stamsg->sockfd >= 0)
	{
		close(stamsg->sockfd);
		stamsg->sockfd = -1;
	}
	unlink(stamsg->sockpath);
	
	return EAG_RETURN_OK;
}

static int
stamsg_proc(eag_stamsg_t *stamsg, uint8_t usermac[6],
		uint32_t user_ip, EagMsg *sta_msg,char *path)
{
	struct app_conn_t *appconn = NULL;
	struct appsession tmpsession = {0};
	struct timeval tv = {0};
	time_t timenow = 0;
	int ret = 0;
	char user_macstr[32] = "";
	char user_ipstr[32] = "";
	char ap_macstr[32] = "";
	char new_apmacstr[32] = "";
	unsigned int security_type = 0;
	int macauth_switch = 0;
	unsigned int key_type;
	char dns1_ip[32]="";
	char dns2_ip[32]="";
	uint64_t mac_f = 0;
	char zero_mac[6]={0};
	
	eag_authorize_t *eag_auth = NULL;
	struct sync_user_info * sync_user = NULL;
    eag_sync_t *sync;
    int num = 0;
		   
	eag_time_gettimeofday(&tv,NULL);
	timenow = tv.tv_sec;
	macauth_switch = eag_macauth_get_macauth_switch(stamsg->macauth);
	switch(sta_msg->Op) {
	case WID_ADD:
		if (0 == user_ip) {
			eag_log_warning("stamsg_proc receive WID_ADD, userip = 0");
		}
		#if 0
		if (0 != user_ip) {
			ip2str(user_ip, user_ipstr, sizeof(user_ipstr));
			eag_log_info("stamsg_proc, WID_ADD del eap or none authorize user_ip %s",
				user_ipstr);
			eag_captive_del_eap_authorize(stamsg->captive, user_ip);
		}
		#endif
		/* TODO: if essid changed, del mac_preauth */
		mac2str(usermac, user_macstr, sizeof(user_macstr), ':');

		/*if (eag_hansi_is_enable(stamsg->eaghansi)
			&& !eag_hansi_is_master(stamsg->eaghansi))
		{
			eag_log_info("receive WID_ADD usermac=%s, but hansi is backup, ignore it",
				user_macstr);
			return 0;
		}*/
		
		strncpy(tmpsession.essid, (char *)sta_msg->STA.ssid, 32);
        memcpy(tmpsession.usermac,usermac,PKT_ETH_ALEN);
        tmpsession.user_ip = user_ip;
		memcpy(tmpsession.intf,(char *)sta_msg->STA.iface,sizeof(tmpsession.intf)-1);
		memcpy(tmpsession.bridge,(char *)sta_msg->STA.bridge,sizeof(tmpsession.bridge)-1);
        memcpy(tmpsession.sock_path,path,strlen(path));
		/*eag_log_info("%s,%d, sock_path %s,path %s\n",__func__,__LINE__,tmpsession.sock_path,path);
		key_type = PORTAL_KEYTYPE_ESSID;
                    if(( NULL == portal_srv_get_by_key(stamsg->portalconf,key_type,sta_msg->STA.ssid)) &&(0 != user_ip))
		{
			eag_authorize_t *eag_auth = NULL;
			eag_auth = eag_authorieze_get_iptables_auth();
                            eag_authorize_do_authorize(eag_auth,&tmpsession);
			eag_log_info("%s,%d\n",__func__,__LINE__);
			break;
		}*/
			 
		mac8tomac64(usermac, &mac_f);
        if (0 != eag_captive_find_mac_in_white_rule(stamsg->captive, mac_f)){

			appconn = appconn_find_by_usermac(stamsg->appdb, usermac);
			if (NULL == appconn) {

				eag_log_info("stamsg_proc, appconn not exist, usermac=%s",user_macstr);
				if (0 == tmpsession.user_ip)
			   {
					break;
				}
				appconn = appconn_create_by_sta_v2(stamsg->appdb, &tmpsession);
				if (NULL == appconn){			
					eag_log_info(" NULL == appconn %s,%d\n",__func__,__LINE__);
					return -1;
				}
			} 
		    appconn->session.state = APPCONN_STATUS_AUTHED;
			appconn->session.server_auth_type = EAG_AUTH_TYPE_MAC;
			eag_auth = eag_authorieze_get_iptables_auth();
            eag_authorize_do_authorize(eag_auth,&tmpsession);
          
		    eag_auth_log(appconn->session, "online");
		   	eag_log_info("stamsg_proc, WID_ADD break");
			break;

		}
		

		appconn = appconn_find_by_usermac(stamsg->appdb, usermac);
		if (NULL == appconn) {
			eag_log_info("stamsg_proc, appconn not exist, usermac=%s",
				user_macstr);
			appconn = appconn_create_by_sta_v2(stamsg->appdb, &tmpsession);
			if (NULL == appconn) {
            			eag_log_info("stamsg_proc, appconn not exist, usermac=%s",
            				user_macstr);
            			return 0;
			}

		}
		if ((appconn->session.user_ip == 0)  && (user_ip != 0))
		{
			  appconn->session.user_ip = user_ip;
			   appconn_update_ip_htable(stamsg->appdb,appconn);	
			   return 0;
		}
		eag_log_info("essid %s, ssid %s",appconn->session.essid,tmpsession.essid);
		if(appconn->session.state == APPCONN_STATUS_AUTHED) 
		{
			if (strcmp(appconn->session.essid,tmpsession.essid))
			{
				//memcpy(appconn->session.essid,tmpsession.essid,MAX_ESSID_LENGTH);
				eag_log_info("stamasg_proc ssid change");
				terminate_appconn(appconn, stamsg->eagins, 
							RADIUS_TERMINATE_CAUSE_USER_REQUEST);
				return 0;
			}
			else if(memcmp(appconn->session.intf,tmpsession.intf,MAX_IF_NAME_LEN))
			{
            	eag_auth = eag_authorieze_get_iptables_auth();
				eag_log_info("intf %s,ip %d",appconn->session.intf,appconn->session.user_ip);
		        eag_authorize_de_authorize(eag_auth,&(appconn->session));
				//tmpsession.user_ip=appconn->session.user_ip;
		        memcpy(appconn->session.intf,tmpsession.intf,sizeof(tmpsession.intf)-1);
				appconn->session.last_connect_ap_time = timenow;
				eag_log_info("intf %s,ip %d",appconn->session.intf,appconn->session.user_ip);
				eag_authorize_do_authorize(eag_auth,&(appconn->session));
				sync = eag_ins_get_sync(stamsg->eagins);
		        sync_user = eag_sync_user_find(sync,&tmpsession);
				if (sync_user  != NULL)
				{
		        	sync_user->bk_input_octets += appconn->session.input_octets;
					sync_user->bk_output_octets += appconn->session.output_octets;                     
				}
				return 0;
		                                    	
			}
				
		}
		if(appconn->session.state != APPCONN_STATUS_AUTHED)
		{
			sync = eag_ins_get_sync(stamsg->eagins);
		    sync_user = eag_sync_user_find(sync,&tmpsession);
			if(sync_user !=  NULL)
				eag_log_info("session.essid %s, sync.essid  %s",appconn->session.essid,sync_user->essid);
		    if((sync_user !=  NULL) && ( 0 == memcmp(appconn->session.essid,sync_user->essid,MAX_ESSID_LENGTH)))
		     {
		   		eag_log_info("session.username %s, sync.username %s",appconn->session.username,sync_user->username);
		   		appconn->session.state = APPCONN_STATUS_AUTHED;
				appconn->session.sta_state = SESSION_STA_STATUS_CONNECT;
		    	appconn->session.user_ip = sync_user->user_ip;
		    	memcpy(appconn->session.username,sync_user->username,USERNAMESIZE);
				eag_log_info("session.username %s, sync.username %s",appconn->session.username,sync_user->username);
		     	appconn_update_ip_htable(stamsg->appdb,appconn);
		     	char zero_username[USERNAMESIZE]={0};
		     	if(memcmp(appconn->session.username,zero_username,USERNAMESIZE))
		     	{
		            appconn_update_name_htable(stamsg->appdb,appconn);
		     	}
		  		eag_auth = eag_authorieze_get_iptables_auth();
		  		eag_authorize_do_authorize(eag_auth,&(appconn->session));
		  		appconn->session.last_connect_ap_time = timenow;
		        return 0;
		                    	
		    }
		    else
				eag_log_info("msg usermac:%s, userip:%s,this user does not exist.",user_macstr, user_ipstr);
		}
		appconn->session.sta_state = SESSION_STA_STATUS_CONNECT;
       
		mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr), ':');
		ip2str(appconn->session.user_ip, user_ipstr, sizeof(user_ipstr));
		
		
		eag_log_info("Receive WID_ADD msg usermac:%s, userip:%s, status:%s,"
			" from apmac:%s, apname:%s, ssid:%s to apmac:%s, apname:%s, ssid:%s",
			user_macstr, user_ipstr,
			APPCONN_STATUS_AUTHED == appconn->session.state?
				"Authed":"NotAuthed",
			ap_macstr, appconn->session.apname, appconn->session.essid,
			new_apmacstr, tmpsession.apname, tmpsession.essid);

			if (APPCONN_STATUS_AUTHED == appconn->session.state) {
				if (EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
                			eag_bss_message_count(stamsg->eagstat, appconn, BSS_USER_CONNECTED_TOTAL_TIME, 
                                	(timenow - appconn->session.last_connect_ap_time));
    			    } else {
                			eag_bss_message_count(stamsg->eagstat, appconn, BSS_MACAUTH_USER_CONNECTED_TOTAL_TIME, 
                                	(timenow - appconn->session.last_connect_ap_time));
    			    }
			}
		    strncpy(appconn->session.essid,tmpsession.essid,  sizeof(tmpsession.essid)-1);
		  	memcpy(appconn->session.intf,tmpsession.intf,sizeof(tmpsession.intf)-1);
			appconn->session.last_connect_ap_time = timenow;
			appconn_set_nasid(appconn, stamsg->nasidconf);
			appconn_set_nasportid(appconn, stamsg->nasportidconf);
			ret = appconn_config_portalsrv(appconn, stamsg->portalconf);
			if (0 != ret) {
				eag_log_warning("stamsg_proc "
					"appconn_config_portalsrv failed, usermac:%s ret=%d",
					user_macstr, ret);
			}

			if (APPCONN_STATUS_AUTHED == appconn->session.state) {
				if (ACCURIS_MACAUTH == eag_macauth_type) {
                                    eag_radius_auth_change_tag(stamsg->radius, appconn);
				}
			}

		break;		
	case WID_DEL:
		if (0 == user_ip) {
			eag_log_warning("stamsg_proc receive WID_DEL, userip = 0");
		}
		#if 0
		if (0 != user_ip) {
			ip2str(user_ip, user_ipstr, sizeof(user_ipstr));
			eag_log_info("stamsg_proc, WID_DEL del eap or none authorize user_ip %s",
				user_ipstr);
			eag_captive_del_eap_authorize(stamsg->captive, user_ip);
		}
		#endif
		if (macauth_switch) {
			del_eag_preauth_by_ip_or_mac(stamsg->macauth, user_ip, usermac);
		}
		mac2str(usermac, user_macstr, sizeof(user_macstr), ':');
	
		/*if (eag_hansi_is_enable(stamsg->eaghansi)
			&& !eag_hansi_is_master(stamsg->eaghansi))
		{
			eag_log_info("receive WID_DEL usermac=%s, but hansi is backup, ignore it",
				user_macstr);
			return 0;
		}*/
		strncpy(tmpsession.essid, (char *)sta_msg->STA.ssid, 32);
        memcpy(tmpsession.usermac,usermac,PKT_ETH_ALEN);
        tmpsession.user_ip = user_ip;
		memcpy(tmpsession.intf,(char *)sta_msg->STA.iface,sizeof(tmpsession.intf)-1);
		memcpy(tmpsession.bridge,(char *)sta_msg->STA.bridge,sizeof(tmpsession.bridge)-1);
        memcpy(tmpsession.sock_path,path,strlen(path));
                  /*  key_type = PORTAL_KEYTYPE_ESSID;
                    if(( NULL == portal_srv_get_by_key(stamsg->portalconf,key_type,sta_msg->STA.ssid)) &&(0 != user_ip))
                    {
			eag_authorize_t *eag_auth = NULL;
			eag_auth = eag_authorieze_get_iptables_auth();
                              eag_authorize_de_authorize(eag_auth,&tmpsession);
			break;
		}*/


		mac8tomac64(usermac, &mac_f);
		if (0 != eag_captive_find_mac_in_white_rule(stamsg->captive, mac_f)){
			eag_auth = eag_authorieze_get_iptables_auth();
			eag_authorize_de_authorize(eag_auth,&tmpsession);
			appconn = appconn_find_by_usermac(stamsg->appdb, usermac);		  
			if (NULL != appconn) {
			    eag_auth_log(appconn->session, "offline");
				appconn_del_from_db(appconn);
				appconn_free(appconn);
			}
			eag_log_info("stamsg_proc, WID_DEL break");
			break;				  
		}
	
		appconn = appconn_find_by_usermac(stamsg->appdb, usermac);
		if (NULL == appconn) {
			eag_log_info("stamsg_proc, appconn not exist, usermac=%s",
				user_macstr);
			return 0;
		}
        
		mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr), ':');
		ip2str(appconn->session.user_ip, user_ipstr, sizeof(user_ipstr));

		appconn->session.sta_state = SESSION_STA_STATUS_UNCONNECT;
		 //strncpy(appconn->session.essid,tmpsession.essid,  sizeof(tmpsession.essid)-1);
		eag_log_info("Receive leave msg usermac:%s, userip:%s, status:%s,"
			" apmac:%s, apname:%s, ssid:%s, leave_reason:%d",
			user_macstr, user_ipstr,
			APPCONN_STATUS_AUTHED == appconn->session.state?
				"Authed":"NotAuthed",
			ap_macstr, appconn->session.apname, appconn->session.essid, 
			appconn->session.leave_reason);

		if (macauth_switch) {
			del_eag_preauth_by_ip_or_mac(stamsg->macauth, appconn->session.user_ip, usermac);
		}
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
#if 0
			if (SESSION_STA_LEAVE_NORMAL == sta_msg->STA.reason) {
				eag_log_debug("eag_stamsg", "stamsg_proc receive WID_DEL"
					" and user(%s) leave normal", user_ipstr);
				appconn->session.session_stop_time = timenow;
				eag_portal_notify_logout_nowait(stamsg->portal, appconn);
				terminate_appconn(appconn, stamsg->eagins,
					RADIUS_TERMINATE_CAUSE_LOST_CARRIER);
			} else {
				eag_log_debug("eag_stamsg", "stamsg_proc receive WID_DEL"
					" and user(%s) leave abnormal(%u)", user_ipstr, sta_msg->STA.reason);
			}
#endif			
		} else {
			appconn_del_from_db(appconn);
			appconn_free(appconn);
		}
		break;	
	case WID_UPDATE:
		if (0 == user_ip) {
			eag_log_warning("stamsg_proc receive WID_UPDATE, userip = 0");
		}

		mac2str(usermac, user_macstr, sizeof(user_macstr), ':');
		strncpy(tmpsession.essid, (char *)sta_msg->STA.ssid, 32);
        memcpy(tmpsession.usermac,usermac,PKT_ETH_ALEN);
        tmpsession.user_ip = user_ip;
		memcpy(tmpsession.intf,(char *)sta_msg->STA.iface,sizeof(tmpsession.intf)-1);
		memcpy(tmpsession.bridge,(char *)sta_msg->STA.bridge,sizeof(tmpsession.bridge)-1);
       	memcpy(tmpsession.sock_path,path,strlen(path));
      		
		appconn = appconn_find_by_usermac(stamsg->appdb, usermac);
		if (NULL == appconn) {
			eag_log_info("stamsg_proc, appconn not exist, usermac=%s",
				user_macstr);
				appconn = appconn_find_by_userip(stamsg->appdb, user_ip);
				if(NULL == appconn)
					return 0;
		}

		mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr), ':');
		ip2str(appconn->session.user_ip, user_ipstr, sizeof(user_ipstr));
		 strncpy(appconn->session.essid,tmpsession.essid,  sizeof(tmpsession.essid)-1);
		 memcpy(appconn->session.intf,tmpsession.intf,sizeof(tmpsession.intf)-1);
		 if(memcmp(appconn->session.usermac,zero_mac,6) == 0)
		 {
			memcpy(appconn->session.usermac,usermac,6);
			appconn_update_mac_htable(stamsg->appdb,appconn);
		 }
		eag_log_info("Receive leave msg usermac:%s, userip:%s, status:%s,"
			" apmac:%s, apname:%s, ssid:%s",
			user_macstr, user_ipstr,
			APPCONN_STATUS_AUTHED == appconn->session.state?
				"Authed":"NotAuthed",
			ap_macstr, appconn->session.apname, appconn->session.essid);

	
		break;	
	case OPEN_ROAM:
		/* STAMSG_ROAM */
		if (0 == user_ip) {
			eag_log_warning("stamsg_proc receive OPEN_ROAM, userip = 0");
		}
		#if 0
		if (0 != user_ip) {
			ip2str(user_ip, user_ipstr, sizeof(user_ipstr));
			eag_log_info("stamsg_proc, OPEN_ROAM del eap or none authorize user_ip %s",
				user_ipstr);
			eag_captive_del_eap_authorize(stamsg->captive, user_ip);
		}
		#endif
		/* TODO: if essid changed, del mac_preauth */
		mac2str(usermac, user_macstr, sizeof(user_macstr), ':');
		strncpy(tmpsession.essid, (char *)sta_msg->STA.ssid, 32);
        memcpy(tmpsession.usermac,usermac,PKT_ETH_ALEN);
        tmpsession.user_ip = user_ip;
		memcpy(tmpsession.intf,(char *)sta_msg->STA.iface,sizeof(tmpsession.intf)-1);
		memcpy(tmpsession.bridge,(char *)sta_msg->STA.bridge,sizeof(tmpsession.bridge)-1);
		appconn = appconn_find_by_usermac(stamsg->appdb, usermac);
		if (NULL == appconn) {
			eag_log_info("stamsg_proc, appconn not exist, usermac=%s",
				user_macstr);
			return 0;
		}
		appconn->session.sta_state = SESSION_STA_STATUS_CONNECT;
		
		mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr), ':');
		ip2str(appconn->session.user_ip, user_ipstr, sizeof(user_ipstr));
		
	
		mac2str(tmpsession.apmac, new_apmacstr, sizeof(new_apmacstr), ':');

		eag_log_info("Receive roam msg usermac:%s, userip:%s, status:%s,"
			" from apmac:%s, apname:%s, ssid:%s to apmac:%s, apname:%s, ssid:%s",
			user_macstr, user_ipstr,
			APPCONN_STATUS_AUTHED == appconn->session.state?
				"Authed":"NotAuthed",
			ap_macstr, appconn->session.apname, appconn->session.essid,
			new_apmacstr, tmpsession.apname, tmpsession.essid);

		if (0 != strcmp(tmpsession.essid, appconn->session.essid)) {
			if (macauth_switch) {
				del_eag_preauth_by_ip_or_mac(stamsg->macauth, user_ip, usermac);
			}
			if (APPCONN_STATUS_AUTHED == appconn->session.state) {
				appconn->session.session_stop_time = timenow;
				eag_portal_notify_logout_nowait(stamsg->portal, appconn);
				terminate_appconn(appconn, stamsg->eagins, 
						RADIUS_TERMINATE_CAUSE_LOST_CARRIER);
			} else {
				appconn_del_from_db(appconn);
				appconn_free(appconn);
			}
		} else  if (APPCONN_STATUS_AUTHED == appconn->session.state) {   /* essid not changed */
			sync = eag_ins_get_sync(stamsg->eagins);
            sync_user = eag_sync_user_find(sync,&tmpsession);
            if(sync_user !=  NULL)
            {
            	sync_user->bk_input_octets = appconn->session.input_octets;
            	sync_user->bk_output_octets = appconn->session.output_octets;
            }
            else
            	eag_log_info("msg usermac:%s, userip:%s,this user does not exist.",user_macstr, user_ipstr);
			eag_stamsg_send(stamsg,&(appconn->session),SYNC_UPDATE);
			eag_auth = eag_authorieze_get_iptables_auth();
            eag_authorize_de_authorize(eag_auth,&(appconn->session));
			appconn_del_from_db(appconn);
            char zero_username[USERNAMESIZE]={0};
            if(memcmp(zero_username,appconn->session.username,USERNAMESIZE))
           	{
               	appconn_del_name_htable(appconn);
           	}
			appconn_free(appconn);
			
		}else {
				appconn_del_from_db(appconn);
				appconn_free(appconn);
		}
		break;

	case SYNC_AUTH:
		//eag_log_warning("stamsg_proc receive SYNC_AUTH");
		mac2str(usermac, user_macstr, sizeof(user_macstr), ':');
        ip2str(user_ip, user_ipstr, sizeof(user_ipstr));
		strncpy(tmpsession.essid, (char *)sta_msg->STA.ssid, 32);
        memcpy(tmpsession.usermac,usermac,PKT_ETH_ALEN);
        tmpsession.user_ip = user_ip;
		memcpy(tmpsession.intf,(char *)sta_msg->STA.iface,sizeof(tmpsession.intf)-1);
		memcpy(tmpsession.bridge,(char *)sta_msg->STA.bridge,sizeof(tmpsession.bridge)-1);
		tmpsession.session_start_time = sta_msg->STA.session_start_time;
		memcpy(tmpsession.username,sta_msg->STA.username,USERNAMESIZE);
     	eag_log_info("stamsg_proc receive SYNC_AUTH usermac:%s, userip:%s,essid %s,session_time %d",user_macstr, user_ipstr,tmpsession.essid,tmpsession.session_start_time);
     	sync = eag_ins_get_sync(stamsg->eagins);
		sync_user = eag_sync_user_find(sync,&tmpsession);
       	if(sync_user ==  NULL)
       	{
        	sync_user = eag_sync_user_info_new(sync,&tmpsession);
        	eag_sync_add(sync,sync_user);
       	}
		else
			eag_log_info("msg usermac:%s, userip:%s, this user already exist.",user_macstr, user_ipstr);

		appconn = appconn_find_by_usermac(stamsg->appdb, usermac);
		if (NULL == appconn) {
			eag_log_info("stamsg_proc, appconn not exist, usermac=%s",
				user_macstr);
			return 0;
		}
		if(appconn->session.state == APPCONN_STATUS_AUTHED)
		{
			if (strcmp(appconn->session.essid,tmpsession.essid))
			{
				terminate_appconn(appconn, stamsg->eagins,RADIUS_TERMINATE_CAUSE_USER_REQUEST);
				return 0;
			}
			
			
		}
		/*eag_log_info("Receive SYNC_AUTH msg usermac:%s, userip:%s,sync->ssid:%s ,tmpsession.ssid:%s",
			user_macstr, user_ipstr,sync_user->essid,tmpsession.essid);*/
	       	break;	

	case SYNC_DEL_AUTH:
		//eag_log_warning("stamsg_proc receive SYNC_DEL_AUTH");
		mac2str(usermac, user_macstr, sizeof(user_macstr), ':');
		ip2str(user_ip, user_ipstr, sizeof(user_ipstr));
        memcpy(tmpsession.usermac,usermac,PKT_ETH_ALEN);
        tmpsession.user_ip = user_ip;
		strncpy(tmpsession.essid, (char *)sta_msg->STA.ssid, 32);
		eag_log_info("stamsg_proc receive SYNC_DEL_AUTH usermac %s, userip %s,ssid = %s",user_macstr,user_ipstr,tmpsession.essid);
        sync = eag_ins_get_sync(stamsg->eagins);
    	sync_user = eag_sync_user_find(sync,&tmpsession);
        if(sync_user !=  NULL)
        {
	   		eag_sync_del(sync,sync_user);
            eag_sync_user_info_free(sync,sync_user);
        }
    	else
			eag_log_info("msg usermac:%s, userip:%s,this user does not exist.",user_macstr, user_ipstr);
  		break;	
	case SYNC_UPDATE:
		//eag_log_warning("stamsg_proc receive SYNC_UPDATE");
		mac2str(usermac, user_macstr, sizeof(user_macstr), ':');
		ip2str(user_ip, user_ipstr, sizeof(user_ipstr));
		strncpy(tmpsession.essid, (char *)sta_msg->STA.ssid,32);
        memcpy(tmpsession.usermac,usermac,PKT_ETH_ALEN);
        tmpsession.user_ip = user_ip;
		memcpy(tmpsession.intf,(char *)sta_msg->STA.iface,sizeof(tmpsession.intf)-1);
		memcpy(tmpsession.bridge,(char *)sta_msg->STA.bridge,sizeof(tmpsession.bridge)-1);
		tmpsession.session_start_time = sta_msg->STA.session_start_time;
		memcpy(tmpsession.username,sta_msg->STA.username,USERNAMESIZE);
	
		sync = eag_ins_get_sync(stamsg->eagins);
        sync_user = eag_sync_user_find(sync,&tmpsession);
        if(sync_user !=  NULL)
        {
            sync_user->bk_input_octets = sta_msg->STA.bk_input_octets;
			sync_user->bk_output_octets = sta_msg->STA.bk_output_octets;
        }
		else
		{
			eag_log_info("msg usermac:%s, userip:%s,this user does not exist.",user_macstr, user_ipstr);
			sync_user = eag_sync_user_info_new(sync,&tmpsession);
			sync_user->bk_input_octets = sta_msg->STA.bk_input_octets;
			sync_user->bk_output_octets = sta_msg->STA.bk_output_octets;
            eag_sync_add(sync,sync_user);
			
		 }
         break;	
	case NEW_AP_JOIN:
		//eag_log_warning("stamsg_proc receive NEW_AP_JOIN");
		memcpy(tmpsession.intf,(char *)sta_msg->STA.iface,sizeof(tmpsession.intf)-1);
		memcpy(tmpsession.bridge,(char *)sta_msg->STA.bridge,sizeof(tmpsession.bridge)-1);
        ret = eag_stamsg_new_ap_join_send(stamsg,&tmpsession,NEW_AP_JOIN_UPDATE);
       	break;	
	case NEW_AP_JOIN_UPDATE:
		//eag_log_warning("stamsg_proc receive NEW_AP_JOIN_UPDATE");
		sync = eag_ins_get_sync(stamsg->eagins);
		struct sync_user_info *user;
		uint8_t *buf = NULL;
		buf = (uint8_t *)sta_msg->user_data;
		for (num = 0; num < sta_msg->user_num; num++)
		{
                            
			user =(struct sync_user_info * )buf;
			mac2str(user->usermac, user_macstr, sizeof(user_macstr), ':');
			//eag_log_info("stamsg_proc receive NEW_AP_JOIN_UPDATE :   mac %s",user_macstr);
            memcpy(tmpsession.username,user->username, USERNAMESIZE);
			memcpy(tmpsession.essid, user->essid, MAX_ESSID_LENGTH);
	       	memcpy(tmpsession.usermac,user->usermac,PKT_ETH_ALEN);
	        tmpsession.user_ip = user->user_ip;
			tmpsession.session_start_time = user->session_start_time;
	    	sync_user = eag_sync_user_find(sync,&tmpsession);
	        mac2str(tmpsession.usermac, user_macstr, sizeof(user_macstr), ':');
	        ip2str(tmpsession.user_ip, user_ipstr, sizeof(user_ipstr));
	       /* eag_log_info("usermac %s,userip %s,username %s,essid %s,sessiontime %d",\
	                        user_macstr, user_ipstr,tmpsession.username,tmpsession.essid,tmpsession.session_start_time);
	        eag_log_info("usermac %s,userip %s,username %s,essid %s,sessiontime %d,input %d,output %d",\
	                        user_macstr, user_ipstr,tmpsession.username,user->essid,user->session_start_time,user->bk_input_octets,user->bk_input_octets);*/
	                                       
	        if(sync_user ==  NULL)
	        {
	        	sync_user = eag_sync_user_info_new(sync,&tmpsession);
				sync_user->bk_input_octets = user->bk_input_octets;
	   			sync_user->bk_output_octets = user->bk_output_octets;
	            eag_sync_add(sync,sync_user);
	            mac2str(sync_user->usermac, user_macstr, sizeof(user_macstr), ':');
	            ip2str(sync_user->user_ip, user_ipstr, sizeof(user_ipstr));
	            eag_log_info("usermac %s,userip %s,username %s,essid %s,sessiontime %d,bk_input_octets %d,bk_output_octets %d",\
	               	user_macstr, user_ipstr,sync_user->username,sync_user->essid,sync_user->session_start_time,sync_user->bk_output_octets,\
	                     sync_user->bk_input_octets);
	        }
	    	else
				eag_log_info("msg usermac:%s, userip:%s, this user already exist.",user_macstr, user_ipstr);
	        buf = buf +sizeof(struct sync_user_info);
		}
		break;
	#if 0
	case ASD_AUTH:
		if (0 == user_ip) {
			eag_log_warning("stamsg_proc receive ASD_AUTH, userip = 0");
			return -1;
		}
		
		ip2str(user_ip, user_ipstr, sizeof(user_ipstr));
		eag_log_info("stamsg_proc, ASD_AUTH add eap or none authorize user_ip %s",
				user_ipstr);
		eag_captive_eap_authorize(stamsg->captive, user_ip);
		break;
	case ASD_DEL_AUTH:
		if (0 == user_ip) {
			eag_log_warning("stamsg_proc receive ASD_DEL_AUTH, userip = 0");
			return -1;
		}
		
		ip2str(user_ip, user_ipstr, sizeof(user_ipstr));
		eag_log_info("stamsg_proc, ASD_DEL_AUTH del eap or none authorize user_ip %s",
				user_ipstr);
		eag_captive_del_eap_authorize(stamsg->captive, user_ip);
		break;
	#endif
	default:
		eag_log_err("stamsg_proc unexpected stamsg type %u", sta_msg->Op);
		break;
	}

	return EAG_RETURN_OK;
}

static int
stamsg_receive(eag_thread_t *thread)
{
	eag_stamsg_t *stamsg = NULL;
	struct sockaddr_un addr = {0};
	socklen_t len = 0;
	ssize_t nbyte = 0;
	EagMsg sta_msg = {0};
	uint8_t usermac[6] = {0};
	uint32_t user_ip=0;
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
    int i = 0;
          
	
	
	if (NULL == thread) {
		eag_log_err("stamsg_receive input error");
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	memset(&sta_msg, 0, sizeof(sta_msg));
	stamsg = eag_thread_get_arg(thread);
	if (NULL == stamsg) {
		eag_log_err("stamsg_receive stamsg null");
		return EAG_ERR_NULL_POINTER;
	}

	len = sizeof(addr);
	nbyte = recvfrom(stamsg->sockfd, &sta_msg, sizeof(EagMsg), 0,
					(struct sockaddr *)&addr, &len);
	if (nbyte < 0) {
		eag_log_err("stamsg_receive recvfrom failed: %s, fd(%d)",
			safe_strerror(errno), stamsg->sockfd);
		return EAG_ERR_SOCKET_RECV_FAILED;
	}
	
	addr.sun_path[sizeof(addr.sun_path)-1] = '\0'; 
		
	if (nbyte < sizeof(EagMsg)) {
		eag_log_warning("stamsg_receive msg size %d < EagMsg size %d",
			nbyte, sizeof(EagMsg));
		return -1;
	}
	
	if (WID_ADD != sta_msg.Op && WID_DEL != sta_msg.Op && UPDATE_IP != sta_msg.Op&& OPEN_ROAM != sta_msg.Op && WID_UPDATE != sta_msg.Op\
		&& SYNC_AUTH != sta_msg.Op && SYNC_DEL_AUTH != sta_msg.Op && SYNC_UPDATE != sta_msg.Op\
		&& NEW_AP_JOIN != sta_msg.Op && NEW_AP_JOIN_UPDATE != sta_msg.Op){
		eag_log_warning("stamsg receive unexpected EagMsg Op:%d",
			sta_msg.Op);
		return -1;
	}

	memcpy(usermac, sta_msg.STA.addr, sizeof(sta_msg.STA.addr));
	user_ip=sta_msg.STA.ip_addr;
	ip2str(user_ip, user_ipstr, sizeof(user_ipstr));
	mac2str(usermac, user_macstr, sizeof(user_macstr), ':');
	
	for (i = 0; i < intf_num; i++ )
	{
	        if (!strcmp(global_intf[i],sta_msg.STA.iface))
	                break;
	}
	//eag_log_info("i = %d, intf_num = %d",i, intf_num);
	if (i == intf_num)
	    return EAG_RETURN_OK;
    eag_log_info("stamsg_recieive usermac %s, userip %s,intf %s,OP: %d",user_macstr,user_ipstr,sta_msg.STA.iface,sta_msg.Op ); 
	stamsg_proc(stamsg, usermac, user_ip, &sta_msg,addr.sun_path);

	return EAG_RETURN_OK;
}

/*notify ASD  the user authorize state*/
int
eag_stamsg_send(eag_stamsg_t *stamsg,
		struct appsession *session,
		Operate Op)
{
	EagMsg sta_msg = {0};
	struct sockaddr_un addr = {0};
	socklen_t len = 0;
	ssize_t nbyte = 0;
	char ipstr[32] = "";
	char macstr[32] = "";
	char path[64]={0};
	
	if (NULL == stamsg || NULL == session) {
		eag_log_err("eag_stamsg_send input error");
		return EAG_ERR_NULL_POINTER;
	}

	memset(&sta_msg, 0, sizeof(sta_msg));
	sta_msg.Op = Op;
	sta_msg.STA.ip_addr = session->user_ip;
	memcpy(sta_msg.STA.addr, session->usermac, sizeof(sta_msg.STA.addr));

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	sprintf(path,STAMSG_SOCK_PATH_WAM"%s",session->intf);
	strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */
	if(Op == SYNC_AUTH)
	{
		  sta_msg.STA.session_start_time = session->session_start_time;
		  memcpy(sta_msg.STA.ssid,session->essid,MAX_ESSID_LENGTH);
		  memcpy(sta_msg.STA.username,session->username,USERNAMESIZE);

	}
	else if(Op == SYNC_DEL_AUTH)
	{
		memcpy(sta_msg.STA.ssid,session->essid,MAX_ESSID_LENGTH);
		eag_log_info("%s,%d,ssid %s",__func__,__LINE__,sta_msg.STA.ssid);
	}
	else if(Op == SYNC_UPDATE)
	{
    	sta_msg.STA.session_start_time = session->session_start_time;
		memcpy(sta_msg.STA.ssid,session->essid,MAX_ESSID_LENGTH);
		memcpy(sta_msg.STA.username,session->username,USERNAMESIZE);
		sta_msg.STA.bk_input_octets = session->input_octets;
        sta_msg.STA.bk_output_octets = session->output_octets;
	}
     	ip2str(session->user_ip, ipstr, sizeof(ipstr));
	mac2str(session->usermac, macstr, sizeof(macstr), ':');
	eag_log_info("stamsg send sockpath:%s, userip:%s, usermac:%s, Op:%d",
			addr.sun_path, ipstr, macstr, Op);
	nbyte = sendto(stamsg->sockfd, &sta_msg, sizeof(EagMsg), MSG_DONTWAIT,
					(struct sockaddr *)(&addr), len);
	if (nbyte < 0) {
		eag_log_err("eag_stamsg_send sendto failed, fd(%d), path(%s), %s",
			stamsg->sockfd, addr.sun_path, safe_strerror(errno));
		return -1;
	}
	if (nbyte != sizeof(sta_msg)) {
		eag_log_err("eag_stamsg_send sendto failed, nbyte(%d)!=sizeof(tm)(%d)",
			nbyte, sizeof(sta_msg));
		return -1;
	}

	return 0;
}

int
eag_stamsg_new_ap_join_send(eag_stamsg_t *stamsg,
		struct appsession *session,
		Operate Op)
{
	EagMsg sta_msg = {0};
	struct sockaddr_un addr = {0};
	socklen_t len = 0;
	ssize_t nbyte = 0;
	char ipstr[32] = "";
	char macstr[32] = "";
	char path[64]={0};
	appconn_db_t *appdb = NULL;
	struct app_conn_t *appconn = NULL;
	struct list_head *head = NULL;
	struct sync_user_info *sync_user;
	eag_sync_t *sync;
	uint8_t * buf;
	int i =0;
	
	if (NULL == stamsg || NULL == session) {
		eag_log_err("eag_stamsg_new_ap_join_send input error");
		return EAG_ERR_NULL_POINTER;
	}

	memset(&sta_msg, 0, sizeof(sta_msg));
	sta_msg.Op = Op;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	sprintf(path,STAMSG_SOCK_PATH_WAM"%s",session->intf);
	strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */
     
	eag_log_info("stamsg send sockpath:%s, userip:%s, usermac:%s, Op:%d",
			addr.sun_path, ipstr, macstr, Op);
            appdb = stamsg->appdb;
           head = appconn_db_get_head(appdb);
            sync = eag_ins_get_sync(stamsg->eagins);
	  buf = (uint8_t *)sta_msg.user_data;
    list_for_each_entry(appconn, head, node)
	{
        	if (APPCONN_STATUS_AUTHED == appconn->session.state) {
		    	sync_user = eag_sync_user_find(sync,&(appconn->session));
		        if(sync_user == NULL)
		        {
		        	sync_user = eag_sync_user_info_new(sync,&(appconn->session));
		        	eag_sync_add(sync,sync_user);

		        }
		        eag_log_debug("debug","userip %d,username %s,essid %s,sessiontime %d,bk_input_octets %d,bk_output_octets %d",\
		        sync_user->user_ip,sync_user->username,sync_user->essid,sync_user->session_start_time,sync_user->bk_input_octets,\
		        sync_user->bk_input_octets);
				memcpy(buf,sync_user,sizeof(struct sync_user_info));
				buf = buf + sizeof(struct sync_user_info);
				i++;    
        	}
		    if ( i == 4)
		    {
			       sta_msg.user_num = i;
    		                nbyte = sendto(stamsg->sockfd, &sta_msg, sizeof(EagMsg), MSG_DONTWAIT,
    					                (struct sockaddr *)(&addr), len);
                                	if (nbyte < 0) {
                                		eag_log_err("eag_stamsg_new_ap_join_send sendto failed, fd(%d), path(%s), %s",
                                			stamsg->sockfd, addr.sun_path, safe_strerror(errno));
                                		return -1;
                                	}
                                	if (nbyte != sizeof(sta_msg)) {
                                		eag_log_err("eag_stamsg_new_ap_join_send sendto failed, nbyte(%d)!=sizeof(tm)(%d)",
                                			nbyte, sizeof(sta_msg));
                                		return -1;
                                	}
				i = 0;
			          buf = (uint8_t *)sta_msg.user_data;
			           memset(buf,0,800);
		    }
      }
	  if (i > 0 && i < 4)
	  {
	  	           sta_msg.user_num = i;
                              nbyte = sendto(stamsg->sockfd, &sta_msg, sizeof(EagMsg), MSG_DONTWAIT,
                    					(struct sockaddr *)(&addr), len);
                    	if (nbyte < 0) {
                    		eag_log_err("eag_stamsg_send sendto failed, fd(%d), path(%s), %s",
                    			stamsg->sockfd, addr.sun_path, safe_strerror(errno));
                    		return -1;
                    	}
                    	if (nbyte != sizeof(sta_msg)) {
                    		eag_log_err("eag_stamsg_send sendto failed, nbyte(%d)!=sizeof(tm)(%d)",
                    			nbyte, sizeof(sta_msg));
                    		return -1;
                    	}
	  }

	return 0;
}


int
eag_stamsg_update(eag_stamsg_t *stamsg,
		struct appsession *session,char *intf,Operate Op)
{
	EagMsg sta_msg = {0};
	struct sockaddr_un addr = {0};
	socklen_t len = 0;
	ssize_t nbyte = 0;
	char ipstr[32] = "";
	char macstr[32] = "";
	char path[64]={0};
	
	if (NULL == stamsg || NULL == session) {
		eag_log_err("eag_stamsg_send input error");
		return EAG_ERR_NULL_POINTER;
	}

	memset(&sta_msg, 0, sizeof(sta_msg));
	sta_msg.Op = Op;
	sta_msg.STA.ip_addr = session->user_ip;
	memcpy(sta_msg.STA.addr, session->usermac, sizeof(sta_msg.STA.addr));

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	sprintf(path,STAMSG_SOCK_PATH_WAM"%s",intf);
	strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

	ip2str(session->user_ip, ipstr, sizeof(ipstr));
	mac2str(session->usermac, macstr, sizeof(macstr), ':');
	eag_log_info("stamsg send sockpath:%s, userip:%s, usermac:%s, Op:%d",
			addr.sun_path, ipstr, macstr, Op);
	nbyte = sendto(stamsg->sockfd, &sta_msg, sizeof(EagMsg), MSG_DONTWAIT,
					(struct sockaddr *)(&addr), len);
	if (nbyte < 0) {
		eag_log_err("eag_stamsg_send sendto failed, fd(%d), path(%s), %s",
			stamsg->sockfd, addr.sun_path, safe_strerror(errno));
		return -1;
	}
	if (nbyte != sizeof(sta_msg)) {
		eag_log_err("eag_stamsg_send sendto failed, nbyte(%d)!=sizeof(tm)(%d)",
			nbyte, sizeof(sta_msg));
		return -1;
	}

	return 0;
}


int
eag_stamsg_set_thread_master(eag_stamsg_t *stamsg,
		eag_thread_master_t *master)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_thread_master input error");
		return -1;
	}

	stamsg->master = master;

	return 0;
}

int
eag_stamsg_set_eagins(eag_stamsg_t *stamsg,
		eag_ins_t *eagins)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_eagins input error");
		return -1;
	}

	stamsg->eagins = eagins;

	return 0;
}

int
eag_stamsg_set_portal(eag_stamsg_t *stamsg,
		eag_portal_t *portal)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_portal input error");
		return -1;
	}

	stamsg->portal = portal;

	return EAG_RETURN_OK;
}

int
eag_stamsg_set_radius(eag_stamsg_t *stamsg,
		eag_radius_t *radius)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_radius input error");
		return -1;
	}

	stamsg->radius = radius;

	return EAG_RETURN_OK;
}

/*int
eag_stamsg_set_eagdbus(eag_stamsg_t *stamsg,
		eag_dbus_t *eagdbus)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_eagdbus input error");
		return -1;
	}

	stamsg->eagdbus = eagdbus;

	return EAG_RETURN_OK;
}*/

int
eag_stamsg_set_appdb(eag_stamsg_t *stamsg,
		appconn_db_t *appdb)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_appdb input error");
		return -1;
	}

	stamsg->appdb = appdb;

	return EAG_RETURN_OK;
}

int
eag_stamsg_set_captive(eag_stamsg_t *stamsg,
		eag_captive_t *captive)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_captive input error");
		return -1;
	}

	stamsg->captive = captive;

	return EAG_RETURN_OK;
}

int
eag_stamsg_set_macauth(eag_stamsg_t *stamsg,
		eag_macauth_t *macauth)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_macauth input error");
		return -1;
	}

	stamsg->macauth = macauth;

	return EAG_RETURN_OK;
}

int
eag_stamsg_set_portal_conf(eag_stamsg_t *stamsg,
		struct portal_conf *portalconf)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_portal_conf input error");
		return -1;
	}

	stamsg->portalconf = portalconf;

	return EAG_RETURN_OK;
}

int
eag_stamsg_set_nasid_conf(eag_stamsg_t *stamsg,
		struct nasid_conf *nasidconf)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_nasid_conf input error");
		return -1;
	}

	stamsg->nasidconf = nasidconf;

	return EAG_RETURN_OK;
}

int
eag_stamsg_set_nasportid_conf(eag_stamsg_t *stamsg,
		struct nasportid_conf *nasportidconf)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_nasportid_conf input error");
		return -1;
	}

	stamsg->nasportidconf = nasportidconf;

	return EAG_RETURN_OK;
}

int
eag_stamsg_set_eagstat(eag_stamsg_t *stamsg,
		eag_statistics_t *eagstat)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_eagstat input error");
		return -1;
	}

	stamsg->eagstat = eagstat;

	return EAG_RETURN_OK;

}

/*int
eag_stamsg_set_eaghansi(eag_stamsg_t *stamsg,
		eag_hansi_t *eaghansi)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_eaghansi input error");
		return -1;
	}

	stamsg->eaghansi = eaghansi;

	return EAG_RETURN_OK;

}*/

static void
eag_stamsg_event(eag_stamsg_event_t event,
		eag_stamsg_t *stamsg)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_event input error");
		return;
	}

	switch (event) {
	case EAG_STAMSG_READ:
		stamsg->t_read =
		    eag_thread_add_read(stamsg->master, stamsg_receive,
					stamsg, stamsg->sockfd);
		break;
	default:
		break;
	}
}

