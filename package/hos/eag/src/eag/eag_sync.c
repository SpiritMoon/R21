/*******************************************************************************
Copyright (C) Autelan Technology


This software file is owned and distributed by Autelan Technology 
********************************************************************************


THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR 
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
********************************************************************************
* eag_statistics.h
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
* eag statistics
*
*
*******************************************************************************/

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
	
#include "nm_list.h"
#include "hashtable.h"
#include "eag_mem.h"
#include "eag_log.h"
#include "eag_blkmem.h"
#include "eag_time.h"
#include "eag_util.h"

#include "appconn.h"
#include "eag_sync.h"
#include "eag_interface.h"

#define EAG_SYNC_BLKMEM_NAME		"ap_sync_blkmem"
#define EAG_SYNC_BLKMEM_ITEMNUM		128
#define EAG_SYNC_BLKMEM_MAXNUM		16



eag_sync_t *
eag_sync_create(uint32_t size)
{
	eag_sync_t *eagsync = NULL;
	
	if (0 == size) {
		eag_log_err("eag_statistics_create input error");
		return NULL;
	}

	eagsync = eag_malloc(sizeof(eag_sync_t ));
	if (NULL == eagsync) {
		eag_log_err("eag_statistics_create malloc failed");
		goto failed_0;
	}
	
	memset(eagsync, 0, sizeof(eag_sync_t));
	if (EAG_RETURN_OK != hashtable_create_table(&(eagsync->mac_htable), size)) {
		eag_log_err("eag_sync_create hashtable create failed");
		goto failed_1;
	}

	if (EAG_RETURN_OK != eag_blkmem_create(&(eagsync->sync_blkmem),
							EAG_SYNC_BLKMEM_NAME,
							sizeof(struct sync_user_info),
							EAG_SYNC_BLKMEM_ITEMNUM,
							EAG_SYNC_BLKMEM_MAXNUM)) {
		eag_log_err("eag_sync_create blkmem_create failed");
		goto failed_2;
	}

	
	INIT_LIST_HEAD(&(eagsync->head));

	eagsync->user_num = 0;

	eag_log_info("eag_sync create ok");
	return eagsync;

failed_2:
	hashtable_destroy_table(&(eagsync->mac_htable));
failed_1:
	eag_free(eagsync);
failed_0:
	return NULL;
}

int
eag_sync_clear(eag_sync_t *sync)
{
	struct sync_user_info *user_info= NULL;
	//struct list_head *head = NULL;
	struct sync_user_info *node = NULL;
	
	if (NULL == sync) {
		eag_log_err("eag_sync_clear input error");
		return -1;
	}

	list_for_each_entry_safe(user_info, node, &(sync->head), node) {
		eag_sync_del(sync,user_info);
		eag_sync_user_info_free(sync,user_info);
		}

	return 0;
}


int
eag_sync_destroy(eag_sync_t *eagsync)
{
	if (NULL == eagsync) {
		eag_log_err("eag_sync_destroy input error");
		return -1;
	}
	
	if (NULL != eagsync->sync_blkmem) {
		eag_blkmem_destroy(&(eagsync->sync_blkmem));
	}
	if (NULL != eagsync->mac_htable) {
		hashtable_destroy_table(&(eagsync->mac_htable));
	}
	eag_free(eagsync);

	eag_log_info("eag_sync destroy ok");

	return 0;
}

struct sync_user_info *
eag_sync_user_info_new(eag_sync_t *eagsync,struct appsession *session)
{
	struct sync_user_info *sync_user = NULL;
	char macstr[32] = "";

	if (NULL == eagsync || NULL == session) {
		eag_log_err("eag_sync_user_info_new input error");
		return NULL;
	}
	
	sync_user = eag_blkmem_malloc_item(eagsync->sync_blkmem);
	if (NULL == sync_user) {
		eag_log_err("eag_sync_user_info_new blkmem_malloc_item failed");
		return NULL;
	}
	
	memset(sync_user, 0, sizeof(struct sync_user_info));
	sync_user->user_ip=session->user_ip;
	memcpy(sync_user->usermac,session->usermac,6);
	memcpy(sync_user->username,session->username,USERNAMESIZE);
	memcpy(sync_user->essid,session->essid,MAX_ESSID_LENGTH);
	//eag_log_info("username; %s ,session->username : %s,essid :%s",sync_user->username,session->username,sync_user->essid);
	sync_user->session_start_time = session->session_start_time;
    //eag_log_info("sync->sessiom_time: %d ,session->session_time : %d",sync_user->session_start_time,session->session_start_time);
	INIT_LIST_HEAD(&(sync_user->node));
	return sync_user;
}

int
eag_sync_user_info_free(eag_sync_t *eagsync,struct sync_user_info *sync_user)
{
	
	if (NULL == eagsync || NULL == sync_user) {
		eag_log_err("eag_sync_user_info_free input error");
		return -1;
	}
	
	eag_blkmem_free_item(eagsync->sync_blkmem, sync_user);
	return 0;
}

 void eag_show_sync_user(eag_sync_t *eagsync)
  {
	  struct sync_user_info *user_info= NULL;
	  struct hlist_head *head = NULL;
	  char user_macstr[32] = "";
	  char user_ipstr[32] = "";
	  
	  if (NULL == eagsync ) {
		  eag_log_err("eag_sync_user_find input error");
		  return ;
	  }
	  
	  eag_log_info("###########################%s,%d,sync_num = %d##############################",__func__,__LINE__,eagsync->user_num);
	  list_for_each_entry(user_info, &(eagsync->head), node) {
	  		mac2str(user_info->usermac, user_macstr, sizeof(user_macstr), ':');
        	ip2str(user_info->user_ip, user_ipstr, sizeof(user_ipstr));
			eag_log_info("user_mac: %s ,user_ip: %s,ssid %s, sessionime %d",user_macstr,user_ipstr,user_info->essid,user_info->session_start_time);
			eag_log_info("addr:  %p ",user_info);
	  }
	  eag_log_info("##############################%s,%d########################################",__func__,__LINE__);
  
	 return;
  }


 int
eag_sync_add(eag_sync_t *eagsync,struct sync_user_info *sync_user)
{
	if (NULL == eagsync || NULL == sync_user) {
		eag_log_err("eag_sync_add input error");
		return -1;
	}
		
	hashtable_check_add_node(eagsync->mac_htable, sync_user->usermac, 6,
			&(sync_user->hnode));
	list_add_tail(&(sync_user->node), &(eagsync->head));

	eagsync->user_num++;

	return 0;
}

int
eag_sync_del(eag_sync_t *eagsync ,struct sync_user_info *sync_user)
{

	if (NULL == eagsync || NULL == sync_user) {
		eag_log_err("eag_sync_del input error");
		return -1;
	}

	list_del(&(sync_user->node));
	hlist_del(&(sync_user->hnode));

	eagsync->user_num--;
	
	return 0;
}
 struct sync_user_info*
eag_sync_username_find(eag_sync_t *eagsync, const char *username )
{
	struct sync_user_info *user_info= NULL;
	struct hlist_head *head = NULL;
	char user_macstr[32] = "";
	
	if (NULL == eagsync || NULL == username) {
		eag_log_err("eag_sync_user_find input error");
		return NULL;
	}
	list_for_each_entry(user_info, &(eagsync->head), node) {
		if (0 == memcmp(username, user_info->username, USERNAMESIZE)) {
			//eag_log_info("find eag_sync_user_find username=%s",username);
			return user_info;
		}
	}

	//eag_log_info( "eag_sync_user_find username=%s",username);
	
	return NULL;
}

 
 void eag_find_sync_ssid_delete_user(eag_sync_t *eagsync, const char *ssid )
 {
	 struct sync_user_info *user_info= NULL;
	 struct hlist_head *head = NULL;
	 
	 if (NULL == eagsync || NULL == ssid) {
		 eag_log_err("eag_sync_user_find input error");
		 return ;
	 }
	 //eag_log_info("%s,%d,ssid = %s",__func__,__LINE__,ssid);
	 list_for_each_entry(user_info, &(eagsync->head), node) {
	 	//eag_log_info("sync->ssid %s",user_info->essid);
		 if (0 == memcmp(ssid, user_info->essid, MAX_ESSID_LENGTH)) {
		 	eag_log_info("user ip %d",user_info->user_ip);
		 	eag_sync_del(eagsync,user_info);
			eag_sync_user_info_free(eagsync,user_info);
			
			return;
			 
		 }
	 }
	 
	 //eag_log_info("%s,%d",__func__,__LINE__);
 
	return;
 }

 struct sync_user_info*
eag_sync_user_find(eag_sync_t *eagsync, struct appsession *session)
{
	struct sync_user_info *user_info= NULL;
	struct hlist_head *head = NULL;
	struct hlist_node *node = NULL;
	char user_macstr[32] = "";
	
	if (NULL == eagsync || NULL == session) {
		eag_log_err("eag_sync_user_find input error");
		return NULL;
	}
	
	mac2str(session->usermac, user_macstr, sizeof(user_macstr), ':');
	
	head = hashtable_get_hash_list(eagsync->mac_htable, session->usermac, 6);
	if (NULL == head) {
		eag_log_err("eag_sync_user_find head null");
		return NULL;
	}
	
	hlist_for_each_entry(user_info, node, head,hnode) {
		if (0 == memcmp(session->usermac, user_info->usermac, 6) && (0 == strcmp(session->essid,user_info->essid))) {
			//eag_log_info("find eag_sync_user_find usermac=%s,ssid %s",	user_macstr,user_info->essid);
			return user_info;
		}
	}

	//eag_log_info( "@####  eag_sync_user_find usermac=%s,ssid %s",user_macstr,session->essid);
	
	return NULL;
}

struct list_head *
eag_sync_get_user_head(eag_sync_t *eagsync)
{
	return &(eagsync->head);
}

