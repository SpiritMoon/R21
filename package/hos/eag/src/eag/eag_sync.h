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

#ifndef _EAG_SYNC_H
#define _EAG_SYNC_H

#include <stdint.h>
#include "eag_def.h"
#include "eag_time.h"

struct sync_user_info{
	struct list_head node;
	struct list_head hnode;
          uint32_t user_ip;
	uint8_t usermac[PKT_ETH_ALEN];
	char username[USERNAMESIZE];
	char essid[MAX_ESSID_LENGTH];
	//uint32_t session_time;
	time_t session_start_time;
	uint64_t bk_input_octets;
	uint64_t bk_output_octets;
};

struct eag_sync {
	struct list_head head;			
	hashtable *mac_htable;	
	eag_blk_mem_t *sync_blkmem;
	int user_num;
};

eag_sync_t *
eag_sync_create(uint32_t size);

int
eag_sync_clear(eag_sync_t *sync);
int
eag_sync_destroy(eag_sync_t *eagstat);

struct sync_user_info *
eag_sync_user_info_new(eag_sync_t *eagsync,struct appsession*session);

int
eag_sync_user_info_free(eag_sync_t *eagsync,struct sync_user_info *sync_user);

 int
eag_sync_add(eag_sync_t *eagsync,struct sync_user_info *sync_user);

 int
eag_sync_del(eag_sync_t *eagsync ,struct sync_user_info *sync_user);

 struct sync_user_info*
eag_sync_user_find(eag_sync_t *eagsync, struct appsession*session);

  struct sync_user_info*
eag_sync_username_find(eag_sync_t *eagsync, const char *username );
  
void eag_find_sync_ssid_delete_user(eag_sync_t *eagsync, const char *ssid );
void eag_show_sync_user(eag_sync_t *eagsync);


#endif		/* _EAG_STATISTICS_H */

