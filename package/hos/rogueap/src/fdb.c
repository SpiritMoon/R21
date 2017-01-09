/******************************************************************************
  File Name    : fdb.c
  Author       : zhaoej
  Date         : 20160225
  Description  : FDB form of bridge info
******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/time.h>
#include <linux/sockios.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>
#include <linux/in6.h>
#include <linux/if_bridge.h>



#include "rogue_utils.h"
int br_fd =0;

struct br_entry BR[MAX_BRIDGES];
static int show_bridge(char* name, int index);
int br_foreach_bridge(int (*iterator)(char *,int ),int x);
int br_fdb_macs(char * brname,int x);


static int show_bridge(char* name, int i)
{
	memcpy(BR[i].brname,name,IFNAMSIZ);
	return 0;
}

static int compare_fdbs(const void *_f0, const void *_f1)
{
	const struct fdb_entry *f0 = _f0;
	const struct fdb_entry *f1 = _f1;
	return memcmp(f0->mac_addr, f1->mac_addr, 6);
}
Bool br_init(void)
{
	char str[STR_BUF];
	memset(str, 0, STR_BUF);

	if((br_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		sprintf(str,"init socket error=%d!",errno);
		rogue_debug(MODULE_ROGUE, ROGUEAP_LOG_LEVEL_ERR,str);
		rogue_debug_error("[ROGUEAP]: create bridge socket failed,error=%d",errno);
		return FALSE;
	}
	return TRUE;
}

int get_fdb_form(){
	int br_num = 0;
	int ret = -1;
	int i,j;

	memset(BR, 0, 1024);
	memset(FDB, 0, 1024);
	br_num = br_foreach_bridge(show_bridge, 0);

	for(i = 0; i < br_num; i++){
		ret = br_fdb_macs(BR[i].brname,ret);
	}
	qsort(FDB, ret+1, sizeof(struct fdb_entry), compare_fdbs);
	if(list_debug){
		dump_file_open("w+");
		fprintf(DUMP_FILE, "\n======================FDB Form Information======================\n");
		fprintf(DUMP_FILE,"MAC_ID\tMAC_ADDR\t\tMAC_ID\tMAC_ADDR\n");
		for(j = 0; j< ret+1; j++){	
			if(j%2==0 && j!=0){
				fprintf(DUMP_FILE, "\n");
			}
			fprintf(DUMP_FILE, "%d\t%2x:%2x:%2x:%2x:%2x:%2x\t",j,
		 		FDB[j].mac_addr[0], FDB[j].mac_addr[1], FDB[j].mac_addr[2],
		 		FDB[j].mac_addr[3], FDB[j].mac_addr[4], FDB[j].mac_addr[5]);
		}
		fprintf(DUMP_FILE,"\n");
		dump_file_close();
	}
	return ret;
}

int br_foreach_bridge(int (*iterator)(char *,int ),int x)
{
	int i, ret=0, num;
	char ifname[IFNAMSIZ];
	int ifindices[MAX_BRIDGES];
	unsigned long args[3] = { BRCTL_GET_BRIDGES, 
				 (unsigned long)ifindices, MAX_BRIDGES };

	num = ioctl(br_fd, SIOCGIFBR, args);
	if (num < 0) {
		rogue_debug_error("[ROGUEAP]: Get bridge indices failed: %s",strerror(errno));
		return -errno;
	}

	for (i = 0; i < num; i++) {
		if (!if_indextoname(ifindices[i], ifname)) {
			rogue_debug_error("[ROGUEAP]: get find name for ifindex %d\n",ifindices[i]);
			return -errno;
		}
		++ret;
		x = i;
		if(iterator(ifname, x)) 
			break;
	}
	return ret;
}

int br_read_fdb(const char *bridge, struct fdb_entry *fdbs, unsigned long offset, int num)
{
	int i, n;
	struct __fdb_entry fe[num];

	unsigned long args[4] = { BRCTL_GET_FDB_ENTRIES,
				  (unsigned long) fe,
				  num, offset };
	struct ifreq ifr;
	int retries = 0;

	strncpy(ifr.ifr_name, bridge, IFNAMSIZ);
	ifr.ifr_data = (char *) args;

retry:
	n = ioctl(br_fd, SIOCDEVPRIVATE, &ifr);
	/* table can change during ioctl processing */
	if (n < 0 && errno == EAGAIN && ++retries < 10) {
		sleep(0);
		goto retry;
	}

	for (i = 0; i < n; i++){ 
		memcpy((fdbs+i)->mac_addr, (fe+i)->mac_addr, 6);
	}
	return n;
}

int br_fdb_macs(char * brname,int j)
{
#define CHUNK 128
	int i, n;
	int fdb_mac=0;
	struct fdb_entry *fdb = NULL,*tmp_fdb = NULL;
	int offset = 0;

	for(;;) {
		tmp_fdb = realloc(fdb, (offset + CHUNK) * sizeof(struct fdb_entry));
		if (!tmp_fdb) {
			rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_ERR,"Realloc memory failed!");
			rogue_debug_error("[ROGUEAP]: Realloc memory failed!");
			free(fdb);
			return 0;
		}
		fdb = tmp_fdb;
		n = br_read_fdb(brname, fdb+offset, offset, CHUNK);
		if (n == 0)
			break;
		
		if (n < 0) {
			rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_ERR,"read of forward table failed!");
			rogue_debug_error("[ROGUEAP]: read of forward table failed: %s\n",strerror(errno));
			free(fdb);
			return 0;
		}
		offset += n;
	}
	
	for (i = 0; i < offset; i++) {
		j++;
		const struct fdb_entry *f = fdb + i;
		if(j < MAX_FDB){
			memcpy(FDB[j].mac_addr, f->mac_addr, 6);
			fdb_mac=j;
		}
	}
	if(j >= MAX_FDB){
		rogue_debug(MODULE_ROGUE,ROGUEAP_LOG_LEVEL_WARNING,"More than the FDB list(1024)MAC maximum!");	
	}
	
	free(fdb);
	return fdb_mac;
}

