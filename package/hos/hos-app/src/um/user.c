#include "utils.h"
#include "tid.h"
#include "um.h"

#define UMALECLIENT  "hanset"
int um_open_voice = 0;	//default close
int um_open_bgs = 1;	//default open


static inline int
hashbuf(byte *buf, int len, int mask)
{
    int i;
    int sum = 0;
    
    for (i=0; i<len; i++) {
        sum += (int)buf[i];
    }

    return sum & mask;
}

static inline int
hashmac(byte mac[])
{
    return hashbuf(mac, OS_MACSIZE, UM_HASHMASK);
}

static inline int
haship(uint32_t ip)
{
    return hashbuf((byte *)&ip, sizeof(ip), UM_HASHMASK);
}

static inline bool
in_list(struct list_head *node)
{
    return  (node->next && node->prev) && false==list_empty(node);
}

static inline int
__remove(struct apuser *user, void (*cb)(struct apuser *user))
{
    if (NULL==user) {
        return -EKEYNULL;
    }
    /*
    * not in list
    */
    else if (false==in_list(&user->node.list)) {
        debug_user_trace("[um]:__remove nothing(not in list)");
        
        return 0;
    }
    
    list_del(&user->node.list);
    if (is_good_mac(user->mac)) {
        hlist_del_init(&user->node.mac);
    }
    if (user->ip) {
        hlist_del_init(&user->node.ip);
    }
    umc.head.count--;

    if (cb) {
        cb(user);
    }

    return 0;
}

static inline int
__insert(struct apuser *user, void (*cb)(struct apuser *user))
{
    char *action;

	debug_user_trace( "[um]:__insert vap addr : %02x:%02x:%02x:%02x:%02x:%02x", user->vap[0],user->vap[1] ,user->vap[2] ,user->vap[3] ,user->vap[4] ,user->vap[5]);

    
    if (NULL==user) {
        return -EKEYNULL;
    }
    /*
    * have in list
    */
    else if (in_list(&user->node.list)) {
        return -EINLIST;
    }
        
    list_add(&user->node.list, &umc.head.list);
    if (is_good_mac(user->mac)) {
        hlist_add_head(&user->node.mac, &umc.head.mac[hashmac(user->mac)]);
    }
    if (user->ip) {
        hlist_add_head(&user->node.ip,  &umc.head.ip[haship(user->ip)]);
    }
    umc.head.count++;

    if (cb) {
        cb(user);

        action = "create";
    } else {
        action = "update";
    }

    debug_user_trace("[um]:%s user, count(%d)", action, umc.head.count);
    um_user_dump(user, action);
    
    return 0;
}

static struct apuser *
__create(byte mac[])
{
    struct apuser *user = (struct apuser *)os_malloc(sizeof(*user));
    if (NULL==user) {
        return NULL;
    }
    
    um_user_init(user, true);
    os_maccpy(user->mac, mac);
    user->wifi.uptime = time(NULL);
    
    return user;
}

void
__um_user_dump(struct apuser *user, char *action)
{
    debug_user_trace("[um]: =====%s user begin======", action);

	debug_user_trace("[um]: __um_user_dump vap addr : %02x:%02x:%02x:%02x:%02x:%02x\n",user->vap[0],user->vap[1] ,user->vap[2] ,user->vap[3] ,user->vap[4] ,user->vap[5]);

    debug_user_trace("\t[um]: ap            = %s",  um_macstring(user->ap));
    debug_user_trace("\t[um]: vap           = %s",  um_macstring(user->vap));
    debug_user_trace("\t[um]: mac           = %s",  um_macstring(user->mac));
    debug_user_trace("\t[um]: ip            = %s",  user->stdevinfo.ipaddr);
    debug_user_trace("\t[um]: ifname        = %s",  user->ifname);
    debug_user_trace("\t[um]: radioid       = %d",  user->radioid);
    debug_user_trace("\t[um]: wlanid        = %d",  user->wlanid);
    debug_user_trace("\t[um]: uptime        = %u",  user->wifi.uptime);
	debug_user_trace("\t[um]: mode          = %u",  user->wifi.mode);
	debug_user_trace("\t[um]: livetime      = %u",  user->wifi.livetime);
    debug_user_trace("\t[um]: rx.bytes      = %llu",user->wifi.rx.bytes);
	debug_user_trace("\t[um]: rx.packets    = %u",  user->wifi.rx.packets);
	debug_user_trace("\t[um]: rx.rate       = %u",  user->wifi.rx.rate);
    debug_user_trace("\t[um]: rx.wifirate   = %u",  user->wifi.rx.wifirate);
    debug_user_trace("\t[um]: tx.bytes      = %llu",user->wifi.tx.bytes);
	debug_user_trace("\t[um]: tx.packets    = %u",  user->wifi.tx.packets);	
	debug_user_trace("\t[um]: tx.rate       = %u",  user->wifi.tx.rate);
  	debug_user_trace("\t[um]: tx.wifirate   = %u",  user->wifi.tx.wifirate);
	debug_user_trace("\t[um]: portal.state  = %d",  user->portal.state);	
	debug_user_trace("\t[um]: portal.type   = %d",  user->portal.type);
    debug_user_trace("\t[um]: portal.enable = %d",  user->portal.enable);
	debug_user_trace("\t[um]: portal.state  = %s",  um_user_portal_state(user));	
	debug_user_trace("\t[um]: portal.type   = %s",  um_user_portal_type(user));
    debug_user_trace("\t[um]: hostname      = %s",  user->stdevinfo.hostname);
    debug_user_trace("\t[um]: devtype       = %s",  user->stdevinfo.devtype);
    debug_user_trace("\t[um]: ostype        = %s",  user->stdevinfo.ostype);
    debug_user_trace("\t[um]: cputype       = %s",  user->stdevinfo.cputype);
    debug_user_trace("\t[um]: devmodel      = %s",  user->stdevinfo.devmodel);
    debug_user_trace("\t[um]: delaytime     = %u",  user->delaytime);
    debug_user_trace("\t[um]: packetloss    = %u",  user->packetloss);
    debug_user_trace("\t[um]: rx_retr       = %u",  user->rx_retr);
    debug_user_trace("\t[um]: tx_retr       = %u",  user->tx_retr);

    debug_user_trace("[um]: =====%s user end======", action);

    return;
}
static uint32_t get_ip_from_arp(char *mac)
{
	FILE *fp = NULL;
	uint32_t ip = 0;
	char str_tmp_cmd[256];
	char str_tmp_ip[256];

	memset(str_tmp_cmd, 0, sizeof(str_tmp_cmd));
	memset(str_tmp_ip, 0, sizeof(str_tmp_ip));

	sprintf(str_tmp_cmd, "/sbin/arp -a |awk '{if($4==\"%s\"){print $2}}'|tr -d '(|)'", mac);

	fp = popen(str_tmp_cmd,"r");
	if(NULL == fp)
	{
		debug_main_waring("[um]: arp get fail");
		return 0;
	}

	if(NULL == fgets(str_tmp_ip, sizeof(str_tmp_ip), fp))
	{
		debug_main_waring("[um]: ip is not find for %s in arp", mac);
		pclose(fp);
		return 0;
	}

	str_tmp_ip[strlen(str_tmp_ip) - 1] = '\0';

	ip = ntohl(inet_addr(str_tmp_ip));

	pclose(fp);
	debug_main_waring("[um]: get ip is [%s] for %s from arp", str_tmp_ip, mac);

	return ip;
}

//Add by liumengmeng 2016-8-8 :get ip from ap 
static uint32_t get_ip_from_ap(char *mac)
{
	FILE *fp = NULL;
	uint32_t ip = 0;
	char str_tmp_cmd[256];
	char str_tmp_ip[256];
	
	memset(str_tmp_cmd, 0, sizeof(str_tmp_cmd));
	memset(str_tmp_ip, 0, sizeof(str_tmp_ip));
		
	sprintf(str_tmp_cmd, "/usr/sbin/sta_list | awk '{if($1==\"%s\") {print $2;}}'", mac);
	
	fp = popen(str_tmp_cmd,"r");
	if(NULL == fp)
	{
		debug_main_waring("[um]: sta_list get fail");
		return 0;
	}
	
	if(NULL == fgets(str_tmp_ip, sizeof(str_tmp_ip), fp))
	{
		debug_main_waring("[um]: ip is not find for %s in sta_list", mac);
		pclose(fp);
		return 0;
	}
	
	str_tmp_ip[strlen(str_tmp_ip) - 1] = '\0';
	
	ip = ntohl(inet_addr(str_tmp_ip));
		
	pclose(fp);
	debug_main_waring("[um]: get ip is [%s] for %s from sta_list", str_tmp_ip, mac);
	
	return ip;
}
//add end 2016-8-8 by liumengmeng 
struct apuser *
um_user_update(struct apuser *info, um_user_update_f *update)
{
    struct apuser *user = NULL;
    bool created = false;
    int devupdate = -1;
	
//Add by liumengmeng 2016-8-8 :to determine whether it is normal mac 
	if (!is_good_mac(info->mac))
	{
		return NULL;
	}
//Add end 2016-8-8	
	debug_user_trace( "[um]:um_user_update vap addr : %02x:%02x:%02x:%02x:%02x:%02x\n",info->vap[0],info->vap[1] ,info->vap[2] ,info->vap[3] ,info->vap[4] ,info->vap[5]);
    
    /*
    * if no found, create new
    */
    user = um_user_getbymac(info->mac);
    if (NULL==user) {
        user = __create(info->mac);
        if (NULL==user) {
            return NULL;
        }
        created = true;
    }
    
    /*
    * maybe update hash key(user mac/ip)
    *   so, remove it first
    */
    __remove(user, NULL);
    (*update)(created, user, info);
    
    //begin add for voice 
    struct devinfo *pstdevinfo;
    pstdevinfo = &user->stdevinfo;
    if (0 == user->is_iptables && 0 == strcasecmp((pstdevinfo->devtype), UMALECLIENT))
    {
        if (0 != user->ip)
        {
            /*  add iptables */
            char cmd_buf[128];
            memset(cmd_buf, 0, sizeof(cmd_buf));
            sprintf(cmd_buf, "iptables -t mangle -A FORWARD -d %s -j DSCP --set-dscp 0x30", os_ipstring(user->ip));
            system(cmd_buf);

            memset(cmd_buf, 0, sizeof(cmd_buf));
            sprintf(cmd_buf, "iptables -t mangle -A FORWARD -s %s -j DSCP --set-dscp 0x30", os_ipstring(user->ip));
            system(cmd_buf);

            user->is_iptables = 1;
            debug_tid_waring("[um]: add iptables %s \r\n", os_ipstring(user->ip));
        }
    }
    //end
    
    //um_rwlock_rdlock();
    //delay_insert_ip(user->stdevinfo.ipaddr);
    //delay_update_stadelay(user);
    //um_rwlock_unlock();
    __insert(user, created?um_ubus_insert_cb:NULL);
    um_ubus_devinfo_cb(user);

    /*
    * reset aging
    */
    user->aging = um_agtimes();

	if (user->stdevinfo.ipaddr[0] == 0 && user->ip != 0)
	{
		memcpy(user->stdevinfo.ipaddr, os_ipstring(user->ip), sizeof(user->stdevinfo.ipaddr));
	}
	if (0 == user->ip)
	{
		user->ip = get_ip_from_arp(um_macstring(user->mac));
	}
//Add by liumengmeng 2016-8-8 :get ip 
#if 1
	if (0 == user->ip)
	{
		user->ip = get_ip_from_ap(um_macstring(user->mac));
	}
#endif 
//Add end
	if (created)
	{
		debug_tid_waring("[um]:um_user_update creat:%d mac: %x:%x:%x:%x:%x:%x ip:%s\r\n", (int)created,
			user->mac[0], user->mac[1],user->mac[2],user->mac[3],user->mac[4],user->mac[5], os_ipstring(user->ip));
	}

    return user;
}

int
um_user_foreach(um_foreach_f *foreach, void *data)
{
    multi_value_u mv;
    struct apuser *user, *n;
    
    list_for_each_entry_safe(user, n, &umc.head.list, node.list) {
        mv.value = (*foreach)(user, data);
        if (mv2_is_break(mv)) {
            return mv2_result(mv);
        }
    }
    
    return 0;
}

void is_open_backscan()
{
    struct apuser *user = NULL;
    
    list_for_each_entry(user, &umc.head.list, node.list) 
    {
        if (user->con_statics > 0) 
        {
            break;
        }
    }

    if (&umc.head.list == &(user->node.list))
    {
        /* open scanning */
        if (1 == um_open_voice && 0 == um_open_bgs)
        {
			um_open_bgs = 1;
            system("bg-s -x pause_scanning=0");
            debug_tid_waring("[um]:bg-s -x pause_scanning=0 open bg-s\r\n");
        }
    }
    
    return;
}

struct apuser *
um_user_getbymac(byte mac[])
{
    struct apuser *user;
    struct hlist_head *head = &umc.head.mac[hashmac(mac)];
    
    hlist_for_each_entry(user, head, node.mac) {
        if (os_maceq(user->mac, mac)) {
            return user;
        }
    }

    return NULL;
}

struct apuser *
um_user_getbyip(uint32_t ip)
{
    struct apuser *user;
    struct hlist_head *head = &umc.head.ip[haship(ip)];
    
    hlist_for_each_entry(user, head, node.ip) {
        if (user->ip==ip) {
            return user;
        }
    }

    return NULL;
}

int
um_user_del(struct apuser *user)
{
    int ret = -1;

    ret = __remove(user, um_ubus_remove_cb);
    if (user != NULL)
    {
        //begin add for voice 
        struct devinfo *pstdevinfo;
        pstdevinfo = &user->stdevinfo;
        if (0 == strcasecmp((pstdevinfo->devtype), UMALECLIENT) && 0 != user->ip)
        {
            // del iptable
            char cmd_buf[128];
            memset(cmd_buf, 0, sizeof(cmd_buf));
            sprintf(cmd_buf, "iptables -t mangle -D FORWARD -d %s -j DSCP --set-dscp 0x30", os_ipstring(user->ip));
            system(cmd_buf);

            memset(cmd_buf, 0, sizeof(cmd_buf));
            sprintf(cmd_buf, "iptables -t mangle -D FORWARD -s %s -j DSCP --set-dscp 0x30", os_ipstring(user->ip));
            system(cmd_buf);
            debug_tid_waring("[um]: del iptables %s \r\n", os_ipstring(user->ip));
        }
        //end
        debug_tid_waring("[um]: um user del %s \r\n", os_ipstring(user->ip));
        free(user);
    }
    
    return ret;
}

static inline bool
macmatch(byte umac[], byte fmac[], byte mask[])
{
    if (is_good_mac(fmac)) {
        if (is_zero_mac(mask)) {
            /*
            * mac NOT zero
            * macmask zero
            *
            * use mac filter
            */
            if (false==os_maceq(umac, fmac)) {
                return false;
            }
        } else {
            /*
            * mac NOT zero
            * macmask NOT zero
            *
            * use mac/macmask filter
            */
            if (false==os_macmaskmach(umac, fmac, mask)) {
                return false;
            }
        }
    }

    return true;
}


static inline bool
ipmatch(unsigned int uip, unsigned int fip, unsigned int mask)
{
    if (fip) {
        if (0==mask) {
            /*
            * ip NOT zero
            * ipmask zero
            *
            * use ip filter
            */
            if (uip != fip) {
                return false;
            }
        } else {
            /*
            * ip NOT zero
            * ipmask NOT zero
            *
            * use ip/ipmask filter
            */
            if (false==os_ipmatch(uip, fip, mask)) {
                return false;
            }
        }
    }

    return true;
}

static bool
match(struct apuser *user, struct user_filter *filter)
{
    /* local not matched */
    if (filter->local && false==user->local) {
        return false;
    }
    
    if (false==macmatch(user->mac, filter->mac, filter->macmask)) {
        return false;
    }
    
    if (false==macmatch(user->ap, filter->ap, filter->apmask)) {
        return false;
    }
    
    if (false==ipmatch(user->ip, filter->ip, filter->ipmask)) {
        return false;
    }
    
    if (filter->radioid>=0 && user->radioid!=filter->radioid) {
        return false;
    }

    if (filter->wlanid>=0 && user->wlanid!=filter->wlanid) {
        return false;
    }

    /* all matched */
    return true;
}

static multi_value_t
getby_cb(struct apuser *user, void *data)
{
    void **param = (void **)data;
    struct user_filter *filter = (struct user_filter *)param[0];
    um_get_f *get = (um_get_f *)param[1];
    void *arg = param[2];
    
    if (match(user, filter)) {
        return (*get)(user, arg);
    } else {
        return mv2_OK;
    }
}

int
um_user_getby(struct user_filter *filter, um_get_f *get, void *data)
{
    void *param[] = {
        (void *)filter,
        (void *)get,
        (void *)data,
    };
    
    return um_user_foreach(getby_cb, param);
}

char *
um_macstring(byte mac[])
{
    static char macstring[1+MACSTRINGLEN_L];

    os_macsaprintf(mac, macstring, ':');

    return macstring;
}

/******************************************************************************/
