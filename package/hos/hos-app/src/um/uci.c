#include "utils.h"
#include "tid.h"
#include "um.h"

extern int um_open_voice;

static struct um_intf *
intf_create(char *ifname)
{
    struct um_intf *intf = NULL;

    intf = (struct um_intf *)os_zalloc(sizeof(*intf));
    if (NULL==intf) {
        return NULL;
    }
    os_strdcpy(intf->ifname, ifname);

    debug_uci_trace("[um]:load intf(%s)", ifname);
    
    return intf;
}

static void
intf_destroy(struct um_intf *intf)
{
    debug_uci_trace("[um]:unload intf(%s)", intf->ifname);
    
    os_free(intf);

    return;
}

static void
intf_insert(struct um_intf *intf, struct list_head *head)
{
    list_add(&intf->node, head);

    return;
}

static void
intf_remove(struct um_intf *intf, bool delete_user)
{
    if (delete_user) {
    }
    
    list_del(&intf->node);

    return;
}

static void 
uci_init(void)
{
    umc.uci.ctx = uci_alloc_context();
    if (NULL==umc.uci.ctx) {
        debug_uci_waring("[um]:open uci context failed");

        return;
    } else {
        debug_uci_trace("[um]:open uci context");
    }

#if 0
    uci_set_confdir(umc.uci.ctx, "/etc/config");
    debug_uci_trace("set uci config path");
#endif

    return;
}

static void 
uci_fini(void)
{
    if (umc.uci.ctx) {
        uci_free_context(umc.uci.ctx);
        debug_uci_trace("[um]:close uci context");
    }

    return;
}

static void
package_close(struct uci_package *p)
{
    if (umc.uci.ctx && p) {
        uci_unload(umc.uci.ctx, p);
        debug_uci_trace("[um]:close uci package(%p)", p);
    }

    return;
}

static struct uci_package *
package_open(char *name)
{
    struct uci_package *package = NULL;
    int err = 0;
    
    err = uci_load(umc.uci.ctx, name, &package);
    if (err) {
        debug_uci_waring("[um]:open uci package(%s) failed", name);
    } else {
        debug_uci_trace("[um]:open uci package(%s)", name);
    }

    return package;
}


static void
section_to_blob
(
    struct uci_section *s, 
    struct uci_blob_param_list *param, 
    struct blob_attr *tb[],
    int count
)
{
    if (param->n_params == count) {
        um_blob_buf_init();
        uci_to_blob(&b, s, param);
        blobmsg_parse(param->params, param->n_params, tb, blob_data(b.head), blob_len(b.head));
    } else {
        os_assert(0);
    }

    return;
}

static struct um_intf *
__load_intf(char *ifname, struct blob_attr *tb[], int count, struct list_head *head)
{
    struct blob_attr *p;
    struct um_intf *intf = NULL;
    bool disable = false;
    
    p = tb[UM_INTFPOLICY_DISABLE];
    if (p) {
        disable = blobmsg_get_bool(p);
    }
    
    if (disable) {
        debug_uci_trace("[um]:no load disabled intf(%s)", ifname);
        
        return NULL;
    }
    
    intf = intf_create(ifname);
    if (NULL==intf) {
        debug_uci_waring("[um]:create intf(%s) failed", ifname);
        
        return NULL;
    }
    intf_insert(intf, head);

    debug_uci_trace("[um]:load intf(%s) to tmp", ifname);
    
    return intf;
}

static int
load_radio(struct uci_section *s, struct blob_attr *tb[], int count, struct list_head *head)
{
    struct um_intf *intf;
    char *ifname = s->e.name;
    int radioid = 0;

    intf = __load_intf(ifname, tb, count, head);
    if (NULL==intf) {
        return 0;
    }
    intf->type = UM_INTF_RADIO;
#if 1
    if (1 != os_sscanf(ifname, "wifi%d", &radioid)) {
        debug_uci_waring("load radio failed(bad name:%s)", ifname);
        
        return -EFORMAT;
    }
#else
    if (1 != os_sscanf(ifname, "radio%d", &radioid)) {
        debug_uci_waring("[um]:load radio failed(bad name:%s)", ifname);
        
        return -EFORMAT;
    }
#endif
    intf->radioid = radioid;
    
    debug_uci_trace("[um]:load %s to tmp", ifname);
    
    return 0;
}

static int
load_wlan(struct list_head *head)
{
	struct blob_attr *p;
	struct um_intf *intf,*intf_tmp,*b;
	char *ifname = NULL;
	char tmp[20][8]={0}; 
	int i = 0 ;     
	int num = 0;
	int radioid = 0;
	int wlanid  = 0;
	int ret = -1;
	FILE *fp;
	char buf[256];
	int continue_flag = 0 ;

	fp = fopen("/proc/net/wireless", "r");

	if(fp)
	{
		while(fgets(buf, sizeof(buf) - 1, fp))
		{
			continue_flag=0;
			ifname = strtok(buf, ":");
			if (strstr(ifname, "ath"))
			{
				while(*ifname && isspace(*ifname))
				{
					ifname ++;
				}

				if(strncmp(ifname, "athscan", 7) == 0)
				{
					continue;
				}
				debug_uci_trace("[um]:load intf(%s) to tmp", ifname);

/*Name:liumengmeng ,fix the memory leak £¬if the interface exist£¬continue */
				strcpy(tmp[i++],ifname);            
				list_for_each_entry_safe(intf_tmp, b, (&umc.uci.wlan.tmp), node) {
					if(strcmp(ifname, intf_tmp->ifname) == 0)
					{
						continue_flag=1;
						break;
					}
				}
				if(continue_flag == 1)
					continue; 
/*end liumengmeng */

				intf = intf_create(ifname);
				if (NULL==intf)
				{
					debug_uci_waring("[um]:create intf(%s) failed", ifname);
					ret = -1;
					break;
				}

				intf_insert(intf, head);

				os_sscanf(ifname, "ath%d", &num);
				radioid = num / 10;
				wlanid = num % 10;

				intf->type      = UM_INTF_WLAN;
				intf->radioid   = radioid;
				intf->wlanid    = wlanid;
			}
		}
#if 1
//add by liumengmeng 2016-8-5  aging the  umc.uci.wlan.tmp 
		list_for_each_entry_safe(intf_tmp, b, (&umc.uci.wlan.tmp), node)
		{
			bool matched = false;
			for(i = 0;tmp[i][0]!= 0;i++) 
			{
				if(strcmp(tmp[i],intf_tmp->ifname) == 0)
				{
					matched=true;
					break;
				}
			}
			if (false == matched)
			{ 
				intf_remove(intf_tmp, false);
				intf_destroy(intf_tmp);  
				debug_uci_trace("[um]:delete %s from tmp", intf_tmp->ifname);
			}
		}
//add end 2016-8-5
#endif 

		fclose(fp);
		ret = 0;
		
		return ret;
	}
}


static void
load_intf(
    struct uci_package *wireless,
    struct um_uci *uci,
    int (*load)(struct uci_section *s, struct blob_attr *tb[], int count, struct list_head *head)
)
{
    struct uci_element *e = NULL;
    int count = uci->param.n_params;
    struct blob_attr **tb = (struct blob_attr **)os_alloca(count * sizeof(struct blob_attr *));
    
    if (NULL==tb) {
        return;
    }
    
	uci_foreach_element(&wireless->sections, e) {
		struct uci_section *s = uci_to_section(e);
		
		if (0==os_strcmp(s->type, uci->uci_type)) {
    		section_to_blob(s, &uci->param, tb, count);
    		(*load)(s, tb, count, &uci->tmp);
		}
	}

    return;
}

static int
intf_compare(int type)
{
    struct um_intf *intf_cfg, *intf_tmp, *a, *b;
    struct list_head *cfg;
    struct list_head *tmp;

    switch(type) {
        case UM_INTF_RADIO:
            cfg = &umc.uci.radio.cfg;
            tmp = &umc.uci.radio.tmp;
            break;
        case UM_INTF_WLAN:
            cfg = &umc.uci.wlan.cfg;
            tmp = &umc.uci.wlan.tmp;
            break;
        default:
            return -EINVAL0;
    }
    
    /*
    * delete the intf(in cfg, NOT in tmp)
    */
    list_for_each_entry_safe(intf_cfg, a, cfg, node) {
        bool matched = false;
        
        list_for_each_entry_safe(intf_tmp, b, tmp, node) {
            if (0==os_stracmp(intf_cfg->ifname, intf_tmp->ifname)) {
                matched = true;
                
                break;
            }
        }
        
        if (false==matched) {
            intf_remove(intf_cfg, false);
            intf_destroy(intf_cfg);
            
            debug_uci_trace("[um]:delete %s from cfg", intf_cfg->ifname);
        }
    }

    /*
    * move the intf(NOT in cfg, in tmp), tmp==>cfg
    */
    list_for_each_entry_safe(intf_tmp, a, tmp, node) {
        bool matched = false;
        
        list_for_each_entry_safe(intf_cfg, b, cfg, node) {
            if (0==os_stracmp(intf_cfg->ifname, intf_tmp->ifname)) {
                matched = true;
                
                break;
            }
        }
        
        /*
        * the intf in tmp, but NOT in cfg, move it(tmp==>cfg)
        */
        if (false==matched) {
            intf_remove(intf_tmp, false);
            intf_insert(intf_tmp, cfg);

            debug_uci_trace("[um]:move %s from tmp to cfg", intf_tmp->ifname);
        }
        /*
        * the intf in both tmp and cfg
        */
        else {
            debug_uci_trace("[um]:keep %s in cfg", intf_tmp->ifname);
        }
    }

    return 0;
}

int load_wireless()
{
    int ret = -1;
    
	ret = load_wlan(&umc.uci.wlan.tmp);
	if (ret < 0)
	{
	    debug_uci_trace("[um]:load wlan intf fail");
        return -1;
	}
	
	intf_compare(UM_INTF_WLAN);
    
	return 0;
}

static void um_load_section(struct uci_section *s)
{
	struct uci_element *e = NULL;
    struct uci_option *o = NULL;
    
	uci_foreach_element(&s->options, e) {
        o = uci_to_option(e);
        if (!strncmp(e->name, "switch", strlen(e->name)))
        {
            if (!strncmp(o->v.string, "1", strlen(o->v.string)))
            {
                um_open_voice = 1;
            }
            else
            {
                um_open_voice = 0;
            }
        }
    }
    
    return;
}

static int
load_um(struct uci_package *um)
{
	struct uci_element *e = NULL;
    struct uci_section *s = NULL;

	uci_foreach_element(&um->sections, e) {
		s = uci_to_section(e);
        um_load_section(s);
	}
	
	debug_uci_trace("[um]:load um config voice aware %d", um_open_voice);
    
	return 0;
}

int um_uci_load(void)
{
    //struct uci_package *wireless = NULL;
    struct uci_package *um = NULL;
    int err = 0;
    
    uci_init();

#if 0
    /* load wireless uci */
    wireless = package_open("wireless");
    if (NULL==wireless) {
        err = -EINVAL1;
        debug_uci_waring("[um]:wireless open failed(%d)", err);
        
        goto error;
    }

    err = load_wireless(wireless);
    if (err<0) {
        debug_uci_waring("[um]:wireless load failed(%d)", err);
        
        goto error;
    }
#endif 
    /* load um uci */
    um = package_open("usermgn");
    if (NULL==um) {
        err = -EINVAL1;
        debug_uci_waring("[um]:um uci open failed(%d)", err);
        
        goto error;
    }

    err = load_um(um);
    if (err<0) {
        debug_uci_waring("[um]:um uci load failed(%d)", err);
        
        goto error;
    }
    debug_uci_trace("[um]:uci load");

    /* go down */
error:
    //package_close(wireless);
    package_close(um);
    uci_fini();
    
    return err;
}

/******************************************************************************/
