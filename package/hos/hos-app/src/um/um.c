#include <pthread.h>

#include "utils.h"
#include "tid.h"
#include "um.h"

static pthread_rwlock_t sta_rw_lock;
static pthread_rwlock_t cli_rw_lock;
extern um_open_voice;
extern um_open_bgs;


int um_rwlock_rdlock(void)
{
    return pthread_rwlock_rdlock(&sta_rw_lock);
}

int um_rwlock_wrlock(void)
{
    return pthread_rwlock_wrlock(&sta_rw_lock);
}

int um_rwlock_unlock(void)
{
    return pthread_rwlock_unlock(&sta_rw_lock);
}

int um_rwlock_init(void)
{    
    return pthread_rwlock_init(&sta_rw_lock, NULL);
}

int cli_rwlock_rdlock(void)
{
    return pthread_rwlock_rdlock(&cli_rw_lock);
}

int cli_rwlock_wrlock(void)
{
    return pthread_rwlock_wrlock(&cli_rw_lock);
}

int cli_rwlock_unlock(void)
{
    return pthread_rwlock_unlock(&cli_rw_lock);
}

int cli_rwlock_init(void)
{    
    return pthread_rwlock_init(&cli_rw_lock, NULL);
}

static inline unsigned int
timerms(struct um_timer *utm)
{
    return appkey_get(utm->akid, utm->deft);
}

static void
usertimer(struct uloop_timeout *timeout, int (*timer)(void))
{
    struct um_timer *utm = container_of(timeout, struct um_timer, tm);
    
    uloop_timeout_set(timeout, timerms(utm));
    
    (*timer)();

    return;
}

static void
wifitimer(struct uloop_timeout *timeout)
{
    usertimer(timeout, um_l2user_timer);

    return;
}

static void
portaltimer(struct uloop_timeout *timeout)
{
    usertimer(timeout, um_l3user_timer);

    return;
}

static void
um_connect_statics_check(uint32_t ip)
{
    FILE *url_file;
    int ret = -1;
    char cmd_buf[128];
    char output_buf[128];
    int buf_len = 0;
    int cnt = 0;
    
    if (0 == ip)
    {
        return;
    }
    
    memset(cmd_buf, 0, sizeof(cmd_buf));
    memset(output_buf, 0, sizeof(output_buf));
    
    sprintf(cmd_buf, "/usr/sbin/l7check %s", os_ipstring(ip));
    
    /* open pipe */
    url_file = popen(cmd_buf, "r");
    if (NULL == url_file) 
    {
        debug_main_waring("[um]: show url info fail");
        return;
    }

    /* get url */
    if (NULL == fgets(output_buf, sizeof(output_buf), url_file)) 
    {
        debug_main_waring("[um]: load url info fail");
        pclose(url_file);
        return;
    }
    
    /* close pipe */
    pclose(url_file);

    cnt = atoi(output_buf);
    debug_main_trace("[um]: um_connect_statics_check ip=%s cnt=%d", os_ipstring(ip), cnt);
    
    um_connect_statics_set(ip, cnt);

    return;
}

static uint32_t
get_ip_from_ap(char *mac)
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
        debug_main_waring("[um]: ip is not find for %s", mac);
        pclose(fp);
        return 0;
    }

	str_tmp_ip[strlen(str_tmp_ip) - 1] = '\0';

    ip = ntohl(inet_addr(str_tmp_ip));
    
    pclose(fp);
    debug_main_trace("[um]: get ip is [%s] for %s", str_tmp_ip, mac);

    return ip;
}

static multi_value_t 
aging_cb(struct apuser *user, void *data)
{
    if (user->local)
    { 
        if (0 != user->ip)
        {
            if (user->con_time > 3)
            {
                um_connect_statics_check(user->ip);
                
                user->con_time = 0;
            }
            else
            {
                user->con_time++;
            }
        }
//Remove by liumengmeng  2016-8-17
        /* get ip */
#if 0
        if (0 == user->ip)
        {
            user->ip = get_ip_from_ap(um_macstring(user->mac));
        }
#endif
//End romove 

        user->aging--;
        if (user->aging <= 0)
        {
            um_user_del(user);
        }
    }
    
    return mv2_OK;
}

static int
aging(void)
{
    cli_rwlock_wrlock();
#if 1
	if (1 == um_open_voice && 0 == um_open_bgs)
	{
    	is_open_backscan();
	}
#endif
    um_user_foreach(aging_cb, NULL);
    cli_rwlock_unlock();
    
    return 0;
}

static void
agingtimer(struct uloop_timeout *timeout)
{
    usertimer(timeout, aging);

    return;
}

static void
reporttimer(struct uloop_timeout *timeout)
{
    usertimer(timeout, um_ubus_report);

    return;
}

struct ubus_method um_user_object_methods[] = {
	{ .name = "restart", .handler = um_ubus_handle_restart },
	{ .name = "reload", .handler = um_ubus_handle_reload },
	UBUS_METHOD("getuser", um_ubus_handle_getuser, umc.policy.getuser),
};

struct um_control umc = {
    .head   = {
        .mac    = {HLIST_HEAD_INIT},
        .ip     = {HLIST_HEAD_INIT},
        .list   = LIST_HEAD_INIT(umc.head.list),
    },

    .timer = {
        .wifi   = UM_TIMER_INITER(UM_TIMERMS_WIFI, wifitimer),
        .portal = UM_TIMER_INITER(UM_TIMERMS_PORTAL, portaltimer),
        .aging  = UM_TIMER_INITER(UM_TIMERMS_AGING, agingtimer),
        .report = UM_TIMER_INITER(UM_TIMERMS_REPORT, reporttimer),
    },

    .portal = {
        .wifidog = {
            [UM_WIFIDOG_STATE_UNKNOW]   = "unknow",
            [UM_WIFIDOG_STATE_PROBATION]= "probation",
            [UM_WIFIDOG_STATE_KNOW]     = "know",
        },
        
        .type = {
            [UM_PORTAL_TYPE_WIFIDOG]    = "wifidog",
        },

        .state = {
            [UM_PORTAL_TYPE_WIFIDOG]    = umc.portal.wifidog,
        },
        
    },
    
    .ev = {
        .new    = { .deft = OS_ON},
        .delete = { .deft = OS_ON},
        .update = { .deft = OS_OFF},
        .report = { .deft = OS_ON},
        .devinfo = { .deft = OS_ON },
    },
    
    .policy = {
        .user   = UM_USER_POLICY_INITER,
        .getuser= UM_GETUSER_POLICY_INITER,
        .radio  = UM_RADIOPOLICY_INITER,
        .wlan   = UM_WLANPOLICY_INITER,
    },

    .uci = {
        .radio = {
            .param  = UM_PARAM_INITER(umc.policy.radio),
            .cfg    = LIST_HEAD_INIT(umc.uci.radio.cfg),
            .tmp    = LIST_HEAD_INIT(umc.uci.radio.tmp),
            .uci_type = UM_UCI_INTF_RADIO,
        },
        .wlan = {
            .param  = UM_PARAM_INITER(umc.policy.wlan),
            .cfg    = LIST_HEAD_INIT(umc.uci.wlan.cfg),
            .tmp    = LIST_HEAD_INIT(umc.uci.wlan.tmp),
            .uci_type = UM_UCI_INTF_WLAN,
        },
    },
    
    .obj = {
        .methods= um_user_object_methods,
        .type   = UBUS_OBJECT_TYPE("umd", um_user_object_methods),
        .object = {
        	.name = "user-manage",
        	.type = &umc.obj.type,
        	.methods = um_user_object_methods,
        	.n_methods = os_count_of(um_user_object_methods),
        }
    },
};

static void
handle_signal(int signo)
{
	uloop_end();

    return;
}

/*
* copy/change from netifd
*/
static void
setup_signals(void)
{
	struct sigaction s;

	memset(&s, 0, sizeof(s));
	s.sa_handler = handle_signal;
	s.sa_flags = 0;
	sigaction(SIGINT, &s, NULL);
	sigaction(SIGTERM, &s, NULL);
	//sigaction(SIGUSR1, &s, NULL);
	//sigaction(SIGUSR2, &s, NULL);

	//s.sa_handler = SIG_IGN;
	//sigaction(SIGPIPE, &s, NULL);

    os_sigaction_callstack();
	
    return;
}

static void
addusertimer(struct um_timer *utm)
{
    uloop_timeout_set(&utm->tm, appkey_get(utm->akid, utm->deft));

    return;
}

int main(int argc, char **argv)
{
    char *path = NULL;
    int ret = 0;
    pthread_t ntid = -1;
    pthread_t dtid = -1;
    pthread_t nl7 = -1; 

    ret = um_create_stabuf();
    if (ret < 0)
    {
        debug_main_error("[um]: create station buffer failed!");
        exit(-1);
    }

    ret = cli_rwlock_init();
    if (ret < 0)
    {
        debug_main_error("[um]: init um rwlock failed!");
        exit(-1);
    }

    ret = pthread_create(&ntid, NULL, tid_pthreadhandle, NULL);
    if (0 != ret)
    {
        debug_main_error("[um]: create pthread for tid failed!");

        exit(-1);
    }

    ret = pthread_create(&nl7, NULL, l7_pthreadhandle, NULL);
    if (0 != ret)
    {
        debug_main_error("[um]: create pthread for L7 failed!");

        exit(-1);
    }
    
    /*
    ret = pthread_create(&dtid, NULL, delay_pthreadhandle, NULL);
    if (0 != ret)
    {
        debug_main_error("[um]:delay pthread create failed!");

        exit(-1);
    }
    */
    
	setup_signals();
	
	ret = um_uci_load();
    if (ret < 0) 
    {
        debug_main_error("[um]: load uci cfg failed!");
		exit(-1);
	}

    ret = um_ubus_init(path);
    if (ret < 0) 
    {
        debug_main_error("[um]: init ubus failed!");
		goto finish;
	}

    addusertimer(&umc.timer.wifi);
    addusertimer(&umc.timer.portal);
    addusertimer(&umc.timer.aging);
    addusertimer(&umc.timer.report);
    
    debug_main_trace("[um]: init success!");

    uloop_run();
    
finish:
	um_ubus_fini();
	debug_main_error("[um]: um finish exit!");
	exit(-1);
}


#define UM_AKID_INIT(_akid, _name, _deft) do{ \
    _akid = appkey_getbyname(_name); \
    debug_main_trace("[um]:%s=%d", _name, appkey_get(_akid, _deft)); \
}while(0)

static os_constructor void 
um_akid_initer(void)
{
    UM_AKID_INIT(umc.debug.error,   "debug_error",      OS_OFF);
    UM_AKID_INIT(umc.debug.warning, "debug_warning",    OS_OFF);
    UM_AKID_INIT(umc.debug.trace,   "debug_trace",      OS_OFF);
    UM_AKID_INIT(umc.debug.main,    "debug_main",       OS_OFF);
    UM_AKID_INIT(umc.debug.uci,     "debug_uci",        OS_OFF);
    UM_AKID_INIT(umc.debug.tid,     "debug_tid",        OS_OFF);
    UM_AKID_INIT(umc.debug.ubus,    "debug_ubus",       OS_OFF);
    UM_AKID_INIT(umc.debug.user,    "debug_user",       OS_OFF);
    UM_AKID_INIT(umc.debug.l2timer, "debug_l2timer",    OS_OFF);

    UM_AKID_INIT(umc.timer.wifi.akid,   "timer_l2ms",     umc.timer.wifi.deft);
    UM_AKID_INIT(umc.timer.portal.akid, "timer_l3ms",     umc.timer.portal.deft);
    UM_AKID_INIT(umc.timer.report.akid, "timer_reportms", umc.timer.report.deft);
    UM_AKID_INIT(umc.timer.aging.akid,  "timer_agms",     umc.timer.aging.deft);
    UM_AKID_INIT(umc.timer.agtimes,     "timer_agtimes",  UM_AGING_TIMES);

    UM_AKID_INIT(umc.ev.new.akid,       "event_new",    umc.ev.new.deft);
    UM_AKID_INIT(umc.ev.delete.akid,    "event_delete", umc.ev.delete.deft);
    UM_AKID_INIT(umc.ev.update.akid,    "event_update", umc.ev.update.deft);
    UM_AKID_INIT(umc.ev.report.akid,    "event_report", umc.ev.report.deft);
    UM_AKID_INIT(umc.ev.devinfo.akid,   "event_devinfo", umc.ev.devinfo.deft);
}

AKID_DEBUGER; /* must last os_constructor */
/******************************************************************************/
