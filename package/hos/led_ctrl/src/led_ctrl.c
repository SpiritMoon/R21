#include <libubox/blobmsg_json.h>
#include "libubus.h"
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>

#define NO_COLOR    0
#define RED         (1 << 0)
#define BLUE        (1 << 1)
#define GREEN       (1 << 2)
#define YELLOW      (1 << 3)

#define    STATUS_ERROR -1
#define    STATUS_EMPTY  0
#define    STATUS_ABNORMAL      (1 << 0)
#define    STATUS_NOSSID        (1 << 1)
#define    STATUS_FREQ2         (1 << 2)
#define    STATUS_FREQ5         (1 << 3)

#define SHOW_STATUS_INTERVAL 10
#define OPERATION_TIMEOUT    5

enum
{
    LED_ON,
    LED_TIMER,
    LED_POLL,
};

#define USER_OP_DEFAULT          "default_mode"
#define USER_OP_NIGHT_MODE       "night_mode"
#define USER_OP_ON               "on"
#define USER_OP_BLINK            "blink"

static pthread_mutex_t uo_status_mutex=PTHREAD_MUTEX_INITIALIZER;
static char user_op_status[64]=USER_OP_DEFAULT;          /* record user operation */
static struct ubus_context *ctx_srv;
static volatile int show_status_interval;
static pthread_t pid;
static pthread_t ip_pid;

static pthread_mutex_t mutex=PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
static volatile int g_status = STATUS_EMPTY;  /* protected by mutex */

/* restore 操作需要解锁mutex,但是如果随意restore，恰好另一个进程已经lock了mutex就会出bug,所以用restore_lock保持互斥 */
static pthread_mutex_t restore_lock=PTHREAD_MUTEX_INITIALIZER;


static void _led_off(void)
{
    system("for i in /sys/class/leds/*/trigger; do echo none > $i; done");
}
static void led_off(void)
{
    g_status = STATUS_EMPTY;       /* clear status, led_off should be protected by mutex */
    _led_off();
}

static void led_on(int which, int type)
{
    char cmd[128];
    int cmd_len;

    if(which == NO_COLOR)
        return;

    cmd_len = sprintf(cmd, "echo %s > /sys/class/leds/",
            type == LED_ON ? "default-on": (type == LED_TIMER ? "timer" : "poll"));

    if(which & RED)
    {
        cmd[cmd_len] = '\0';
        strcat(cmd, "ap152_afi\\:red/trigger");
        system(cmd);
    }
    if(which & BLUE)
    {
        cmd[cmd_len] = '\0';
        strcat(cmd, "ap152_afi\\:blue/trigger");
        system(cmd);
    }
    if(which & GREEN)
    {
        cmd[cmd_len] = '\0';
        strcat(cmd, "ap152_afi\\:green/trigger");
        system(cmd);
    }
    if(which & YELLOW)
    {
        cmd[cmd_len] = '\0';
        strcat(cmd, "ap152_afi\\:yellow/trigger");
        system(cmd);
    }
}

static int network_status(void)
{
    int jump, abnormal;
    int status;
    FILE *fp;
    char buf[256] = {0};

    fp = popen("/bin/ubus call network.device status '{\"name\":\"eth0\"}' 2>/dev/null", "r");
    if(fp == NULL)
    {
        syslog(LOG_DEBUG, "%s network.devices status failed\n", __func__);
        return STATUS_ERROR;
    }

    abnormal = 1;
    while(fgets(buf, sizeof(buf), fp))
    {
        if(strstr(buf, "\"carrier\": true"))
        {
            abnormal = 0;
            break;
        }
    }

    pclose(fp);

    if(abnormal)
        return STATUS_ABNORMAL;


    fp = popen("/usr/sbin/iwconfig 2>/dev/null", "r");
    if(fp == NULL)
    {
        syslog(LOG_DEBUG, "%s popen:%s\n", __func__, strerror(errno));
        return STATUS_ERROR;
    }

    status = 0;
    jump = 0;
    while(fgets(buf, sizeof(buf), fp))
    {
        char *freq;
        if(strncmp(buf, "athscan", 7) == 0)
            jump = 1;
        if(jump == 1)
        {
            if(buf[0] == '\n')
                jump = 0;
            continue;
        }
        if(strncmp(buf, "ath", 3) == 0)
        {
            if(strstr(buf, "ESSID:\"\""))
                status |= STATUS_NOSSID;
            continue;
        }
        if((freq = strstr(buf, "Frequency")))
        {
            freq += 10;
            if(atoi(freq) == 5)
                status |= STATUS_FREQ5;
            else if(atoi(freq) == 2)
                status |= STATUS_FREQ2;
            jump = 1;
            continue;
        }
    }

    pclose(fp);

    return status?status:STATUS_ABNORMAL;
}

static void show_status(void)
{
    int status, nr_of_band;

    status = network_status();
    if(status == STATUS_ERROR)
        return;

    /* 安全起见,即使状态没有改变，仍然重新写入proc状态 */
//    if(status == g_status)
 //       return;

    if(status != g_status)          /* 每次都off会闪 */
        _led_off();

    g_status = status;

    nr_of_band = 0;
    if(status & STATUS_FREQ2)
        nr_of_band ++;
    if(status & STATUS_FREQ5)
        nr_of_band ++;

    if((status == STATUS_ABNORMAL) || nr_of_band == 0)
        return led_on(RED, LED_TIMER);

    if(status & STATUS_NOSSID)
        return led_on(GREEN, LED_TIMER);

    if(nr_of_band == 1)
        return led_on(GREEN, LED_ON);

    return led_on(BLUE|GREEN, LED_ON);
}

static void *status_check(void *arg)
{
    (void)arg;
    while(1)
    {
        pthread_mutex_lock(&restore_lock);
        if(pthread_mutex_trylock(&mutex) == 0)
        {
            show_status();
            pthread_mutex_unlock(&mutex);
        }
        pthread_mutex_unlock(&restore_lock);
        sleep(show_status_interval);
    }
    return NULL;
}

// sar 1 1 for web, not belong to ledctrl
static void *sar_update(void *unused)
{
    (void)unused;
    while(1)
    {
        char *cmd="sar 1 1 |grep Average|awk '{print $8}' > /tmp/cpu_utilization_tmp"
            "&& mv /tmp/cpu_utilization_tmp /tmp/cpu_utilization";
        system(cmd);
        sleep(10);
    }
    return NULL;
}
//add by liumengmeng 2016-8-11 ip address collision detection
int exec_system_cmd(char *cmd)
{

    FILE *fp;
	FILE *fp_file;
	char StrLine[1024] = {0};
	if ((fp_file=fopen("/tmp/log/arp_reply.log","w+"))==NULL)
    { 
       // printf("Cannot open file/n");
       	return -1;
    }
    fp = popen(cmd,"r");
    if(fp == NULL)
    { 	
    	fclose(fp_file);
        return -1;
    }
    while (!feof(fp)) 
    { 
        memset(StrLine,0,sizeof(StrLine));
        fgets(StrLine,1024,fp);
	fwrite(StrLine,strlen(StrLine),1,fp_file);
    }
	fclose(fp_file);
	pclose(fp);
    return 0;
}

static void * ip_detection_check(void *arg)
{

	FILE *fp;
    char buf[64] = {0};
	char mac_tmp[64] = {0};
	char cmd_str[128];
	char tmp[6] = {0};
	int len = 0;
	while(1)
    {   
    	sleep(60);
    	fp = popen("/sbin/ifconfig br-wan | awk -F \" \" '/Bcast/ {print $2}'| awk -F \":\" '{print$2}' 2>/dev/null","r");
		if(fp == NULL)
		{
        //	syslog(LOG_DEBUG, "ifconfig command failed can not get the device IP address\n");
			continue;
    	}
		memset(buf, 0, sizeof(buf));
		if(fgets(buf, sizeof(buf), fp) == NULL)
		{
	//		syslog(LOG_DEBUG, "Get the device IP is NULL\n");
			pclose(fp);
			continue;
		}
		len = strlen(buf);
		buf[len-1] = '\0'; 
		pclose(fp);
		memset(cmd_str, 0, sizeof(cmd_str));
		sprintf(cmd_str,"/usr/sbin/arping -c 3 -I br-wan %s ",buf);	
		exec_system_cmd(cmd_str);
		memset(cmd_str, 0, sizeof(cmd_str));
		sprintf(cmd_str,"cat /tmp/log/arp_reply.log | grep Received |awk '{print $2}' 2>/dev/null");
		fp = popen(cmd_str,"r");
		if(fp == NULL)
		{
        //	syslog(LOG_DEBUG, " Open ARP reply log faild\n");
			continue;
    	}
		if(fgets(tmp, sizeof(tmp), fp) == NULL)
		{
	//		syslog(LOG_DEBUG, "GET Arp reply result faild\n");
			pclose(fp);
			continue;
		}
		pclose(fp);
		len = strlen(tmp);
		tmp[len-1] = '\0'; 
		if(strcmp(tmp,"0") != 0)
		{
			memset(cmd_str, 0, sizeof(cmd_str));
			memset(mac_tmp, 0, sizeof(mac_tmp));
			sprintf(cmd_str,"cat /tmp/log/arp_reply.log | grep Unicast | awk  'NR==2 {print $5}' 2>/dev/null");
			fp = popen(cmd_str,"r");
			if(fp == NULL)
			{
        //		syslog(LOG_DEBUG, "TO get conflicts  mac open ARP reply log faild\n");
				continue;
    		}
			if(fgets(mac_tmp, sizeof(mac_tmp), fp) == NULL)
			{
	//			syslog(LOG_DEBUG, "GET conflicts mac faild\n");
				pclose(fp);
				continue;
			}
			pclose(fp);
			syslog(LOG_DEBUG, "Device IP %s conflicts with the device %s,Received %s reply\n", buf,mac_tmp,tmp);	
		}		
    }
	return NULL;
}
//add end 2016-8-11 by liumengmeng
static void srv_init(void) 
{
    show_status_interval = SHOW_STATUS_INTERVAL;
    openlog("led_control", 0, 0);
#if 0
    {
        // sar 1 1 for web, not belong to ledctrl
        static pthread_t sar_pid;
        if(pthread_create(&sar_pid, NULL, sar_update, NULL) < 0)
        {
            syslog(LOG_DEBUG, "pthread_create failed\n");
            exit(1);
        }
    }
#endif
    if(pthread_create(&pid, NULL, status_check, NULL) < 0)
    {
        syslog(LOG_DEBUG, "pthread_create failed\n");
        exit(1);
    }
	if(pthread_create(&ip_pid, NULL, ip_detection_check, NULL) < 0)
    {
        syslog(LOG_DEBUG, "pthread_create failed\n");
        exit(1);
    }
	
	
}

static void srv_fini(void)
{
    closelog();
}

enum
{
    POLICY_BLINK,
    __BLINK_MAX
};
static const struct blobmsg_policy policy_blink[] = {
    [POLICY_BLINK] = { .name = "leds", .type = BLOBMSG_TYPE_STRING },
};

static int led_set_blink(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    int type;
    char *instruction, *p;
    struct blob_attr *tb[__BLINK_MAX];
    struct timespec timeout; 

    if(clock_gettime(CLOCK_REALTIME, &timeout) < 0)
    {
        syslog(LOG_DEBUG, "%s %s\n", __func__, strerror(errno));
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    timeout.tv_sec += OPERATION_TIMEOUT;

    blobmsg_parse(policy_blink, ARRAY_SIZE(policy_blink), tb, blob_data(msg), blob_len(msg));

    if(!tb[POLICY_BLINK])
        return UBUS_STATUS_INVALID_ARGUMENT;

    instruction = blobmsg_get_string(tb[POLICY_BLINK]);

    if(strlen(instruction) == 0)
        return UBUS_STATUS_INVALID_ARGUMENT;

    if(pthread_mutex_timedlock(&mutex, &timeout) != 0)
        return UBUS_STATUS_TIMEOUT;

    if(strlen(instruction) == 1)
        type = LED_TIMER;
    else
        type = LED_POLL;

    led_off();
    for(p = instruction; *p; p++)
    {
        switch(*p)
        {
            case 'R':
                led_on(RED, type);
                break;
            case 'G':
                led_on(GREEN, type);
                break;
            case 'B':
                led_on(BLUE, type);
                break;
            case 'Y':
                led_on(YELLOW, type);
                break;
            default:
                show_status();
                pthread_mutex_unlock(&mutex);
                return UBUS_STATUS_INVALID_ARGUMENT;
        }
    }
    pthread_mutex_lock(&uo_status_mutex);
    snprintf(user_op_status, sizeof(user_op_status), USER_OP_BLINK "%s", instruction);
    pthread_mutex_unlock(&uo_status_mutex);

    return 0;
}

enum
{
    POLICY_ON,
    __ON_MAX
};
static const struct blobmsg_policy policy_on[] = {
    [POLICY_ON] = { .name = "leds", .type = BLOBMSG_TYPE_STRING },
};

static int led_set_on(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    int color;
    char *instruction, *p;
    struct blob_attr *tb[__BLINK_MAX];
    struct timespec timeout; 

    if(clock_gettime(CLOCK_REALTIME, &timeout) < 0)
    {
        syslog(LOG_DEBUG, "%s %s\n", __func__, strerror(errno));
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    timeout.tv_sec += OPERATION_TIMEOUT;

    blobmsg_parse(policy_on, ARRAY_SIZE(policy_on), tb, blob_data(msg), blob_len(msg));

    if(!tb[POLICY_BLINK])
        return UBUS_STATUS_INVALID_ARGUMENT;

    instruction = blobmsg_get_string(tb[POLICY_BLINK]);

   // if(strlen(instruction) == 0)
    //    return UBUS_STATUS_INVALID_ARGUMENT;

    if(pthread_mutex_timedlock(&mutex, &timeout) != 0)
        return UBUS_STATUS_TIMEOUT;


    color = NO_COLOR;
    for(p = instruction; *p; p++)
    {
        switch(*p)
        {
            case 'R':
                color |= RED;
                break;
            case 'G':
                color |= GREEN;
                break;
            case 'B':
                color |= BLUE;
                break;
            case 'Y':
                color |= YELLOW;
                break;
            default:
                pthread_mutex_unlock(&mutex);
                return UBUS_STATUS_INVALID_ARGUMENT;
        }
    }
    led_off();
    led_on(color, LED_ON);

    pthread_mutex_lock(&uo_status_mutex);
    if(strlen(instruction) == 0)
        strcpy(user_op_status, USER_OP_NIGHT_MODE);
    else
        snprintf(user_op_status, sizeof(user_op_status), USER_OP_ON "%s", instruction);
    pthread_mutex_unlock(&uo_status_mutex);

    return 0;
}

static int led_set_night_mode(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{

    struct timespec timeout; 

    if(clock_gettime(CLOCK_REALTIME, &timeout) < 0)
    {
        syslog(LOG_DEBUG, "%s %s\n", __func__, strerror(errno));
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    timeout.tv_sec += OPERATION_TIMEOUT;

    if(pthread_mutex_timedlock(&mutex, &timeout) != 0)
        return UBUS_STATUS_TIMEOUT;

    led_off();

    pthread_mutex_lock(&uo_status_mutex);
    strcpy(user_op_status, USER_OP_NIGHT_MODE);
    pthread_mutex_unlock(&uo_status_mutex);

    return 0;
}

static int led_set_restore(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    led_off();
    show_status();

    pthread_mutex_lock(&uo_status_mutex);
    strcpy(user_op_status, USER_OP_DEFAULT);
    pthread_mutex_unlock(&uo_status_mutex);

    pthread_mutex_lock(&restore_lock);
    pthread_mutex_unlock(&mutex);
    pthread_mutex_unlock(&restore_lock);
    return 0;
}

static int led_show_user_ops(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    static struct blob_buf b;

    blob_buf_init(&b, 0);

    pthread_mutex_lock(&uo_status_mutex);

    if(strncmp(user_op_status, USER_OP_DEFAULT, sizeof(USER_OP_DEFAULT)-1) == 0)
        blobmsg_add_string(&b, USER_OP_DEFAULT, "");
    else if(strncmp(user_op_status, USER_OP_NIGHT_MODE, sizeof(USER_OP_NIGHT_MODE)-1) == 0)
        blobmsg_add_string(&b, USER_OP_NIGHT_MODE, "");
    else if(strncmp(user_op_status, USER_OP_ON, sizeof(USER_OP_ON)-1) == 0)
        blobmsg_add_string(&b, USER_OP_ON, &user_op_status[sizeof(USER_OP_ON)-1]);
    else if(strncmp(user_op_status, USER_OP_BLINK, sizeof(USER_OP_BLINK)-1) == 0)
        blobmsg_add_string(&b, USER_OP_BLINK, &user_op_status[sizeof(USER_OP_BLINK)-1]);

    pthread_mutex_unlock(&uo_status_mutex);

    ubus_send_reply(ctx, req, b.head);

    return UBUS_STATUS_OK;
}

static const struct ubus_method led_set_methods[] = {
    UBUS_METHOD("blink", led_set_blink, policy_blink),
    UBUS_METHOD("on",    led_set_on,    policy_on),
    UBUS_METHOD_NOARG("night_mode",   led_set_night_mode),
    UBUS_METHOD_NOARG("restore",   led_set_restore),
    UBUS_METHOD_NOARG("status",   led_show_user_ops),
};

static struct ubus_object_type ledctl_object_type = 
UBUS_OBJECT_TYPE("ledctrl", led_set_methods);


static struct ubus_object ledctl_object = {
    .name = "ledctrl",
    .type = &ledctl_object_type,
    .methods = led_set_methods,
    .n_methods = ARRAY_SIZE(led_set_methods),
};
static void server_main(void)
{
    int ret;

    ret = ubus_add_object(ctx_srv, &ledctl_object);
    if (ret)
    {
        syslog(LOG_DEBUG, "Failed to add object: %s\n", ubus_strerror(ret));
        exit(1);
    }

    uloop_run();
}


int main(int argc, char **argv)
{
    srv_init();

    if(atexit(srv_fini) != 0)
        exit(1);

    uloop_init();

    signal(SIGPIPE, SIG_IGN);

    ctx_srv = ubus_connect(NULL);
    if (!ctx_srv) {
        syslog(LOG_DEBUG, "Failed to connect to ubus\n");
        return -1;
    }

    ubus_add_uloop(ctx_srv);

    server_main();

    ubus_free(ctx_srv);
    uloop_done();

    return 0;
}

