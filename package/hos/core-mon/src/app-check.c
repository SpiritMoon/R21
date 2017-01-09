#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"
#include "app-check.h"
#include "core-monitor.h"

#define MAX_STAT_CHECK_COUNT          5
#define CORE_CFG_FILE_PATH            "/etc/core-mon.conf"
#define WAM_CRASH_FLAG_FILE           "/tmp/wam-crash"

static APP_INFO_T appInfoList;

static b8 g_wam_crashed = 0;
char *g_wireless_app_list[] = {
    "iwconfig", "iwlist", "ifconfig", NULL,
};

static void * get_app_info(int get_type, int key)
{
    APP_INFO_T* app_info = NULL;
    struct list_head *pos, *n;
    APP_INFO_T *cur;

    list_for_each_safe(pos, n, &appInfoList.list) {
        cur = list_entry(pos, APP_INFO_T, list);

        switch (get_type) {
        case GET_APPINFO_WITH_APP_NAME:
            if (0 == strcmp((char*)key, cur->app_name)) {
                app_info = cur;
            }
            break;

        default:
            break;
        }

        if (NULL != app_info) {
            break;
        }
    }

    return (void *)app_info;
}

static void add_app_info(const char *name, int max_check_count)
{
    APP_INFO_T *cur;

    if (!get_app_info(GET_APPINFO_WITH_APP_NAME, (int)name)) {
        cur = malloc(sizeof(APP_INFO_T));

        memset(cur, 0, sizeof(APP_INFO_T));

        strcpy(cur->app_name, name);

        cur->app_pid = 0;
        cur->max_exit_check_count = max_check_count;
        cur->exit_check_count = 0;
        cur->stat_check_count = 0;
        cur->max_stat_check_count = MAX_STAT_CHECK_COUNT;

        _log(LOG_NOTICE, "add [%s, %d]", name, max_check_count);

        list_add_tail(&(cur->list), &(appInfoList.list));
    }
}

static void add_wireless_abnormal_check_app(void)
{
    _log(LOG_NOTICE, "=== add wireless check app");

    int i;
    for (i = 0; g_wireless_app_list[i] != NULL; i++) {
        add_app_info(g_wireless_app_list[i], 5);
    }
}

/*
#name: app name for registering core
#exit check count: reboot after single app exit reach or above count

#name, max-exit-check-count

ubusd, 5
configd, 5
*/
static void parse_cfg_file(void)
{
    FILE *fp = NULL;
    char line_tmp[MAX_LINE_SIZE+1];
    char app_name[MAX_NAME_LEN];
    int exitcount;
    char *cur, *next;

    INIT_LIST_HEAD(&appInfoList.list);

    fp = fopen(CORE_CFG_FILE_PATH, "r");

    if (fp) {
        _log(LOG_NOTICE, "parse %s", CORE_CFG_FILE_PATH);

        memset(line_tmp, 0, sizeof(line_tmp));
        while (fgets(line_tmp, MAX_LINE_SIZE, fp) != NULL) {

            // overlook comment
            if (strstr(line_tmp, "#") != NULL) {
                continue;
            }

            cur = line_tmp;
            next = strstr(cur, ",");
            if (next == NULL) {
                continue;
            }

            while (*cur == ' ') cur++;

            memset(app_name, 0, sizeof(app_name));
            memcpy(app_name, cur, next-cur);

            cur = next + 1;

            while (*cur == ' ') cur++;

            sscanf(cur, "%d", &exitcount);

            add_app_info(app_name, exitcount);
            memset(line_tmp, 0, sizeof(line_tmp));
        }

        fclose(fp);

    } else { // config file not exist, use default
        _log(LOG_WARNING, "cannot open %s, use default", CORE_CFG_FILE_PATH);

        char *default_check_list[] = {
            "netifd", "cluster_mgt", "cluster_cor",
            "eag", "lighttpd", "ubusd", "configd",
            NULL,
        };

        int i;
        for (i = 0; default_check_list[i] != NULL; i++) {
            add_app_info(default_check_list[i], 5);
        }
    }

    add_wireless_abnormal_check_app();
}

static pid_t get_pid_by_name(const char *pname)
{
    if (pname == NULL) {
        return 0;
    }

    char cmd[MAX_LINE_SIZE];
    char res_buf[MAX_LINE_SIZE];
    pid_t cpid = 0;

    sprintf(cmd, "pgrep %s", pname);
    memset(res_buf, 0, sizeof(res_buf));

    if (check_cmd_response(cmd, res_buf, MAX_LINE_SIZE) == 0) {
        cpid = atoi(res_buf);
        _log(LOG_NOTICE, "%s - pid [%d]", pname, cpid);
        return cpid;
    }

    _log(LOG_WARNING, "pgrep %s failed", pname);
    return 0;
}

static process_stat_e get_process_stat(const char *pname, pid_t pid)
{
    if (pname == NULL || pid == 0) {
        return PROCESS_STAT_NONE;
    }

    char cmd[MAX_LINE_SIZE];
    char res_buf[MAX_LINE_SIZE];

    sprintf(cmd, "[ -d /proc/%d ] && cat /proc/%d/status | grep State", pid, pid);
    memset(res_buf, 0, sizeof(res_buf));

    if (check_cmd_response(cmd, res_buf, MAX_LINE_SIZE) != 0) {
        _log(LOG_WARNING, "get process stat failed");
        return PROCESS_STAT_NONE;
    }

    if (strlen(res_buf) == 0) {
        return PROCESS_STAT_NONE;
    }

    char *nextp;

    // e.g.
    // State:	S (sleeping)
    nextp = strstr(res_buf, ":");
    if (nextp == NULL) {
        return PROCESS_STAT_NONE;
    }
    nextp++;

    while (*nextp == ' ' || *nextp == '\t') nextp++;

    char stat = *nextp;
    _log(LOG_NOTICE, "%s - process state [%c]", pname, stat);

    switch (stat) {
    case 'R':
        return PROCESS_STAT_R;
    case 'S':
        return PROCESS_STAT_S;
    case 'D':
        return PROCESS_STAT_D;
    case 'T':
        return PROCESS_STAT_T;
    case 'Z':
        return PROCESS_STAT_Z;
    default:
        return PROCESS_STAT_NONE;
    }
}

static b8 is_wireless_process(APP_INFO_T *cur)
{
    if (cur == NULL) {
        return 0;
    }

    int i;

    for (i = 0; g_wireless_app_list[i] != NULL; i++) {
        if (strstr(cur->app_name, g_wireless_app_list[i])) {
            return 1;
        }
    }

    return 0;
}

static void check_app_exit(APP_INFO_T *cur)
{
    if (cur == NULL) {
        return;
    }

    char cmd[MAX_LINE_SIZE];
    char res_buf[MAX_LINE_SIZE];
    pid_t pid;

    pid = get_pid_by_name(cur->app_name);
    cur->app_pid = pid;

    // do not check wireless app exit
    if (is_wireless_process(cur)) {
        return;
    }

    if (cur->app_pid == 0) {
        cur->exit_check_count++;
        _log(LOG_NOTICE, "%s - exit [%d]", cur->app_name, cur->exit_check_count);
    } else {
        cur->exit_check_count = 0;
    }

    if (cur->exit_check_count >= cur->max_exit_check_count) {

        char reason[MAX_LINE_SIZE];
        sprintf(reason, "%s - exit [%d] reached max [%d]",
                cur->app_name, cur->exit_check_count, cur->max_exit_check_count);
        record_reboot_reason(reason);

        han_start_timer(CORE_TIMER_REBOOT_DELAY, 2000);
    }
}

static void check_wireless_app_stat(APP_INFO_T *cur)
{
    if (cur == NULL || cur->app_pid == 0) {
        return;
    }

    char cmd[MAX_LINE_SIZE];
    char res_buf[MAX_LINE_SIZE];
    process_stat_e pstat;

    pstat = get_process_stat(cur->app_name, cur->app_pid);
    if (pstat == PROCESS_STAT_D) {
        cur->stat_check_count++;
    } else {
        cur->stat_check_count = 0;
    }

    if (cur->stat_check_count >= cur->max_stat_check_count) {
        char reason[MAX_LINE_SIZE];
        sprintf(reason, "%s - wireless stat check [%d] reached max [%d]",
                cur->app_name, cur->stat_check_count, cur->max_stat_check_count);
        record_reboot_reason(reason);

        han_start_timer(CORE_TIMER_REBOOT_DELAY, 2000);
    }
}

static void check_normal_app_stat(APP_INFO_T *cur)
{
    if (cur == NULL || cur->app_pid == 0) {
        return;
    }

    char cmd[MAX_LINE_SIZE];
    char res_buf[MAX_LINE_SIZE];
    process_stat_e pstat;

    pstat = get_process_stat(cur->app_name, cur->app_pid);
    if (pstat == PROCESS_STAT_Z) {
        cur->stat_check_count++;
    } else {
        cur->stat_check_count = 0;
    }

    if (cur->stat_check_count >= cur->max_stat_check_count) {
        char reason[MAX_LINE_SIZE];
        sprintf(reason, "%s - stat check [%d] reached max [%d]",
                cur->app_name, cur->stat_check_count, cur->max_stat_check_count);
        record_reboot_reason(reason);

        han_start_timer(CORE_TIMER_REBOOT_DELAY, 2000);
    }
}

static void check_app_stat(APP_INFO_T *cur)
{
    if (cur == NULL || cur->app_pid == 0) {
        return;
    }

    if (is_wireless_process(cur)) {
        check_wireless_app_stat(cur);
    } else {
        check_normal_app_stat(cur);
    }
}

void app_check_init(void)
{
    g_wam_crashed = 0;

    parse_cfg_file();
}

void check_wam_crash(void)
{
    if (access(WAM_CRASH_FLAG_FILE, F_OK) == 0) {

        g_wam_crashed = 1;

        char reason[MAX_LINE_SIZE];
        sprintf(reason, "wam app crash");
        record_reboot_reason(reason);

        han_start_timer(CORE_TIMER_REBOOT_DELAY, 2000);
    } else {
        g_wam_crashed = 0;
    }
}

b8 is_wam_crashed(void)
{
    return g_wam_crashed;
}

int travel_apps(void)
{
    struct list_head *pos, *n;
    APP_INFO_T *cur;

    _log(LOG_NOTICE, "travel apps");
    list_for_each_safe(pos, n, &appInfoList.list) {
        cur = list_entry(pos, APP_INFO_T, list);

        check_app_exit(cur);
        check_app_stat(cur);
    }

    return 0;
}

b8 is_wireless_crashed(void)
{
    APP_INFO_T* app_info = NULL;
    int i;

    for (i = 0; g_wireless_app_list[i] != NULL; i++) {
        app_info = get_app_info(GET_APPINFO_WITH_APP_NAME,
                                (int)g_wireless_app_list[i]);

        if (app_info) {
            if (app_info->stat_check_count >= app_info->max_stat_check_count) {
                return 1;
            }
        }
    }

    return 0;
}