#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#include "common.h"

#define MAX_DIFF_BYTES                100
#define ONLINE_USR_INFO_MAX           10
#define ONLINE_USR_INFO_FILE          "/tmp/online-usr-info"
#define ONLINE_USR_COUNT_FILE         "/tmp/online-usr-count"

static b8 g_online_usr_alive = 0;
static u32 g_online_usr_num = 0;

typedef struct {
    char mac[20];
    u32 rbytes;
    u32 tbytes;
} online_usr_info_st;

online_usr_info_st g_online_usr_info[ONLINE_USR_INFO_MAX];

static int get_on_line_user_num(void)
{
    char cmd[MAX_LINE_SIZE];
    char res_buf[MAX_LINE_SIZE];
    int user_num = 0;

    memset(res_buf, 0, sizeof(res_buf));
    sprintf(cmd, "sta_list | awk '{print $2}' | sed '/^$/d' | sed '/IP/d' | wc -l > %s &", ONLINE_USR_COUNT_FILE);
    system(cmd);
    sprintf(cmd, "sleep 1; cat %s", ONLINE_USR_COUNT_FILE);
    if (check_cmd_response(cmd, res_buf, MAX_LINE_SIZE) == 0) {
        user_num = atoi(res_buf);
    }

    return user_num;
}

static void fill_data(const char *inbuf, online_usr_info_st *outbuf)
{
    const char *pos = inbuf;
    char rxdata[64];
    char txdata[64];
    int j = 0;

    memset(rxdata, 0, sizeof(rxdata));
    memset(txdata, 0, sizeof(txdata));

    j = 0;
    while (*pos != ',') {
        outbuf->mac[j] = *pos;
        j++; pos++;
    }
    pos++;

    // get rx bytes
    j = 0;
    while (*pos != ',') {
        rxdata[j] = *pos;
        j++; pos++;
    }
    outbuf->rbytes = atoi(rxdata);

    pos++;

    // get tx bytes
    j = 0;
    while (*pos != ',') {
        txdata[j] = *pos;
        j++; pos++;
    }
    outbuf->tbytes = atoi(txdata);
}

static b8 is_usr_data_updating(online_usr_info_st *user)
{
    int i = 0;
    int usr_changed = 1;

    for (i = 0; i < ONLINE_USR_INFO_MAX; i++) {

        if (strstr(g_online_usr_info[i].mac, user->mac)) {

            usr_changed = 0;

            if (abs(g_online_usr_info[i].rbytes - user->rbytes) > MAX_DIFF_BYTES) {
                return 1;
            }

            if (abs(g_online_usr_info[i].rbytes - user->rbytes) > MAX_DIFF_BYTES) {
                return 1;
            }
        }
    }

    // new usr appear
    if (usr_changed) {
        return 1;
    }

    return 0;
}

static void update_online_usr_info(void)
{
    char line_buf[MAX_LINE_SIZE];

    memset(g_online_usr_info, 0, sizeof(g_online_usr_info));

    FILE *fp;
    int i = 0;

    memset(line_buf, 0, sizeof(line_buf));
    fp = fopen(ONLINE_USR_INFO_FILE, "r");
    if (fp) {
        while (fgets(line_buf, MAX_LINE_SIZE, fp)) {
            if (i < ONLINE_USR_INFO_MAX) {
                fill_data(line_buf, g_online_usr_info+i);
                i++;
            }

            memset(line_buf, 0, sizeof(line_buf));
        }
        fclose(fp);
    }
}

static void check_online_usr_data_updating(void)
{
    FILE *fp;
    int i;
    char line_buf[MAX_LINE_SIZE];
    int update_flag = 0;
    char cmd[MAX_LINE_SIZE];

    sprintf(cmd,
            "sta_list | awk '{print $1\",\"$4\",\"$5\",\"}' | grep \":\" | sed '/SSID/d' > %s",
            ONLINE_USR_INFO_FILE);
    system(cmd);

    online_usr_info_st tmp_user_info;
    memset(&tmp_user_info, 0, sizeof(tmp_user_info));

    fp = fopen(ONLINE_USR_INFO_FILE, "r");
    if (fp) {
        memset(line_buf, 0, sizeof(line_buf));

        while (fgets(line_buf, MAX_LINE_SIZE, fp)) {
            fill_data(line_buf, &tmp_user_info);
            memset(line_buf, 0, sizeof(line_buf));

            if (is_usr_data_updating(&tmp_user_info)) {
                update_flag = 1;
                break;
            }
        }

        fclose(fp);
    } else {
        return;
    }

    if (update_flag) {
        g_online_usr_alive = 1;
    } else {
        g_online_usr_alive = 0;
    }
    _log(LOG_NOTICE, "online user = [%d], alive = [%d]",
         g_online_usr_num, g_online_usr_alive);
}

void check_online_usr_alive(void)
{
    g_online_usr_num = get_on_line_user_num();

    if (g_online_usr_num == 0) {
        g_online_usr_alive = 0;

    } else if (g_online_usr_num <= ONLINE_USR_INFO_MAX) {

        check_online_usr_data_updating();
        update_online_usr_info();

    } else {
        g_online_usr_alive = 1;
    }
}

b8 is_online_user_alive(void)
{
    return g_online_usr_alive;
}

void online_user_check_init(void)
{
    memset(g_online_usr_info, 0, sizeof(g_online_usr_info));
}
