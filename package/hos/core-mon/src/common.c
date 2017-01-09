#include <stdio.h>
#include <time.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

#include "common.h"

#define CORE_REBOOT_INFO_FILE         "/etc/cfm/core-mon-reboot-info"

void record_reboot_reason(const char *reason)
{
    if (reason == NULL) {
        return;
    }

    time_t now;
    struct tm *tm_now;

    time(&now);
    tm_now = localtime(&now);

    char time_val[MAX_LINE_SIZE];
    sprintf(time_val, "%d-%d-%d %d:%d:%d", 1900+tm_now->tm_year, 1+tm_now->tm_mon,
            tm_now->tm_mday, tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec);

    FILE *log_fp = fopen(CORE_REBOOT_INFO_FILE, "a+");
    if (log_fp) {
        fprintf(log_fp, "%s - %s\n", time_val, reason);
        fclose(log_fp);
    } else {
        _log(LOG_NOTICE, "fopen CORE_REBOOT_INFO_FILE err");
        return;
    }

    // keep 20 lines most
    char cmd[MAX_LINE_SIZE];
    sprintf(cmd, "lnum=`sed -n '$=' %s`; [ $lnum -gt 20 ] && sed -i '1d' %s",
            CORE_REBOOT_INFO_FILE, CORE_REBOOT_INFO_FILE);
    system(cmd);
}

void collect_sys_info(void)
{
    char cmd[MAX_LINE_SIZE];
    char res_buf[MAX_LINE_SIZE];

    // uptime
    memset(res_buf, 0, sizeof(res_buf));
    sprintf(cmd, "uptime");
    if (check_cmd_response(cmd, res_buf, MAX_LINE_SIZE) == 0) {
        _log(LOG_NOTICE, "[%s]", res_buf);
    }

    // cpu info
    // CPU     %user     %nice   %system   %iowait    %steal     %idle
    memset(res_buf, 0, sizeof(res_buf));
    sprintf(cmd, "sar -u 1 1 | grep Average | awk -F ':' '{print $2}'");
    if (check_cmd_response(cmd, res_buf, MAX_LINE_SIZE) == 0) {
        _log(LOG_NOTICE, "cpu user nice system iowait steal idle [%s]", res_buf);
    }

    // mem info
    // kbmemfree kbmemused  %memused kbbuffers  kbcached  kbcommit   %commit
    memset(res_buf, 0, sizeof(res_buf));
    sprintf(cmd, "sar -r 1 1 | grep Average | awk -F ':' '{print $2}'");
    if (check_cmd_response(cmd, res_buf, MAX_LINE_SIZE) == 0) {
        _log(LOG_NOTICE, "kbmemfree kbmemused memused kbbuffers kbcached kbcommit commit [%s]", res_buf);
    }
}

int check_cmd_response(const char *cmd, char *ret, u32 ret_size)
{
    if (cmd == NULL || ret_size == 0 || ret == NULL) {
        return -1;
    }

    FILE *fd = popen(cmd, "r");
    if (fd == NULL) {
        _log(LOG_NOTICE, "popen err");
        return -1;
    }

    // reads in at most one less than size characters from stream
    // and stores them into the buffer pointed to by s.
    // Reading stops after an EOF or a newline.
    fgets(ret, ret_size, fd);
    pclose(fd);

    int rlen = 0;
    rlen = strlen(ret);

    if (rlen > 0 && ret[rlen-1] == '\n') {
        ret[rlen-1] = '\0';
    }

    return 0;
}

