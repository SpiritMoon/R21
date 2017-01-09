#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

#include "common.h"
#include "core-monitor.h"
#include "online-user-check.h"

#define MAX_UPGRADE_MEM               18432  // 18MB

static b8 g_over_mem_count = 0;

static b8 clear_log(void)
{
    if (is_online_user_alive()) {
        return 0;
    }

    _log(LOG_NOTICE, "clear logs for freeing mem");

	/* delete files bigger than 3M */
	system("find  /tmp/*.log -size +3072k -exec rm {} \; -exec echo -e $(date '+%F %T') :'  ' rm {} '\t' bigger than 3M>>/etc/cfm/delete_log \;");
	system("find  /tmp/log/* -size +3072k -exec rm {} \; -exec echo -e $(date '+%F %T') :'  ' rm {} '\t' bigger than 3M>>/etc/cfm/delete_log \;");

	/* delete logs in delete_log except the last 30 lines */
	system("[ `ls -l /etc/cfm/delete_log |awk '{print $5}'` -gt 20280 ] && awk -v l=`wc -l /etc/cfm/delete_log|awk '{print $1}'` '{if(NR > l-30) print $0}' /etc/cfm/delete_log >/tmp/delete_log_tmpfile ;test -f /tmp/delete_log_tmpfile&& mv /tmp/delete_log_tmpfile /etc/cfm/delete_log");


    return 1;
}

static u32 get_current_free_mem(void)
{
    char cmd[MAX_LINE_SIZE];
    char res_buf[MAX_LINE_SIZE];

    sprintf(cmd, "cat /proc/meminfo | sed -n '/MemFree/p' | awk '{print $2}'");

    memset(res_buf, 0, sizeof(res_buf));
    if (check_cmd_response(cmd, res_buf, MAX_LINE_SIZE) < 0) {
        _log(LOG_WARNING, "free mem check failed");
        return 0;
    }

    u32 free_bytes = atoi(res_buf);

    return free_bytes;
}

/**
 * @testcase:
 *   dd if=/dev/zero of=/tmp/xx2 bs=1M count=15
 */
void check_free_mem(void)
{
    u32 free_bytes = get_current_free_mem();
    if (free_bytes == 0) {
        return;
    }

    _log(LOG_NOTICE, "free mem check [free = %d]", free_bytes);

    if (free_bytes >= MAX_UPGRADE_MEM) {
        g_over_mem_count = 0;
        return;
    }

    // free_bytes < MAX_UPGRADE_MEM
    g_over_mem_count++;
	system("echo 1 > /proc/sys/vm/drop_caches");
    if (g_over_mem_count >= 5) {

        if (clear_log()) {
            free_bytes = get_current_free_mem();
            if (free_bytes >= MAX_UPGRADE_MEM) {
                return;
            }
        }

        char reason[MAX_LINE_SIZE];
        sprintf(reason, "free mem [%u] not enough for upgrade", free_bytes);
        record_reboot_reason(reason);

        han_start_timer(CORE_TIMER_REBOOT_DELAY, 2000);
    }

}
