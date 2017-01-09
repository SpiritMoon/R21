#include <stdlib.h>
#include <syslog.h>
#include <signal.h>
#include <unistd.h>

#include "common.h"
#include "core-monitor.h"
#include "app-check.h"
#include "online-user-check.h"
#include "mem-check.h"
#include "web-login-check.h"

#define APP_EXIT_CHECK_PERIOD         300 // 5 mins
#define FREE_MEM_CHECK_PERIOD         720 // 12 mins
#define WAM_CHECK_PERIOD              30
#define WEB_LOGIN_CHECK_PERIOD        160
#define ONLINE_USR_ALIVE_CHECK_PERIOD 30

HAN_MSG_QUEUE *han_main_queue = NULL;

static inline void core_clean(void)
{
    han_destroy_msg(han_main_queue);
    han_destroy_timer();
}

static void reboot_system(void)
{
    core_clean();
    system("sync");

    _log(LOG_WARNING, "core-monitor reboot...");
    system("reset_reason add 08");
    system("ps > /etc/cfm/core-mon-ps-file");
    system("reboot");
    sleep(3);
}

static b8 can_reboot(void)
{
    _log(LOG_NOTICE, "check can_reboot");

    // if warm or wireless crashed, then web user login check and
    // online user alive check will not work
    if (is_wam_crashed() || is_wireless_crashed()) {
        return 1;
    }

    if (is_web_user_login()) {
        return 0;
    }

    if (is_online_user_alive()) {
        return 0;
    }

    return 1;
}

/*
 * for safely quit during upgrading
 */
static void core_terminate(int sig)
{
    _log(LOG_NOTICE, "got TERM signal");
    core_clean();

    exit(0);
}

static void core_init(void)
{
    // SIGTERM will be received once system upgrade
    signal(SIGTERM, core_terminate);

    app_check_init();
    online_user_check_init();

    han_main_queue = han_init_msg(0);
    han_init_timer(CORE_TIMER_MAX, han_main_queue);

    han_start_timer(CORE_TIMER_REAVEL_APP, 1000*(APP_EXIT_CHECK_PERIOD));
    han_start_timer(CORE_TIMER_CHECK_MEM, 1000*(FREE_MEM_CHECK_PERIOD));
    han_start_timer(CORE_TIMER_CHECK_WAM, 1000*(WAM_CHECK_PERIOD));
    han_start_timer(CORE_TIMER_CHECK_WEB_LOGIN, 1000*(WEB_LOGIN_CHECK_PERIOD));
    han_start_timer(CORE_TIMER_CHECK_ONLINE_USR_ALIVE,
                    1000*(ONLINE_USR_ALIVE_CHECK_PERIOD));
}

static void procTimer(u32 timer_id)
{
    switch (timer_id) {
    case CORE_TIMER_REBOOT_DELAY:
        _log(LOG_NOTICE, "timer CORE_TIMER_REBOOT_DELAY");
        if (can_reboot()) {
            collect_sys_info();
            reboot_system();
        }
        break;

    case CORE_TIMER_REAVEL_APP:
        _log(LOG_NOTICE, "timer CORE_TIMER_REAVEL_APP");
        travel_apps();
        han_start_timer(CORE_TIMER_REAVEL_APP, 1000*(APP_EXIT_CHECK_PERIOD));
        break;

    case CORE_TIMER_CHECK_WAM:
        _log(LOG_NOTICE, "timer CORE_TIMER_CHECK_WAM");
        check_wam_crash();
        han_start_timer(CORE_TIMER_CHECK_WAM, 1000*(WAM_CHECK_PERIOD));
        break;

    case CORE_TIMER_CHECK_MEM:
        _log(LOG_NOTICE, "timer CORE_TIMER_CHECK_MEM");
        check_free_mem();
        han_start_timer(CORE_TIMER_CHECK_MEM, 1000*(FREE_MEM_CHECK_PERIOD));
        break;

    case CORE_TIMER_CHECK_WEB_LOGIN:
        _log(LOG_NOTICE, "timer CORE_TIMER_CHECK_WEB_LOGIN");
        check_web_login();
        han_start_timer(CORE_TIMER_CHECK_WEB_LOGIN, 1000*(WEB_LOGIN_CHECK_PERIOD));
        break;

    case CORE_TIMER_CHECK_ONLINE_USR_ALIVE:
        _log(LOG_NOTICE, "timer CORE_TIMER_CHECK_ONLINE_USR_ALIVE");
        check_online_usr_alive();
        han_start_timer(CORE_TIMER_CHECK_ONLINE_USR_ALIVE,
                        1000*(ONLINE_USR_ALIVE_CHECK_PERIOD));
        break;

    default:
        _log(LOG_NOTICE, "timer INVALID");
        break;
    }

    return;
}

int main(int argc, char *argv[])
{
    _log(LOG_NOTICE, "core-monitor start");

    core_init();

    HAN_MSG *pMsg = NULL;

    while (1) {
        pMsg = han_get_msg(han_main_queue);
        if (NULL != pMsg) {
            switch (pMsg->msgType) {
            case HAN_MSG_TYPE_TIMER:
                procTimer(pMsg->msgID);
                break;

            default:
                break;
            }

            han_free(pMsg);
        }
    }

    core_clean();

    return 0;
}
