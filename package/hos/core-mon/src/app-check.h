#ifndef APP_CHECK_H
#define APP_CHECK_H

#include "common.h"
#include "list.h"

typedef struct {
    char app_name[MAX_NAME_LEN];
    int exit_check_count;
    int max_exit_check_count;
    int stat_check_count;
    int max_stat_check_count;

    int app_stat;
    pid_t app_pid;

    struct list_head list;
} APP_INFO_T;

enum {
    GET_APPINFO_WITH_APP_PID,
    GET_APPINFO_WITH_APP_NAME,
};

typedef enum {
    PROCESS_STAT_NONE = 0,
    PROCESS_STAT_R, // running
    PROCESS_STAT_S, // interruptible
    PROCESS_STAT_D, // uninterruptible
    PROCESS_STAT_T, // stopped or traced
    PROCESS_STAT_Z, // zombie
} process_stat_e;

void app_check_init(void);
int travel_apps(void);
void check_wam_crash(void);
b8 is_wam_crashed(void);
b8 is_wireless_crashed(void);

#endif // APP_CHECK_H