#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

#include "common.h"

#define WEB_LOGIN_CHECK_FILE          "/tmp/web-login-flag"

static unsigned char g_web_user_login = 0;

b8 is_web_user_login(void)
{
    return g_web_user_login;
}

void check_web_login(void)
{
    if (access(WEB_LOGIN_CHECK_FILE, F_OK) != 0) {
        g_web_user_login = 0;
        return;
    }

    FILE *fp;
    char flushnum_buf[MAX_NAME_LEN+1];
    static int old_flush_num = 0;

    memset(flushnum_buf, 0, sizeof(flushnum_buf));

    fp = fopen(WEB_LOGIN_CHECK_FILE, "r");
    if (fp == NULL) {
        return;
    }

    if (fgets(flushnum_buf, MAX_NAME_LEN, fp)) {
        int len = strlen(flushnum_buf);
        if (flushnum_buf[len] == '\n') {
            flushnum_buf[len] = '\0';
        }

        int new_flush_num = atoi(flushnum_buf);

        if (new_flush_num == old_flush_num) {
            g_web_user_login = 0;
        } else {
            g_web_user_login = 1;
            old_flush_num = new_flush_num;
        }

        _log(LOG_NOTICE, "update web flush num [%d]", new_flush_num);
    }

    fclose(fp);
}

