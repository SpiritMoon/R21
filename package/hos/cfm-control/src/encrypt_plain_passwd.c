#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <stdarg.h>

#define ENCPT_APP_NAME              "/usr/bin/scvt"

#define SYNC_PUB_DIR                "/tmp/config-pub"

#define SYNC_AUTH_LOCAL_FILE        "/tmp/config-pub/auth_local"
#define AUTH_LOCAL_FILE             "/etc/config/auth_local"
#define AUTH_LOCAL_TMP_FILE         "/tmp/tmp_auth_local"

#define SYNC_WIRELESS_FILE          "/tmp/config-pub/wireless"
#define WIRELESS_FILE               "/etc/config/wireless"
#define WIRELESS_TMP_FILE           "/tmp/tmp_wireless"

#define LOG_MODULE                  "encrypt"

#define MAX_LOG_LINE_LEN            256
#define UCI_CMD_LEN                 1024
#define BUF_LEN                     512

typedef enum {
    TYPE_NONE = 0,
    TYPE_BOOT,
    TYPE_SYNC,
} update_type_e;

static void _log(int level, const char *format, ...)
{
	char buf[MAX_LOG_LINE_LEN+1];

    if (level < 0 || level > 7) {
        level = 5; // LOG_NOTICE
    }

	va_list ptr;
	va_start(ptr, format);
	vsnprintf(buf, MAX_LOG_LINE_LEN, format, ptr);
	va_end(ptr);

	openlog(LOG_MODULE, 0, LOG_USER);
	syslog(level, "%s", buf);
	closelog();
}

static int check_cmd_response(const char *cmd, char *ret, unsigned int ret_size)
{
    if (cmd == NULL || ret_size == 0 || ret == NULL) {
        _log(LOG_INFO, "%s invalid parameters", __func__);
        return -1;
    }

    FILE *fd = popen(cmd, "r");
    if (fd == NULL) {
        _log(LOG_INFO, "popen err");
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

static void encrypt_plain_passwd(const char *plain_passwd, char *obuf)
{
    if (plain_passwd == 0) return;

    char cmd[BUF_LEN];
    char cmd_res_buf[BUF_LEN];
    int ret;

    snprintf(cmd, sizeof(cmd), "%s enc %s", ENCPT_APP_NAME, plain_passwd);
    memset(cmd_res_buf, 0, sizeof(cmd_res_buf));
    ret = check_cmd_response(cmd, cmd_res_buf, BUF_LEN);
    if (ret < 0) {
        _log(LOG_INFO, "check_cmd_response enc passwd");
        return;
    }

    strncpy(obuf, cmd_res_buf, BUF_LEN);
}

static void generate_tmp_wireless_file(update_type_e type)
{
    char cmd[BUF_LEN];

    // create && save .key option
    memset(cmd, 0, sizeof(cmd));
    if (type == TYPE_SYNC) {
        snprintf(cmd, sizeof(cmd),
                 "uci -c %s show wireless | grep .key > %s",
                 SYNC_PUB_DIR, WIRELESS_TMP_FILE);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "uci show wireless | grep .key > %s", WIRELESS_TMP_FILE);
    }
    system(cmd);

    // attach auth_secret option
    memset(cmd, 0, sizeof(cmd));
    if (type == TYPE_SYNC) {
        snprintf(cmd, sizeof(cmd),
                 "uci -c %s show wireless | grep auth_secret >> %s",
                 SYNC_PUB_DIR, WIRELESS_TMP_FILE);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "uci show wireless | grep auth_secret >> %s", WIRELESS_TMP_FILE);
    }
    system(cmd);

    // attach acct_secret option
    memset(cmd, 0, sizeof(cmd));
    if (type == TYPE_SYNC) {
        snprintf(cmd, sizeof(cmd),
                 "uci -c %s show wireless | grep acct_secret >> %s",
                 SYNC_PUB_DIR, WIRELESS_TMP_FILE);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "uci show wireless | grep acct_secret >> %s", WIRELESS_TMP_FILE);
    }
    system(cmd);
}

/**
 * sample:
 *   wireless.773232_2G_wifi0.key=88b6cc7ec
 */
static void get_wireless_passwd_option(const char *inbuf, char *obuf)
{
    if (inbuf == NULL) return;
    if (strstr(inbuf, "=") == NULL) return;

    const char *next = inbuf;
    int option_index = 0;

    while (*next != '=') {
        obuf[option_index] = *next;

        option_index++;
        next++;
    }
}

/**
 * sample:
 *   wireless.773232_2G_wifi0.key=88b6cc7ec
 */
static void get_wireless_plain_passwd(const char *inbuf, char *obuf)
{
    if (inbuf == NULL) return;

    const char *next;

    next = strstr(inbuf, "=");
    if (next == NULL) return;

    next++;

    int plain_index = 0;

    while (*next != ' ' && *next != '\n') {
        obuf[plain_index] = *next;

        plain_index++;
        next++;
    }
}

static void update_wireless_config(update_type_e type, const char *inbuf)
{
    if (inbuf == NULL) return;

    char passwd_option[BUF_LEN];
    char plain_passwd[BUF_LEN];
    char encrypted_passwd[BUF_LEN];
    char cmd[UCI_CMD_LEN];

    memset(passwd_option, 0, sizeof(passwd_option));
    get_wireless_passwd_option(inbuf, passwd_option);

    memset(plain_passwd, 0, sizeof(plain_passwd));
    get_wireless_plain_passwd(inbuf, plain_passwd);

    memset(encrypted_passwd, 0, sizeof(encrypted_passwd));
    encrypt_plain_passwd(plain_passwd, encrypted_passwd);

    if (type == TYPE_SYNC) {
        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd),
                 "uci -c %s set %s=%s", SYNC_PUB_DIR, passwd_option, encrypted_passwd);
        system(cmd);

        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd),
                 "uci -c %s commit wireless", SYNC_PUB_DIR);
        system(cmd);

    } else {
        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd),
                 "cluster-cfg set %s=%s", passwd_option, encrypted_passwd);
        system(cmd);
    }
}

static void encrypt_wireless_ssid_passwd(update_type_e type)
{
    generate_tmp_wireless_file(type);

    FILE *fp;
    fp = fopen(WIRELESS_TMP_FILE, "r");
    if (fp == NULL) {
        _log(LOG_DEBUG, "fopen wireless tmp err");
        return;
    }

    char buf[UCI_CMD_LEN];
    memset(buf, 0, sizeof(buf));

    while (fgets(buf, sizeof(buf), fp)) {
        update_wireless_config(type, buf);

        memset(buf, 0, sizeof(buf));
    }

    fclose(fp);
    fp = NULL;

    remove(WIRELESS_TMP_FILE);
}

/**
 * sample:
 *   'username passwd # # # # # 2016.08.20 2016.08.31'
 */
static void get_userinfo_rest(const char *userinfo, char *obuf)
{
    if (userinfo == NULL) return;

    const char *next;

    next = strstr(userinfo, " ");
    if (next == NULL) return;

    while (*next == ' ') next++;
    while (*next != ' ') next++;
    while (*next == ' ') next++;

    int rest_index = 0;

    while (*next != '\0') {
        obuf[rest_index] = *next;

        rest_index++;
        next++;
    }
}

/**
 * sample:
 *   'username passwd # # # # # 2016.08.20 2016.08.31'
 */
static void get_userinfo_passwd(const char *userinfo, char *obuf)
{
    if (userinfo == NULL) return;

    const char *next;

    next = strstr(userinfo, " ");
    if (next == NULL) return;

    while (*next == ' ') next++;

    int passwd_index = 0;

    while (*next != ' ') {
        obuf[passwd_index] = *next;

        passwd_index++;
        next++;
    }
}

/**
 * sample:
 *   'username passwd # # # # # 2016.08.20 2016.08.31'
 */
static void get_userinfo_username(const char *userinfo, char *obuf)
{
    if (userinfo == NULL) return;

    const char *next;

    next = strstr(userinfo, "'");
    if (next == NULL) return;

    next++;

    int name_index = 0;

    while (*next != ' ') {
        obuf[name_index] = *next;

        name_index++;
        next++;
    }
}


/**
 * sample:
 *   list userinfo 'username passwd # # # # # 2016.08.20 2016.08.31'
 */
static void get_one_userinfo(const char *inbuf, char *obuf)
{
    if (inbuf == NULL) {
        return;
    }

    const char *next;

    next = strstr(inbuf, "'");
    if (next == NULL) {
        return;
    }

    int userinfo_index = 0;

    while (*next != '\n') {
        obuf[userinfo_index] = *next;

        userinfo_index++;
        next++;
    }
}

static inline void compose_encrypted_userinfo(const char *userinfo, char *obuf)
{
    char name[BUF_LEN];
    char plain_passwd[BUF_LEN];
    char encrypted_passwd[BUF_LEN];
    char rest[BUF_LEN];

    memset(name, 0, sizeof(name));
    memset(plain_passwd, 0, sizeof(plain_passwd));
    memset(encrypted_passwd, 0, sizeof(encrypted_passwd));
    memset(rest, 0, sizeof(rest));

    get_userinfo_username(userinfo, name);
    get_userinfo_passwd(userinfo, plain_passwd);
    get_userinfo_rest(userinfo, rest);

    encrypt_plain_passwd(plain_passwd, encrypted_passwd);

    snprintf(obuf, UCI_CMD_LEN, "'%s %s %s", name, encrypted_passwd, rest);
}

static void update_auth_local_config(update_type_e type, const char *userinfo,
                                     const char *enc_userinfo)
{
    if (userinfo == NULL || enc_userinfo == NULL) return;

    char cmd[UCI_CMD_LEN];

    if (type == TYPE_SYNC) {
        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd),
                 "uci -c %s del_list auth_local.accout.userinfo=%s",
                 SYNC_PUB_DIR, userinfo);
        system(cmd);

        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd),
                 "uci -c %s add_list auth_local.accout.userinfo=%s",
                 SYNC_PUB_DIR, enc_userinfo);
        system(cmd);

        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd), "uci -c %s commit auth_local", SYNC_PUB_DIR);
        system(cmd);

    } else {
        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd),
                 "cluster-cfg del_list auth_local.accout.userinfo=%s", userinfo);
        system(cmd);

        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd),
                 "cluster-cfg add_list auth_local.accout.userinfo=%s", enc_userinfo);
        system(cmd);
    }
}

static void encrypt_auth_local_passwd(update_type_e type)
{
    char cmd[BUF_LEN];

    memset(cmd, 0, sizeof(cmd));
    if (type == TYPE_SYNC) {
        snprintf(cmd, sizeof(cmd), "cp %s %s",
                 SYNC_AUTH_LOCAL_FILE, AUTH_LOCAL_TMP_FILE);
    } else {
        snprintf(cmd, sizeof(cmd), "cp %s %s",
                 AUTH_LOCAL_FILE, AUTH_LOCAL_TMP_FILE);
    }
    system(cmd);

    FILE *fp;
    fp = fopen(AUTH_LOCAL_TMP_FILE, "r");
    if (fp == NULL) {
        _log(LOG_DEBUG, "fopen auth_local_tmp err");
        return;
    }

    char userinfo_buf[UCI_CMD_LEN];
    char encrypted_userinfo_buf[UCI_CMD_LEN];
    char buf[UCI_CMD_LEN];

    memset(userinfo_buf, 0, sizeof(userinfo_buf));
    memset(encrypted_userinfo_buf, 0, sizeof(encrypted_userinfo_buf));
    memset(buf, 0, sizeof(buf));

    while (fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, "userinfo")) {
            get_one_userinfo(buf, userinfo_buf);
            compose_encrypted_userinfo(userinfo_buf, encrypted_userinfo_buf);
            update_auth_local_config(type, userinfo_buf, encrypted_userinfo_buf);

            memset(userinfo_buf, 0, sizeof(userinfo_buf));
            memset(encrypted_userinfo_buf, 0, sizeof(encrypted_userinfo_buf));
        }

        memset(buf, 0, sizeof(buf));
    }

    fclose(fp);
    fp = NULL;

    remove(AUTH_LOCAL_TMP_FILE);
}

static inline update_type_e get_action_type(const char *par)
{
    if (strcmp(par, "boot") == 0) {
        return TYPE_BOOT;
    } else if (strcmp(par, "sync") == 0) {
        return TYPE_SYNC;
    }

    return TYPE_NONE;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        _log(LOG_DEBUG, "invalid main parameter num");
        return -1;
    }

    update_type_e type;

    type = get_action_type(argv[1]);
    if (type == TYPE_NONE) {
        _log(LOG_DEBUG, "invalid main parameter value");
        return -1;
    }

    encrypt_auth_local_passwd(type);
    encrypt_wireless_ssid_passwd(type);

    return 0;
}
