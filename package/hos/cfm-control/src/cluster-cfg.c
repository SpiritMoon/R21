#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DEBUG_EN

#define LOCKFILE                "/var/lock/cclock"
#define LOGFILE                 "/tmp/cluster-cfg.log"

#define PUB_CFG_DIR             "/etc/cfm/config/config-pub"
#define PRIV_CFG_DIR            "/etc/cfm/config/config-priv"
#define PUB_CFG_MD5_FILE        "/etc/cfm/config/config-pub/pub-cfg-md5"
#define PUB_CFG_REV_NUM_FILE    "/etc/cfm/config/config-pub/revisionnumber"

#define MAX_CMD_LEN             1024
#define MAX_WRAP_LEN            800
#define MAX_NAME_LEN            128
#define MAX_REV_NUMBER          2147483640

typedef enum {
    PUB_CFG_TYPE = 0,
    PRIV_CFG_TYPE,

    CFG_TYPE_MAX,
} cfg_type_e;

typedef enum {
    CMD_TYPE_WRITE = 0,
    CMD_TYPE_READ,

    CMD_TYPE_MAX,
} cmd_type_e;

FILE *g_log_fp = NULL;

static int is_read_cmd(const char *cmd)
{
    const char* r_cmd_list[] = {
        "export", "show", "get", "list_wlan", "get_wlan", "show_wlan_list_op", NULL
    };

    int cmd_index = 0;

    while (r_cmd_list[cmd_index] != NULL) {
        if (strcmp(cmd, r_cmd_list[cmd_index]) == 0) {
            return 1;
        }

        cmd_index++;
    }

    return 0;
}

static void read_cfg(cfg_type_e cfgtype, const char *cmd, const char *cfgname)
{
    char fullcmd[MAX_CMD_LEN+1];

    memset(fullcmd, 0, sizeof(fullcmd));

    if (cfgtype == PUB_CFG_TYPE) {
        snprintf(fullcmd, MAX_CMD_LEN, "uci -c %s %s", PUB_CFG_DIR, cmd);
    } else {
        snprintf(fullcmd, MAX_CMD_LEN, "uci -c %s %s", PRIV_CFG_DIR, cmd);
    }

    system(fullcmd);

#ifdef DEBUG_EN
    //fprintf(g_log_fp, "rcmd = [%s]\n", fullcmd);
#endif
}

static void update_pub_cfg_rev_number(void)
{
    FILE *fp;
    char revnum_buf[MAX_NAME_LEN+1];

    memset(revnum_buf, 0, sizeof(revnum_buf));

    fp = fopen(PUB_CFG_REV_NUM_FILE, "r");
    if (fp) {
        if (fgets(revnum_buf, MAX_NAME_LEN, fp)) {
            int len = strlen(revnum_buf);
            if (revnum_buf[len] == '\n') {
                revnum_buf[len] = '\0';
            }

            unsigned long current_num;

            current_num = atol(revnum_buf);
            current_num++;
            if (current_num >= MAX_REV_NUMBER) {
                current_num = 1;
            }

            sprintf(revnum_buf, "%lu\n", current_num);
        } else {
            sprintf(revnum_buf, "1\n");
        }
    }

    if (fp) {
        fclose(fp);
        fp = NULL;
    } else {
        sprintf(revnum_buf, "1\n");
    }

    fp = fopen(PUB_CFG_REV_NUM_FILE, "w");
    if (fp) {
        fputs(revnum_buf, fp);
        fclose(fp);
    }
}

static void update_pub_cfg_md5(void)
{
    char cmd[MAX_CMD_LEN+1];

    if (access(PUB_CFG_MD5_FILE, F_OK) == 0) {
        remove(PUB_CFG_MD5_FILE);
    }

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "cd %s; md5sum * > %s", PUB_CFG_DIR, PUB_CFG_MD5_FILE);
    system(cmd);
}

static void write_cfg(cfg_type_e cfgtype, const char *cmd, const char *cfgname)
{
    char fullcmd[MAX_CMD_LEN+1];

    // write default config
    snprintf(fullcmd, MAX_CMD_LEN, "uci %s; uci commit %s", cmd, cfgname);
    system(fullcmd);

    if (cfgtype == PUB_CFG_TYPE) {
        // write public config
        snprintf(fullcmd, MAX_CMD_LEN, "uci -c %s %s; uci -c %s commit %s",
                 PUB_CFG_DIR, cmd, PUB_CFG_DIR, cfgname);
        system(fullcmd);

#ifdef DEBUG_EN
    fprintf(g_log_fp, "wcmd = [%s]\n", fullcmd);
#endif

        // update public config rev number and md5
        update_pub_cfg_rev_number();
        update_pub_cfg_md5();
    } else {
        // write private config
        snprintf(fullcmd, MAX_CMD_LEN, "uci -c %s %s; uci -c %s commit %s",
                 PRIV_CFG_DIR, cmd, PRIV_CFG_DIR, cfgname);
        system(fullcmd);
    }
}

static int is_mac_valid(const char *mac)
{
    int index = 0;

    while (isxdigit(*mac) || *mac == ':') {
        mac++;
        index++;
    }

    if (index == 17) {
        return 1;
    }

    return 0;
}

static int overlook_options(int argc, char *argv[], cfg_type_e cfgtype, char *buf)
{
    int para_seq;
    int offset = 0;

    if (cfgtype == PRIV_CFG_TYPE) {
        para_seq = 2;
    } else {
        para_seq = 1;
    }

    while (para_seq < argc) {

        // overlook options start with '-'
        if (*argv[para_seq] != '-') {
            int paralen = strlen(argv[para_seq]);

            if (offset + paralen >= MAX_CMD_LEN) {
#ifdef DEBUG_EN
                fprintf(g_log_fp, " %s > MAX_CMD_LEN\n", __func__);
#endif
                return -1;
            }

            strncpy(buf+offset, argv[para_seq], paralen);
            offset += paralen;

            // add space except for the last parameter
            if (para_seq + 1 != argc) {
                buf[offset] = ' ';
                offset += 1;
            }
        }

        para_seq++;
    }

    return 0;
}

/**
 * check_buf separator can only be ' '
 */
static int get_cmdname_cfgname(const char *check_buf,  char *cmdname, char *cfgname)
{
    // === get cmd name
    int name_index = 0;
    int buf_index = 0;

    // skip spaces
    while (check_buf[buf_index] == ' ') {
        buf_index++;
    }

    char c;

    c = check_buf[buf_index];
    while (c != ' ' && c != '\0' && c != '.') {
        buf_index++;

        cmdname[name_index] = c;
        name_index++;

        if (name_index == MAX_NAME_LEN) {
#ifdef DEBUG_EN
            fprintf(g_log_fp, "config name too long > %d\n", name_index);
#endif
            return -1;
        }

        c = check_buf[buf_index];
    }

    if (c == '\0' || c == '.') {
        return -1;
    }

    // === get config name
    // jump spaces
    while (check_buf[buf_index] == ' ') {
        buf_index++;
    }

    int cfg_index = 0;

    c = check_buf[buf_index];
    while (c != ' ' && c != '\0' && c != '.') {
        cfgname[cfg_index] = c;

        cfg_index++;
        buf_index++;

        if (cfg_index == MAX_NAME_LEN) {
#ifdef DEBUG_EN
            fprintf(g_log_fp, "config name too long > %d\n", cfg_index);
#endif
            return -1;
        }

        c = check_buf[buf_index];
    }

    return 0;
}

static void wrap_params(const char *in_buf, char *out_buf)
{
    int in_pos;
    int out_pos = 0;
    int org_len = strlen(in_buf);
    unsigned char equal_flag = 0;

    out_buf[out_pos++] = '\"';
    for (in_pos = 0; in_pos < org_len; in_pos++) {
        if (in_buf[in_pos] == '.') {
            out_buf[out_pos++] = '\"';
            out_buf[out_pos++] = '.';
            out_buf[out_pos++] = '\"';
        } else if (in_buf[in_pos] == '=' && equal_flag == 0) {
            out_buf[out_pos++] = '\"';
            out_buf[out_pos++] = '=';
            out_buf[out_pos++] = '\"';
            equal_flag = 1;
        } else {
            if (in_buf[in_pos] == '\"' || in_buf[in_pos] == '$') {
                out_buf[out_pos++] = '\\';
            }

            out_buf[out_pos++] = in_buf[in_pos];
        }

        if (out_pos >= MAX_WRAP_LEN) {
            break;
        }
    }
    if (in_pos == org_len) {
        out_buf[out_pos++] = '\"';
    }

    out_buf[out_pos] = '\0';
}

static int draw_valid_parameters(int argc, char *argv[], cfg_type_e cfgtype, char *valid_buf)
{
    int para_seq;
    int offset;
    int paralen;

    char swap_buf[MAX_CMD_LEN+1];

    if (cfgtype == PRIV_CFG_TYPE) {
        para_seq = 2;
    } else {
        para_seq = 1;
    }

    offset = 0;
    while (para_seq < argc) {
        paralen = strlen(argv[para_seq]);

        if (offset + paralen >= MAX_CMD_LEN) {
            return -1;
        }

        // support "a"."b c d"."e"="x y z" feature
        if (strstr(argv[para_seq], ".")) {
            memset(swap_buf, 0, sizeof(swap_buf));
            wrap_params(argv[para_seq], swap_buf);
            int swap_len = strlen(swap_buf);
            if (offset + swap_len >= MAX_CMD_LEN) {
                return -1;
            }
            strncpy(valid_buf+offset, swap_buf, swap_len);
            offset += swap_len;
        } else {
            strncpy(valid_buf+offset, argv[para_seq], paralen);
            offset += paralen;
        }

        // add space except for the last parameter
        if (para_seq + 1 != argc) {
            valid_buf[offset] = ' ';
            offset += 1;
        }

        para_seq++;
    }

    return 0;
}

static int log_init(void)
{
    struct stat sbuf;

    if (stat(LOGFILE, &sbuf) == 0) {
        // larger than 100k, del it
        if (sbuf.st_size > 102400) {
            if (g_log_fp) {
                fclose(g_log_fp);
            }

            remove(LOGFILE);
        }
    }

    if ((g_log_fp = fopen(LOGFILE, "a")) == NULL) {
        perror("fopen");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        printf("Usage: cluster-cfg [<mac-addr>] [<options>] [cmd] [arguments]\n");
        return -1;
    }

#ifdef DEBUG_EN
    if (log_init() < 0) {
        return -1;
    }
#endif

    // === get cfg type
    cfg_type_e cfgtype;

    if (is_mac_valid(argv[1])) {
        cfgtype = PRIV_CFG_TYPE;
    } else {
        cfgtype = PUB_CFG_TYPE;
    }

    // === get valid parameters
    char valid_buf[MAX_CMD_LEN+1];
    memset(valid_buf, 0, sizeof(valid_buf));

    if (draw_valid_parameters(argc, argv, cfgtype, valid_buf) < 0) {
#ifdef DEBUG_EN
        fprintf(g_log_fp, "draw full cmd err\n");
#endif
        return -1;
    }
#ifdef DEBUG_EN
    //fprintf(g_log_fp, "  => valid params [%s]\n", valid_buf);
#endif

    // === get cmd name and config name
    char check_buf[MAX_CMD_LEN+1];
    memset(check_buf, 0, sizeof(check_buf));

    if (overlook_options(argc, argv, cfgtype, check_buf) < 0) {
#ifdef DEBUG_EN
        fprintf(g_log_fp, "overlook options err\n");
#endif
        return -1;
    }

    char cmdname[MAX_NAME_LEN+1];
    char cfgname[MAX_NAME_LEN+1];

    memset(cmdname, 0, sizeof(cmdname));
    memset(cfgname, 0, sizeof(cfgname));

    if (get_cmdname_cfgname(check_buf, cmdname, cfgname) < 0) {
#ifdef DEBUG_EN
        fprintf(g_log_fp, "get cmd name and cfg name err\n");
#endif
        return -1;
    }

    int lockfd;

    // === Place an exclusive lock
    // Only one process may hold an exclusive lock for a given file at a given time.
    if ((lockfd = open(LOCKFILE, O_CREAT)) < 0) {
        perror("open");
        return -1;
    }

    if (flock(lockfd, LOCK_EX) < 0) {
        perror("flock");
        return -1;
    }

    // do read or write
    if (is_read_cmd(cmdname)) {
        read_cfg(cfgtype, valid_buf, cfgname);
    } else {
        write_cfg(cfgtype, valid_buf, cfgname);
    }

    flock(lockfd, LOCK_UN);

    return 0;
}