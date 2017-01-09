/* packed bin structure
   |-------------+------------+------------------+-------------+-------------|
   | Header Type | Header Len |                 Header Buf                   |
   |-------------+------------+------------------+-------------+-------------|
   |                          | md5 type         | md5 len     | md5 buf     |
   |-------------+------------+------------------+-------------+-------------|
   |                          | version type     | version len | version buf |
   |-------------+------------+------------------+-------------+-------------|
   |                          | devinfo type     | devinfo len | devinfo buf |
   |-------------+------------+------------------+-------------+-------------|
   |                            xxx.bin                                      |
   |-------------+------------+------------------+-------------+-------------|
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdarg.h>
#include <syslog.h>

#include "tlv_node.h"

//#define DEBUG

#define VERSION_FNAME "/etc/version/version"
#define DEVINFO_FNAME "/tmp/sysinfo/board_name"
#define LOG_PREFIX    "=upgrade="
#define LOG_MODULE    "osupgrade"

#define MAX_HEAD_LEN               4096
#define BUF_LEN                    256
#define SWAP_LEN                   1024
#define MAX_LOG_LINE_LEN           256

char g_packed_bin_name[BUF_LEN] = "";

static int _log(int level, const char *format, ...)
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

/**
 * get normal node
 */
static tlv_node_st* tlv_get_next_node(tlv_node_st* p_now)
{
    return (tlv_node_st *)(((char*)(p_now)) + NODE_TYPE_SIZE + NODE_LEN_SIZE + ntohl(p_now->len));
}

static unsigned char get_node_type(tlv_node_st *p_node_now)
{
    return *(unsigned char *)((char *)p_node_now);
}

static uint32_t get_node_buf_len(tlv_node_st *p_node_now)
{
    uint32_t node_buf_len = 0;

    node_buf_len = ntohl(*(uint32_t *)(((char *)p_node_now) + NODE_TYPE_SIZE));
    return node_buf_len;
}

static char * get_node_buf_val(tlv_node_st *p_node_now)
{
    return (char *)(((char*)p_node_now) + NODE_TYPE_SIZE + NODE_LEN_SIZE);
}

static int tlv_get_root_node(FILE *fp, tlv_node_st *p_root, int max_root_len)
{
    if (fp == NULL || p_root == NULL) {
        return -1;
    }

    size_t rlen = 0;
    char dumpbuf[BUF_LEN] = "";

    // check root type
    rlen = fread(dumpbuf, 1, NODE_TYPE_SIZE, fp);
    if (rlen != NODE_TYPE_SIZE) {
        printf("fread error\n");
        return -2;
    }

    p_root->type = dumpbuf[0];
    if (p_root->type != TYPE_ROOT_HEAD) {
        printf("header type invalid!\n");
        return -3;
    }

    memset(dumpbuf, 0, BUF_LEN);

    // get root len
    rlen = fread(dumpbuf, 1, NODE_LEN_SIZE, fp);
    if (rlen != NODE_LEN_SIZE) {
        printf("fread err\n");
        return -2;
    }

    p_root->len = *(uint32_t *)&dumpbuf[0];
    uint32_t root_buf_len = ntohl(p_root->len);
    if (root_buf_len > max_root_len) {
        printf("root len invalid!\n");
        return -3;
    }

    p_root->p_buf = (char *) calloc(1, root_buf_len);
    if (p_root->p_buf == NULL) {
        printf("calloc err!\n");
        exit(1);
    }

    rlen = fread(p_root->p_buf, 1, root_buf_len, fp);
    if (rlen != root_buf_len) {
        return -2;
    }

    return 0;
}

static int system_cmd(char *cmd ,char *ret, int ret_size)
{
    FILE *fd = popen(cmd, "r");
    if (fd == NULL) {
        return -1;
    }

    fgets(ret, ret_size, fd);
    pclose(fd);

    // avoid buf overrun, and cut '\n'
    int len = 0;
    len = strlen(ret);
    if (ret[len-1] == '\n') {
        ret[len-1] = '\0';
    }

    return 0;
}

/**
 * draw the bin header and restore the original bin in-place
 * truncate the tail at last.
 */
static void unpack_bin(tlv_node_st *p_root)
{
    FILE *packedbin_fp = NULL;

    packedbin_fp = fopen(g_packed_bin_name, "r+");
    if (packedbin_fp == NULL) {
        printf("fopen err\n");
        exit(1);
    }

    if (tlv_get_root_node(packedbin_fp, p_root, MAX_HEAD_LEN) < 0) {
        fclose(packedbin_fp);
        exit(1);
    }

    // dump original bin
    size_t wlen = 0;
    size_t rlen = 0;
    char restore_buf[SWAP_LEN] = "";

    // copy from current position (packedbin_fp) to the bin beginning
    // for saving ram consuming (nearly 14M)
    long org_offset;
    long restore_offset;

    org_offset = ftell(packedbin_fp);
    restore_offset = 0;

    while ((rlen = fread(restore_buf, 1, SWAP_LEN, packedbin_fp)) > 0) {

        // update original bin offset
        org_offset += rlen;

        // move the file position indicator to dump position
        if (fseek(packedbin_fp, restore_offset, SEEK_SET) < 0) {
            perror("fseek restore_offset");
            fclose(packedbin_fp);
            exit(1);
        }

        // be careful: don't dirty the original bin content
        wlen = fwrite(restore_buf, 1, rlen, packedbin_fp);
        if (wlen != rlen) {
            perror("fwrite\n");
            fclose(packedbin_fp);
            exit(1);
        }

        memset(restore_buf, 0, sizeof(restore_buf));

        // update dump offset
        restore_offset += wlen;

        // move the position indicator to previous bin position
        if (fseek(packedbin_fp, org_offset, SEEK_SET) < 0) {
            perror("fseek org_offset");
            fclose(packedbin_fp);
            exit(1);
        }
    }
    fclose(packedbin_fp);

    // truncate the file
    if (truncate(g_packed_bin_name, (off_t)restore_offset) < 0) {
        perror("truncate");
        exit(1);
    }
}

static int check_md5(tlv_node_st *p_node)
{
    if (p_node == NULL) {
        return -1;
    }

    char cmd[BUF_LEN] = "";
    char md5_buf[BUF_LEN] = "";

    sprintf(cmd, "md5sum %s | cut -d ' ' -f 1", g_packed_bin_name);
    if (system_cmd(cmd, md5_buf, BUF_LEN) < 0) {
        printf("popen err\n");
        exit(1);
    }

#ifdef DEBUG
    printf("md5_buf = %s\n", get_node_buf_val(p_node));
    printf("dump md5 = %s\n", md5_buf);
#endif

    int ret = 0;
    ret = memcmp(get_node_buf_val(p_node), md5_buf, get_node_buf_len(p_node));
    if (ret != 0) {
        printf("md5 invalid!\n");
        _log(LOG_ERR, "%s md5 invalid", LOG_PREFIX);
        return -1;
    }

    return 0;
}

static int check_version(tlv_node_st *p_node)
{
    if (p_node == NULL) {
        return -1;
    }

    char cmd[BUF_LEN] = "";
    char ver_buf[BUF_LEN] = "";

    sprintf(cmd, "head -n 1 %s", VERSION_FNAME);
    if (system_cmd(cmd, ver_buf, BUF_LEN) < 0) {
        printf("popen err\n");
        exit(1);
    }

#ifdef DEBUG
    printf("ver_buf = %s\n", get_node_buf_val(p_node));
    printf("version file = %s\n", ver_buf);
#endif

    return 0;
}

static int check_devinfo(tlv_node_st *p_node)
{
    if (p_node == NULL) {
        return -1;
    }

    char cmd[BUF_LEN] = "";
    char devinfo_buf[BUF_LEN] = "";

    sprintf(cmd, "head -n 1 %s", DEVINFO_FNAME);
    if (system_cmd(cmd, devinfo_buf, BUF_LEN) < 0) {
        printf("popen err\n");
        exit(1);
    }

#ifdef DEBUG
    printf("devinfo_buf = %s\n", get_node_buf_val(p_node));
    printf("devinfo file = %s\n", devinfo_buf);
#endif

    int ret = 0;
    ret = memcmp(get_node_buf_val(p_node), devinfo_buf, get_node_buf_len(p_node));
    if (ret != 0) {
        printf("device info invalid!\n");
        _log(LOG_ERR, "%s device info invalid", LOG_PREFIX);
        return -1;
    }

    return 0;
}

static int check_bin_header(tlv_node_st *p_root)
{
    tlv_node_st *p_node_now;
    uint32_t offset = 0;
    uint32_t next_node_len = 0;
    uint32_t root_buf_len = ntohl(p_root->len);
    int ret = 0;

    p_node_now = (tlv_node_st *)((char *)(p_root->p_buf));

    while (p_node_now != NULL) {

        switch (get_node_type(p_node_now))
        {
        case TYPE_CNT_MD5:
            ret = check_md5(p_node_now);
            break;

        case TYPE_CNT_VERSION:
            ret = check_version(p_node_now);
            break;

        case TYPE_CNT_DEVINFO:
            ret = check_devinfo(p_node_now);
            break;

        default:
            printf("node type err\n");
            return -1;
        }

        if (ret < 0) {
            return -1;
        }

        p_node_now->len = *(uint32_t *)(((char *)p_node_now) + NODE_TYPE_SIZE);
        next_node_len = ntohl(p_node_now->len);

        offset += NODE_TYPE_SIZE + NODE_LEN_SIZE + next_node_len;

        if (offset >= root_buf_len) {
            p_node_now = NULL;
        }
        else {
            p_node_now = tlv_get_next_node(p_node_now);
        }
    }

    return 0;
}

static void do_upgrade()
{
    char cmd[BUF_LEN] = "";

    // restore leds as default
    sprintf(cmd, "%s", "ubus call ledctrl restore");
    system(cmd);

    // write reset reason
    sprintf(cmd, "%s", "/usr/sbin/reset_reason add 05");
    system(cmd);

    // red, blue led blink
    sprintf(cmd, "%s", "ubus call ledctrl blink '{\"leds\":\"RB\"}' > /dev/null");
    system(cmd);

	system("ifconfig wifi0 down");
	system("ifconfig wifi1 down");

	/* wait for wifi down */
    sleep(2);

    // do sysupgrade
    sprintf(cmd, "sysupgrade %s", g_packed_bin_name);
    system(cmd);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
		printf("Usage: %s [packed-upgrade-bin]\n", argv[0]);
		return -1;
	}

    if (access(argv[1], F_OK) < 0) {
        printf("%s not exist.\n", argv[1]);
        return -1;
    }

    sprintf(g_packed_bin_name, "%s", argv[1]);

    if (access(VERSION_FNAME, F_OK) < 0) {
        printf("%s not exist.\n", VERSION_FNAME);
        return -1;
    }

    if (access(DEVINFO_FNAME, F_OK) < 0) {
        printf("%s not exist.\n", DEVINFO_FNAME);
        return -1;
    }

    tlv_node_st root_node;
    unpack_bin(&root_node);

    if (check_bin_header(&root_node) < 0) {
        printf("upgrade bin invalid!\n");
        exit(1);
    }

    do_upgrade();

    return 0;
}
