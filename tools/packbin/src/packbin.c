#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "tlv_node.h"

//#define DEBUG

#define BUF_LEN         256
#define MAX_NODES_NUM   10
#define MAIN_VER_FILE   "package/hos/base-files/base-files-AP152_AFI/base-files-AFI_A1/etc/version/version"
#define BUILD_NO_FILE   "package/hos/base-files/base-files-AP152_AFI/base-files-AFI_A1/etc/version/buildno"

char g_bin_name[BUF_LEN];
char g_outbin_name[BUF_LEN];
char g_version_name[BUF_LEN];
char g_buildno_name[BUF_LEN];
char g_devinfo[BUF_LEN];

char * g_nodes_handler[MAX_NODES_NUM] = { NULL };

static int tlv_add_node_buf_handler(tlv_node_st *p_node)
{
    if (p_node == NULL) {
        return -1;
    }

    int nodes_cnt = 0;

    for (nodes_cnt = 0; nodes_cnt < MAX_NODES_NUM; nodes_cnt++) {
        if (g_nodes_handler[nodes_cnt] == NULL) {
            g_nodes_handler[nodes_cnt] = p_node->p_buf;
            break;
        }
    }

    if (nodes_cnt == MAX_NODES_NUM) {
        return -1;
    }

    return 0;
}

static void tlv_free_all_nodes_buf_handler()
{
    int nodes_cnt = 0;

    for (nodes_cnt = 0; nodes_cnt < MAX_NODES_NUM; nodes_cnt++) {
        if (g_nodes_handler[nodes_cnt] != NULL) {
            free(g_nodes_handler[nodes_cnt]);
            g_nodes_handler[nodes_cnt] = NULL;
        }
    }
}

/**
 * make sure the str is tailed with '\0'
 * this api is used only for normal node
 */
static int tlv_put_string_item(unsigned char type, const char *str, tlv_node_st *p_node_out)
{
    uint32_t len = (uint32_t) strlen(str);
    tlv_node_st *p = p_node_out;
    char tmp_buf[BUF_LEN] = "";

    memcpy(tmp_buf, str, len);
    if (tmp_buf[len-1] == '\n') {
        tmp_buf[len-1] = '\0';
    }

    p->type = type;

    int clen = strlen(tmp_buf);
    p->p_buf = (char *) calloc(1, clen+1);
    memcpy(p->p_buf, tmp_buf, clen+1);
    p->len = clen+1;

    if (tlv_add_node_buf_handler(p) < 0) {
        printf("Max nodes now!\n");
        free(p->p_buf);
        exit(1);
    }

    return p->len + sizeof(p->len) + 1;
}

static void tlv_put_node_to_root_buf(tlv_node_st *p_root, uint32_t offset, tlv_node_st *p_node)
{
#ifdef DEBUG
    printf("== offset = %d, type = %d, len = %d, buf = %s\n",
           offset, p_node->type, p_node->len, p_node->p_buf);
#endif

    memcpy(p_root->p_buf+offset, &p_node->type, NODE_TYPE_SIZE);

    uint32_t node_len = htonl(p_node->len);
    memcpy(p_root->p_buf+offset+NODE_TYPE_SIZE, &node_len, NODE_LEN_SIZE);

    memcpy(p_root->p_buf+offset+NODE_TYPE_SIZE+NODE_LEN_SIZE,
           p_node->p_buf, p_node->len);
}

static int system_cmd(char *cmd , char *ret, int ret_size)
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
    if (len > 0 && ret[len-1] == '\n') {
        ret[len-1] = '\0';
    }

    return 0;
}

static int add_md5_node(tlv_node_st *p_node_out)
{
    char cmd[BUF_LEN] = "";
    char md5_buf[BUF_LEN] = "";

    // compute md5
    sprintf(cmd, "md5sum %s | cut -d ' ' -f 1", g_bin_name);
    if (system_cmd(cmd, md5_buf, BUF_LEN) < 0) {
        printf("popen err\n");
        exit(1);
    }

    return tlv_put_string_item(TYPE_CNT_MD5, md5_buf, p_node_out);
}

/**
 * full version format is `main-ver.buildno'
 */
static int add_version_node(tlv_node_st *p_node_out)
{
    char cmd[BUF_LEN];
    char ver_buf[BUF_LEN];
    char buildno_buf[BUF_LEN];
    char full_ver_buf[BUF_LEN];

    memset(ver_buf, 0, sizeof(ver_buf));
    sprintf(cmd, "head -n 1 %s", g_version_name);
    if (system_cmd(cmd, ver_buf, BUF_LEN) < 0) {
        printf("popen err\n");
        exit(1);
    }

    memset(buildno_buf, 0, sizeof(buildno_buf));
    sprintf(cmd, "head -n 1 %s", g_buildno_name);
    if (system_cmd(cmd, buildno_buf, BUF_LEN) < 0) {
        printf("popen err\n");
        exit(1);
    }

    memset(full_ver_buf, 0, sizeof(full_ver_buf));
    if (strlen(buildno_buf) > 0) {
        snprintf(full_ver_buf, BUF_LEN, "%s.%s", ver_buf, buildno_buf);
    } else {
        snprintf(full_ver_buf, BUF_LEN, "%s", ver_buf);
    }

    return tlv_put_string_item(TYPE_CNT_VERSION, full_ver_buf, p_node_out);
}

static int add_devinfo_node(tlv_node_st *p_node_out)
{
    return tlv_put_string_item(TYPE_CNT_DEVINFO, g_devinfo, p_node_out);
}

static void generate_bin_header(tlv_node_st *p_node_out)
{
    tlv_node_st * p_root = p_node_out;
    int offset = 0;

    tlv_node_st md5_node;
    int md5_node_total_len = add_md5_node(&md5_node);
    offset += md5_node_total_len;

    tlv_node_st ver_node;
    int ver_node_total_len = add_version_node(&ver_node);
    offset += ver_node_total_len;

    tlv_node_st devinfo_node;
    int devinfo_node_total_len = add_devinfo_node(&devinfo_node);
    offset += devinfo_node_total_len;

    p_root->type = TYPE_ROOT_HEAD;
    p_root->len = htonl(offset);
    p_root->p_buf = (char *)calloc(1, offset);

#ifdef DEBUG
    printf("root type = %d, root len = %d, offset = %d\n", p_root->type, ntohl(p_root->len), offset);
#endif

        // add notes to root buffer
    tlv_put_node_to_root_buf(p_root, 0, &md5_node);
    offset = md5_node_total_len;
    tlv_put_node_to_root_buf(p_root, offset, &ver_node);
    offset += ver_node_total_len;
    tlv_put_node_to_root_buf(p_root, offset, &devinfo_node);
    offset += devinfo_node_total_len;

#ifdef DEBUG
    printf("total len = %d\n", offset);
#endif
    // free nodes memory
    tlv_free_all_nodes_buf_handler();
}

static void pack_bin_file()
{
    tlv_node_st root_node;

    generate_bin_header(&root_node);

    FILE *dump_fp = NULL;
    size_t wlen = 0;

    dump_fp = fopen(g_outbin_name, "wb");
    if (dump_fp == NULL) {
        printf("fopen err\n");
        exit(1);
    }

    // dump the header to out-file
    wlen = fwrite(&root_node.type, 1, sizeof(root_node.type), dump_fp);
    if (wlen != sizeof(root_node.type)) {
        printf("write header type err\n");
        fclose(dump_fp);
        exit(1);
    }

    int root_len_size = sizeof(root_node.len);
    wlen = fwrite(&root_node.len, 1, root_len_size, dump_fp);
    if (wlen != root_len_size) {
        printf("write header len err\n");
        fclose(dump_fp);
        exit(1);
    }

    int root_buf_len = ntohl(root_node.len);
    wlen = fwrite(root_node.p_buf, 1, root_buf_len, dump_fp);
    if (wlen != root_buf_len) {
        printf("write header buf err\n");
        fclose(dump_fp);
        exit(1);
    }

    // free header buf
    free(root_node.p_buf);

    // dump the xxx.bin to out-file
    char dumpbuf[256] = "";
    size_t rlen = 0;
    FILE *orgbin_fp = NULL;

    orgbin_fp = fopen(g_bin_name, "r");
    if (orgbin_fp == NULL) {
        printf("fopen err\n");
        fclose(dump_fp);
        exit(1);
    }

    while ((rlen = fread(dumpbuf, 1, 256, orgbin_fp)) > 0) {
        wlen = fwrite(dumpbuf, 1, rlen, dump_fp);
        if (wlen != rlen) {
            printf("dump original bin err\n");
            fclose(orgbin_fp);
            fclose(dump_fp);
            exit(1);
        }
        memset(dumpbuf, 0, sizeof(dumpbuf));
    }
    fclose(orgbin_fp);
    fclose(dump_fp);
}

/**
 * params:
 *    argv[1] - project root dir
 *    argv[2] - device info string
 *    argv[3] - original upgrade bin name
 *    argv[4] - packed upgrade bin name
 */
int main(int argc, char *argv[])
{
    if (argc != 5) {
		printf("Usage: %s [topdir] [dev-info]\n", argv[0]);
		return -1;
	}

    char root_dir[BUF_LEN];
    char org_bin_name[BUF_LEN];
    char out_bin_name[BUF_LEN];
    char dev_info_str[BUF_LEN];

    sprintf(root_dir, "%s", argv[1]);
    sprintf(dev_info_str, "%s", argv[2]);
    sprintf(org_bin_name, "%s", argv[3]);
    sprintf(out_bin_name, "%s", argv[4]);

    if (access(root_dir, F_OK) < 0) {
        printf("%s not exist.\n", argv[1]);
        return -1;
    }

    sprintf(g_bin_name, "%s/bin/ar71xx/%s", root_dir, org_bin_name);
    sprintf(g_outbin_name, "%s/bin/ar71xx/%s", root_dir, out_bin_name);

    sprintf(g_version_name, "%s/%s", root_dir, MAIN_VER_FILE);
    if (access(g_version_name, F_OK) < 0) {
        printf("%s not exist.\n", g_version_name);
        return -1;
    }

    sprintf(g_buildno_name, "%s/%s", root_dir, BUILD_NO_FILE);
    if (access(g_buildno_name, F_OK) < 0) {
        printf("%s not exist.\n", g_buildno_name);
        return -1;
    }

    sprintf(g_devinfo, "%s", dev_info_str);

    pack_bin_file();

    return 0;
}
