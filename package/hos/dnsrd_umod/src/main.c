/******************************************************************************
  File Name    : main.c
  Author       : lhc
  Date         : 20160302
  Description  : dnsrd main fun
******************************************************************************/
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>
#include <netinet/in.h>

#include "dnsrd_parse.h"
#include "dnsrd_debug.h"

#define NETLINK_DNSRD 23
#define DNSRD_APURLLEN 128
#define DNSRD_SHOWCFGURL "showurlinfo"

unsigned char dnsrd_debug_level = 3;

/******************************************************************************
  Function Name    : replace_domain
  Author           : lhc
  Date             : 20160302
  Description      : replace domain
  Param            : char *output_url            output url
                     char *input_url             input url
  return Code      : ret = 0   success 
                     ret != 0  fail
******************************************************************************/
static int replace_domain(char *buf_output, char *buf_input)
{
    char *token = NULL;
    int buf_len = 0;
    int tmp_len = 0;
    int tmp_flag = 0;

    /* rm \n */
    buf_len = strlen(buf_input);
    if ('\n' == buf_input[buf_len - 1])
    {
        buf_input[buf_len - 1] = 0;
    }

    /* replace domain */
    token = strtok(buf_input, ".");
    if (NULL == token)
    {
        dnsrd_debug_waring("[DNSRD]: replace url info fail");
        return -1;
    }
    
    while (NULL != token)
    {
        tmp_len = strlen(token);
        buf_output[tmp_flag] = (char)tmp_len;
        tmp_flag++;
        memcpy(buf_output + tmp_flag, token, tmp_len);
        tmp_flag += tmp_len;
        
        token = strtok(NULL, ".");
    }
    
    return 0;
}

/******************************************************************************
  Function Name    : dnsrd_cfg_load
  Author           : lhc
  Date             : 20160302
  Description      : load url from system
  Param            : char *ap_mgmt_url            url buf
  return Code      : ret = 0   success
                     ret != 0  fail
******************************************************************************/
static int dnsrd_cfg_load(char *ap_mgmt_url)
{
    FILE *url_file;
    int ret = -1;
    char tmp_url[DNSRD_APURLLEN];
    
    memset(tmp_url, 0, DNSRD_APURLLEN);

    /* open pipe */
    url_file = popen(DNSRD_SHOWCFGURL, "r");
    if (NULL == url_file) 
    {
        dnsrd_debug_waring("[DNSRD]: show url info fail");
        return -1;
    }

    /* get url */
    if (NULL == fgets(tmp_url, DNSRD_APURLLEN, url_file)) 
    {
        dnsrd_debug_waring("[DNSRD]: load url info fail");
        pclose(url_file);
        return -1;
    }

    /* replace url */
    ret = replace_domain(ap_mgmt_url, tmp_url);
    if (0 == ret)
    {
        dnsrd_debug_waring("[DNSRD]: load url info success \n");
    }

    /* close pipe */
    pclose(url_file);

    return ret;
}

/******************************************************************************
  Function Name    : main
  Author           : lhc
  Date             : 20160302
  Description      : dnsrd main fun
  Param            :
  return Code      :
******************************************************************************/
int main(int argc, char **argv)
{
    int  netlink_sock = -1;
    int  ret = -1;
    char ap_mgmt_url[DNSRD_APURLLEN];
    struct sockaddr_nl src_addr;
    
    /* load dnsrd cfg */
    memset(ap_mgmt_url, 0, DNSRD_APURLLEN); 
    ret = dnsrd_cfg_load(ap_mgmt_url);
    if (0 != ret)
    {
        dnsrd_debug_error("[DNSRD]: load cfg failed");
        return -1;
    }
    
    /* creat socket */
    netlink_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_DNSRD);
	if (netlink_sock < 0)
	{
	    dnsrd_debug_error("[DNSRD]: creat netlink socket failed");
        return -1;
	}

	/* bind */
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
    src_addr.nl_groups = 0;
    ret = bind(netlink_sock, (struct sockaddr*)&src_addr, sizeof(src_addr));
	if (ret < 0) 
	{
        dnsrd_debug_error("[DNSRD]: bind netlink failed");
        close(netlink_sock);
        return -1;
	}

    /* send cfg to KDRM */
    ret = Dnsrd_sendmsg_to_kernel(netlink_sock, ap_mgmt_url, DNSRD_APURLLEN);
    if (ret < 0) 
	{
        dnsrd_debug_error("[DNSRD]: send cfg to dnsrd_kmod failed");
        close(netlink_sock);
        return -1;
	}
	
    /* process msg */
    while(1)
    {
        Dnsrd_recvmsg_form_kernel(netlink_sock);
    }

    close(netlink_sock);
    
    return 0;
}
