#include <sys/types.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/un.h>

#include <linux/rtnetlink.h>

#include <sys/stat.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <libubox/blobmsg_json.h>
#include "libubus.h"
#include <syslog.h>


#include "igmpsnp_com.h"





#ifndef ULONG
#define ULONG unsigned long
#endif

#ifndef LONG
#define LONG long 
#endif

#ifndef USHORT
#define USHORT unsigned short
#endif

#ifndef UCHAR
#define UCHAR unsigned char
#endif

#ifndef CHAR
#define CHAR char
#endif

#ifndef  SHORT
#define SHORT short
#endif

#ifndef	UINT
#define	UINT	unsigned int
#endif

#ifndef	INT
#define INT		int
#endif

#ifndef	VOID
#define	VOID	void
#endif




#ifndef IPPROTO_IGMP
#define IPPROTO_IGMP 	2		/*IGMP protocol type*/
#endif


#define IGMP_REPORT_V1 0x12 /*V1 report*/
#define IGMP_REPORT_V2 0x16 /*V2 report*/
#define IGMP_LEAVE_V2  0x17 /*V2 leave*/
#define IGMP_REPORT_V3 0x22	/*V3 report*/
#define IGMP_REPORT_V3_JOIN 0x04	
#define IGMP_REPORT_V3_LEAVE 0x03
#define IPPROTO_IGMP_V1 1
#define IPPROTO_IGMP_V2 2 
#define IPPROTO_IGMP_V3 3
#define IPPROTO_IGMP_TIMEOUT 180   /*for igmp v1 */
#define IGMP_SNOOP_NO	0
#define IGMP_SNOOP_YES	1





/************************************config value*****************************************/

UINT igmp_snoop_debug = IGMP_SNOOP_NO;
USHORT igmp_hosttimerout_interval = IPPROTO_IGMP_TIMEOUT; 


/****************************thread value***********************************************/
pthread_t thread_recvskb;
pthread_t thread_msg;
pthread_t thread_recvevent;
pthread_t thread_timer;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;	/*Ïß³ÌËø*/


#define ADD_PORT 1
#define DEL_PORT 2

#define CMD_LEN 256
#define SYSMAC_ADDRESS_LEN 6



#define MUCAST_ALL 0x4f000001 // 244.0.0.1
#define MUCAST_LEVEL 0x4f000002 // 244.0.0.2 
#define IGMP_MASK 0x7fffff 



/************************get ifname list*************************************************/

#ifndef IFNAMSIZ
#define IFNAMSIZ    16
#endif
#define PATH_PROCNET_DEV    "/proc/net/dev"
#define PATH_MCGROUPLIST_FILE    "/tmp/mcgrouplist"


#define SUCCESS                           (1)
#define FAILURE                           !(SUCCESS)
#define MAX_DEV_NUM                       (2)             // As of now Dual radio, three radio in future

#define EXPECTED_MAX_VAPS       (30 * MAX_DEV_NUM)

#define err(fmt, args...) do {\
    printf("icm : %s %d " fmt "\n", __func__, __LINE__, ## args); \
    } while (0)


/* Structure to hold radio and VAP names read from /proc */
typedef struct
{
    UCHAR **ifnames;
    INT max_size;
    INT curr_size;
} sys_ifnames;

sys_ifnames vap_listing;
int vap_index[16];




typedef struct igmphdr{
	 UCHAR type;
	 UCHAR MaxResTime;
	 USHORT checksum;
	 UINT gaddr;
}igmp_head;

struct igmpv3_grec {
	UCHAR	grec_type;
	UCHAR	grec_auxwords;
	USHORT	grec_nsrcs;
	UINT	grec_mca;
};

struct igmpv3_report {   //only support one 
	UCHAR type;
	UCHAR resv1;
	USHORT csum;
	USHORT resv2;
	USHORT numofgrec;
	struct igmpv3_grec grec[0];
};




/********** multicast station state structure **********************************************/
typedef struct MC_sta_state
{
	struct MC_sta_state *next;	/*next port*/
	UCHAR sta_macaddr[SYSMAC_ADDRESS_LEN];			/*index*/
	USHORT	ver_flag;			/*IGMP version 1-v1, 2-v2,3-v3*/
	USHORT hosttimer_id;		/*IGMP V1 timer id*/
}MC_sta_state;
/************************** multicast group struct *************************************/
typedef struct MC_group
{
	struct MC_group	*next;
	UINT	MC_ipadd;			/*mc group ip*/	
	struct	MC_sta_state *stalist;	/*port state list*/
}MC_group;

typedef enum igmpstastate
{
	IGMP_GROUP_ADD,
	IGMP_GROUP_DEL,	
	IGMP_STA_ADD,
	IGMP_STA_DEL,
	
}igmpstastate;


#define NETLINK_GENERIC       16
#define NETLINK_DETECTOR_IGMP (NETLINK_GENERIC + 8)  /*igmp netlink id */
#define NETLINK_IGMP_ADD  3
#define NETLINK_IGMP_DEL  4

#define MODULE_ID_IGMPSNP 0x101 /* to be discussed */
#define MAX_MSG_PAYLOAD 128
int nlsock_to_igmpsnp = 0;
int nlsock_to_kernel = 0;


typedef struct 
{
	struct nlmsghdr nlh;
	char buf[MAX_MSG_PAYLOAD];
}igmpsnp_nlmsg;

igmpsnp_nlmsg config_parm_from_igmpsnp;



#define IGMP_SNP_TYPE_OPTION 0x00
#define IGMP_SNP_TYPE_GROUP_IP 0x01
#define IGMP_SNP_TYPE_STA_MAC 0x02

//tlv message define
#define TLV_MSG_TYPE_LEN 1
#define TLV_MSG_LENGTH_LEN 1

#pragma pack(push, 1)
struct IGMP_TLV {
	u_int8_t t_op;
	u_int8_t l_op;
	u_int8_t v_op;
	u_int8_t t_group_ip;
	u_int8_t l_group_ip;
	u_int32_t v_group_ip;
	u_int8_t t_sta_mac;
	u_int8_t l_sta_mac;
	u_int8_t v_sta_mac[6];
};

struct igmp_snp_list{
	u_int8_t member_num;
	struct IGMP_TLV tlv;
};
#pragma pack(pop)



MC_group	 *p_mcgrouplist = NULL;



/**************************************************************************

 * Function     : igmpsnp reload

 **************************************************************************/


int get_igmpv1_hostinterval()
{
    FILE *fp;
    char str_tmp_cmd[CMD_LEN];
    char szVal[CMD_LEN];
    memset( str_tmp_cmd, 0, CMD_LEN );
    memset(szVal, 0x00, sizeof(szVal));
    strcpy( str_tmp_cmd,  "/sbin/uci  get igmp.igmpsnp.hostlifeinterval");	

    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }

    return atoi(szVal);
}





static struct ubus_context *ctx;


int
	igmpsnp_ubus_handle_reload(
		struct ubus_context *ctx, 
		struct ubus_object *obj,
		struct ubus_request_data *req, 
		const char *method,
		struct blob_attr *msg
	)
	{
	    igmp_hosttimerout_interval = get_igmpv1_hostinterval();			
		return 0;
	}


static const struct ubus_method igmpsnp_methods[] = {
	{ .name = "reload", .handler = igmpsnp_ubus_handle_reload },

		
};

static struct ubus_object_type igmpsnp_object_type = 
	UBUS_OBJECT_TYPE("create", igmpsnp_methods);


static struct ubus_object igmpsnp_object = {
	.name = "igmpsnp",
	.type = &igmpsnp_object_type,
	.methods = igmpsnp_methods,
	.n_methods = ARRAY_SIZE(igmpsnp_methods),
};


int 
igmpsnp_ubus_init(char *path)
{
	int err;
	int ret;

    uloop_init();
	
	ctx = ubus_connect(path);
	if (!ctx) {
		igmp_snp_syslog_err( "Failed to connect to ubus\n");
		return -1;
	}

	ubus_add_uloop(ctx);
	
	ret = ubus_add_object(ctx, &igmpsnp_object);
	if (ret)
		igmp_snp_syslog_warn( "Failed to add object: %s\n", ubus_strerror(ret));

    
	return 0;
}

void
igmpsnp_ubus_fini(void)
{
    if (ctx) {
	    ubus_free(ctx);
	    uloop_done();
	}
    
	igmp_debug_log("[igmpsnp]:ubus fini");

    return;
}

/**************************************************************************

 * Function     : icm_is_dev_ifname_valid
 * Description  : find if the argument string stands for a valid
 *                device name
 * Input params : string
 * Return       : 1: valid, 0: invalid
 **************************************************************************/


int icm_is_dev_ifname_valid(const char *ifname)
{
    int i;
    int basename_len = 0;

    if (ifname == NULL) {
        return 0;
    }

    /* We assume ifname has atleast IFNAMSIZ characters,
       as is the convention for Linux interface names. */

    if (strncmp(ifname, "ath", 3) == 0) {
        basename_len = 3;
    } else if (strncmp(ifname, "wlan", 4) == 0) {
        basename_len = 4;
    } else {
        return 0;
    }

    if (!ifname[basename_len] || !isdigit(ifname[basename_len])) {
        return 0;
    }

    /* We don't make any assumptions on max no. of VAP interfaces,
       at this step. */
    for (i = basename_len + 1; i < IFNAMSIZ; i++)
    {
        if (!ifname[i]) {
            break;
        }

        if (!isdigit(ifname[i])) {
            return 0;
        }
    }

    return 1;
}


/**************************************************************************

 * Function     : icm_sys_ifnames_extend
 * Description  : extend sys_ifnames structure
 * Input params : pointer to sys_ifnames structure, additional max size
 * Return       : 0 on success, standard negative error code on failure
 
  **************************************************************************/
static int icm_sys_ifnames_extend(sys_ifnames *ifs, int additional_size)
{
    int i;
    char **tempptr;

    if (ifs == NULL) {
        return -EINVAL;
    }

    tempptr = (char**)realloc(ifs->ifnames,
                              (ifs->max_size + additional_size) * sizeof(char *));

    if(!tempptr) {
        /* Original block untouched */
        /* The caller must call icm_sys_ifnames_deinit() */
        return -1;
    }

    ifs->ifnames = tempptr;

    for (i = ifs->max_size; i < (ifs->max_size + additional_size); i++) {
        ifs->ifnames[i] = (char*)malloc(IFNAMSIZ * sizeof(char));

        if (!(ifs->ifnames[i])) {
            /* The caller must call icm_sys_ifnames_deinit() */
            return -1;
        }
        ifs->max_size += 1;
    }

    return 0;
}

/**************************************************************************

 * Function     : icm_sys_ifnames_add
 * Description  : add an interface name to sys_ifnames structure
 * Input params : pointer to sys_ifnames structure, interface name
 * Return       : 0 on success, standard negative error code on failure
 
 **************************************************************************/

static int icm_sys_ifnames_add(sys_ifnames *ifs, char *ifname)
{
   int tempidx = 0;

   if (ifs->curr_size == ifs->max_size) {
        // Full
        return -1;
   }

   tempidx = ifs->curr_size;
   strncpy(ifs->ifnames[tempidx], ifname, IFNAMSIZ);
   ifs->curr_size++;

   return 0;
}


/**************************************************************************

 * Function     : icm_sys_ifnames_init
 * Description  : initialize sys_ifnames structure
 * Input params : pointer to sys_ifnames structure, base max size
 * Return       : 0 on success, standard negative error code on failure
 **************************************************************************/

static int icm_sys_ifnames_init(sys_ifnames *ifs, int base_max_size)
{
    int i;

    if (ifs == NULL) {
        return -EINVAL;
    }

    ifs->ifnames = (char**)malloc(base_max_size * sizeof(char*));
    if(!(ifs->ifnames)) {
        return -ENOMEM;
    }

    ifs->curr_size = 0;
    ifs->max_size = 0;

    for (i = 0; i < base_max_size; i++) {
        ifs->ifnames[i] = (char*)malloc(IFNAMSIZ * sizeof(char));
        if (!(ifs->ifnames[i])) {
            /* The caller must call icm_sys_ifnames_deinit() */
            return -1;
        }
        ifs->max_size += 1;
    }

    return 0;
}


/**************************************************************************

 * Function     : icm_build_vap_listing
 * Description  : build VAP listing for current system, into sys_ifnames structure
 * Input params : pointer to sys_ifnames structure
 * Return       : success/failure
  **************************************************************************/
static int icm_build_vap_listing(sys_ifnames *vap_listing)
{
    FILE *fp;
    int i = 0, j = 0;
    char buf[512];
    char temp_name[IFNAMSIZ];
    int ret;
    int status = FAILURE;

    fp = fopen(PATH_PROCNET_DEV, "r");

    if (NULL == fp) {
        igmp_snp_syslog_err("icm : " PATH_PROCNET_DEV);
        return FAILURE;
    }

    /* Skip unwanted lines */
    fgets(buf, sizeof(buf), fp);
    fgets(buf, sizeof(buf), fp);

    while (fgets(buf, sizeof(buf), fp))
    {
        i = 0;
        j = 0;

        while (j < (IFNAMSIZ - 1) && buf[i] != ':') {
            if (isalnum(buf[i])) {
                temp_name[j] = buf[i];
                j++;
            }
            i++;
        }
        temp_name[j] = '\0';

        if (icm_is_dev_ifname_valid(temp_name)) {
            ret = icm_sys_ifnames_add(vap_listing, temp_name);

            if (ret < 0) {
                ret = icm_sys_ifnames_extend(vap_listing, 10);

                if (ret < 0)
                {
                    igmp_snp_syslog_warn("Could not extend ifnames allocation");
                    goto bad;
                }

                ret = icm_sys_ifnames_add(vap_listing, temp_name);

                if (ret < 0)
                {
                    igmp_snp_syslog_warn("Could not add to ifnames");
                    goto bad;
                }
            }
        }
    }

    status = SUCCESS;

bad:
    fclose(fp);
    return status;
}        



/**************************************************************************

 * Function     : icm_sys_ifnames_deinit
 * Description  : de-initialize sys_ifnames structure
 * Input params : pointer to sys_ifnames structure
 **************************************************************************/
static void icm_sys_ifnames_deinit(sys_ifnames *ifs)
{
    int i;

    if (ifs == NULL) {
        return;
    }

    if (!ifs->ifnames) {
        return;
    }

    for (i = 0; i < ifs->max_size; i++) {
        free(ifs->ifnames[i]);
    }

    free(ifs->ifnames);
    ifs->ifnames = NULL;
    ifs->max_size = 0;
    ifs->curr_size = 0;
}



INT init_igmp_snp_vaplist(void)
{
	int status = FAILURE;
	int i ;

	if (icm_sys_ifnames_init(&vap_listing, EXPECTED_MAX_VAPS) < 0) {
        igmp_snp_syslog_warn("Could not initialize VAP listing");
        return FAILURE;
    }

    if (icm_build_vap_listing(&vap_listing) != SUCCESS) {
        igmp_snp_syslog_warn("Could not create VAP listing");
        goto bad;
    }

	status = SUCCESS;
	
	bad:
    //icm_sys_ifnames_deinit(&vap_listing);
    return status;



}



/*
*****************************************************
* FuncName:nlsock_create_to_kernel
* Description:create netlink socket to kernel
*****************************************************
*/
int nlsock_create_to_kernel( UINT mc_ipaddr,UCHAR sta_macaddr[],USHORT option)
{

	igmp_debug_log( "nlsock_create_to_kernel\n");

	int nlsock_fd = 0;
	int creat_try = 0;
	struct sockaddr_nl src_addr, dest_addr;
	struct msghdr msg;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;

	struct igmp_snp_list list; 
	struct IGMP_TLV *tlv = &list.tlv;
  int i ;

	for (creat_try = 0; creat_try < 3; creat_try ++)
	{

		nlsock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_DETECTOR_IGMP);
		if (nlsock_fd < 0)
			continue;
		else
			break;
	}
	if (nlsock_fd < 0)
	{
		igmp_snp_syslog_err( "failed to create netlink socket to igmpsnp\n");
		
		return -1;
	}
	
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;
	dest_addr.nl_groups = 0;


	if(NULL== (nlh=(struct nlmsghdr*)malloc(NLMSG_SPACE(MAX_MSG_PAYLOAD)))){
		   igmp_snp_syslog_err("alloc mem failed!");
		   return 1;
	}


	nlh->nlmsg_len= NLMSG_SPACE(MAX_MSG_PAYLOAD);
	nlh->nlmsg_pid= 0x02;
	nlh->nlmsg_type= 0;
	nlh->nlmsg_flags= 0;
	


	
	memset(&list,0x0,sizeof(struct igmp_snp_list));

	list.member_num = 1;
	tlv->t_op = IGMP_SNP_TYPE_OPTION;
	tlv->l_op = sizeof(tlv->v_op);
	tlv->v_op = option;
	
	tlv->t_group_ip = IGMP_SNP_TYPE_GROUP_IP;
	tlv->l_group_ip = sizeof(tlv->v_group_ip);
	tlv->v_group_ip = mc_ipaddr;
	
	tlv->t_sta_mac = IGMP_SNP_TYPE_STA_MAC;
	tlv->l_sta_mac = 6;
	memcpy(tlv->v_sta_mac,sta_macaddr,6);






    memcpy(NLMSG_DATA(nlh), &list,sizeof(struct igmp_snp_list));
	
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

#if 0
	igmp_debug_log("user message:\n");
	for(i = 0; i < nlh->nlmsg_len; i ++){
	  if(i && i%20 ==0) igmp_snp_syslog_dbg("\n");
	  igmp_snp_syslog_dbg("%02x ", ((unsigned char*)nlh)[i]);
   }	
	igmp_snp_syslog_dbg("\n");
#endif

	sendmsg(nlsock_fd, &msg, 0);

	
    close(nlsock_fd);
	free(nlh);

}


/**************************************************************************
* igmp_snp_searchsta()
*
* DESCRIPTION:
*		This function finds a station in groupp-sta list. when sta offline delete the station from all mc group
*
* INPUTS:		
*		 UINT    - MC group ip address
*		 char[]  - Station mac address
*		 operate - station operate
*
* OUTPUTS:
*		 NONE
*						  
* RETURN VALUE:
*		IGMPSNP_RETURN_CODE_OK -  on sucess
*
*		
**************************************************************************/
LONG igmp_snp_deletesta( UCHAR sta_macaddr[])


{
	MC_group *loopupput = NULL;
	
	MC_sta_state *pprevSta = NULL;
	MC_sta_state *lstaput =NULL;
		
	INT del_flg = 0;
	INT ret = IGMPSNP_RETURN_CODE_OK;

	
	loopupput = p_mcgrouplist;
	
	while (NULL != loopupput)
	{

		
		lstaput =loopupput->stalist;
			
		while (NULL != lstaput)
		{
		
			if (memcmp (lstaput->sta_macaddr,sta_macaddr,SYSMAC_ADDRESS_LEN ) == 0 )
			{
				
				break;
			}

			pprevSta = lstaput;
			lstaput = lstaput->next;			
			
		}
		if(NULL != lstaput)
		{

			if (lstaput == loopupput->stalist)
			{
				loopupput->stalist = lstaput->next;	
			}
			else
			{
				pprevSta->next = lstaput->next;
			}

			free(lstaput);
			lstaput = NULL;
					

		}

		
		loopupput = loopupput->next;
	}

	//create_mcgrouplist_file();

	return IGMPSNP_RETURN_CODE_OK;

}


/**************************************************************************
* igmp_snp_searchgroup()
*
* DESCRIPTION:
*		This function finds a station in groupp-sta list.
*
* INPUTS:		
*		 UINT    - MC group ip address
*		 char[]  - Station mac address
*		 operate - station operate
*
* OUTPUTS:
*		 NONE
*						  
* RETURN VALUE:
*		IGMPSNP_RETURN_CODE_OK -  on sucess
*
*		
**************************************************************************/
INT igmp_snp_searchgroup( UINT mc_ipaddr,UCHAR sta_macaddr[],USHORT	ver_flag,igmpstastate operate)


{
	MC_group *pTemp = NULL;
	MC_group *pPrev = NULL;
	MC_group *pnewgroup = NULL;
	MC_group *loopupput = NULL;
	
	MC_sta_state *pSta = NULL;
	MC_sta_state *pprevSta = NULL;
	MC_sta_state *pnewsta = NULL;
	MC_sta_state *lstaput =NULL;
	MC_sta_state *pHost = NULL;
		
	INT del_flg = 0;
	INT ret = IGMPSNP_RETURN_CODE_OK;

	INT num = 0;


	igmp_snp_syslog_dbg("%s :igmp_snp_searchgroup: pgroup->MC_ipadd: %x\n ,sta_macaddr:%02x,%02x,%02x,%02x,%02x,%02x,operate :%d \n",__FUNCTION__, mc_ipaddr,sta_macaddr[0],sta_macaddr[1],sta_macaddr[2],sta_macaddr[3],sta_macaddr[4],sta_macaddr[5],operate);


	loopupput = p_mcgrouplist;

	igmp_debug_log("===============================================\n");

	igmp_debug_log("%-20s%-20s\n","mc group","station addr");
	
	while (NULL != loopupput)
	{
		
		lstaput =loopupput->stalist;
			
		while (NULL != lstaput)
		{
				num ++ ;
				if(num == 1 )
				{
					igmp_debug_log("%-20x   %02x:%02x:%02x:%02x:%02x:%02x\n", loopupput->MC_ipadd,lstaput->sta_macaddr[0],lstaput->sta_macaddr[1],lstaput->sta_macaddr[2],lstaput->sta_macaddr[3],lstaput->sta_macaddr[4],lstaput->sta_macaddr[5]);	
					

				}
				else
				{
					igmp_debug_log("%-20s   %02x:%02x:%02x:%02x:%02x:%02x\n", "",lstaput->sta_macaddr[0],lstaput->sta_macaddr[1],lstaput->sta_macaddr[2],lstaput->sta_macaddr[3],lstaput->sta_macaddr[4],lstaput->sta_macaddr[5]);
					

				}
			
			lstaput = lstaput->next;
			
		}
		loopupput = loopupput->next;
		num = 0 ;
	}
	igmp_debug_log("===============================================\n");



	
	pTemp = p_mcgrouplist;

	pPrev = pTemp;
	
	while (NULL != pTemp)
	{

		
		if (pTemp->MC_ipadd == mc_ipaddr)
		{

			break;
		}
		pPrev = pTemp;				/*NOT pPrev->next = pTemp;*/
		pTemp = pTemp->next;
	}		
	


	if (NULL != pTemp)             /* Found the group */
	{
		igmp_debug_log("%s :find mc group: addr= %x.\n",__FUNCTION__, pTemp->MC_ipadd);
		
		if (IGMP_GROUP_DEL == operate)
		{


			 pSta = pTemp->stalist;
			 
			 while (NULL != pSta)
			 {
				 if (memcmp (pSta->sta_macaddr,sta_macaddr,SYSMAC_ADDRESS_LEN) == 0 )
				 {
					 break;
				 }
				pprevSta = pSta;
				pSta = pSta->next;	
				
			 }
			 if (NULL != pSta) 
			 {

					
					if (pSta == pTemp->stalist)
					{
						pTemp->stalist = pSta->next;	
					}
					else
					{
						pprevSta->next = pSta->next;
					}

					free(pSta);
					pSta = NULL;

					#if 0  // if none delete the group
					if ( NULL == pTemp->stalist)  
					{
						 if(pTemp == p_mcgrouplist)
						 {
						 	p_mcgrouplist = pTemp->next;
						 }
						 else
						 {
						 	pPrev->next =  pTemp->next;
						 }

						 free(pTemp);
						 pTemp = NULL;
					}
					#endif
					
					igmp_debug_log("%s :delete sta ok from  p_mcgrouplist success.\n",__FUNCTION__);
					return IGMPSNP_RETURN_CODE_OK;
					
			 }
			 else
			 {
			 		
					igmp_debug_log("%s :Not found sta .\n",__FUNCTION__);
					return IGMPSNP_RETURN_CODE_ERROR;

			 }


		}

		else if (IGMP_GROUP_ADD == operate)
		{

			
			 pSta = pTemp->stalist;
			 
			 while (NULL != pSta)
			 {

				
				igmp_debug_log("pSta->sta_macaddr:%02x,%02x,%02x,%02x,%02x,%02x ,%d \n",pSta->sta_macaddr[0],pSta->sta_macaddr[1],pSta->sta_macaddr[2],pSta->sta_macaddr[3],pSta->sta_macaddr[4],pSta->sta_macaddr[5],strlen(pSta->sta_macaddr));
				igmp_debug_log("sta_macaddr:%02x,%02x,%02x,%02x,%02x,%02x\n,%d \n ",sta_macaddr[0],sta_macaddr[1],sta_macaddr[2],sta_macaddr[3],sta_macaddr[4],sta_macaddr[5],strlen(sta_macaddr));

				 if (memcmp (pSta->sta_macaddr ,sta_macaddr,SYSMAC_ADDRESS_LEN) == 0)
				 {
				 
					 break;
				 }
				 
				pSta = pSta->next;	
				
			 }
			 if (NULL != pSta) 
			 {
			 		 if(IPPROTO_IGMP_V1 == ver_flag )
					 {
							 pSta->hosttimer_id = igmp_hosttimerout_interval;
					 }

					igmp_debug_log("%s :found the station success.\n",__FUNCTION__);
		
			 }
			 else
			 {
			 		igmp_debug_log("%s :creat the station .\n",__FUNCTION__);
					igmp_debug_log("%s :igmp_snp_searchgroup: sta_macaddr:%x,%x,%x,%x,%x,%x\n",__FUNCTION__, sta_macaddr[0],sta_macaddr[1],sta_macaddr[2],sta_macaddr[3],sta_macaddr[4],sta_macaddr[5]);				

					pnewsta= (MC_sta_state*)malloc(sizeof(MC_sta_state));
					if (NULL == pnewsta)
					{
						igmp_snp_syslog_err("alloc memory for routerport failed.\n");
						p_mcgrouplist = NULL;
						return IGMPSNP_RETURN_CODE_NULL_PTR;
					}
					memset(pnewsta, 0, sizeof(MC_sta_state));
					memcpy(pnewsta->sta_macaddr,sta_macaddr,SYSMAC_ADDRESS_LEN);
					
					if(IPPROTO_IGMP_V1 == ver_flag )
					{
						pnewsta->hosttimer_id = igmp_hosttimerout_interval;
					}

					pnewsta->ver_flag = ver_flag;
					
					pnewsta->next = pTemp->stalist;
					pTemp->stalist = pnewsta;

			 }
			
					
		}

		return IGMPSNP_RETURN_CODE_OK;

	}

	/* If NOT FOUND the MC GROUP */
	igmp_debug_log("%s :Not found any mc-group %x in p_mcgrouplist.\n",__FUNCTION__, mc_ipaddr);
						
	switch (operate)
	{

		case IGMP_GROUP_ADD:
			{
				igmp_debug_log( "%s :create a new list element and add to node \n",__FUNCTION__);
				pnewgroup = (MC_group *)malloc(sizeof(MC_group));
				if (NULL == pnewgroup)
				{
					igmp_snp_syslog_err("alloc memory for mc group failed.\n");
					p_mcgrouplist = NULL;
					return IGMPSNP_RETURN_CODE_NULL_PTR;
				}
				memset(pnewgroup, 0, sizeof(MC_group));
				pnewgroup->MC_ipadd = mc_ipaddr;

				pnewgroup->stalist = (MC_sta_state *)malloc(sizeof(MC_sta_state));
				memcpy(pnewgroup->stalist->sta_macaddr , sta_macaddr,SYSMAC_ADDRESS_LEN);
				pnewgroup->stalist->ver_flag = ver_flag;
				
				if(IPPROTO_IGMP_V1 == ver_flag )
					pnewgroup->stalist->hosttimer_id = igmp_hosttimerout_interval;
				else
					pnewgroup->stalist->hosttimer_id = 0;
				
				pnewgroup->stalist->next = NULL;
				pnewgroup->next = p_mcgrouplist; /*p_mcgrouplist*/				
				p_mcgrouplist = pnewgroup;
				igmp_debug_log("%s :Add first mc-group: %x\n ,sta_macaddr:%x,%x,%x,%x,%x,%x,, sucess.\n",__FUNCTION__,mc_ipaddr,sta_macaddr[0],sta_macaddr[1],sta_macaddr[2],sta_macaddr[3],sta_macaddr[4],sta_macaddr[5]);
				
			}
		
			break;
		case IGMP_GROUP_DEL:
			igmp_debug_log("%s :not found  .\n",__FUNCTION__);
			return IGMPSNP_RETURN_CODE_ERROR;       /* not found */
		default :
			break;
	}
	return IGMPSNP_RETURN_CODE_OK;

}




 /**********************************************************************************
 * init_igmp_snp_timer()
 *
 * INPUTS:
 *		 cur - mc group timer
 * OUTPUTS:
 *		 null
 * RETURN VALUE:
 *		 null
 * DESCRIPTION:
 *		  mc group timeout handle
 ***********************************************************************************/
 VOID igmp_snp_global_timer_func( timer_element *cur )
 {

	 MC_group *loopupput = NULL;
	 MC_sta_state *lstaput =NULL;	 
	 INT del_flg = 0;
	 INT ret = IGMPSNP_RETURN_CODE_OK;
	 	 	 

	  
	 loopupput = p_mcgrouplist;
	 
	 while (NULL != loopupput )
	 {
	 

		 	lstaput =loopupput->stalist;
			 
			 while (NULL != lstaput)
			 {
			 
				  if (IPPROTO_IGMP_V1 == lstaput->ver_flag )
				  {


						 if( 0 != lstaput->hosttimer_id )
						 {
							 if( 1 == lstaput->hosttimer_id )
							 {
								 lstaput->hosttimer_id = 0;	 /*time expire, set state*/
								 
								 //igmp_snp_syslog_dbg("igmp_snp_global_timer_func: sta %x,%x,%x,%x,%x,%x the hosttimerid Timer out \n",lstaput->sta_macaddr[0],lstaput->sta_macaddr[1],lstaput->sta_macaddr[2],lstaput->sta_macaddr[3],lstaput->sta_macaddr[4],lstaput->sta_macaddr[5]);


								 igmp_snp_searchgroup(loopupput->MC_ipadd,lstaput->sta_macaddr,lstaput->ver_flag,IGMP_GROUP_DEL);

								 nlsock_create_to_kernel(loopupput->MC_ipadd,lstaput->sta_macaddr,NETLINK_IGMP_DEL);


								 create_mcgrouplist_file();
								 
								 break;
							 }
							 
							 lstaput->hosttimer_id--;
						 }
				  }
				 lstaput = lstaput->next;
			 }
		
		 loopupput = loopupput->next;
	 }

	 
 }

 /**********************************************************************************
 *init_igmp_snp_timer()
 *
 *INPUTS:
 *	 none
 *
 *OUTPUTS:
 *
 *RETURN VALUE:
 *		 IGMPSNP_RETURN_CODE_OK - on success
 *		 IGMPSNP_RETURN_CODE_CREATE_TIMER_ERROR - create timer error
 *		 IGMPSNP_RETURN_CODE_ADD_TIMER_ERROR - add timer error 
 *
 *DESCRIPTION:
 *	 create mc group timer
 *
 ***********************************************************************************/
 INT init_igmp_snp_timer(void)
 {
	 timer_element *new_timer = NULL;
	 UINT ret = IGMPSNP_RETURN_CODE_OK;
	 
	 igmp_debug_log("START:init_igmp_snp_timer\n");
 
	 ret = create_timer(TIMER_TYPE_LOOP,\
							 TIMER_PRIORI_NORMAL,\
							 1000,  /* here 1 means 1ms, for timer thread wake up every usleep(1000) */
							 (void *)igmp_snp_global_timer_func,\
							 NULL,\
							 0,\
							 new_timer);

	 
	 
	 if( IGMPSNP_RETURN_CODE_OK != ret )
	 {
		 igmp_snp_syslog_err("create timer failed,ret = %x.\n",ret);
		 igmp_debug_log("END:init_igmp_snp_timer\n");
		 return IGMPSNP_RETURN_CODE_CREATE_TIMER_ERROR;
	 }


	 return IGMPSNP_RETURN_CODE_OK;
 }

 /*
 *****************************************************
 * FuncName:nlsock_create_to_igmp
 * Description:create netlink socket to igmpsnp
 *****************************************************
 */
 int nlsock_create_to_igmpsnp(void)
 {
	 int nlsock_fd = 0;
	 int creat_try = 0;
	 struct sockaddr_nl src_addr, dest_addr;
	 struct msghdr msg;
	 struct nlmsghdr *nlh = NULL;
 
	 for (creat_try = 0; creat_try < 3; creat_try ++)
	 {
		 nlsock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_DETECTOR_IGMP);
		 if (nlsock_fd < 0)
			 continue;
		 else
			 break;
	 }
	 if (nlsock_fd < 0)
	 {
		 igmp_snp_syslog_err( "failed to create netlink socket to igmpsnp\n");
		 return IGMPSNP_RETURN_CODE_ERROR;
	 }
	 memset(&src_addr, 0, sizeof(src_addr));
	 src_addr.nl_family = AF_NETLINK;
	 src_addr.nl_pid = 0x02;
	 src_addr.nl_groups = 0;
 
	 if (bind(nlsock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)))
	 {
		 igmp_snp_syslog_err( "failed to create netlink socket to igmpsnp\n");
		 close(nlsock_fd);
		 return IGMPSNP_RETURN_CODE_ERROR;
	 }
 
	 return nlsock_fd;
 }
 
 
 int  parse_netlink_msg(char * buf)//,struct MC_LIST_UPDATE* list_entry)
 {	 
	 u_int16_t tmp_len = 0;
	 u_int16_t tmp_total_len = 0;
	 u_int8_t type = 0;
	 UCHAR sta_macaddr[6];
     int igmp_len = sizeof(struct igmp_snp_list);
	 buf ++;
		 while(tmp_total_len < igmp_len){ 
			 switch(*buf){				 
				 case IGMP_SNP_TYPE_OPTION:
				 buf ++;
				 tmp_len = *buf;
				 buf ++;
				 type = *buf;
				 break;	
				 
				 case IGMP_SNP_TYPE_GROUP_IP:
				 buf ++;
				 tmp_len = *buf;
				 buf ++;
				 break;
				 
				 case IGMP_SNP_TYPE_STA_MAC:
				 buf ++;
				 tmp_len = *buf;
				 buf ++;
				 memcpy(sta_macaddr,buf,6);  				 
				 igmp_snp_syslog_dbg("parse_netlink_msg:sta_macaddr:%x,%x,%x,%x,%x,%x\n",sta_macaddr[0],sta_macaddr[1],sta_macaddr[2],sta_macaddr[3],sta_macaddr[4],sta_macaddr[5]);
				 igmp_snp_deletesta(sta_macaddr);
				 break;
			 }
			 buf += tmp_len;
			 tmp_total_len += (TLV_MSG_TYPE_LEN + TLV_MSG_LENGTH_LEN + tmp_len);
		 }	 
 
 }
 
 
 
 /*
 ***********************************************************
 * FuncName:recv_scan_locate_parm
 * Description:recv scan params from wtpd,update scan params
				 in detector and restart scan locate task
 * Return:0 success, -1 failure.
 ***********************************************************
 */
 int recv_scan_locate_parm(int nlsock_to_igmpsnp)
 {

	 int recv_status = 0;
	 int error = 0;
	 struct sockaddr from_addr;
	 socklen_t addr_len;
	 addr_len = sizeof(struct sockaddr_nl);
	 
	 /* wangjianru modified for coverity check 2013-10-29 */
	 memset(&config_parm_from_igmpsnp.buf, 0, MAX_MSG_PAYLOAD);
	 /* gengzj added end */
	 
	 recv_status = recvfrom(nlsock_to_igmpsnp, &config_parm_from_igmpsnp, 
		 sizeof(config_parm_from_igmpsnp), 0, (struct sockaddr *)&from_addr, &addr_len);
	 
	 if (recv_status < 0)
	 {
		 igmp_snp_syslog_err("recv config params from kernnel failed!\n");
		 return IGMPSNP_RETURN_CODE_ERROR;
	 }
	 else
	 {
		 igmp_snp_syslog_dbg("recv scan locate params ok, recv_status: %d\n", recv_status);
 
		 igmp_debug_log("=================recv igmpsnp buf=================%s\n", config_parm_from_igmpsnp.buf);
		 
		 error = parse_netlink_msg(config_parm_from_igmpsnp.buf);
		 if (error < 0)
		 {
			 igmp_snp_syslog_err("parse config msg from kernel failed,continue.\n");
			 return IGMPSNP_RETURN_CODE_ERROR;
		 }
		 else
		 {
			 igmp_snp_syslog_dbg("parse_netlink_msg ok.\n");
			 return IGMPSNP_RETURN_CODE_OK;
		 }
	 }
	 
 }

 int rtnl_fd = 0;
 INT g_sockfd;
 fd_set rdfds; 


 void 
 init_rtnl_fd(void)
 {
	 struct sockaddr_nl s_addr;

 	
	 rtnl_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	 if (rtnl_fd > 0) {
		 bzero(&s_addr, sizeof(s_addr));
		 s_addr.nl_family = AF_NETLINK;
		 s_addr.nl_pid = getpid();
		 s_addr.nl_groups = RTNLGRP_LINK;

		 if (bind(rtnl_fd, (struct sockaddr *) &s_addr, sizeof(s_addr)) < 0) {
			 printf("Bind rtnl_fd failed");
			 exit(0);
		 }
		 return ;
	 }
	 perror("Socket rtnl_fd failed");

	 exit(0);
 }


 void
 try_rebind_monitor_interface(void)
 {
	 struct {
		 struct nlmsghdr nlh;
		 struct ifinfomsg msg;
		 u_int8_t pad[4000];
	 } resp;
	 ssize_t read_bytes = -1;
	 char ifname[IFNAMSIZ]= {0};
	 int i=0;
	 int j =0 ;
	 struct ifreq ifr;
	 
	 memset(&resp, 0, sizeof(resp));
	 read_bytes = recv(rtnl_fd, &resp, sizeof(resp), 0);
	 if (read_bytes < 0 || !NLMSG_OK(&resp.nlh, read_bytes) 
		 || resp.nlh.nlmsg_type != RTM_NEWLINK) 
		 return;

	 
	 if_indextoname(resp.msg.ifi_index, ifname);
	 if (memcmp(ifname, "athscan", strlen("athscan")) == 0)
		 return;
	 
	 if ((resp.msg.ifi_change & IFF_UP) && //flag changes
		 (resp.msg.ifi_flags & IFF_UP)) //up operation
	 {	 
			init_igmp_snp_vaplist();//get vap list by wangjr
	 }
	 
     FD_ZERO(&rdfds); 
	 FD_SET(g_sockfd, &rdfds);

	 
	 for(i=0; i<vap_listing.curr_size; i++)
	 {
		  strncpy(ifr.ifr_name,vap_listing.ifnames[i],strlen(vap_listing.ifnames[i])+1);
		  if((ioctl(g_sockfd,SIOCGIFINDEX,&ifr) == -1))
		  {
			   igmp_snp_syslog_warn("Could not ioctl the device\n");
		  }
		  igmp_debug_log("%s :%s 's index is %d\n",__FUNCTION__,vap_listing.ifnames[i], ifr.ifr_ifindex);
		  vap_index[j++] = ifr.ifr_ifindex;
	 }
 }


 void *create_recvevent_thread(void)
{


    init_rtnl_fd();	
			

    while (1)
    {
        try_rebind_monitor_interface();
			
    }
				
}

//#if 0

/**********************************************************************************
*create_timer_thread()
*
*DESCRIPTION:
*	init igmp_snoop timer thread
*
*INPUTS:
*	null
*OUTPUTS:
*	null
*RETURN VALUE:
*	null
*
***********************************************************************************/

static void *create_timer_thread(void)
{
	INT ret = 0;
	INT timer_id;
	timer_element *tnext = NULL;
		
	while(1)
	{
		ret = usleep(1000);

		if( -1 == ret )
		{
			igmp_snp_syslog_err("create timer thread:usleep error.\n");
			return;
		}
		pthread_mutex_trylock(&mutex);
		while(igmp_timer_list.lock)
			igmp_timer_list.lock = 0;

		if( igmp_timer_list.first_timer )
		{
			tnext = igmp_timer_list.first_timer;
			while( tnext )
			{
				tnext->current++;
				if(tnext->current == tnext->expires )
				{
					if( NULL != tnext->func )
						tnext->func(tnext);

					if( TIMER_TYPE_NOLOOP == tnext->type )
					{		/*NO LOOP*/
						timer_id = tnext->id;
						tnext = tnext->next;
						igmp_timer_list.lock = 1;
						del_timer(&igmp_timer_list,timer_id);
						igmp_timer_list.lock = 0;
						continue;
					}
					else
					{		/*LOOP*/
						tnext->current = 0;
					}
				}
				tnext = tnext->next;
			}
		}
		igmp_timer_list.lock = 1;
		pthread_mutex_unlock(&mutex);
	}	
	igmp_debug_log("Create timer thread success!\n");
}

// #endif









/**********************************************************************************
* create_recvskb_thread()
*
* DESCRIPTION:
*	init igmp_snoop receive skb thread
*
* INPUTS:
* none
*
* OUTPUTS:
*
* RETURN VALUE:
*	
***********************************************************************************/
 void *create_recvskb_thread(void)
{
    
    struct sock_filter BPF_code[] = {
        { 0x28, 0, 0, 0x0000000c },
		{ 0x15, 0, 3, 0x00000800 },
		{ 0x30, 0, 0, 0x00000017 },
		{ 0x15, 0, 1, 0x00000002 },
		{ 0x6, 0, 0, 0x00000060 },
		{ 0x6, 0, 0, 0x00000000 }
	};	

	
	INT i = 0;

	
    fd_set rdfds; 
	struct timeval tv;
	INT ret,flag;
    INT bytes;
    struct sockaddr_ll from;
	INT fromlen;
	

	struct ethhdr *ethinfo;
	struct iphdr *ip;
	struct igmphdr *igmp;
	struct igmpv3_report *v3_report = NULL;
		
	struct sock_fprog filter;
	filter.len = 6;
	filter.filter = BPF_code;	


	 init_igmp_snp_vaplist();//get vap list by wangjr


     UCHAR *packet = (
     CHAR *)malloc(2048*sizeof(char));
	
     if ((g_sockfd=(socket(PF_PACKET, SOCK_RAW, htons(0x003)))) < 0) 
	 {
	    igmp_snp_syslog_err("Could not open raw socket\n");
	    return;
	 }
	 if(setsockopt(g_sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0)
	 {
		igmp_snp_syslog_err("set option filter error\r\n");
		close(g_sockfd);
		return;
	 }

     FD_ZERO(&rdfds); 
	 FD_SET(g_sockfd, &rdfds);
	 tv.tv_sec = 60;
	 tv.tv_usec = 0;
	
	struct ifreq ifr;
    INT j = 0;
    for(i=0; i<vap_listing.curr_size; i++)
    {
    	 strncpy(ifr.ifr_name,vap_listing.ifnames[i],strlen(vap_listing.ifnames[i])+1);
    	 if((ioctl(g_sockfd,SIOCGIFINDEX,&ifr) == -1))
	     {
		      igmp_snp_syslog_warn("Could not ioctl the device\n");
	     }
	     igmp_debug_log("%s :%s 's index is %d\n",__FUNCTION__,vap_listing.ifnames[i], ifr.ifr_ifindex);
	     vap_index[j++] = ifr.ifr_ifindex;
    }


    
	while(1){
	ret = select(g_sockfd+ 1, &rdfds, NULL, NULL, NULL); 
    if(ret < 0) 
	{
		igmp_snp_syslog_err("select error\n");
		return;
	}
	else if(ret == 0) 
	{
		igmp_snp_syslog_err("recvfrom time out\n"); 
		return;
	}
	else 
	{
		if(FD_ISSET(g_sockfd, &rdfds)) 
		{
			memset(&from, 0, sizeof(struct sockaddr_ll));
			fromlen = sizeof(struct sockaddr_ll);
			bytes = recvfrom(g_sockfd,packet,2048, 0,(struct sockaddr *) &from, &fromlen);
			if(bytes<=0) 
			{
			    igmp_snp_syslog_err("recvfrom error%s\n",strerror(errno));
				igmp_snp_syslog_err("g_sockfd = %d, packet = %d\n",g_sockfd,packet);
				return;
			}
			
			flag = 0;
		    ethinfo = (struct ethhdr *)packet;			
			ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
            for(i=0; i<vap_listing.curr_size; i++)
            {
            	igmp_debug_log("%s :vap index is %d\n",__FUNCTION__,vap_index[i]);
            	if(vap_index[i] == from.sll_ifindex)
            	    flag = 1;	
            }
           igmp_debug_log("%s :protocol = %d\n",__FUNCTION__,ip->protocol);
           igmp_debug_log("%s :flag = %d\n", __FUNCTION__,flag);
           
            if( IPPROTO_IGMP == ip->protocol  && 1 ==  flag)
            {
	
				 igmp_debug_log("%s :recv mac %x,%x,%x,%x,%x,%x\r\n",__FUNCTION__,from.sll_addr[0],from.sll_addr[1],from.sll_addr[2],from.sll_addr[3],from.sll_addr[4],from.sll_addr[5]);
				if (bytes < (int) (sizeof(struct ethhdr) + sizeof(struct iphdr) + 8)) {
					igmp_snp_syslog_err("message too short, ignoring\n\r");
					free(packet);
					return;
				}
				if (bytes < ntohs(ip->tot_len)) {
					igmp_snp_syslog_err("Truncated packet,bytes = %d,tot-len = %d\n\r",bytes, ntohs(ip->tot_len));
					free(packet);
					return;
				}
				
				
			   igmp = (struct igmphdr *)(packet + sizeof(struct ethhdr) + (ip->ihl)*4);		   
			   igmp_debug_log("%s :igmp type: %x\n", __FUNCTION__,igmp->type);
			   
			   if( IGMP_REPORT_V3 != igmp->type)
			   {
				   unsigned char *test = &(igmp->gaddr);
				   
				   igmp_debug_log("igmp group id : %x --- %x\n",igmp->gaddr, igmp->gaddr&0x7fffff);
				   
					
					if( IGMP_REPORT_V1 == igmp->type)
					{
						igmp_snp_syslog_dbg("Received IGMPv1 reports\n");
						
						igmp_snp_searchgroup(igmp->gaddr,from.sll_addr,IPPROTO_IGMP_V1,IGMP_GROUP_ADD);
						create_mcgrouplist_file();
						nlsock_create_to_kernel(igmp->gaddr,from.sll_addr,NETLINK_IGMP_ADD);
						
					}
					else if(IGMP_REPORT_V2 == igmp->type)
					{
						igmp_snp_syslog_dbg("Received IGMPv2 reports\n");
						igmp_snp_searchgroup(igmp->gaddr,from.sll_addr,IPPROTO_IGMP_V2,IGMP_GROUP_ADD);
						create_mcgrouplist_file();
						nlsock_create_to_kernel(igmp->gaddr,from.sll_addr,NETLINK_IGMP_ADD);
					}				
					else if(IGMP_LEAVE_V2 ==igmp->type)
					{
						igmp_snp_syslog_dbg("Received IGMPv2 leaves\n");
						igmp_snp_searchgroup(igmp->gaddr,from.sll_addr,IPPROTO_IGMP_V2,IGMP_GROUP_DEL);
						create_mcgrouplist_file();
						nlsock_create_to_kernel(igmp->gaddr,from.sll_addr,NETLINK_IGMP_DEL);
					}
					else 
					{
						igmp_snp_syslog_dbg("Received IGMP general queries\n");
					}
				   
			   }
			   else
			   {
			   		igmp_snp_syslog_dbg("Received IGMPv3 reports\n");
					
			   		v3_report = (struct igmpv3_report*)(packet + sizeof(struct ethhdr) + (ip->ihl)*4);

						igmp_snp_syslog_dbg("v3 type %x code %x cksum %x group %x  v3-type %x\n", \
									v3_report->type,v3_report->resv1,v3_report->csum,	\
									v3_report->grec[0].grec_mca,v3_report->grec[0].grec_type);

					if( v3_report->numofgrec >1 )
					{
						igmp_snp_syslog_info("IGMP SNP can NOT support V3 multi-group report, when number of Group Records > 1.\n");
			
						//return IGMPSNP_RETURN_CODE_ERROR ;
					}
					else
					{
						 if (v3_report->grec[0].grec_type == IGMP_REPORT_V3_JOIN)
						 {
						 	//igmp_snp_searchgroup(v3_report->grec[0].grec_mca,from.sll_addr,IPPROTO_IGMP_V3,IGMP_GROUP_ADD);
							//create_mcgrouplist_file();
							nlsock_create_to_kernel(v3_report->grec[0].grec_mca,from.sll_addr,NETLINK_IGMP_ADD);
						 }
						 else if(v3_report->grec[0].grec_type == IGMP_REPORT_V3_LEAVE)
						 {	
						 	//igmp_snp_searchgroup(v3_report->grec[0].grec_mca,from.sll_addr,IPPROTO_IGMP_V3,IGMP_GROUP_DEL);
							//create_mcgrouplist_file();
							nlsock_create_to_kernel(v3_report->grec[0].grec_mca,from.sll_addr,NETLINK_IGMP_DEL);
						 }	
						 else
						 {
						 	;;
						 }
					}
			   }
		  }
		}	
	}
}
}


int create_mcgrouplist_file()
{

	MC_group *loopupput = NULL;
	MC_sta_state *lstaput =NULL;

	FILE *fp;
	int num =0 ;

	loopupput = p_mcgrouplist;
	
	fp = fopen(PATH_MCGROUPLIST_FILE, "w+");

	if (NULL == fp) {
		igmp_snp_syslog_err("err open : " PATH_MCGROUPLIST_FILE);
		return FAILURE;
	}

	fprintf(fp,"%-20s%-20s\n","mc group","station addr");
	

	while (NULL != loopupput)
	{
		
		lstaput =loopupput->stalist;
			
		while (NULL != lstaput)
		{
				num ++ ;
				if (num == 1 )
				{
					fprintf(fp,"%-20x%02x:%02x:%02x:%02x:%02x:%02x\n", loopupput->MC_ipadd,lstaput->sta_macaddr[0],lstaput->sta_macaddr[1],lstaput->sta_macaddr[2],lstaput->sta_macaddr[3],lstaput->sta_macaddr[4],lstaput->sta_macaddr[5]); 
					fflush(fp);				

				}
				else
				{
					fprintf(fp,"%-20s%02x:%02x:%02x:%02x:%02x:%02x\n", "",lstaput->sta_macaddr[0],lstaput->sta_macaddr[1],lstaput->sta_macaddr[2],lstaput->sta_macaddr[3],lstaput->sta_macaddr[4],lstaput->sta_macaddr[5]);
					fflush(fp);

				}
				
			lstaput = lstaput->next;
			
		}
		loopupput = loopupput->next;
		num = 0 ;
	}
	
	fclose(fp);
}

//# if 0








static void usage(void)
{		
 	fprintf(stderr,			
		"\n"		
		"usage: igmpsnp [-hd] [-i <hostlifeinterval>] " 		
		"\n" 
		"options:\n" 
		"   -h	show this usage\n"
		"   -d   show more debug messages \n"
		"   -i	set igmpv1 the hostlifeinterval\n");		
		exit(1);
}


 int main(int argc, char *argv[])
{

	INT ret;
	INT i;
	INT c ; 
	char *path = NULL;
	
	for (;;) {				
		c = getopt(argc, argv, "dhi:"); 
		if (c < 0)
			break;
		switch (c) {
			case 'h':
				usage();
				break;
			case 'd':
				igmp_snoop_debug = IGMP_SNOOP_YES;
				igmp_debug_log("igmp_snoop_debug = %d\n",igmp_snoop_debug); 
				break; 
			case 'i':
				igmp_hosttimerout_interval = atoi(optarg);
				igmp_snp_syslog_dbg("igmp_hosttimerout_interval = %d\n",igmp_hosttimerout_interval); 
				break;
			default:
				usage();
				break; 
		}
	}


	igmpsnp_ubus_init(path);



    ret = pthread_create(&thread_recvskb,NULL,(void *)create_recvskb_thread,NULL);
	if( 0 != ret )
	{
		igmp_snp_syslog_err("Create packet skb thread fail.\n");
		pthread_join(thread_recvskb,NULL);
		return ;
	}
	igmp_snp_syslog_dbg("Create data recvskb thread ok.\n");


	

	
	ret = pthread_create(&thread_recvevent,NULL,(void *)create_recvevent_thread,NULL);
	if( 0 != ret )
	{
		igmp_snp_syslog_err("create_recvevent_thread fail.\n");
		pthread_join(thread_recvevent,NULL);
		return ;
	}
	igmp_snp_syslog_dbg("create_recvevent_thread ok.\n");


	ret = pthread_create(&thread_timer,NULL,(void *)create_timer_thread,NULL);
	if( 0 != ret )
	{
		igmp_snp_syslog_err("Create timer thread fail. \n");
		pthread_join(thread_timer,NULL);
		return ;
	}

	
	
	if( IGMPSNP_RETURN_CODE_OK != init_igmp_snp_timer())
	{
		igmp_snp_syslog_warn("init_igmp_snp_timer: fail in set global timer.\n");

	}


	create_mcgrouplist_file();

	uloop_run();	
	igmpsnp_ubus_fini();

	pthread_join(thread_recvskb,NULL);
	pthread_join(thread_recvevent,NULL);
	pthread_join(thread_timer,NULL);



}



