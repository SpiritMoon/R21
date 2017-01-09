#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <inttypes.h>

#define FIFO_SERVER "/tmp/cluster_fifo"
#define   CMD_FIFO_SEND  "/tmp/cmd_fifo_send"
#define   CMD_FIFO_RECV  "/tmp/cmd_fifo_recv"
#define MAX_CLUSTER_AP 16
#define MAC_LEN  6       
#define L_RADIO_NUM		4



int flags = 0;
typedef struct priority {
    u_int8_t overload[2];
    u_int8_t priority;
    u_int8_t config_seq;
    u_int8_t product_type;
    u_int8_t mac_tail[3];
} PRI;

typedef union cluster_priority {
    u_int64_t ap_priority;
    PRI prio;
} CLUSTER_PRI;

typedef struct {
		unsigned char radioid;
			unsigned char channel;            
				unsigned char txpower;           
					unsigned char rssi;
}WTP_RADIO_H;

typedef struct
{
	unsigned char ap_base_mac[MAC_LEN];
    unsigned char radiocnt;
	WTP_RADIO_H ap_radio[L_RADIO_NUM];
}Scan_Info;



typedef struct cluster_member {

    uint16_t  on;  //  0 is alive  ;1 is delete
    uint8_t state;  // running ? or lost
    uint8_t role;  // pvc /svc/vc ? 1:2:3
    uint8_t mac[6];
    uint32_t ip;
    uint32_t ssid;
    uint32_t cluster_id;
    // uint32_t prio;
    CLUSTER_PRI prio;
	uint8_t radiocnt;
	WTP_RADIO_H WTP_Radio[4];
    uint32_t auth;    //  0 is not ;1 is auth
    //uint8_t config_seq;
    //uint8_t product_type;
    pthread_mutex_t entry_mutex;
    uint32_t timer; // ageing time  default 30s
    uint32_t pre_free;
	unsigned char neighbor_cnt;
	Scan_Info rssi_of_others[MAX_CLUSTER_AP];
	uint8_t ap_name[32];
	uint8_t ap_version[16];
} cluster_m_t;



typedef enum cluster_cmd {
    SHOW = 1,
    AUTH,
    UNAUTH,
    DEL,
    VIP,
	SET_TIME
} CLUSTER_CMD;


struct cmd_head {
    uint8_t type;
    uint8_t mac[6];
    uint32_t ip;
	char netmask[32];
};

#define ENTRY_SIZE  128
#define ENTRY_ALL_SIZE   sizeof(struct cluster_member)* ENTRY_SIZE
cluster_m_t *show_entry;
cluster_m_t entry[ENTRY_SIZE];
struct cmd_head cmd;


void show_members_all(cluster_m_t *entry)
{

    int i, count=128;
    // pipe  or  af_local ?
    //count=table.entry_cnt;

    printf("mac                 ip               prio   state   role   auth    name      version \n");
    for(i = 0; i < count; i++) {

        if(entry[i].on != 1 )
            continue;

		printf("%02x:%02x:%02x:%02x:%02x:%02x   %s     %d     %d     %d      %d     %s      %s\n",entry[i].mac[0],entry[i].mac[1],entry[i].mac[2],
					entry[i].mac[3],entry[i].mac[4],entry[i].mac[5],inet_ntoa(entry[i].ip),
               entry[i].prio.prio.priority, entry[i].state, entry[i].role, entry[i].auth,entry[i].ap_name,entry[i].ap_version);


    }


}





int show_ap_list(void)
{

    int i, fd_r, fd_w, n,ret,val;
    char buf[ENTRY_ALL_SIZE];
	fd_set rd;
	struct timeval tv;

    memset(entry, 0, sizeof(struct cluster_member) * 128);

    /* test */
    if((fd_w = open(CMD_FIFO_RECV, O_WRONLY | O_NONBLOCK)) < 0) {
        printf("open fifo  fail\n");
        return 1;
    }


    cmd.type = SHOW;
    write(fd_w, (void *)&cmd, sizeof(cmd));



    if((fd_r = open(CMD_FIFO_SEND, O_RDONLY | O_NONBLOCK)) < 0) {
        printf("open fifo  fail\n");
		return 1;
    }

	FD_ZERO(&rd);
	FD_SET(fd_r,&rd);
	tv.tv_sec = 3;
	tv.tv_usec = 0;

	ret = select(fd_r +1,&rd,NULL,NULL,&tv);
	if(ret > 0)
	{
		if(FD_ISSET(fd_r,&rd))
		{
			val = read(fd_r, entry, ENTRY_ALL_SIZE);
			show_members_all(entry);

		}
	}else if(ret == 0)
	{
		printf("show  ap list timeout\n");
	}

    close(fd_w);
    close(fd_r);

    return val;


}




int config_ap(struct cmd_head cmd)
{

    int i, fd_r, fd_w, n, val;

    /* test */
    if((fd_w = open(CMD_FIFO_RECV, O_WRONLY )) < 0) {
        printf("open fifo	fail\n");
        return 1;
    }

    val = write(fd_w, (void *)&cmd, sizeof(struct cmd_head));

    //read_back();

    //printf("write:%d\n",val);

    close(fd_w);


    return val;


}

int check_big()
{
    u_int16_t tmp = 1;
    u_int8_t *p;

    p =(uint8_t *) &tmp;
    if(p[1] == 1)
        return 1;
    else
        return 0;




}

void get_mac(u_int8_t *str)
{
    u_int16_t mac[6];
    u_int8_t  *p;
    int i = 0;

    if(check_big()) {

        sscanf((void *)str, "%2hx:%2hx:%2hx:%2hx:%2hx:%2hx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

        for(i = 0; i < 6; i++) {
            p = (u_int8_t *)&mac[i];
            memcpy(&cmd.mac[i], &p[1], 1);
        }

    } else {

        sscanf((void *)str, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &cmd.mac[0], &cmd.mac[1], &cmd.mac[2], &cmd.mac[3], &cmd.mac[4], &cmd.mac[5]);

    }


}


int main(int argc, void *argv[])
{


    int i, fd_r, fd_w, n;
    int ret;
    char buf[ENTRY_ALL_SIZE];

    if(argc < 2) {
        printf("too less args\n");
        return 1;
    }



    memset((void *)&cmd, 0, sizeof(struct cmd_head));

    if(!memcmp(argv[1], "show", 4)) {
        ret = show_ap_list();
        return 0;
    }


    if(argc == 3) {

			get_mac(argv[2]);

    }
	else if(argc == 4)
	{
		cmd.ip = inet_addr(argv[2]);
		//printf("%d  \n",cmd.ip);
		memcpy(cmd.netmask,argv[3],strlen(argv[3]));
	}
	else
	{
	
	
		printf("error  arg\n");
		return 1;
	
	}




   // printf("%02x:%02x:%02x:%02x:%02x:%02x\n", cmd.mac[0], cmd.mac[1], cmd.mac[2], cmd.mac[3], cmd.mac[4], cmd.mac[5]);

    if(!memcmp(argv[1], "auth", 4)) {

        cmd.type = AUTH;
        // memcpy(cmd.mac,,6);

        ret = config_ap(cmd);
    } else if(!memcmp(argv[1], "unauth", 6)) {
        cmd.type = UNAUTH;
        ret = config_ap(cmd);
    } else if(!memcmp(argv[1], "del", 3)) {
        cmd.type = DEL;
        ret = config_ap(cmd);
    } else if(!memcmp(argv[1], "vip", 3)) {
        cmd.type = VIP;
		cmd.ip = inet_addr(argv[2]);
		if(argv[3]!=NULL)
		memcpy(cmd.netmask,argv[3],strlen(argv[3]));
        ret = config_ap(cmd);
    } else if(!memcmp(argv[1],"set",3)){
		cmd.type = SET_TIME;
		cmd.ip=1;
		if(argv[2]!=NULL)
		{
			cmd.ip = atoi(argv[2]);
		}
		printf("set time:%d seconds\n",cmd.ip*30);
		if(cmd.ip < 1 ||  cmd.ip > 120)
		{
			printf("error args\n");
			return 1;
		}
		ret = config_ap(cmd);
	}else {
        printf("args  error \n");
        return 1;
    }




    return 0;

}
