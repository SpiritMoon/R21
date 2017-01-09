#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <errno.h>
#include <stdio.h>

#include "sfe_genl.h"

static struct nl_sock *sock;
static int family;

void sfe_genl_close()
{
	nl_close(sock);
	nl_socket_free(sock);
}

static struct nla_policy sfe_genl_policy[SFE_A_MAX + 1] = {
	[SFE_A_UNSPEC]	= { .type = NLA_UNSPEC },
	[SFE_A_SRC_IP]	= { .type = NLA_U32 },
	[SFE_A_DST_IP]	= { .type = NLA_U32 },
	[SFE_A_SRC_PORT]= { .type = NLA_U16 },
	[SFE_A_DST_PORT]= { .type = NLA_U16 },
	[SFE_A_PROTO]	= { .type = NLA_U8 },
	[SFE_A_DIR]		= { .type = NLA_U8 },
	[SFE_A_FLAG]	= { .type = NLA_U16 },
	[SFE_A_PACKET]	= { .type = NLA_U64 },
	[SFE_A_BYTE]	= { .type = NLA_U64 },
};

void dump_sfe_flow(struct nlattr *attrs[])
{
	char src_ipstr[16] = {0};
	char dst_ipstr[16] = {0};
	uint32_t saddr, daddr;
	saddr = nla_get_u32(attrs[SFE_A_SRC_IP]);
	daddr = nla_get_u32(attrs[SFE_A_DST_IP]);

	printf("%16s:%-6u->%16s:%-6u %s %c %04x %llu %llu\n", 
		inet_ntop(AF_INET, &saddr, src_ipstr, sizeof(src_ipstr)),
		ntohs(nla_get_u16(attrs[SFE_A_SRC_PORT])),
		inet_ntop(AF_INET, &daddr, dst_ipstr, sizeof(dst_ipstr)),
		ntohs(nla_get_u16(attrs[SFE_A_DST_PORT])),
		nla_get_u8(attrs[SFE_A_PROTO]) == IPPROTO_UDP ? "UDP" : "TCP",
		nla_get_u8(attrs[SFE_A_DIR]) == 0 ? 'O' : 'R',
		nla_get_u16(attrs[SFE_A_FLAG]),
		nla_get_u64(attrs[SFE_A_PACKET]),
		nla_get_u64(attrs[SFE_A_BYTE]));
}

static int parse_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct genlmsghdr *gnlh = nlmsg_data(nlh);
	struct nlattr *attrs[SFE_A_MAX+1];

	if (nlh->nlmsg_type == NLMSG_DONE) {
		puts("-- END --");
		sfe_genl_close();
		exit(0);
	}

	genlmsg_parse(nlh, 0, attrs, SFE_A_MAX, sfe_genl_policy);

	switch (gnlh->cmd) {
	case SFE_FLOW_C_GET:
		dump_sfe_flow(attrs);
		break;
	default:
		return NL_SKIP;
	}

	return NL_OK;
}

int sfe_genl_init()
{
	sock = nl_socket_alloc();
	if (sock == NULL) {
		printf("Unable to allocate socket.\n");
		return -1;
	}
	genl_connect(sock);

	family = genl_ctrl_resolve(sock, SFE_GENL_FAMILY_NAME);
	if (family < 0) {
		nl_close(sock);
		nl_socket_free(sock);
		printf("Unable to resolve family\n");
		return -1;
	}

	nl_socket_disable_seq_check(sock);
	nl_socket_modify_cb(sock, NL_CB_MSG_IN, NL_CB_CUSTOM, parse_cb, NULL);

	return 0;
}

int sfe_flow_get() {
	struct nl_msg *msg;
	int ret;

	msg = nlmsg_alloc();
	if (msg == NULL) {
		printf("Unable to allocate message\n");
		return -1;
	}

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family,
			0, NLM_F_REQUEST | NLM_F_DUMP,
			SFE_FLOW_C_GET, 1);

	ret = nl_send_auto_complete(sock, msg);
	if (ret < 0) {
		printf("nl_send_auto_complete failed");
	}

	nlmsg_free(msg);

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	if (sfe_genl_init() < 0) {
		printf("Unable to init generic netlink\n");
		exit(1);
	}

	if (sfe_flow_get()) {
		printf("Send failed\n");
		return 0;
	}

	/* printf("waiting for netlink response\n"); */
	/* this never returns */
	while (1) {
		ret = nl_recvmsgs_default(sock);
		if (ret < 0) {
			perror("recv genl msg error, exit!\n");
			break;
		}
	}

	sfe_genl_close();

	return 0;
}
