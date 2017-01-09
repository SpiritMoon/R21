
#include <linux/types.h>
#include <linux/netdevice.h>
#include <net/netfilter/nf_conntrack.h>

#include "sfe.h"

/*
 * By default Linux IP header and transport layer header structures are
 * unpacked, assuming that such headers should be 32-bit aligned.
 * Unfortunately some wireless adaptors can't cope with this requirement and
 * some CPUs can't handle misaligned accesses.  For those platforms we
 * define SFE_IPV4_UNALIGNED_IP_HEADER and mark the structures as packed.
 * When we do this the compiler will generate slightly worse code than for the
 * aligned case (on most platforms) but will be much quicker than fixing
 * things up in an unaligned trap handler.
 */
#define SFE_IPV4_UNALIGNED_IP_HEADER 1
#if SFE_IPV4_UNALIGNED_IP_HEADER
#define SFE_IPV4_UNALIGNED_STRUCT __attribute__((packed))
#else
#define SFE_IPV4_UNALIGNED_STRUCT
#endif

/*
 * An Ethernet header, but with an optional "packed" attribute to
 * help with performance on some platforms (see the definition of
 * SFE_IPV4_UNALIGNED_STRUCT)
 */
struct sfe_ipv4_eth_hdr {
	__be16 h_dest[ETH_ALEN / 2];
	__be16 h_source[ETH_ALEN / 2];
	__be16 h_proto;
} SFE_IPV4_UNALIGNED_STRUCT;

#define DSCP_MASK	0xfc	/* 11111100 */
#define DSCP_SHIFT	2
#define DSCP_MAX	0x3f	/* 00111111 */

/*
 * An IPv4 header, but with an optional "packed" attribute to
 * help with performance on some platforms (see the definition of
 * SFE_IPV4_UNALIGNED_STRUCT)
 */
struct sfe_ipv4_ip_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 ihl:4,
	     version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8 version:4,
	     ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;

	/*
	 * The options start here.
	 */
} SFE_IPV4_UNALIGNED_STRUCT;

/*
 * A UDP header, but with an optional "packed" attribute to
 * help with performance on some platforms (see the definition of
 * SFE_IPV4_UNALIGNED_STRUCT)
 */
struct sfe_ipv4_udp_hdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
} SFE_IPV4_UNALIGNED_STRUCT;

/*
 * A TCP header, but with an optional "packed" attribute to
 * help with performance on some platforms (see the definition of
 * SFE_IPV4_UNALIGNED_STRUCT)
 */
struct sfe_ipv4_tcp_hdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16 res1:4,
	      doff:4,
	      fin:1,
	      syn:1,
	      rst:1,
	      psh:1,
	      ack:1,
	      urg:1,
	      ece:1,
	      cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16 doff:4,
	      res1:4,
	      cwr:1,
	      ece:1,
	      urg:1,
	      ack:1,
	      psh:1,
	      rst:1,
	      syn:1,
	      fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__be16 window;
	__sum16	check;
	__be16 urg_ptr;
} SFE_IPV4_UNALIGNED_STRUCT;

/*
 * Bit flags for IPv4 connection matching entry.
 */
#define SFE_FLOW_FLAG_MARK (1<<0)
					/* Fast Ethernet header write */
#define SFE_FLOW_FLAG_PRIORITY (1<<1)
					/* remark priority of SKB */
#define SFE_FLOW_FLAG_DSCP (1<<2)
					/* remark DSCP of packet */
#define SFE_FLOW_FLAG_WRITE_L2_HDR	(1<<3)

#define SFE_FLOW_FLAG_WRITE_FAST_ETH_HDR	(1<<4)

/*
 * IPv4 connection matching structure.
 */
struct sfe_flow {
	struct hlist_node hnode;
	struct nf_conn *nfct;
	enum ip_conntrack_info ctinfo;
	struct sfe_flow *counter;
	atomic_t use;

	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t protocol;

	uint8_t dir;

	/*
	 * Control the operations of the match.
	 */
	uint16_t flags;			/* Bit flags */

	uint32_t rx_packet_count;	/* Number of packets RX'd */
	uint32_t rx_byte_count;		/* Number of bytes RX'd */


	/*
	 * QoS information
	 */
	uint32_t priority;
	uint32_t dscp;
	uint32_t mark;

	unsigned char dst_mac[ETH_ALEN];
};

/*
 * IPv4 connections and hash table size information.
 */
#define SFE_FLOW_HASH_SHIFT 10
#define SFE_FLOW_HASH_SIZE (1 << SFE_FLOW_HASH_SHIFT)
#define SFE_FLOW_HASH_MASK (SFE_FLOW_HASH_SIZE - 1)
#define SFE_FLOW_MAX	(1 << 16) /* 64K */

enum sfe_exp_stat {
	SFE_EXP_IPV4_UDP_HEADER_INCOMPLETE,
	SFE_EXP_IPV4_UDP_NO_FLOW,
	SFE_EXP_IPV4_IP_OPTIONS,
	SFE_EXP_IPV4_IP_FRAGMENT,
	SFE_EXP_IPV4_IP_TTL,
	SFE_EXP_IPV4_LOOPBACK,
	SFE_EXP_IPV4_MULTICAST,
	SFE_EXP_IPV4_MTU,
	SFE_EXP_IPV4_DST_MAC,
	SFE_EXP_IPV4_TCP_HEADER_INCOMPLETE,
	SFE_EXP_IPV4_TCP_NO_FLOW_SLOW_FLAGS,
	SFE_EXP_IPV4_TCP_NO_FLOW_FAST_FLAGS,
	SFE_EXP_IPV4_TCP_FLAGS,
	SFE_EXP_IPV4_NON_INITIAL_FRAGMENT,
	SFE_EXP_IPV4_UNSUPPORTED_PROTOCOL,
	SFE_EXP_FM_PACKET_BROADCAST,
	SFE_EXP_FM_PACKET_MULTICAST,
	SFE_EXP_FM_NO_IIF,
	SFE_EXP_FM_NO_CT,
	SFE_EXP_FM_CT_UNTRACK,
	SFE_EXP_FM_CT_UNCONFIRMED,
	SFE_EXP_FM_CT_HAS_HELPER,
	SFE_EXP_FM_IP_HEADER_INCOMPLETE,
	SFE_EXP_FM_IP_MUTILCAST,
	SFE_EXP_FM_TCP_UNASSURED,
	SFE_EXP_FM_TCP_UNESTABLISHED,
	SFE_EXP_FM_UNSUPPORTED_PROTOCOL,
	SFE_EXP_FM_LOCAL_OUT,
	SFE_EXP_FM_DPI_UNFINISHED,
	SFE_EXCEPTION_MAX,
};


struct sfe_stat{
	unsigned int flow_add;
	unsigned int flow_delete;
	unsigned int flow_match_hits;
	unsigned int flow_match_miss;
	unsigned int packets_forwarded;
	unsigned int packets_not_forwarded;
	unsigned int exception[SFE_EXCEPTION_MAX];
};

/*
 * Per-module structure.
 */
struct sfe_ipv4 {
	spinlock_t hash_lock;	/* Loack for flow_hash */
	struct hlist_head flow_hash[SFE_FLOW_HASH_SIZE];

	struct kmem_cache *flow_cache;

	atomic_t count;

	/*
	 * Statistics.
	 */
	struct sfe_stat __percpu *stat;

	/*
	 * Control state.
	 */
	struct kobject *sys_sfe_ipv4;	/* sysfs linkage */
	int debug_dev;			/* Major number of the debug char device */
};

bool sfe_ipv4_recv(struct sk_buff *skb);
struct sfe_flow *sfe_flow_alloc(void);
void sfe_flow_free(struct sfe_flow *flow);
void sfe_flow_add(struct sfe_flow *new_flow);
void sfe_flow_delete(struct sfe_flow *flow);
void sfe_flow_flush(void);
struct sfe_flow *sfe_flow_find(uint8_t protocol,
									    __be32 src_ip, __be16 src_port,
									    __be32 dst_ip, __be16 dst_port);

