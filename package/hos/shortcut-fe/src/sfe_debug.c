#include <linux/sysfs.h>

#include "sfe.h"
#include "sfe_ipv4.h"

/*
 * write state.
 */
struct sfe_ipv4_debug_write_state {
	int state;			/* output file state machine state */
	int iter_exception;		/* Next exception iterator */
};

typedef bool (*sfe_ipv4_debug_write_method_t)(struct sfe_ipv4 *si, char *buffer, char *msg, size_t *length,
						  int *total_read, struct sfe_ipv4_debug_write_state *ws);

static char *sfe_ipv4_exception_events_string[SFE_EXCEPTION_MAX] = {
	"UDP_HEADER_INCOMPLETE",
	"UDP_NO_FLOW",
	"IP_OPTIONS",
	"IP_FRAGMENT",
	"IP_TTL",
	"LOOPBACK",
	"MULTICAST",
	"MTU",
	"DST_MAC",
	"TCP_HEADER_INCOMPLETE",
	"TCP_NO_FLOW_SLOW_FLAGS",
	"TCP_NO_FLOW_FAST_FLAGS",
	"TCP_FLAGS",
	"NON_INITIAL_FRAGMENT",
	"UNSUPPORTED_PROTOCOL",
	"FM_PACKET_BROADCAST",
	"FM_PACKET_MULTICAST",
	"FM_NO_IIF",
	"FM_NO_CT",
	"FM_CT_UNTRACK",
	"FM_CT_UNCONFIRMED",
	"FM_CT_HAS_HELPER",
	"FM_IP_HEADER_INCOMPLETE",
	"FM_IP_MUTILCAST",
	"FM_TCP_UNASSURED",
	"FM_TCP_UNESTABLISHED",
	"FM_UNSUPPORTED_PROTOCOL",
	"FM_LOCAL_OUT",
	"FM_DPI_UNFINISHED"
};

#define CHAR_DEV_MSG_SIZE 768

/*
 * sfe_ipv4_debug_dev_read_connections_connection()
 *	Generate part of the output.
 */
static bool sfe_ipv4_debug_dev_read_connections_connection(struct sfe_ipv4 *si, char *buffer, char *msg, size_t *length,
							   int *total_read, struct sfe_ipv4_debug_write_state *ws)
{
	struct sfe_flow *c;
	int bytes_read;
	char *protocol;
	__be32 src_ip;
	__be16 src_port;
	__be32 dst_ip;
	__be16 dst_port;
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint32_t mark, priority, dscp;
	unsigned hash_idx = 0;

	spin_lock_bh(&si->hash_lock);

	bytes_read = snprintf(msg, CHAR_DEV_MSG_SIZE, "connection:\n");
	if (copy_to_user(buffer + *total_read, msg, CHAR_DEV_MSG_SIZE)) {
		spin_unlock_bh(&si->hash_lock);
		return false;
	}
	*length -= bytes_read;
	*total_read += bytes_read;
	for (hash_idx = 0; hash_idx < SFE_FLOW_HASH_SIZE; ++hash_idx) {
		hlist_for_each_entry(c, &si->flow_hash[hash_idx], hnode) {
			protocol = c->protocol == IPPROTO_UDP ? "UDP" : "TCP";
			src_ip = c->src_ip;
			src_port = c->src_port;
			dst_ip = c->dst_ip;
			dst_port = c->dst_port;
			priority = c->priority;
			dscp = c->dscp;
			rx_packets = c->rx_packet_count;
			rx_bytes = c->rx_byte_count;
			mark = c->mark;

			bytes_read = snprintf(msg, CHAR_DEV_MSG_SIZE,
						"\t%s %pI4:%u -> %pI4:%u "
						"priority=%u dscp=%u mark=%08x "
						"rx_pkts=%llu rx_bytes=%llu\n",
						protocol,
						&src_ip,
						ntohs(src_port),
						&dst_ip,
						ntohs(dst_port),
						priority, dscp, mark,
						rx_packets, rx_bytes);
			if (copy_to_user(buffer + *total_read, msg, CHAR_DEV_MSG_SIZE)) {
				break;
			}
			*length -= bytes_read;
			*total_read += bytes_read;

			if (*length < CHAR_DEV_MSG_SIZE) {
				break;
			}
		}
		if (*length < CHAR_DEV_MSG_SIZE) {
			break;
		}
	}

	spin_unlock_bh(&si->hash_lock);

	ws->state++;

	return true;
}

/*
 * sfe_ipv4_debug_dev_read_exceptions_start()
 *	Generate part of the output.
 */
static bool sfe_ipv4_debug_dev_read_exceptions_start(struct sfe_ipv4 *si, char *buffer, char *msg, size_t *length,
						     int *total_read, struct sfe_ipv4_debug_write_state *ws)
{
	int bytes_read;

	bytes_read = snprintf(msg, CHAR_DEV_MSG_SIZE, "exceptions:\n");
	if (copy_to_user(buffer + *total_read, msg, CHAR_DEV_MSG_SIZE)) {
		return false;
	}

	*length -= bytes_read;
	*total_read += bytes_read;

	ws->state++;
	return true;
}

/*
 * sfe_ipv4_debug_dev_read_exceptions_exception()
 *	Generate part of the output.
 */
static bool sfe_ipv4_debug_dev_read_exceptions_exception(struct sfe_ipv4 *si, char *buffer, char *msg, size_t *length,
							 int *total_read, struct sfe_ipv4_debug_write_state *ws)
{
	unsigned int ct = 0;
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		const struct sfe_stat *stat = per_cpu_ptr(si->stat, cpu);
		ct += stat->exception[ws->iter_exception];
	}

	if (ct) {
		int bytes_read;

		bytes_read = snprintf(msg, CHAR_DEV_MSG_SIZE,
				      "\t%s=%u\n",
				      sfe_ipv4_exception_events_string[ws->iter_exception],
				      ct);
		if (copy_to_user(buffer + *total_read, msg, CHAR_DEV_MSG_SIZE)) {
			return false;
		}

		*length -= bytes_read;
		*total_read += bytes_read;
	}

	ws->iter_exception++;
	if (ws->iter_exception >= SFE_EXCEPTION_MAX) {
		ws->iter_exception = 0;
		ws->state++;
	}

	return true;
}

/*
 * sfe_ipv4_debug_dev_read_stats()
 *	Generate part of the output.
 */
static bool sfe_ipv4_debug_dev_read_stats(struct sfe_ipv4 *si, char *buffer, char *msg, size_t *length,
					  int *total_read, struct sfe_ipv4_debug_write_state *ws)
{
	int bytes_read;
	unsigned int cpu;
	unsigned int flow_number = 0;
	unsigned int flow_add = 0;
	unsigned int flow_delete = 0;
	unsigned int flow_match_hits = 0;
	unsigned int flow_match_miss = 0;
	unsigned int packets_forwarded = 0;
	unsigned int packets_not_forwarded = 0;

	flow_number = atomic_read(&si->count);
	for_each_possible_cpu(cpu) {
		const struct sfe_stat *stat
			= per_cpu_ptr(si->stat, cpu);
		flow_add += stat->flow_add;
		flow_delete += stat->flow_delete;
		flow_match_hits += stat->flow_match_hits;
		flow_match_miss += stat->flow_match_miss;
		packets_forwarded += stat->packets_forwarded;
		packets_not_forwarded += stat->packets_not_forwarded;
	}

	bytes_read = snprintf(msg, CHAR_DEV_MSG_SIZE, "stats:\n"
			      "\tflow_number=%u\n"
			      "\tflow_add=%u\n"
			      "\tflow_delete=%u\n"
			      "\tflow_match_hits=%u\n"
			      "\tflow_match_miss=%u\n"
			      "\tpackets_forwarded=%u\n"
			      "\tpackets_not_forwarded=%u\n",
			      flow_number,
			      flow_add,
			      flow_delete,
			      flow_match_hits,
			      flow_match_miss,
			      packets_forwarded,
			      packets_not_forwarded);
	if (copy_to_user(buffer + *total_read, msg, CHAR_DEV_MSG_SIZE)) {
		return false;
	}

	*length -= bytes_read;
	*total_read += bytes_read;

	ws->state++;
	return true;
}

/*
 * Array of write functions that write various elements that correspond to
 * our output state machine.
 */
sfe_ipv4_debug_write_method_t sfe_ipv4_debug_write_methods[] = {
	sfe_ipv4_debug_dev_read_connections_connection,
	sfe_ipv4_debug_dev_read_exceptions_start,
	sfe_ipv4_debug_dev_read_exceptions_exception,
	sfe_ipv4_debug_dev_read_stats,
};

/*
 * sfe_ipv4_debug_dev_read()
 *	Send info to userspace upon read request from user
 */
static ssize_t sfe_ipv4_debug_dev_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
{
	char msg[CHAR_DEV_MSG_SIZE];
	int total_read = 0;
	struct sfe_ipv4_debug_write_state *ws;

	ws = (struct sfe_ipv4_debug_write_state *)filp->private_data;
	while (ws->state < (sizeof(sfe_ipv4_debug_write_methods)/sizeof(sfe_ipv4_debug_write_method_t))
		&& length > CHAR_DEV_MSG_SIZE) {
		if ((sfe_ipv4_debug_write_methods[ws->state])(si, buffer, msg, &length, &total_read, ws)) {
			continue;
		}
	}

	return total_read;
}

/*
 * sfe_ipv4_debug_dev_write()
 *	Write to char device resets some stats
 */
static ssize_t sfe_ipv4_debug_dev_write(struct file *filp, const char *buffer, size_t length, loff_t *offset)
{
	return length;
}

/*
 * sfe_ipv4_debug_dev_open()
 */
static int sfe_ipv4_debug_dev_open(struct inode *inode, struct file *file)
{
	struct sfe_ipv4_debug_write_state *ws;

	ws = (struct sfe_ipv4_debug_write_state *)file->private_data;
	if (!ws) {
		ws = kzalloc(sizeof(struct sfe_ipv4_debug_write_state), GFP_KERNEL);
		if (!ws) {
			return -ENOMEM;
		}

		ws->state = 0;
		ws->iter_exception = 0;
		file->private_data = ws;
	}

	return 0;
}

/*
 * sfe_ipv4_debug_dev_release()
 */
static int sfe_ipv4_debug_dev_release(struct inode *inode, struct file *file)
{
	struct sfe_ipv4_debug_write_state *ws;

	ws = (struct sfe_ipv4_debug_write_state *)file->private_data;
	if (ws) {
		/*
		 * We've finished with our output so free the write state.
		 */
		kfree(ws);
	}

	return 0;
}

/*
 * sfe_ipv4_get_debug_dev()
 */
static ssize_t sfe_ipv4_get_debug_dev(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	return snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", si->debug_dev);
}

/*
 * sysfs attributes.
 */
static const struct device_attribute sfe_ipv4_debug_dev_attr =
	__ATTR(debug_dev, S_IWUGO | S_IRUGO, sfe_ipv4_get_debug_dev, NULL);


/*
 * File operations used in the debug char device
 */
static struct file_operations sfe_ipv4_debug_dev_fops = {
	.read = sfe_ipv4_debug_dev_read,
	.write = sfe_ipv4_debug_dev_write,
	.open = sfe_ipv4_debug_dev_open,
	.release = sfe_ipv4_debug_dev_release
};

int sfe_debug_init(struct sfe_ipv4 *si)
{
	int result;

	/*
	 * Create sys/sfe_ipv4
	 */
	si->sys_sfe_ipv4 = kobject_create_and_add("sfe_ipv4", NULL);
	if (!si->sys_sfe_ipv4) {
		SFE_LOG_ERROR("failed to register sfe_ipv4\n");
		goto exit1;
	}

	/*
	 * Create files, one for each parameter supported by this module.
	 */
	result = sysfs_create_file(si->sys_sfe_ipv4, &sfe_ipv4_debug_dev_attr.attr);
	if (result) {
		SFE_LOG_ERROR("failed to register debug dev file: %d\n", result);
		goto exit2;
	}


	/*
	 * Register our debug char device.
	 */
	result = register_chrdev(0, "sfe_ipv4", &sfe_ipv4_debug_dev_fops);
	if (result < 0) {
		SFE_LOG_ERROR("Failed to register chrdev: %d\n", result);
		goto exit3;
	}
	si->debug_dev = result;

	return 0;

exit3:
	sysfs_remove_file(si->sys_sfe_ipv4, &sfe_ipv4_debug_dev_attr.attr);
exit2:
	kobject_put(si->sys_sfe_ipv4);
exit1:
	return result;
}

void sfe_debug_exit(struct sfe_ipv4 *si)
{
	unregister_chrdev(si->debug_dev, "sfe_ipv4");

	sysfs_remove_file(si->sys_sfe_ipv4, &sfe_ipv4_debug_dev_attr.attr);

	kobject_put(si->sys_sfe_ipv4);
}

