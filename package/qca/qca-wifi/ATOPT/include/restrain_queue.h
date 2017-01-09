#ifndef __RESTRAIN_QUEUE
#define __RESTRAIN_QUEUE
#include <linux/skbuff.h>

struct restrain_queue {
	spinlock_t q_lock;
	u_int32_t   q_len;
	struct sk_buff *q_whead;
	struct sk_buff *q_wtail;
	u_int16_t   q_max_len;
};
#define PER_CHANNEL_QUEUE_MAX_LENTH 150
#define CHANNEL_2G	14
#define CHANNEL_5G	25
extern struct restrain_queue restrain_q_2g[CHANNEL_2G];
extern struct restrain_queue restrain_q_5g[CHANNEL_5G];

void 
init_restrain_q(bool is_2g);
void 
destroy_restrain_q(bool is_2g);
void 
queue_restrain_q(int channel, struct sk_buff *skb);
struct sk_buff *
dequeue_restrain_q(int channel);
int 
restrain_q_len(int channel);




#endif

