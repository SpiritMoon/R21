
#include "restrain_queue.h"


struct restrain_queue restrain_q_2g[CHANNEL_2G];
struct restrain_queue restrain_q_5g[CHANNEL_5G];

#define INIT_RESTRAIN_QUEUE(_q) do { \
		spin_lock_init(&(_q)->q_lock); \
		(_q)->q_len = 0; \
		(_q)->q_whead = (_q)->q_wtail = NULL; \
	} while(0)

#define ENQUEUE_RESTRAIN_QUEUE(_q, _w) do { \
    (_w)->next = NULL; \
    if ((_q)->q_wtail != NULL) { \
        (_q)->q_wtail->next = (_w); \
        (_q)->q_wtail = _w; \
    } else { \
        (_q)->q_whead =  (_q)->q_wtail =  _w; \
    } \
	++(_q)->q_len; \
} while (0)

#define DEQUEUE_RESTRAIN_DEQUEUE(_q, _w) do { \
    _w = (_q)->q_whead; \
    if (_w) { \
        (_q)->q_whead =  (_w)->next; \
        (_w)->next = NULL; \
        if ( (_q)->q_whead ==  NULL) \
            (_q)->q_wtail =  NULL; \
        --(_q)->q_len; \
    } \
} while (0)

static int
arry_index(int channel)
{
	if (channel >= 1 && channel <= 14)
		return (channel - 1);
#if 0
	else if (channel >= 36 && channel <= 64)
		return (channel / 4 - 9);
	else if (channel >= 100 && channel <= 165)
		return (channel / 4 - 17);
#endif //not yet for 5G
	else 
		return -1;
}

static bool is_2g_channel(int channel)
{
	return (channel <= 14);
}


int restrain_q_len(int channel)
{
	int index = arry_index(channel);
	struct restrain_queue *q = is_2g_channel(channel) ? restrain_q_2g : restrain_q_5g;
	
	if (-1 != index)
		return q[index].q_len;
	return PER_CHANNEL_QUEUE_MAX_LENTH + 1; //channel is wrong, don't insert into queue
}


void queue_restrain_q(int channel, struct sk_buff *skb)
{
	int index = arry_index(channel);
	struct restrain_queue *q = is_2g_channel(channel) ? restrain_q_2g : restrain_q_5g;

	if (-1 != index) {
		spin_lock_bh(&q[index].q_lock);
		ENQUEUE_RESTRAIN_QUEUE(&q[index], skb);
		spin_unlock_bh(&q[index].q_lock);
	} else {
        dev_kfree_skb(skb); //should free here	
    }
	
}

struct sk_buff *
dequeue_restrain_q(int channel)
{
	int index = arry_index(channel);
	struct restrain_queue *q = is_2g_channel(channel) ? restrain_q_2g : restrain_q_5g;
	struct sk_buff *skb = NULL;

	if (-1 != index) {
		spin_lock(&q[index].q_lock);
		DEQUEUE_RESTRAIN_DEQUEUE(&q[index], skb);
		spin_unlock(&q[index].q_lock);
	}
	return skb;
	
}

void 
init_restrain_q(bool is_2g)
{
	struct restrain_queue *q = (is_2g) ? restrain_q_2g : restrain_q_5g;
	int i = 0, ch_num;

	if (is_2g)
		ch_num = sizeof(restrain_q_2g) / sizeof(struct restrain_queue);
	else
		ch_num = sizeof(restrain_q_5g) / sizeof(struct restrain_queue);

	for (; i < ch_num; i++)
		INIT_RESTRAIN_QUEUE(&q[i]);
}

void 
destroy_restrain_q(bool is_2g)
{
	struct restrain_queue *q = (is_2g) ? restrain_q_2g : restrain_q_5g;
	int i = 0, ch_num;
	struct sk_buff *skb = NULL;

	if (is_2g)
		ch_num = sizeof(restrain_q_2g) / sizeof(struct restrain_queue);
	else
		ch_num = sizeof(restrain_q_5g) / sizeof(struct restrain_queue);

	for (; i < ch_num; i++) {
		spin_lock_bh(&q[i].q_lock);
		while(q[i].q_len) {
			DEQUEUE_RESTRAIN_DEQUEUE(&q[i], skb);
			if (skb) {
				dev_kfree_skb(skb);
				skb = NULL;
			}
		}
		spin_unlock_bh(&q[i].q_lock);
	}

}
