#ifndef UTILS_H
#define UTILS_H

#include <pthread.h>

typedef unsigned char       b8;
typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef signed char         s8;
typedef signed short        s16;
typedef signed int          s32;
typedef float               f32;
typedef double              f64;
typedef unsigned long long  u64;

#ifndef TRUE
enum {
    FALSE = 0,
    TRUE,
};
#endif

#define HAN_TIMER_INVALID       ((timer_t)0xFFFFFFFF)

enum {
    HAN_MSG_TYPE_TIMER = 0,
    HAN_MSG_TYPE_EVENT,
    HAN_MSG_TYPE_DATA,
    HAN_MSG_TYPE_STAT,
    HAN_MSG_TYPE_EXIT,

    HAN_MSG_TYPE_MAX
};

typedef enum {
    LOG_DISABLE = 0,
    LOG_FILE,
    LOG_PRINTF
} HAN_LOG_MODE;

typedef struct _han_message_ {
    u32 msgType;
    u32 msgID;
    union {
        u32 status;
        u32 size;
    };
    struct _han_message_ *pNext;
} HAN_MSG;

typedef struct {
    HAN_MSG *pHead;
    HAN_MSG *pTail;
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    u32 timeout; //in second
} HAN_MSG_QUEUE;


HAN_MSG_QUEUE * han_init_msg(u32 timeout /*in second, 0: no timeout*/);
void han_destroy_msg(HAN_MSG_QUEUE *queue);
void han_put_msg(HAN_MSG *curMsg, HAN_MSG_QUEUE *queue);
HAN_MSG *han_get_msg(HAN_MSG_QUEUE *queue);

b8 han_post_event(u32 eventID, void *pParam, u32 paramSize, HAN_MSG_QUEUE *queue);
b8 han_post_stat(u32 objID, u32 stat, HAN_MSG_QUEUE *queue);
b8 han_post_data(u32 dataID, void *pData, u32 size, HAN_MSG_QUEUE *queue);
b8 han_post_exit(HAN_MSG_QUEUE *queue);

void han_init_timer(u32 max_count, HAN_MSG_QUEUE *queue);
void han_destroy_timer();
void han_start_timer(u32 timerID, u32 interval);
void han_stop_timer(u32 timerID);
u32  han_read_left_timer(u32 timerID);

void han_sleep(long long msec);
u32 han_get_ms(void);  //get millisecond
u32 han_get_device_id(void);
int han_get_heartbeat_interval(void);

int han_get_ieee(char *ieee);
s32 han_get_random(void);

void _log(int level, const char *format, ...);
void han_free(void *pPtr);


#endif // UTILS_H
