#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "utils.h"

#define HAN_SIG_TIMER            SIGRTMIN+1
#define LOG_MODULE               "core-mon"
#define MAX_LOG_LINE_LEN         256

typedef struct {
    u32 max_count;
    pthread_mutex_t mutex;
    HAN_MSG_QUEUE *queue;
    timer_t *timers;
} HAN_TIMER;

static HAN_TIMER g_han_timer;

static b8 han_post_timer(u32 timerID, HAN_MSG_QUEUE *queue);
static void han_remove_msg(HAN_MSG *msg, HAN_MSG_QUEUE *queue);

static void han_setTimespecRelative(struct timespec *p_ts, long long msec)
{
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *) NULL);

    /* what's really funny about this is that I know
       pthread_cond_timedwait just turns around and makes this
       a relative time again */
    p_ts->tv_sec = tv.tv_sec + (msec / 1000);
    p_ts->tv_nsec = (tv.tv_usec + (msec % 1000) * 1000L ) * 1000L;
}

void _log(int level, const char *format, ...)
{
	char buf[MAX_LOG_LINE_LEN+1];

    if (level < 0 || level > 7) {
        level = 5; // LOG_NOTICE
    }

	va_list ptr;
	va_start(ptr, format);
	vsnprintf(buf, MAX_LOG_LINE_LEN, format, ptr);
	va_end(ptr);

	openlog(LOG_MODULE, 0, LOG_USER);
	syslog(level, "%s", buf);
	closelog();
}

void * han_timer_thread(void * arg)
{
    sigset_t waitset;
    siginfo_t info;
    pthread_t ppid = pthread_self();

    pthread_detach(ppid);

    sigemptyset(&waitset);
    sigaddset(&waitset, HAN_SIG_TIMER);
    while (1) {
        if (sigwaitinfo(&waitset, &info) != -1) {
            u32 timerID = (u32)info.si_value.sival_int;

            pthread_mutex_lock(&g_han_timer.mutex);
            timer_delete(g_han_timer.timers[timerID]);
            g_han_timer.timers[timerID] = HAN_TIMER_INVALID;
            pthread_mutex_unlock(&g_han_timer.mutex);

            han_post_timer(timerID, g_han_timer.queue);
        }
    }

    return NULL;
}

void han_init_timer(u32 max_count, HAN_MSG_QUEUE *queue)
{
    sigset_t bset, oset;
    pthread_t ppid;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 256*1024);

    g_han_timer.max_count = max_count;
    g_han_timer.timers = malloc(max_count * sizeof(timer_t));

    // HAN_TIMER_INVALID
    memset(g_han_timer.timers, 0xff, max_count*sizeof(timer_t));

    pthread_mutex_init(&g_han_timer.mutex, NULL);

    sigemptyset(&bset);
    sigaddset(&bset, HAN_SIG_TIMER);
    if (pthread_sigmask(SIG_BLOCK, &bset, &oset) != 0) {
        _log(LOG_NOTICE, "timer init fail!");
        return;
    }

    g_han_timer.queue = queue;
    pthread_create(&ppid, &attr, han_timer_thread, NULL);
    pthread_attr_destroy(&attr);
}

void han_destroy_timer(void)
{
	u32 i;

	for (i = 0; i < g_han_timer.max_count; i++) {
		if (g_han_timer.timers[i] != HAN_TIMER_INVALID) {
            timer_delete(g_han_timer.timers[i]);
        }
	}

	pthread_mutex_destroy(&g_han_timer.mutex);

    han_free(g_han_timer.timers);
}

void han_start_timer(u32 timerID, u32 timeMSec)
{
	struct sigevent se;
	struct itimerspec ts;
    HAN_MSG msg;

	if (timerID >= g_han_timer.max_count || timeMSec == 0) {
        return;
    }

	msg.msgID = timerID;
	msg.msgType = HAN_MSG_TYPE_TIMER;
	han_remove_msg(&msg, g_han_timer.queue);

    pthread_mutex_lock(&g_han_timer.mutex);

	if (g_han_timer.timers[timerID] == HAN_TIMER_INVALID) {
		memset(&se, 0, sizeof(se));
		se.sigev_notify = SIGEV_SIGNAL;
		se.sigev_signo = HAN_SIG_TIMER;
        se.sigev_value.sival_int = timerID;

		if (timer_create(CLOCK_REALTIME, &se, &g_han_timer.timers[timerID]) < 0) {
            _log(LOG_NOTICE, "timer create failed");
			pthread_mutex_unlock(&g_han_timer.mutex);
			return;
		}
	}

	ts.it_value.tv_sec = timeMSec / 1000;
	ts.it_value.tv_nsec = (timeMSec % 1000) * 1000000;
	ts.it_interval.tv_sec = 0;
	ts.it_interval.tv_nsec = 0;
	if (timer_settime(g_han_timer.timers[timerID], 0, &ts, NULL) < 0) {
        _log(LOG_NOTICE, "timer set failed");
	}
	pthread_mutex_unlock(&g_han_timer.mutex);
}

u32 han_read_left_timer(u32 timerID)
{
	u32 left = 0;
	struct itimerspec ts;

	pthread_mutex_lock(&g_han_timer.mutex);

	if (g_han_timer.timers[timerID] != HAN_TIMER_INVALID) {
		timer_gettime(g_han_timer.timers[timerID], &ts);
		left = ts.it_value.tv_sec * 1000 + ts.it_value.tv_nsec / 1000000;
	}

	pthread_mutex_unlock(&g_han_timer.mutex);

	return left;
}

void han_stop_timer(u32 timerID)
{
    HAN_MSG msg;

	if (timerID >= g_han_timer.max_count) {
        return;
    }

    pthread_mutex_lock(&g_han_timer.mutex);

	if (g_han_timer.timers[timerID] != HAN_TIMER_INVALID)
	{
		struct itimerspec ts;

		ts.it_value.tv_sec = 0;
		ts.it_value.tv_nsec = 0;
		ts.it_interval.tv_sec = 0;
		ts.it_interval.tv_nsec = 0;
		timer_settime(g_han_timer.timers[timerID], 0, &ts, NULL);
		timer_delete(g_han_timer.timers[timerID]);
	}
	g_han_timer.timers[timerID] = HAN_TIMER_INVALID;
	pthread_mutex_unlock(&g_han_timer.mutex);

    msg.msgID = timerID;
	msg.msgType = HAN_MSG_TYPE_TIMER;
	han_remove_msg(&msg, g_han_timer.queue);
}

HAN_MSG_QUEUE * han_init_msg(u32 timeout)
{
	HAN_MSG_QUEUE *queue;

	queue = malloc(sizeof(HAN_MSG_QUEUE));
    if (queue == NULL) {
        return NULL;
    }
	memset(queue, 0, sizeof(HAN_MSG_QUEUE));

	pthread_mutex_init(&queue->mutex, NULL);
	pthread_cond_init(&queue->cond, NULL);
	queue->timeout = timeout;

	return queue;
}

void han_destroy_msg(HAN_MSG_QUEUE *queue)
{
	HAN_MSG *curMsg;

	if (queue == NULL) {
        return;
    }

	while (queue->pHead) {
		curMsg = queue->pHead;
		queue->pHead = queue->pHead->pNext;
		han_free(curMsg);
	}

	pthread_mutex_destroy(&queue->mutex);
	pthread_cond_destroy(&queue->cond);

    han_free(queue);
}

static void han_remove_msg(HAN_MSG *msg, HAN_MSG_QUEUE *queue)
{
	HAN_MSG *curMsg, *preMsg = NULL, *freeMsg;

	if (queue == NULL || queue->pHead == NULL) {
        return;
    }

	pthread_mutex_lock(&queue->mutex);

	curMsg = queue->pHead;

	while (curMsg) {
        if ((curMsg->msgType == msg->msgType) && (curMsg->msgID == msg->msgID)) {
            freeMsg = curMsg;

            if (curMsg->pNext == NULL) {
                queue->pTail = preMsg;
            }

            if (preMsg == NULL) {
                queue->pHead = curMsg->pNext;
            } else {
                preMsg->pNext = curMsg->pNext;
            }

            curMsg = curMsg->pNext;
            free(freeMsg);
        } else {
            preMsg = curMsg;
            curMsg = curMsg->pNext;
        }
	}
	pthread_mutex_unlock(&queue->mutex);
}

void han_put_msg(HAN_MSG *curMsg, HAN_MSG_QUEUE *queue)
{
	if (queue == NULL || curMsg == NULL) {
        return;
    }

	pthread_mutex_lock(&queue->mutex);

	curMsg->pNext = NULL;
	if (queue->pHead == NULL) {
		queue->pHead = curMsg;
		queue->pTail = curMsg;
	} else {
		queue->pTail->pNext = curMsg;
		queue->pTail = curMsg;
	}

	pthread_cond_signal(&queue->cond);
	pthread_mutex_unlock(&queue->mutex);
}

HAN_MSG *han_get_msg(HAN_MSG_QUEUE *queue)
{
	HAN_MSG *curMsg = NULL;

	if (queue == NULL) {
        return NULL;
    }

	pthread_mutex_lock(&queue->mutex);

    // if no msg, block
	if (queue->pHead == NULL) {
		if (queue->timeout != 0) {
            struct timespec ts;

	        han_setTimespecRelative(&ts, queue->timeout);
	        pthread_cond_timedwait(&queue->cond, &queue->mutex, &ts);
		} else {
            // block-->unlock-->wait() return-->lock
            pthread_cond_wait(&queue->cond, &queue->mutex);
        }
	}

	if (queue->pHead) {
		curMsg = queue->pHead;
		queue->pHead = queue->pHead->pNext;
		curMsg->pNext = NULL;
	}

	pthread_mutex_unlock(&queue->mutex);

	return curMsg;
}

b8 han_post_event(u32 eventID, void *pParam, u32 paramSize, HAN_MSG_QUEUE *queue)
{
    if (queue == NULL) {
        return FALSE;
    }

	HAN_MSG *curMsg = malloc(sizeof(HAN_MSG) + paramSize);
    if (curMsg == NULL) {
        return FALSE;
    }

	u8 *pParamPtr = (u8 *) curMsg + sizeof(HAN_MSG);

	memset(curMsg, 0, sizeof(HAN_MSG));
	curMsg->msgType = HAN_MSG_TYPE_EVENT;
	curMsg->msgID = eventID;
	curMsg->size = paramSize;
	if (paramSize) {
        memcpy(pParamPtr, pParam, paramSize);
    }

	han_put_msg(curMsg, queue);
	return TRUE;
}

b8 han_post_stat(u32 objID, u32 stat, HAN_MSG_QUEUE *queue)
{
    if (queue == NULL) {
        return FALSE;
    }

	HAN_MSG *curMsg = malloc(sizeof(HAN_MSG));
    if (curMsg == NULL) {
        return FALSE;
    }

	memset(curMsg, 0, sizeof(HAN_MSG));
	curMsg->msgType = HAN_MSG_TYPE_STAT;
	curMsg->msgID = objID;
	curMsg->status = stat;

	han_put_msg(curMsg, queue);
	return TRUE;
}

b8 han_post_exit(HAN_MSG_QUEUE *queue)
{
    if (queue == NULL) {
        return FALSE;
    }

    HAN_MSG *curMsg = malloc(sizeof(HAN_MSG));
    if (curMsg == NULL) {
        return FALSE;
    }

    memset(curMsg, 0, sizeof(HAN_MSG));
    curMsg->msgType = HAN_MSG_TYPE_EXIT;
    curMsg->msgID = 0;
    curMsg->status = 0;

    han_put_msg(curMsg, queue);
    return TRUE;
}

static b8 han_post_timer(u32 timerID, HAN_MSG_QUEUE *queue)
{
    if (queue == NULL) {
        return FALSE;
    }

	HAN_MSG *curMsg = malloc(sizeof(HAN_MSG));
    if (curMsg == NULL) {
        return FALSE;
    }

	memset(curMsg, 0, sizeof(HAN_MSG));
	curMsg->msgType = HAN_MSG_TYPE_TIMER;
	curMsg->msgID = timerID;

	han_put_msg(curMsg, queue);
	return TRUE;
}

b8 han_post_data(u32 dataID, void *pData, u32 size, HAN_MSG_QUEUE *queue)
{
    if (queue == NULL) {
        return FALSE;
    }

	HAN_MSG *curMsg = malloc(sizeof(HAN_MSG) + size);
    if (curMsg == NULL) {
        return FALSE;
    }

	u8 *pDataPtr = (u8 *) curMsg + sizeof(HAN_MSG);

	memset(curMsg, 0, sizeof(HAN_MSG));
	curMsg->msgType = HAN_MSG_TYPE_DATA;
	curMsg->msgID = dataID;
	curMsg->size = size;
	if (size) {
        memcpy(pDataPtr, pData, size);
    }

	han_put_msg(curMsg, queue);
	return TRUE;
}

void han_sleep(long long msec)
{
    struct timespec ts;
    int err;

    ts.tv_sec = (msec / 1000);
    ts.tv_nsec = (msec % 1000) * 1000 * 1000;

    do {
        err = nanosleep (&ts, &ts);
    } while (err < 0 && errno == EINTR);
}

u32 han_get_ms(void)
{
	struct timespec tp;

	clock_gettime(CLOCK_MONOTONIC, &tp);
	return (u32)(tp.tv_sec * 1000 + tp.tv_nsec / 1000000);
}

s32 han_get_random(void)
{
    struct timespec tp;

    clock_gettime(CLOCK_MONOTONIC, &tp);
    srand(tp.tv_nsec);

    return rand();
}

void han_free(void *pPtr)
{
	if (pPtr) {
        free(pPtr);
        pPtr = NULL;
    }
}

