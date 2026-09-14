/* Moonlight libc - mqueue (in-process queues; named queues persist
 * as VFS files holding the queue parameters). */
#pragma once

#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>

typedef int mqd_t;

struct mq_attr {
    long mq_flags;
    long mq_maxmsg;
    long mq_msgsize;
    long mq_curmsgs;
};

mqd_t mq_open(const char *name, int flags, ...);
int mq_close(mqd_t q);
int mq_unlink(const char *name);
int mq_send(mqd_t q, const char *msg, unsigned n, unsigned prio);
int mq_receive(mqd_t q, char *msg, unsigned n, unsigned *prio);
int mq_timedsend(mqd_t q, const char *msg, unsigned n, unsigned prio,
                 const struct timespec *ts);
int mq_timedreceive(mqd_t q, char *msg, unsigned n, unsigned *prio,
                    const struct timespec *ts);
int mq_notify(mqd_t q, const struct sigevent *ev);
int mq_getattr(mqd_t q, struct mq_attr *a);
int mq_setattr(mqd_t q, const struct mq_attr *a, struct mq_attr *old);
