/* Moonlight libc - sys/timerfd.h (timers as fds, manager
 * thread + pipe; implemented in src/sysevent.c). */
#pragma once

#include <time.h>

#define TFD_CLOEXEC 02000000
#define TFD_NONBLOCK 04000
#define TFD_TIMER_ABSTIME 1
#define TFD_TIMER_CANCEL_ON_SET 2

int timerfd_create(int clockid, int flags);
int timerfd_settime(int fd, int flags, const struct itimerspec *newv,
                    struct itimerspec *oldv);
int timerfd_gettime(int fd, struct itimerspec *cur);
