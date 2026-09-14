/* Moonlight libc - sys/time. */
#pragma once

#include <sys/types.h>

#ifndef __ML_TIMEVAL_DEFINED
#define __ML_TIMEVAL_DEFINED 1
struct timeval {
    time_t tv_sec;
    long tv_usec;
};
#endif

int gettimeofday(struct timeval *tv, void *tz);
int setitimer(int which, const void *newv, void *oldv);
int getitimer(int which, void *cur);
#define ITIMER_REAL 0
#define ITIMER_VIRTUAL 1
#define ITIMER_PROF 2

struct itimerval {
    struct timeval it_interval;
    struct timeval it_value;
};

unsigned ualarm(unsigned us, unsigned interval);
