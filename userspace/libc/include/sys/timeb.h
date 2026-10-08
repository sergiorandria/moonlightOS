/* Moonlight libc - sys/timeb (ftime over clock_gettime). */
#pragma once

#include <time.h>

struct timeb {
    time_t time;
    unsigned short millitm;
    short timezone;
    short dstflag;
};

int ftime(struct timeb *tb);
