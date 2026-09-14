/* Moonlight libc - sys/resource + sys/times + sys/uio + statvfs +
 * utime + sys/random. */
#pragma once

#include <sys/types.h>
#include <sys/time.h>

typedef unsigned long long rlim_t;

struct rlimit {
    rlim_t rlim_cur;
    rlim_t rlim_max;
};

struct rusage {
    struct timeval ru_utime;
    struct timeval ru_stime;
    long ru_maxrss;
    long ru_ixrss;
    long ru_idrss;
    long ru_isrss;
    long ru_minflt;
    long ru_majflt;
    long ru_nswap;
    long ru_inblock;
    long ru_oublock;
    long ru_msgsnd;
    long ru_msgrcv;
    long ru_nsignals;
    long ru_nvcsw;
    long ru_nivcsw;
};

#define RUSAGE_SELF 0
#define RUSAGE_CHILDREN (-1)
#define RLIMIT_CPU 0
#define RLIMIT_FSIZE 1
#define RLIMIT_DATA 2
#define RLIMIT_STACK 3
#define RLIMIT_CORE 4
#define RLIMIT_RSS 5
#define RLIMIT_NOFILE 7
#define RLIMIT_AS 9
#define RLIM_INFINITY ((rlim_t)-1)
#define RLIM_SAVED_CUR ((rlim_t)-2)
#define RLIM_SAVED_MAX ((rlim_t)-3)

int getrusage(int who, struct rusage *r);
int getrlimit(int res, struct rlimit *r);
int setrlimit(int res, const struct rlimit *r);
int getpriority(int which, id_t who);
int setpriority(int which, id_t who, int prio);
#define PRIO_PROCESS 0
#define PRIO_PGRP 1
#define PRIO_USER 2
