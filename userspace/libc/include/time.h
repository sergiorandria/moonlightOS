/* Moonlight libc - time / sys/time / limits / ctype / assert. */
#pragma once

#include <sys/types.h>

struct timespec {
    time_t tv_sec;
    long tv_nsec;
};

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_BOOTTIME 7

struct itimerspec {
    struct timespec it_interval;
    struct timespec it_value;
};

typedef int timer_t;
#define TIMER_ABSTIME 1

struct sigevent;

int timer_create(int clockid, struct sigevent *ev, timer_t *id);
int timer_settime(timer_t id, int flags, const struct itimerspec *newv,
                  struct itimerspec *oldv);
int timer_gettime(timer_t id, struct itimerspec *cur);
int timer_getoverrun(timer_t id);
int timer_delete(timer_t id);

int clock_gettime(clockid_t id, struct timespec *ts);
int clock_getres(clockid_t id, struct timespec *ts);
int clock_nanosleep(clockid_t id, int flags, const struct timespec *req,
                    struct timespec *rem);
time_t time(time_t *t);
struct tm *gmtime(const time_t *t);
struct tm *gmtime_r(const time_t *t, struct tm *tm);
struct tm *localtime(const time_t *t);
struct tm *localtime_r(const time_t *t, struct tm *tm);
time_t mktime(struct tm *tm);
time_t timegm(struct tm *tm);
double difftime(time_t a, time_t b);
char *asctime(const struct tm *tm);
char *asctime_r(const struct tm *tm, char *buf);
char *ctime(const time_t *t);
char *ctime_r(const time_t *t, char *buf);
size_t strftime(char *s, size_t n, const char *fmt, const struct tm *tm);
char *strptime(const char *s, const char *fmt, struct tm *tm);
struct tm *getdate(const char *s);
extern int getdate_err;
int nanosleep(const struct timespec *req, struct timespec *rem);
int timespec_get(struct timespec *ts, int base);
#define TIME_UTC 1
