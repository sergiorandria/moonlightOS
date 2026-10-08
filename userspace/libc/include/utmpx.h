/* Moonlight libc - utmpx.h (user accounting database;
 * file-backed at /var/run/utmp, implemented in src/utmpx.c). */
#pragma once

#include <sys/types.h>
#include <time.h>

#define UT_LINESIZE 32
#define UT_NAMESIZE 32
#define UT_HOSTSIZE 256

#define EMPTY 0
#define RUN_LVL 1
#define BOOT_TIME 2
#define NEW_TIME 3
#define OLD_TIME 4
#define INIT_PROCESS 5
#define LOGIN_PROCESS 6
#define USER_PROCESS 7
#define DEAD_PROCESS 8
#define ACCOUNTING 9

struct utmpx {
    short ut_type;
    pid_t ut_pid;
    char ut_line[UT_LINESIZE];
    char ut_id[4];
    char ut_user[UT_NAMESIZE];
    char ut_host[UT_HOSTSIZE];
    struct {
        int32_t tv_sec;
        int32_t tv_usec;
    } ut_tv;
    int32_t ut_session;
    struct {
        int32_t e_termination;
        int32_t e_exit;
    } ut_exit;
};

struct utmpx *getutxent(void);
struct utmpx *getutxid(const struct utmpx *id);
struct utmpx *getutxline(const struct utmpx *line);
struct utmpx *pututxline(const struct utmpx *ut);
void setutxent(void);
void endutxent(void);
int utmpxname(const char *file);
