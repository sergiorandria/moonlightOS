/* Moonlight libc - poll/select/epoll over the kernel readiness core. */
#pragma once

#include <sys/types.h>
#include <time.h>

struct pollfd {
    int fd;
    short events;
    short revents;
};

#define POLLIN 0x001
#define POLLPRI 0x002
#define POLLOUT 0x004
#define POLLERR 0x008
#define POLLHUP 0x010
#define POLLNVAL 0x020
#define POLLRDNORM POLLIN
#define POLLWRNORM POLLOUT

typedef struct {
    long bits[1];
} fd_set;

#define FD_SETSIZE 32
void FD_CLR(int fd, fd_set *s);
int FD_ISSET(int fd, fd_set *s);
void FD_SET(int fd, fd_set *s);
void FD_ZERO(fd_set *s);

#ifndef __ML_TIMEVAL_DEFINED
#define __ML_TIMEVAL_DEFINED 1
struct timeval {
    long tv_sec;
    long tv_usec;
};
#endif

int poll(struct pollfd *fds, unsigned nfds, int timeout_ms);
int select(int nfds, fd_set *r, fd_set *w, fd_set *e,
           struct timeval *timeout);
int pselect(int nfds, fd_set *r, fd_set *w, fd_set *e,
            const struct timespec *timeout, const void *sigmask);

#define EPOLLIN 0x001
#define EPOLLPRI 0x002
#define EPOLLOUT 0x004
#define EPOLLERR 0x008
#define EPOLLHUP 0x010
#define EPOLLET (1u << 31)
#define EPOLLONESHOT (1u << 30)
#define EPOLL_CLOEXEC 02000000
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

typedef union {
    void *ptr;
    int fd;
    unsigned u32;
    unsigned long long u64;
} epoll_data_t;

struct epoll_event {
    unsigned events;
    epoll_data_t data;
};

int epoll_create(int n);
int epoll_create1(int flags);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev);
int epoll_wait(int epfd, struct epoll_event *ev, int maxev,
               int timeout_ms);
int epoll_pwait(int epfd, struct epoll_event *ev, int maxev,
                int timeout_ms, const void *sigmask);
