/* libc poll/select/epoll over the kernel readiness core. epoll fds
 * are real kernel objects (pipe-backed event queues); the interest
 * list lives in libc, readiness is re-polled per wait. */
#include <poll.h>
#include <sys/epoll.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <bits/ml_sys.h>
#include <bits/ml_fd.h>

long __ml_ret(long r);

__attribute__((weak)) int __ml_fd_poll(int fd, short *revents);

/* Query managed-fd readiness for one entry; 1 if hook handled it. */
static int ml_poll_managed(struct pollfd *p) {
    short rev = 0;
    int r;
    if (!__ml_fd_poll) return 0;
    p->revents = 0;
    r = __ml_fd_poll(p->fd, &rev);
    if (r == -2) return 0;
    if (r != 0) {
        p->revents = POLLNVAL;
        return 1;
    }
    p->revents = (short)(rev & p->events);
    if ((rev & (POLLERR | POLLHUP | POLLNVAL)) &&
        !(p->events & (POLLERR | POLLHUP | POLLNVAL)))
        p->revents |= (short)(rev & (POLLERR | POLLHUP | POLLNVAL));
    return 1;
}

int poll(struct pollfd *fds, unsigned nfds, int timeout_ms) {
    long long to = -1;
    long r;
    unsigned i, nmanaged = 0;
    if (timeout_ms < -1) {
        errno = EINVAL;
        return -1;
    }
    if (timeout_ms >= 0) to = (long long)timeout_ms * 1000000LL;
    if (nfds > 0 && !fds) {
        errno = EFAULT;
        return -1;
    }
    for (i = 0; i < nfds; i++)
        if (fds[i].fd >= ML_FD_BASE) nmanaged++;
    if (nmanaged == 0) {
        struct {
            long sec;
            long nsec;
        } ts, *tp = 0;
        if (timeout_ms >= 0) {
            ts.sec = timeout_ms / 1000;
            ts.nsec = (long)(timeout_ms % 1000) * 1000000L;
            tp = &ts;
        }
        r = __ml_call6(LX_SYS_ppoll, (long)fds, (long)nfds, (long)tp,
                       0, 0, 0);
        return (int)__ml_ret(r);
    }
    /* Mixed set: slice the wait, polling managed fds in-process and
     * kernel fds with a zero-timeout ppoll each round. */
    {
        struct timespec start, now;
        long long deadline = 0;
        int infinite = timeout_ms < 0;
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (!infinite)
            deadline = start.tv_sec * 1000000000LL + start.tv_nsec + to;
        for (;;) {
            int ready = 0;
            for (i = 0; i < nfds; i++) {
                if (fds[i].fd >= ML_FD_BASE) {
                    ml_poll_managed(&fds[i]);
                    if (fds[i].revents) ready++;
                } else {
                    fds[i].revents = 0;
                }
            }
            /* Kernel subset, non-blocking. */
            {
                struct pollfd kf[64];
                unsigned kn = 0, j;
                struct {
                    long sec;
                    long nsec;
                } zts = {0, 0};
                for (i = 0; i < nfds && kn < 64; i++)
                    if (fds[i].fd < ML_FD_BASE) kf[kn++] = fds[i];
                if (kn) {
                    r = __ml_call6(LX_SYS_ppoll, (long)kf, (long)kn,
                                   (long)&zts, 0, 0, 0);
                    if (r > 0) {
                        for (i = 0, j = 0; i < nfds; i++) {
                            if (fds[i].fd < ML_FD_BASE) {
                                fds[i].revents = kf[j++].revents;
                                if (fds[i].revents) ready++;
                            }
                        }
                    } else if (r < 0) {
                        long e = __ml_ret(r);
                        if (e != 0 && errno != EINTR && errno != EAGAIN)
                            return -1;
                    }
                }
            }
            if (ready) return ready;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (!infinite &&
                now.tv_sec * 1000000000LL + now.tv_nsec >= deadline)
                return 0;
            {
                struct timespec sl = {0, 2000000L}; /* 2ms slice */
                nanosleep(&sl, 0);
            }
        }
    }
}

void FD_CLR(int fd, fd_set *s) {
    if (s && fd >= 0 && fd < FD_SETSIZE) s->bits[0] &= ~(1L << fd);
}

int FD_ISSET(int fd, fd_set *s) {
    if (!s || fd < 0 || fd >= FD_SETSIZE) return 0;
    return (s->bits[0] & (1L << fd)) ? 1 : 0;
}

void FD_SET(int fd, fd_set *s) {
    if (s && fd >= 0 && fd < FD_SETSIZE) s->bits[0] |= 1L << fd;
}

void FD_ZERO(fd_set *s) {
    if (s) s->bits[0] = 0;
}

static int ml_select_common(int nfds, fd_set *r, fd_set *w, fd_set *e,
                            long long timeout_ns) {
    /* Convert fd_sets to a poll list, wait, write back readiness. */
    struct pollfd pf[FD_SETSIZE];
    unsigned n = 0, i;
    long rc;
    long long to = timeout_ns;
    if (nfds < 0 || nfds > FD_SETSIZE) {
        errno = EINVAL;
        return -1;
    }
    for (i = 0; i < (unsigned)nfds; i++) {
        short ev = 0;
        if (r && FD_ISSET((int)i, r)) ev |= POLLIN;
        if (w && FD_ISSET((int)i, w)) ev |= POLLOUT;
        if (e && FD_ISSET((int)i, e)) ev |= POLLPRI;
        if (!ev) continue;
        pf[n].fd = (int)i;
        pf[n].events = ev;
        pf[n].revents = 0;
        n++;
    }
    {
        struct {
            long sec;
            long nsec;
        } ts, *tp = 0;
        if (to >= 0) {
            ts.sec = (long)(to / 1000000000LL);
            ts.nsec = (long)(to % 1000000000LL);
            tp = &ts;
        }
        /* pselect6(fd-less form): use ppoll directly on our list. */
        rc = __ml_call6(LX_SYS_ppoll, (long)pf, (long)n, (long)tp, 0,
                        0, 0);
        if (__ml_ret(rc) != 0 && rc < 0) return -1;
    }
    {
        int ready = 0;
        if (r) FD_ZERO(r);
        if (w) FD_ZERO(w);
        if (e) FD_ZERO(e);
        for (i = 0; i < n; i++) {
            int hit = 0;
            if ((pf[i].revents & (POLLIN | POLLERR | POLLHUP)) && r) {
                FD_SET(pf[i].fd, r);
                hit = 1;
            }
            if ((pf[i].revents & POLLOUT) && w) {
                FD_SET(pf[i].fd, w);
                hit = 1;
            }
            if ((pf[i].revents & POLLPRI) && e) {
                FD_SET(pf[i].fd, e);
                hit = 1;
            }
            if (hit) ready++;
        }
        return ready;
    }
}

int select(int nfds, fd_set *r, fd_set *w, fd_set *e,
           struct timeval *timeout) {
    long long to = -1;
    if (timeout) {
        if (timeout->tv_sec < 0 || timeout->tv_usec < 0 ||
            timeout->tv_usec >= 1000000) {
            errno = EINVAL;
            return -1;
        }
        to = timeout->tv_sec * 1000000000LL +
             timeout->tv_usec * 1000LL;
    }
    return ml_select_common(nfds, r, w, e, to);
}

int pselect(int nfds, fd_set *r, fd_set *w, fd_set *e,
            const struct timespec *timeout, const void *sigmask) {
    long long to = -1;
    (void)sigmask;
    if (timeout) {
        if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 ||
            timeout->tv_nsec >= 1000000000L) {
            errno = EINVAL;
            return -1;
        }
        to = timeout->tv_sec * 1000000000LL + timeout->tv_nsec;
    }
    return ml_select_common(nfds, r, w, e, to);
}

/* ---- epoll: interest list in libc, readiness via poll ---- */

#define ML_EPOLL_MAX 16
typedef struct {
    int used;
    int flags;
    struct {
        int fd;
        unsigned events;
        epoll_data_t data;
    } items[FD_SETSIZE];
    unsigned n;
} ml_epoll_t;

static ml_epoll_t ml_eps[ML_EPOLL_MAX];
static int ml_ep_lock = 0;

static void ml_ep_lock_fn(void) {
    while (__sync_lock_test_and_set(&ml_ep_lock, 1)) sched_yield();
}

static void ml_ep_unlock_fn(void) {
    __sync_lock_release(&ml_ep_lock);
}

int epoll_create(int n) {
    (void)n;
    return epoll_create1(0);
}

int epoll_create1(int flags) {
    int i, pfd[2];
    if (flags & ~EPOLL_CLOEXEC) {
        errno = EINVAL;
        return -1;
    }
    if (pipe2(pfd, flags & EPOLL_CLOEXEC ? O_CLOEXEC : 0) != 0)
        return -1;
    /* The pipe's read end is the epoll fd (never written; the number
     * just needs to be a live fd). Stash the table slot in libc. */
    ml_ep_lock_fn();
    for (i = 0; i < ML_EPOLL_MAX; i++) {
        if (!ml_eps[i].used) {
            ml_eps[i].used = 1;
            ml_eps[i].flags = flags;
            ml_eps[i].n = 0;
            close(pfd[1]);
            ml_ep_unlock_fn();
            return pfd[0];
        }
    }
    ml_ep_unlock_fn();
    close(pfd[0]);
    close(pfd[1]);
    errno = ENOMEM;
    return -1;
}

static ml_epoll_t *ml_ep_find(int epfd, int *slot_out) {
    /* epfds are pipe read ends; find our table by scanning is
     * impossible from the number alone, so keep a parallel map. */
    static int ml_ep_fdmap[ML_EPOLL_MAX];
    static int ml_ep_init = 0;
    int i;
    if (!ml_ep_init) {
        for (i = 0; i < ML_EPOLL_MAX; i++) ml_ep_fdmap[i] = -1;
        ml_ep_init = 1;
    }
    for (i = 0; i < ML_EPOLL_MAX; i++) {
        if (ml_eps[i].used && ml_ep_fdmap[i] == epfd) {
            if (slot_out) *slot_out = i;
            return &ml_eps[i];
        }
    }
    /* First lookup after create: adopt the fd into the newest free
     * mapping. */
    for (i = 0; i < ML_EPOLL_MAX; i++) {
        if (ml_eps[i].used && ml_ep_fdmap[i] == -1) {
            ml_ep_fdmap[i] = epfd;
            if (slot_out) *slot_out = i;
            return &ml_eps[i];
        }
    }
    return 0;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev) {
    ml_epoll_t *ep;
    unsigned i;
    ml_ep_lock_fn();
    ep = ml_ep_find(epfd, 0);
    if (!ep) {
        ml_ep_unlock_fn();
        errno = EBADF;
        return -1;
    }
    if (op == EPOLL_CTL_ADD) {
        if (!ev || ep->n >= FD_SETSIZE) {
            ml_ep_unlock_fn();
            errno = ev ? ENOMEM : EINVAL;
            return -1;
        }
        for (i = 0; i < ep->n; i++) {
            if (ep->items[i].fd == fd) {
                ml_ep_unlock_fn();
                errno = EEXIST;
                return -1;
            }
        }
        ep->items[ep->n].fd = fd;
        ep->items[ep->n].events = ev->events;
        ep->items[ep->n].data = ev->data;
        ep->n++;
        ml_ep_unlock_fn();
        return 0;
    }
    if (op == EPOLL_CTL_DEL) {
        for (i = 0; i < ep->n; i++) {
            if (ep->items[i].fd == fd) {
                ep->items[i] = ep->items[ep->n - 1];
                ep->n--;
                ml_ep_unlock_fn();
                return 0;
            }
        }
        ml_ep_unlock_fn();
        errno = ENOENT;
        return -1;
    }
    if (op == EPOLL_CTL_MOD) {
        if (!ev) {
            ml_ep_unlock_fn();
            errno = EINVAL;
            return -1;
        }
        for (i = 0; i < ep->n; i++) {
            if (ep->items[i].fd == fd) {
                ep->items[i].events = ev->events;
                ep->items[i].data = ev->data;
                ml_ep_unlock_fn();
                return 0;
            }
        }
        ml_ep_unlock_fn();
        errno = ENOENT;
        return -1;
    }
    ml_ep_unlock_fn();
    errno = EINVAL;
    return -1;
}

static int ml_ep_wait(int epfd, struct epoll_event *ev, int maxev,
                      long long timeout_ns) {
    ml_epoll_t *ep;
    struct pollfd pf[FD_SETSIZE];
    unsigned i, n = 0;
    long long deadline = -1;
    ml_ep_lock_fn();
    ep = ml_ep_find(epfd, 0);
    if (!ep || !ev || maxev <= 0) {
        ml_ep_unlock_fn();
        errno = EINVAL;
        return -1;
    }
    for (i = 0; i < ep->n && n < FD_SETSIZE; i++) {
        pf[n].fd = ep->items[i].fd;
        pf[n].events = 0;
        if (ep->items[i].events & EPOLLIN) pf[n].events |= POLLIN;
        if (ep->items[i].events & EPOLLOUT) pf[n].events |= POLLOUT;
        if (ep->items[i].events & EPOLLPRI) pf[n].events |= POLLPRI;
        pf[n].revents = 0;
        n++;
    }
    ml_ep_unlock_fn();
    if (timeout_ns >= 0) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        deadline = now.tv_sec * 1000000000LL + now.tv_nsec + timeout_ns;
    }
    for (;;) {
        struct {
            long sec;
            long nsec;
        } ts, *tp = 0;
        long r;
        int got = 0;
        unsigned k;
        if (timeout_ns >= 0) {
            struct timespec now;
            long long left;
            clock_gettime(CLOCK_MONOTONIC, &now);
            left = deadline - (now.tv_sec * 1000000000LL + now.tv_nsec);
            if (left <= 0 && timeout_ns > 0) left = 0;
            if (timeout_ns == 0) left = 0;
            ts.sec = (long)(left / 1000000000LL);
            ts.nsec = (long)(left % 1000000000LL);
            tp = &ts;
        }
        r = __ml_call6(LX_SYS_ppoll, (long)pf, (long)n, (long)tp, 0, 0,
                       0);
        if (r < 0 && r >= -4095 && (int)-r != 0) {
            /* EINTR restarts unless the deadline passed. */
        }
        ml_ep_lock_fn();
        ep = ml_ep_find(epfd, 0);
        if (ep) {
            for (k = 0; k < n && got < maxev; k++) {
                unsigned mask = 0;
                if (pf[k].revents & POLLIN) mask |= EPOLLIN;
                if (pf[k].revents & POLLOUT) mask |= EPOLLOUT;
                if (pf[k].revents & POLLPRI) mask |= EPOLLPRI;
                if (pf[k].revents & POLLERR) mask |= EPOLLERR;
                if (pf[k].revents & POLLHUP) mask |= EPOLLHUP;
                if (pf[k].revents & POLLNVAL) mask |= EPOLLERR;
                if (!mask) continue;
                /* Map back to the interest entry. */
                for (i = 0; i < ep->n; i++) {
                    if (ep->items[i].fd == pf[k].fd) {
                        ev[got].events = mask & ep->items[i].events;
                        if (mask & (EPOLLERR | EPOLLHUP))
                            ev[got].events |= mask & (EPOLLERR | EPOLLHUP);
                        if (ev[got].events) {
                            ev[got].data = ep->items[i].data;
                            got++;
                        }
                        break;
                    }
                }
            }
        }
        ml_ep_unlock_fn();
        if (got > 0) return got;
        if (timeout_ns == 0) return 0;
        if (timeout_ns > 0) {
            struct timespec now;
            long long left;
            clock_gettime(CLOCK_MONOTONIC, &now);
            left = deadline - (now.tv_sec * 1000000000LL + now.tv_nsec);
            if (left <= 0) return 0;
        }
        sched_yield();
    }
}

int epoll_wait(int epfd, struct epoll_event *ev, int maxev,
               int timeout_ms) {
    long long to;
    if (timeout_ms < -1 || maxev <= 0) {
        errno = EINVAL;
        return -1;
    }
    to = timeout_ms < 0 ? -1 : (long long)timeout_ms * 1000000LL;
    return ml_ep_wait(epfd, ev, maxev, to);
}

int epoll_pwait(int epfd, struct epoll_event *ev, int maxev,
                int timeout_ms, const void *sigmask) {
    (void)sigmask;
    return epoll_wait(epfd, ev, maxev, timeout_ms);
}
