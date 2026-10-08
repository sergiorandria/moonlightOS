/* Moonlight libc - sys/select (alias of poll.h fd API). */
#pragma once

#include <poll.h>

int select(int nfds, fd_set *r, fd_set *w, fd_set *e,
           struct timeval *timeout);
int pselect(int nfds, fd_set *r, fd_set *w, fd_set *e,
            const struct timespec *timeout, const void *sigmask);
