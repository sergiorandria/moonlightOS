/* Libc-managed fd hooks (private). Modules that own synthetic fds
 * (eventfd/timerfd/signalfd/inotify in sysevent.c) implement these;
 * unistd.c/fcntl.c/poll.c call them first as WEAK references (NULL
 * when the module isn't linked). Return ML_FD_PASSTHROUGH when the fd
 * is unknown, leaving errno untouched. */
#pragma once

#include <stddef.h>
#include <sys/types.h>

#define ML_FD_PASSTHROUGH ((ssize_t)-2)
#define ML_FD_BASE 1000

ssize_t __ml_fd_read(int fd, void *buf, size_t n);
ssize_t __ml_fd_write(int fd, const void *buf, size_t n);
int __ml_fd_close(int fd);
off_t __ml_fd_lseek(int fd, off_t off, int whence);
int __ml_fd_getfl(int fd, int *flags);
int __ml_fd_setfl(int fd, int flags);
int __ml_fd_poll(int fd, short *revents);
int __ml_fd_ioctl(int fd, unsigned req, void *arg);
