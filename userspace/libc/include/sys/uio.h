/* Moonlight libc - sys/uio. */
#pragma once

#include <sys/types.h>
#include <unistd.h>

ssize_t readv(int fd, const struct iovec *v, int n);
ssize_t writev(int fd, const struct iovec *v, int n);
