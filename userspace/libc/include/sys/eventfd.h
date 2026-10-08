/* Moonlight libc - sys/eventfd.h (event counters over pipes;
 * implemented in src/sysevent.c). */
#pragma once

#include <stdint.h>

typedef uint64_t eventfd_t;

#define EFD_SEMAPHORE 1
#define EFD_CLOEXEC 02000000
#define EFD_NONBLOCK 04000

int eventfd(unsigned initval, int flags);
int eventfd_read(int fd, eventfd_t *val);
int eventfd_write(int fd, eventfd_t val);
