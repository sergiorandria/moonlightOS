/* Moonlight libc - sys/mman. */
#pragma once

#include <stddef.h>
#include <sys/types.h>

#define PROT_NONE 0x0
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_FAILED ((void *)-1)

#define MS_ASYNC 1
#define MS_SYNC 4
#define MS_INVALIDATE 2

void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off);
int munmap(void *addr, size_t len);
int mprotect(void *addr, size_t len, int prot);
int madvise(void *addr, size_t len, int advice);
void *mremap(void *old, size_t oldlen, size_t newlen, int flags, ...);
#define MREMAP_MAYMOVE 1
#define MREMAP_FIXED 2
int mlockall(int flags);
int munlockall(void);
#define MCL_CURRENT 1
#define MCL_FUTURE 2
/* Single address space, always resident: mlock/munlock/msync validate
 * the range (like madvise) and succeed. shm_* map onto VFS files
 * named "shm.<name>" (the leading '/' is stripped). */
int mlock(const void *addr, size_t len);
int munlock(const void *addr, size_t len);
int msync(void *addr, size_t len, int flags);
int shm_open(const char *name, int flags, mode_t mode);
int shm_unlink(const char *name);
