/* Moonlight libc - sys/shm.h (System V shared memory;
 * single address space: segments are MAP_SHARED arenas,
 * implemented in src/sysvipc.c). */
#pragma once

#include <stddef.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <time.h>

struct shmid_ds {
    struct ipc_perm shm_perm;
    size_t shm_segsz;
    pid_t shm_lpid;
    pid_t shm_cpid;
    unsigned long shm_nattch;
    time_t shm_atime;
    time_t shm_dtime;
    time_t shm_ctime;
};

#define SHM_RDONLY 010000
#define SHM_RND 020000
#define SHM_REMAP 040000
#define SHM_EXEC 0100000
#define SHM_LOCK 11
#define SHM_UNLOCK 12

int shmget(key_t key, size_t size, int flags);
void *shmat(int id, const void *addr, int flags);
int shmdt(const void *addr);
int shmctl(int id, int cmd, struct shmid_ds *buf);
