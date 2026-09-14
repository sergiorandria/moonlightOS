/* Moonlight libc - sys/sem.h (System V semaphores;
 * implemented in src/sysvipc.c). */
#pragma once

#include <sys/ipc.h>
#include <sys/types.h>
#include <time.h>

struct semid_ds {
    struct ipc_perm sem_perm;
    unsigned short *array;
    unsigned short sem_nsems;
    time_t sem_otime;
    time_t sem_ctime;
};

struct sembuf {
    unsigned short sem_num;
    short sem_op;
    short sem_flg;
};

#define SEM_UNDO 010000
#define GETPID 11
#define GETVAL 12
#define GETALL 13
#define GETNCNT 14
#define GETZCNT 15
#define SETVAL 16
#define SETALL 17

union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

int semget(key_t key, int nsems, int flags);
int semop(int id, struct sembuf *ops, size_t nops);
int semtimedop(int id, struct sembuf *ops, size_t nops,
               const struct timespec *timeout);
int semctl(int id, int num, int cmd, ...);
