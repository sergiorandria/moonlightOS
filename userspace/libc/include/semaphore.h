/* Moonlight libc - semaphore (unnamed + named via VFS-shm files). */
#pragma once

#include <time.h>

typedef struct {
    volatile int count;
    int valid;
} sem_t;

#define SEM_FAILED ((sem_t *)0)

int sem_init(sem_t *s, int pshared, unsigned value);
int sem_destroy(sem_t *s);
int sem_wait(sem_t *s);
int sem_trywait(sem_t *s);
int sem_timedwait(sem_t *s, const struct timespec *ts);
int sem_post(sem_t *s);
int sem_getvalue(sem_t *s, int *v);
sem_t *sem_open(const char *name, int flags, ...);
int sem_close(sem_t *s);
int sem_unlink(const char *name);
