/* Moonlight libc - threads (C11).
 *
 * Real implementation over the pthread layer (which itself runs on
 * real kernel TCBs via clone): thrd_create maps to pthread_create
 * with a heap trampoline, mtx_* to pthread_mutex_*, cnd_* to
 * pthread_cond_*, tss_* to pthread_key_*, call_once to
 * pthread_once. No stubs. */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef unsigned long thrd_t;
typedef struct {
    int lock;
    int kind;
} mtx_t;
typedef struct {
    int lock;
    int clocked;
} cnd_t;
typedef unsigned tss_t;
typedef struct {
    int done;
    int lock;
} once_flag;

typedef int (*thrd_start_t)(void *);
typedef void (*tss_dtor_t)(void *);

#define thread_local _Thread_local
#define ONCE_FLAG_INIT {0, 0}
#define TSS_DTOR_ITERATIONS 1

enum {
    thrd_success = 0,
    thrd_busy = 1,
    thrd_error = 2,
    thrd_nomem = 3,
    thrd_timedout = 4
};

enum {
    mtx_plain = 0,
    mtx_recursive = 1,
    mtx_timed = 2
};

int thrd_create(thrd_t *t, thrd_start_t fn, void *arg);
int thrd_equal(thrd_t a, thrd_t b);
thrd_t thrd_current(void);
int thrd_sleep(const struct timespec *dur, struct timespec *rem);
void thrd_yield(void);
void thrd_exit(int code) __attribute__((noreturn));
int thrd_detach(thrd_t t);
int thrd_join(thrd_t t, int *code);

int mtx_init(mtx_t *m, int type);
void mtx_destroy(mtx_t *m);
int mtx_lock(mtx_t *m);
int mtx_timedlock(mtx_t *m, const struct timespec *ts);
int mtx_trylock(mtx_t *m);
int mtx_unlock(mtx_t *m);

int cnd_init(cnd_t *c);
void cnd_destroy(cnd_t *c);
int cnd_signal(cnd_t *c);
int cnd_broadcast(cnd_t *c);
int cnd_wait(cnd_t *c, mtx_t *m);
int cnd_timedwait(cnd_t *c, mtx_t *m, const struct timespec *ts);

int tss_create(tss_t *k, tss_dtor_t dtor);
void tss_delete(tss_t k);
int tss_set(tss_t k, void *v);
void *tss_get(tss_t k);

void call_once(once_flag *f, void (*fn)(void));
