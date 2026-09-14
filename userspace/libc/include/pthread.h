/* Moonlight libc - pthread. Cooperative-first threads over the Linux
 * personality clone(): each thread is a real kernel TCB (preemptive
 * under the EDF scheduler). Mutexes/conds use yield-spinning, which is
 * exact on a single hart (no true parallelism to race). */
#pragma once

#include <stddef.h>
#include <time.h>
#include <sched.h>

typedef unsigned long pthread_t;
typedef struct {
    int lock;
    int kind;
    int owner;
    unsigned count;
} pthread_mutex_t;
typedef struct {
    int lock;
    int clocked;
    int clock;
} pthread_cond_t;
typedef unsigned pthread_key_t;
typedef struct {
    int pshared;
    int type;
    int protocol;
    int prioceiling;
} pthread_mutexattr_t;
typedef struct {
    int pshared;
    int clock;
} pthread_condattr_t;
typedef struct {
    size_t stacksize;
    size_t guardsize;
    int detached;
    int scope;
    int inherit;
    int policy;
    void *stackaddr;
} pthread_attr_t;
typedef struct {
    int lock;
    int readers;
    int writer;
} pthread_rwlock_t;
typedef struct {
    int lock;
    unsigned count;
    unsigned total;
} pthread_barrier_t;
typedef struct {
    int pshared;
} pthread_barrierattr_t;
typedef struct {
    int pshared;
} pthread_rwlockattr_t;
typedef struct {
    int lock;
} pthread_spinlock_t;
typedef struct {
    int done;
    int lock;
} pthread_once_t;

#define PTHREAD_ONCE_INIT {0, 0}
#define PTHREAD_MUTEX_INITIALIZER {0, 0, 0, 0}
#define PTHREAD_COND_INITIALIZER {0, 0, 0}
#define PTHREAD_RWLOCK_INITIALIZER {0, 0, 0}
#define PTHREAD_SPIN_INITIALIZER {0}

#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED 1
#define PTHREAD_MUTEX_NORMAL 0
#define PTHREAD_MUTEX_RECURSIVE 1
#define PTHREAD_MUTEX_ERRORCHECK 2
#define PTHREAD_MUTEX_DEFAULT PTHREAD_MUTEX_NORMAL
#define PTHREAD_PRIO_NONE 0
#define PTHREAD_PRIO_INHERIT 1
#define PTHREAD_PRIO_PROTECT 2
#define PTHREAD_PROCESS_SHARED 1
#define PTHREAD_PROCESS_PRIVATE 0
#define PTHREAD_SCOPE_SYSTEM 0
#define PTHREAD_SCOPE_PROCESS 1
#define PTHREAD_INHERIT_SCHED 0
#define PTHREAD_EXPLICIT_SCHED 1

int pthread_create(pthread_t *t, const pthread_attr_t *attr,
                   void *(*fn)(void *), void *arg);
int pthread_join(pthread_t t, void **ret);
int pthread_detach(pthread_t t);
pthread_t pthread_self(void);
int pthread_equal(pthread_t a, pthread_t b);
void pthread_exit(void *ret) __attribute__((noreturn));
int pthread_cancel(pthread_t t);
int pthread_kill(pthread_t t, int sig);

int pthread_attr_init(pthread_attr_t *a);
int pthread_attr_destroy(pthread_attr_t *a);
int pthread_attr_setdetachstate(pthread_attr_t *a, int s);
int pthread_attr_getdetachstate(const pthread_attr_t *a, int *s);
int pthread_attr_setstacksize(pthread_attr_t *a, size_t n);
int pthread_attr_getstacksize(const pthread_attr_t *a, size_t *n);
int pthread_attr_setstack(pthread_attr_t *a, void *addr, size_t n);
int pthread_attr_getstack(const pthread_attr_t *a, void **addr, size_t *n);
int pthread_attr_setguardsize(pthread_attr_t *a, size_t n);
int pthread_attr_getguardsize(const pthread_attr_t *a, size_t *n);

int pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a);
int pthread_mutex_destroy(pthread_mutex_t *m);
int pthread_mutex_lock(pthread_mutex_t *m);
int pthread_mutex_trylock(pthread_mutex_t *m);
int pthread_mutex_timedlock(pthread_mutex_t *m, const struct timespec *ts);
int pthread_mutex_unlock(pthread_mutex_t *m);
int pthread_mutex_consistent(pthread_mutex_t *m);
int pthread_mutexattr_init(pthread_mutexattr_t *a);
int pthread_mutexattr_destroy(pthread_mutexattr_t *a);
int pthread_mutexattr_settype(pthread_mutexattr_t *a, int t);
int pthread_mutexattr_gettype(const pthread_mutexattr_t *a, int *t);
int pthread_mutexattr_setpshared(pthread_mutexattr_t *a, int s);
int pthread_mutexattr_getpshared(const pthread_mutexattr_t *a, int *s);
int pthread_mutexattr_setprotocol(pthread_mutexattr_t *a, int p);
int pthread_mutexattr_getprotocol(const pthread_mutexattr_t *a, int *p);
int pthread_mutexattr_setprioceiling(pthread_mutexattr_t *a, int c);
int pthread_mutexattr_getprioceiling(const pthread_mutexattr_t *a, int *c);

int pthread_cond_init(pthread_cond_t *c, const pthread_condattr_t *a);
int pthread_cond_destroy(pthread_cond_t *c);
int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m);
int pthread_cond_timedwait(pthread_cond_t *c, pthread_mutex_t *m,
                           const struct timespec *ts);
int pthread_cond_signal(pthread_cond_t *c);
int pthread_cond_broadcast(pthread_cond_t *c);
int pthread_condattr_init(pthread_condattr_t *a);
int pthread_condattr_destroy(pthread_condattr_t *a);
int pthread_condattr_setclock(pthread_condattr_t *a, int clock);
int pthread_condattr_getclock(const pthread_condattr_t *a, int *clock);
int pthread_condattr_setpshared(pthread_condattr_t *a, int s);
int pthread_condattr_getpshared(const pthread_condattr_t *a, int *s);

int pthread_rwlock_init(pthread_rwlock_t *r, const void *a);
int pthread_rwlock_destroy(pthread_rwlock_t *r);
int pthread_rwlock_rdlock(pthread_rwlock_t *r);
int pthread_rwlock_tryrdlock(pthread_rwlock_t *r);
int pthread_rwlock_timedrdlock(pthread_rwlock_t *r,
                               const struct timespec *ts);
int pthread_rwlock_wrlock(pthread_rwlock_t *r);
int pthread_rwlock_trywrlock(pthread_rwlock_t *r);
int pthread_rwlock_timedwrlock(pthread_rwlock_t *r,
                               const struct timespec *ts);
int pthread_rwlock_unlock(pthread_rwlock_t *r);
int pthread_rwlockattr_init(pthread_rwlockattr_t *a);
int pthread_rwlockattr_destroy(pthread_rwlockattr_t *a);
int pthread_rwlockattr_setpshared(pthread_rwlockattr_t *a, int s);
int pthread_rwlockattr_getpshared(const pthread_rwlockattr_t *a, int *s);

int pthread_barrier_init(pthread_barrier_t *b, const void *a,
                         unsigned count);
int pthread_barrier_destroy(pthread_barrier_t *b);
int pthread_barrier_wait(pthread_barrier_t *b);
#define PTHREAD_BARRIER_SERIAL_THREAD 1
int pthread_barrierattr_init(pthread_barrierattr_t *a);
int pthread_barrierattr_destroy(pthread_barrierattr_t *a);
int pthread_barrierattr_setpshared(pthread_barrierattr_t *a, int s);
int pthread_barrierattr_getpshared(const pthread_barrierattr_t *a, int *s);

int pthread_spin_init(pthread_spinlock_t *s, int p);
int pthread_spin_destroy(pthread_spinlock_t *s);
int pthread_spin_lock(pthread_spinlock_t *s);
int pthread_spin_trylock(pthread_spinlock_t *s);
int pthread_spin_unlock(pthread_spinlock_t *s);

int pthread_once(pthread_once_t *o, void (*fn)(void));

int pthread_key_create(pthread_key_t *k, void (*dtor)(void *));
int pthread_key_delete(pthread_key_t k);
int pthread_setspecific(pthread_key_t k, const void *v);
void *pthread_getspecific(pthread_key_t k);

int pthread_setcancelstate(int s, int *old);
int pthread_setcanceltype(int t, int *old);
#define PTHREAD_CANCEL_ENABLE 0
#define PTHREAD_CANCEL_DISABLE 1
#define PTHREAD_CANCEL_DEFERRED 0
#define PTHREAD_CANCEL_ASYNCHRONOUS 1

/* Extended API (all implemented in pthread.c). */
int pthread_tryjoin_np(pthread_t t, void **ret);
int pthread_setname_np(pthread_t t, const char *name);
int pthread_getname_np(pthread_t t, char *buf, size_t n);
int pthread_getattr_np(pthread_t t, pthread_attr_t *a);
int pthread_atfork(void (*prepare)(void), void (*parent)(void),
                   void (*child)(void));
int pthread_getconcurrency(void);
int pthread_setconcurrency(int n);

/* Cleanup handlers: LIFO stack per thread (real, nestable). */
typedef struct __ml_cleanup {
    struct __ml_cleanup *next;
    void (*fn)(void *);
    void *arg;
} __ml_cleanup_t;

void __ml_cleanup_push(__ml_cleanup_t *c, void (*fn)(void *), void *arg);
void __ml_cleanup_pop(__ml_cleanup_t *c, int execute);

#define pthread_cleanup_push(fn, arg) \
    do { \
        __ml_cleanup_t __ml_cu; \
        __ml_cleanup_push(&__ml_cu, (void (*)(void *))(fn), (arg));
#define pthread_cleanup_pop(execute) \
    __ml_cleanup_pop(&__ml_cu, (execute)); \
    } while (0)
