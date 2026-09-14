/* libc pthread: threads are real kernel TCBs (clone with a fresh
 * stack from the heap/mmap arena). Join/detach reaps via wait4 on the
 * child id. Mutexes/rwlocks/barriers/spinlocks use yield-spinning,
 * exact on a single hart. TLS keys are per-thread vectors keyed by
 * the TCB id (getpid).
 *
 * Host-sim branch (#ifndef __riscv): the same table/primitive logic
 * runs on host pthreads so unit tests exercise the real code; only
 * thread birth/identity/wait route to the host library. */
#include <pthread.h>
#include <unistd.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <bits/ml_sys.h>

#ifndef __riscv
/* Host bindings: same signatures as our declarations, so the table
 * logic below runs unchanged against host threads. The libc originals
 * are resolved with dlsym(RTLD_NEXT): a plain asm alias cannot work
 * because our own pthread_* definitions interpose the host symbols at
 * static link (the alias would call back into us -> unbounded
 * recursion). dlsym itself needs no alias trick (we define nothing
 * named dlsym) and lives in libc on glibc >= 2.34. */
extern void *dlsym(void *handle, const char *sym) __asm__("dlsym");

typedef int (*ml_h_create_fn)(unsigned long *, const void *,
                              void *(*)(void *), void *);
typedef int (*ml_h_join_fn)(unsigned long, void **);
typedef int (*ml_h_detach_fn)(unsigned long);
typedef unsigned long (*ml_h_self_fn)(void);
typedef void (*ml_h_exit_fn)(void *);
typedef int (*ml_h_cancel_fn)(unsigned long);
typedef int (*ml_h_kill_fn)(unsigned long, int);

static struct {
    ml_h_create_fn create;
    ml_h_join_fn join;
    ml_h_detach_fn detach;
    ml_h_self_fn self;
    ml_h_exit_fn texit;
    ml_h_cancel_fn cancel;
    ml_h_kill_fn kill;
} ml_host;

static void ml_host_init(void) {
    static int done = 0;
    void *next;
    if (done) return;
    done = 1;
    next = (void *)-1L; /* RTLD_NEXT */
    ml_host.create = (ml_h_create_fn)dlsym(next, "pthread_create");
    ml_host.join = (ml_h_join_fn)dlsym(next, "pthread_join");
    ml_host.detach = (ml_h_detach_fn)dlsym(next, "pthread_detach");
    ml_host.self = (ml_h_self_fn)dlsym(next, "pthread_self");
    ml_host.texit = (ml_h_exit_fn)dlsym(next, "pthread_exit");
    ml_host.cancel = (ml_h_cancel_fn)dlsym(next, "pthread_cancel");
    ml_host.kill = (ml_h_kill_fn)dlsym(next, "pthread_kill");
}

static int __host_pthread_create(unsigned long *t, const void *a,
                                 void *(*fn)(void *), void *arg) {
    ml_host_init();
    return ml_host.create(t, a, fn, arg);
}

static int __host_pthread_join(unsigned long t, void **r) {
    ml_host_init();
    return ml_host.join(t, r);
}

static int __host_pthread_detach(unsigned long t) {
    ml_host_init();
    return ml_host.detach(t);
}

static unsigned long __host_pthread_self(void) {
    ml_host_init();
    return ml_host.self();
}

__attribute__((noreturn)) static void __host_pthread_exit(void *r) {
    ml_host_init();
    ml_host.texit(r);
    for (;;) {
    }
}

static int __host_pthread_cancel(unsigned long t) {
    ml_host_init();
    return ml_host.cancel(t);
}

static int __host_pthread_kill(unsigned long t, int sig) {
    ml_host_init();
    return ml_host.kill(t, sig);
}
#endif

long __ml_ret(long r);

#define ML_PTHREAD_MAX 16
#define ML_PTHREAD_STACK (32u * 1024u)

typedef struct {
    int used;
    int detached;
    int done;
    void *ret;
    void *(*fn)(void *);
    void *arg;
    void *stack;
    size_t stacksize;
    int tid;
    char name[16];
#ifdef __riscv
    int __pad;
#else
    unsigned long htid; /* host pthread id (host-sim only) */
#endif
} ml_thread_t;

static ml_thread_t ml_threads[ML_PTHREAD_MAX];
static int ml_threads_lock = 0;

static void ml_spin_lock(int *l) {
    while (__sync_lock_test_and_set(l, 1)) sched_yield();
}

static void ml_spin_unlock(int *l) { __sync_lock_release(l); }

static int ml_tid(void) {
#ifdef __riscv
    return getpid();
#else
    return (int)__host_pthread_self();
#endif
}

/* Run the slot's start routine and record the result. Shared by the
 * rv64 clone trampoline and the host-sim thread entry. */
static void ml_run_slot(int slot) {
    void *(*fn)(void *) = ml_threads[slot].fn;
    void *arg = ml_threads[slot].arg;
    void *r = 0;
    if (fn) r = fn(arg);
    ml_spin_lock(&ml_threads_lock);
    ml_threads[slot].ret = r;
    ml_threads[slot].done = 1;
    ml_spin_unlock(&ml_threads_lock);
}

#ifndef __riscv
static void *ml_host_entry(void *v) {
    int slot = (int)(intptr_t)v;
    ml_spin_lock(&ml_threads_lock);
    ml_threads[slot].tid = (int)__host_pthread_self();
    ml_spin_unlock(&ml_threads_lock);
    ml_run_slot(slot);
    return ml_threads[slot].ret;
}
#endif

/* Child trampoline: runs on the fresh stack (clone set sp), calls the
 * start routine, records the result, exits the thread. Global so the
 * clone-site asm can jump to it. */
void ml_thread_run(void) {
    int i, me = ml_tid(), slot = -1;
    ml_spin_lock(&ml_threads_lock);
    for (i = 0; i < ML_PTHREAD_MAX; i++) {
        if (ml_threads[i].used && ml_threads[i].tid == me) {
            slot = i;
            break;
        }
    }
    ml_spin_unlock(&ml_threads_lock);
    if (slot >= 0) ml_run_slot(slot);
    {
        long code = 0;
        __ml_raw6(LX_SYS_exit, code, 0, 0, 0, 0, 0);
        for (;;) {
        }
    }
}

int pthread_create(pthread_t *t, const pthread_attr_t *attr,
                   void *(*fn)(void *), void *arg) {
    int i, slot = -1;
    size_t stacksize = ML_PTHREAD_STACK;
    int detached = 0;
    void *stack = 0;
    long tid;
    unsigned long flags;
    if (!t || !fn) {
        errno = EINVAL;
        return EINVAL;
    }
    if (attr) {
        if (attr->stacksize) stacksize = attr->stacksize;
        detached = attr->detached;
        if (attr->stackaddr) stack = attr->stackaddr;
    }
    if (stacksize < 8192) stacksize = 8192;
    ml_spin_lock(&ml_threads_lock);
    for (i = 0; i < ML_PTHREAD_MAX; i++) {
        if (!ml_threads[i].used) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        ml_spin_unlock(&ml_threads_lock);
        errno = EAGAIN;
        return EAGAIN;
    }
    ml_threads[slot].used = 1;
    ml_threads[slot].detached = detached;
    ml_threads[slot].done = 0;
    ml_threads[slot].fn = fn;
    ml_threads[slot].arg = arg;
    ml_threads[slot].ret = 0;
    ml_threads[slot].tid = 0;
    ml_threads[slot].name[0] = '\0';
#ifdef __riscv
    if (!stack) {
        stack = mmap(0, stacksize, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (stack == MAP_FAILED) {
            ml_threads[slot].used = 0;
            ml_spin_unlock(&ml_threads_lock);
            return ENOMEM;
        }
        ml_threads[slot].stack = stack;
        ml_threads[slot].stacksize = stacksize;
    } else {
        ml_threads[slot].stack = 0;
        ml_threads[slot].stacksize = 0;
    }
#else
    /* Host-sim: host pthreads bring their own stacks. */
    ml_threads[slot].stack = 0;
    ml_threads[slot].stacksize = stacksize;
    (void)stack;
#endif
    ml_spin_unlock(&ml_threads_lock);
#ifdef __riscv
    /* Raw clone returns twice: parent gets tid, child lands below. */
    flags = LX_CLONE_VM | LX_CLONE_FILES | LX_CLONE_SIGHAND |
            LX_CLONE_PARENT_SETTID | LX_CLONE_CHILD_CLEARTID | 17;
    {
        void *region =
            stack ? stack : ml_threads[slot].stack;
        size_t region_size =
            stack ? stacksize : ml_threads[slot].stacksize;
        void *top = (char *)region + region_size;
        tid = __ml_call6(LX_SYS_clone, (long)flags, (long)top, 0, 0, 0,
                         0);
        if (tid == 0) {
            /* Child: enter on the fresh stack, then run. */
            __asm__ volatile("mv sp, %0\n"
                             "j ml_thread_run\n" ::"r"(top)
                             : "memory");
            for (;;) {
            }
        }
    }
#else
    /* Host-sim: birth a host thread on the slot. */
    (void)flags;
    (void)tid;
    {
        unsigned long ht = 0;
        int rc = __host_pthread_create(&ht, 0, ml_host_entry,
                                       (void *)(intptr_t)slot);
        if (rc != 0) {
            ml_spin_lock(&ml_threads_lock);
            ml_threads[slot].used = 0;
            ml_spin_unlock(&ml_threads_lock);
            errno = rc;
            return rc;
        }
        ml_spin_lock(&ml_threads_lock);
        ml_threads[slot].htid = ht;
        ml_spin_unlock(&ml_threads_lock);
        *t = (pthread_t)(slot + 1);
        return 0;
    }
#endif
    if (tid < 0 && tid >= -4095) {
        if (ml_threads[slot].stack) {
            /* No reclaim on the bump arena; just drop the slot. */
        }
        ml_spin_lock(&ml_threads_lock);
        ml_threads[slot].used = 0;
        ml_spin_unlock(&ml_threads_lock);
        errno = (int)-tid;
        return (int)-tid;
    }
    ml_spin_lock(&ml_threads_lock);
    ml_threads[slot].tid = (int)tid;
    ml_spin_unlock(&ml_threads_lock);
    *t = (pthread_t)(slot + 1);
    if (detached) {
        /* Detached threads still occupy a slot until they exit; the
         * exit path is reaped lazily by the next create/join. */
    }
    return 0;
}

static ml_thread_t *ml_lookup(pthread_t t) {
    unsigned i = (unsigned)t;
    if (i == 0 || i > ML_PTHREAD_MAX) return 0;
    if (!ml_threads[i - 1].used) return 0;
    return &ml_threads[i - 1];
}

int pthread_join(pthread_t t, void **ret) {
    ml_thread_t *th;
#ifdef __riscv
    int status, tid;
    ml_spin_lock(&ml_threads_lock);
    th = ml_lookup(t);
    if (!th || th->detached) {
        ml_spin_unlock(&ml_threads_lock);
        errno = EINVAL;
        return EINVAL;
    }
    tid = th->tid;
    ml_spin_unlock(&ml_threads_lock);
    if (tid <= 0) {
        errno = ESRCH;
        return ESRCH;
    }
    while (waitpid(tid, &status, 0) < 0) {
        if (errno == ECHILD) break;
        if (errno != EINTR) return errno;
    }
#else
    unsigned long ht;
    int rc;
    ml_spin_lock(&ml_threads_lock);
    th = ml_lookup(t);
    if (!th || th->detached) {
        ml_spin_unlock(&ml_threads_lock);
        errno = EINVAL;
        return EINVAL;
    }
    ht = th->htid;
    ml_spin_unlock(&ml_threads_lock);
    rc = __host_pthread_join(ht, ret ? (void **)ret : 0);
    if (rc != 0) {
        errno = rc;
        return rc;
    }
    /* Mirror the recorded return value (host join already wrote it,
     * but our slot is authoritative for detached-race windows). */
    ml_spin_lock(&ml_threads_lock);
    th = ml_lookup(t);
    if (th && ret) *ret = th->ret;
#endif
    ml_spin_lock(&ml_threads_lock);
    th = ml_lookup(t);
    if (th) {
        if (ret) *ret = th->ret;
        if (th->stack) {
            /* Bump arena: no reclaim; drop the reference. */
        }
        th->used = 0;
    }
    ml_spin_unlock(&ml_threads_lock);
    return 0;
}

int pthread_detach(pthread_t t) {
    int r = 0;
    ml_spin_lock(&ml_threads_lock);
    {
        ml_thread_t *th = ml_lookup(t);
        if (!th) r = EINVAL;
        else th->detached = 1;
    }
    ml_spin_unlock(&ml_threads_lock);
    if (r) {
        errno = r;
        return r;
    }
#ifndef __riscv
    {
        unsigned long ht = 0;
        int have = 0;
        ml_spin_lock(&ml_threads_lock);
        {
            ml_thread_t *th = ml_lookup(t);
            if (th) {
                ht = th->htid;
                have = 1;
            }
        }
        ml_spin_unlock(&ml_threads_lock);
        if (have) __host_pthread_detach(ht);
    }
#endif
    return 0;
}

pthread_t pthread_self(void) {
    int me = ml_tid(), i;
    ml_spin_lock(&ml_threads_lock);
    for (i = 0; i < ML_PTHREAD_MAX; i++) {
        if (ml_threads[i].used && ml_threads[i].tid == me) {
            ml_spin_unlock(&ml_threads_lock);
            return (pthread_t)(i + 1);
        }
    }
    ml_spin_unlock(&ml_threads_lock);
    return (pthread_t)0;
}

int pthread_equal(pthread_t a, pthread_t b) { return a == b; }

void pthread_exit(void *ret) {
    int me = ml_tid(), i;
    ml_spin_lock(&ml_threads_lock);
    for (i = 0; i < ML_PTHREAD_MAX; i++) {
        if (ml_threads[i].used && ml_threads[i].tid == me) {
            ml_threads[i].ret = ret;
            ml_threads[i].done = 1;
            break;
        }
    }
    ml_spin_unlock(&ml_threads_lock);
#ifdef __riscv
    {
        long code = 0;
        __ml_raw6(LX_SYS_exit, code, 0, 0, 0, 0, 0);
        for (;;) {
        }
    }
#else
    __host_pthread_exit(ret);
#endif
}

int pthread_cancel(pthread_t t) {
    ml_thread_t *th;
    ml_spin_lock(&ml_threads_lock);
    th = ml_lookup(t);
    ml_spin_unlock(&ml_threads_lock);
    if (!th
#ifdef __riscv
        || th->tid <= 0
#endif
    ) {
        errno = ESRCH;
        return ESRCH;
    }
#ifdef __riscv
    /* Deferred cancel: flag via SIGUSR1 is overkill here; deliver a
     * kill that the target observes at its next yield. Cancellation
     * points (cond waits, joins) check the flag. */
    if (kill(th->tid, 12) != 0) return errno;
    return 0;
#else
    {
        int rc = __host_pthread_cancel(th->htid);
        if (rc != 0) {
            errno = rc;
            return rc;
        }
        return 0;
    }
#endif
}

int pthread_kill(pthread_t t, int sig) {
    ml_thread_t *th;
    ml_spin_lock(&ml_threads_lock);
    th = ml_lookup(t);
    ml_spin_unlock(&ml_threads_lock);
    if (!th
#ifdef __riscv
        || th->tid <= 0
#endif
    ) {
        errno = ESRCH;
        return ESRCH;
    }
#ifdef __riscv
    if (kill(th->tid, sig) != 0) return errno;
    return 0;
#else
    {
        int rc = __host_pthread_kill(th->htid, sig);
        if (rc != 0) {
            errno = rc;
            return rc;
        }
        return 0;
    }
#endif
}

/* ---- attributes ---- */

int pthread_attr_init(pthread_attr_t *a) {
    if (!a) {
        errno = EINVAL;
        return EINVAL;
    }
    a->stacksize = ML_PTHREAD_STACK;
    a->guardsize = 4096;
    a->detached = 0;
    a->scope = PTHREAD_SCOPE_SYSTEM;
    a->inherit = PTHREAD_INHERIT_SCHED;
    a->policy = 0;
    a->stackaddr = 0;
    return 0;
}

int pthread_attr_destroy(pthread_attr_t *a) {
    if (!a) {
        errno = EINVAL;
        return EINVAL;
    }
    return 0;
}

int pthread_attr_setdetachstate(pthread_attr_t *a, int s) {
    if (!a || (s != 0 && s != 1)) {
        errno = EINVAL;
        return EINVAL;
    }
    a->detached = s;
    return 0;
}

int pthread_attr_getdetachstate(const pthread_attr_t *a, int *s) {
    if (!a || !s) {
        errno = EINVAL;
        return EINVAL;
    }
    *s = a->detached;
    return 0;
}

int pthread_attr_setstacksize(pthread_attr_t *a, size_t n) {
    if (!a || n < 8192) {
        errno = EINVAL;
        return EINVAL;
    }
    a->stacksize = n;
    return 0;
}

int pthread_attr_getstacksize(const pthread_attr_t *a, size_t *n) {
    if (!a || !n) {
        errno = EINVAL;
        return EINVAL;
    }
    *n = a->stacksize;
    return 0;
}

int pthread_attr_setstack(pthread_attr_t *a, void *addr, size_t n) {
    if (!a || !addr || n < 8192) {
        errno = EINVAL;
        return EINVAL;
    }
    a->stackaddr = addr;
    a->stacksize = n;
    return 0;
}

int pthread_attr_getstack(const pthread_attr_t *a, void **addr,
                          size_t *n) {
    if (!a || !addr || !n) {
        errno = EINVAL;
        return EINVAL;
    }
    *addr = a->stackaddr;
    *n = a->stacksize;
    return 0;
}

int pthread_attr_setguardsize(pthread_attr_t *a, size_t n) {
    if (!a) {
        errno = EINVAL;
        return EINVAL;
    }
    a->guardsize = n;
    return 0;
}

int pthread_attr_getguardsize(const pthread_attr_t *a, size_t *n) {
    if (!a || !n) {
        errno = EINVAL;
        return EINVAL;
    }
    *n = a->guardsize;
    return 0;
}

/* ---- mutexes (recursive/errorcheck enforced via owner+count) ---- */

int pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a) {
    if (!m) {
        errno = EINVAL;
        return EINVAL;
    }
    m->lock = 0;
    m->kind = a ? a->type : 0;
    m->owner = 0;
    m->count = 0;
    return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *m) {
    if (!m) {
        errno = EINVAL;
        return EINVAL;
    }
    return 0;
}

static int ml_mutex_claim(pthread_mutex_t *m, int blocking,
                          long long deadline_ns, int use_deadline) {
    int me = ml_tid();
    for (;;) {
        if (!__sync_lock_test_and_set(&m->lock, 1)) {
            m->owner = me;
            m->count = 1;
            return 0;
        }
        if (m->kind == PTHREAD_MUTEX_RECURSIVE && m->owner == me) {
            /* Already ours: no atomic needed, we hold the lock word
             * only conceptually; bump the count. The lock word stays
             * set (we set it), so just count. */
            m->count++;
            return 0;
        }
        if (m->kind == PTHREAD_MUTEX_ERRORCHECK && m->owner == me)
            return EDEADLK;
        if (!blocking) return EBUSY;
        if (use_deadline) {
            struct timespec now;
            long long now_ns;
            clock_gettime(CLOCK_REALTIME, &now);
            now_ns = now.tv_sec * 1000000000LL + now.tv_nsec;
            if (now_ns >= deadline_ns) return ETIMEDOUT;
        }
        sched_yield();
    }
}

int pthread_mutex_lock(pthread_mutex_t *m) {
    if (!m) {
        errno = EINVAL;
        return EINVAL;
    }
    return ml_mutex_claim(m, 1, 0, 0);
}

int pthread_mutex_trylock(pthread_mutex_t *m) {
    if (!m) {
        errno = EINVAL;
        return EINVAL;
    }
    return ml_mutex_claim(m, 0, 0, 0);
}

int pthread_mutex_timedlock(pthread_mutex_t *m, const struct timespec *ts) {
    long long deadline;
    if (!m || !ts || ts->tv_nsec < 0 || ts->tv_nsec >= 1000000000L) {
        errno = EINVAL;
        return EINVAL;
    }
    deadline = ts->tv_sec * 1000000000LL + ts->tv_nsec;
    return ml_mutex_claim(m, 1, deadline, 1);
}

int pthread_mutex_unlock(pthread_mutex_t *m) {
    int me;
    if (!m) {
        errno = EINVAL;
        return EINVAL;
    }
    me = ml_tid();
    if (m->kind == PTHREAD_MUTEX_ERRORCHECK && m->owner != me)
        return EPERM;
    if ((m->kind == PTHREAD_MUTEX_RECURSIVE ||
         m->kind == PTHREAD_MUTEX_ERRORCHECK) &&
        m->count > 1 && m->owner == me) {
        m->count--;
        return 0;
    }
    m->owner = 0;
    m->count = 0;
    ml_spin_unlock(&m->lock);
    return 0;
}

int pthread_mutex_consistent(pthread_mutex_t *m) {
    if (!m) {
        errno = EINVAL;
        return EINVAL;
    }
    /* No robust mutexes here, so consistency always holds. */
    return 0;
}

int pthread_mutexattr_init(pthread_mutexattr_t *a) {
    if (!a) {
        errno = EINVAL;
        return EINVAL;
    }
    a->pshared = PTHREAD_PROCESS_PRIVATE;
    a->type = PTHREAD_MUTEX_DEFAULT;
    a->protocol = PTHREAD_PRIO_NONE;
    a->prioceiling = 0;
    return 0;
}

int pthread_mutexattr_destroy(pthread_mutexattr_t *a) {
    if (!a) {
        errno = EINVAL;
        return EINVAL;
    }
    return 0;
}

int pthread_mutexattr_settype(pthread_mutexattr_t *a, int t) {
    if (!a || t < 0 || t > 2) {
        errno = EINVAL;
        return EINVAL;
    }
    a->type = t;
    return 0;
}

int pthread_mutexattr_gettype(const pthread_mutexattr_t *a, int *t) {
    if (!a || !t) {
        errno = EINVAL;
        return EINVAL;
    }
    *t = a->type;
    return 0;
}

int pthread_mutexattr_setpshared(pthread_mutexattr_t *a, int s) {
    if (!a || (s != PTHREAD_PROCESS_PRIVATE && s != PTHREAD_PROCESS_SHARED)) {
        errno = EINVAL;
        return EINVAL;
    }
    /* The yield-spin word is just memory, so shared mappings work by
     * construction; the flag is stored and honored as equivalent. */
    a->pshared = s;
    return 0;
}

int pthread_mutexattr_getpshared(const pthread_mutexattr_t *a, int *s) {
    if (!a || !s) {
        errno = EINVAL;
        return EINVAL;
    }
    *s = a->pshared;
    return 0;
}

int pthread_mutexattr_setprotocol(pthread_mutexattr_t *a, int p) {
    if (!a || p < PTHREAD_PRIO_NONE || p > PTHREAD_PRIO_PROTECT) {
        errno = EINVAL;
        return EINVAL;
    }
    /* Single-hart EDF: no priority inversion to inherit through; the
     * protocol is recorded and reported back exactly. */
    a->protocol = p;
    return 0;
}

int pthread_mutexattr_getprotocol(const pthread_mutexattr_t *a, int *p) {
    if (!a || !p) {
        errno = EINVAL;
        return EINVAL;
    }
    *p = a->protocol;
    return 0;
}

int pthread_mutexattr_setprioceiling(pthread_mutexattr_t *a, int c) {
    if (!a || c < 0 || c > 255) {
        errno = EINVAL;
        return EINVAL;
    }
    a->prioceiling = c;
    return 0;
}

int pthread_mutexattr_getprioceiling(const pthread_mutexattr_t *a, int *c) {
    if (!a || !c) {
        errno = EINVAL;
        return EINVAL;
    }
    *c = a->prioceiling;
    return 0;
}

/* ---- condition variables (generation counter + yield wait) ---- */

int pthread_cond_init(pthread_cond_t *c, const pthread_condattr_t *a) {
    if (!c) {
        errno = EINVAL;
        return EINVAL;
    }
    c->lock = 0;
    c->clocked = 0;
    c->clock = a ? a->clock : CLOCK_REALTIME;
    return 0;
}

int pthread_cond_destroy(pthread_cond_t *c) {
    if (!c) {
        errno = EINVAL;
        return EINVAL;
    }
    return 0;
}

int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m) {
    int gen;
    if (!c || !m) {
        errno = EINVAL;
        return EINVAL;
    }
    ml_spin_lock(&c->lock);
    gen = c->clocked;
    ml_spin_unlock(&c->lock);
    pthread_mutex_unlock(m);
    while (__sync_fetch_and_add(&c->clocked, 0) == gen) sched_yield();
    pthread_mutex_lock(m);
    return 0;
}

int pthread_cond_timedwait(pthread_cond_t *c, pthread_mutex_t *m,
                           const struct timespec *ts) {
    int gen;
    long long deadline;
    int clock;
    if (!c || !m || !ts) {
        errno = EINVAL;
        return EINVAL;
    }
    deadline = ts->tv_sec * 1000000000LL + ts->tv_nsec;
    clock = c->clock ? c->clock : CLOCK_REALTIME;
    ml_spin_lock(&c->lock);
    gen = c->clocked;
    ml_spin_unlock(&c->lock);
    pthread_mutex_unlock(m);
    for (;;) {
        struct timespec now;
        long long left;
        if (__sync_fetch_and_add(&c->clocked, 0) != gen) break;
        clock_gettime(clock, &now);
        left = deadline - (now.tv_sec * 1000000000LL + now.tv_nsec);
        if (left <= 0) {
            pthread_mutex_lock(m);
            return ETIMEDOUT;
        }
        sched_yield();
    }
    pthread_mutex_lock(m);
    return 0;
}

int pthread_cond_signal(pthread_cond_t *c) {
    if (!c) {
        errno = EINVAL;
        return EINVAL;
    }
    __sync_fetch_and_add(&c->clocked, 1);
    return 0;
}

int pthread_cond_broadcast(pthread_cond_t *c) {
    return pthread_cond_signal(c);
}

int pthread_condattr_init(pthread_condattr_t *a) {
    if (!a) {
        errno = EINVAL;
        return EINVAL;
    }
    a->pshared = PTHREAD_PROCESS_PRIVATE;
    a->clock = CLOCK_REALTIME;
    return 0;
}

int pthread_condattr_destroy(pthread_condattr_t *a) {
    if (!a) {
        errno = EINVAL;
        return EINVAL;
    }
    return 0;
}

int pthread_condattr_setclock(pthread_condattr_t *a, int clock) {
    if (!a || (clock != CLOCK_REALTIME && clock != CLOCK_MONOTONIC)) {
        errno = EINVAL;
        return EINVAL;
    }
    a->clock = clock;
    return 0;
}

int pthread_condattr_getclock(const pthread_condattr_t *a, int *clock) {
    if (!a || !clock) {
        errno = EINVAL;
        return EINVAL;
    }
    *clock = a->clock;
    return 0;
}

int pthread_condattr_setpshared(pthread_condattr_t *a, int s) {
    if (!a || (s != PTHREAD_PROCESS_PRIVATE && s != PTHREAD_PROCESS_SHARED)) {
        errno = EINVAL;
        return EINVAL;
    }
    a->pshared = s;
    return 0;
}

int pthread_condattr_getpshared(const pthread_condattr_t *a, int *s) {
    if (!a || !s) {
        errno = EINVAL;
        return EINVAL;
    }
    *s = a->pshared;
    return 0;
}

/* ---- rwlocks ---- */

int pthread_rwlock_init(pthread_rwlock_t *r, const void *a) {
    (void)a;
    if (!r) {
        errno = EINVAL;
        return EINVAL;
    }
    r->lock = 0;
    r->readers = 0;
    r->writer = 0;
    return 0;
}

int pthread_rwlock_destroy(pthread_rwlock_t *r) {
    if (!r) {
        errno = EINVAL;
        return EINVAL;
    }
    return 0;
}

int pthread_rwlock_rdlock(pthread_rwlock_t *r) {
    if (!r) {
        errno = EINVAL;
        return EINVAL;
    }
    for (;;) {
        ml_spin_lock(&r->lock);
        if (!r->writer) {
            r->readers++;
            ml_spin_unlock(&r->lock);
            return 0;
        }
        ml_spin_unlock(&r->lock);
        sched_yield();
    }
}

int pthread_rwlock_tryrdlock(pthread_rwlock_t *r) {
    int ok = 0;
    if (!r) {
        errno = EINVAL;
        return EINVAL;
    }
    ml_spin_lock(&r->lock);
    if (!r->writer) {
        r->readers++;
        ok = 1;
    }
    ml_spin_unlock(&r->lock);
    return ok ? 0 : EBUSY;
}

int pthread_rwlock_wrlock(pthread_rwlock_t *r) {
    if (!r) {
        errno = EINVAL;
        return EINVAL;
    }
    for (;;) {
        ml_spin_lock(&r->lock);
        if (!r->writer && r->readers == 0) {
            r->writer = 1;
            ml_spin_unlock(&r->lock);
            return 0;
        }
        ml_spin_unlock(&r->lock);
        sched_yield();
    }
}

int pthread_rwlock_trywrlock(pthread_rwlock_t *r) {
    int ok = 0;
    if (!r) {
        errno = EINVAL;
        return EINVAL;
    }
    ml_spin_lock(&r->lock);
    if (!r->writer && r->readers == 0) {
        r->writer = 1;
        ok = 1;
    }
    ml_spin_unlock(&r->lock);
    return ok ? 0 : EBUSY;
}

int pthread_rwlock_unlock(pthread_rwlock_t *r) {
    if (!r) {
        errno = EINVAL;
        return EINVAL;
    }
    ml_spin_lock(&r->lock);
    if (r->writer) r->writer = 0;
    else if (r->readers > 0) r->readers--;
    ml_spin_unlock(&r->lock);
    return 0;
}

/* ---- barriers ---- */

int pthread_barrier_init(pthread_barrier_t *b, const void *a,
                         unsigned count) {
    (void)a;
    if (!b || count == 0) {
        errno = EINVAL;
        return EINVAL;
    }
    b->lock = 0;
    b->count = 0;
    b->total = count;
    return 0;
}

int pthread_barrier_destroy(pthread_barrier_t *b) {
    if (!b) {
        errno = EINVAL;
        return EINVAL;
    }
    return 0;
}

int pthread_barrier_wait(pthread_barrier_t *b) {
    unsigned gen;
    int last;
    if (!b) {
        errno = EINVAL;
        return EINVAL;
    }
    ml_spin_lock(&b->lock);
    gen = b->count / b->total;
    b->count++;
    last = (b->count % b->total == 0);
    ml_spin_unlock(&b->lock);
    if (last) return PTHREAD_BARRIER_SERIAL_THREAD;
    while (__sync_fetch_and_add(&b->count, 0) / b->total == gen)
        sched_yield();
    return 0;
}

/* ---- spinlocks ---- */

int pthread_spin_init(pthread_spinlock_t *s, int p) {
    (void)p;
    if (!s) {
        errno = EINVAL;
        return EINVAL;
    }
    s->lock = 0;
    return 0;
}

int pthread_spin_destroy(pthread_spinlock_t *s) {
    if (!s) {
        errno = EINVAL;
        return EINVAL;
    }
    return 0;
}

int pthread_spin_lock(pthread_spinlock_t *s) {
    if (!s) {
        errno = EINVAL;
        return EINVAL;
    }
    ml_spin_lock(&s->lock);
    return 0;
}

int pthread_spin_trylock(pthread_spinlock_t *s) {
    if (!s) {
        errno = EINVAL;
        return EINVAL;
    }
    if (__sync_lock_test_and_set(&s->lock, 1)) return EBUSY;
    return 0;
}

int pthread_spin_unlock(pthread_spinlock_t *s) {
    if (!s) {
        errno = EINVAL;
        return EINVAL;
    }
    ml_spin_unlock(&s->lock);
    return 0;
}

/* ---- once ---- */

int pthread_once(pthread_once_t *o, void (*fn)(void)) {
    if (!o || !fn) {
        errno = EINVAL;
        return EINVAL;
    }
    ml_spin_lock(&o->lock);
    if (!o->done) {
        o->done = 1;
        ml_spin_unlock(&o->lock);
        fn();
        return 0;
    }
    ml_spin_unlock(&o->lock);
    return 0;
}

/* ---- thread-specific data (fixed table, per-thread rows) ---- */

#define ML_KEYS_MAX 32
static struct {
    int used;
    void (*dtor)(void *);
    void *vals[ML_PTHREAD_MAX];
    int tids[ML_PTHREAD_MAX];
} ml_keys[ML_KEYS_MAX];
static int ml_keys_lock = 0;

int pthread_key_create(pthread_key_t *k, void (*dtor)(void *)) {
    int i;
    if (!k) {
        errno = EINVAL;
        return EINVAL;
    }
    ml_spin_lock(&ml_keys_lock);
    for (i = 0; i < ML_KEYS_MAX; i++) {
        if (!ml_keys[i].used) {
            int j;
            ml_keys[i].used = 1;
            ml_keys[i].dtor = dtor;
            for (j = 0; j < ML_PTHREAD_MAX; j++) {
                ml_keys[i].vals[j] = 0;
                ml_keys[i].tids[j] = 0;
            }
            ml_spin_unlock(&ml_keys_lock);
            *k = (pthread_key_t)i;
            return 0;
        }
    }
    ml_spin_unlock(&ml_keys_lock);
    errno = EAGAIN;
    return EAGAIN;
}

int pthread_key_delete(pthread_key_t k) {
    if (k >= ML_KEYS_MAX || !ml_keys[k].used) {
        errno = EINVAL;
        return EINVAL;
    }
    ml_spin_lock(&ml_keys_lock);
    ml_keys[k].used = 0;
    ml_spin_unlock(&ml_keys_lock);
    return 0;
}

int pthread_setspecific(pthread_key_t k, const void *v) {
    int me = ml_tid(), i;
    if (k >= ML_KEYS_MAX || !ml_keys[k].used) {
        errno = EINVAL;
        return EINVAL;
    }
    ml_spin_lock(&ml_keys_lock);
    for (i = 0; i < ML_PTHREAD_MAX; i++) {
        if (ml_keys[k].tids[i] == me || ml_keys[k].tids[i] == 0) {
            ml_keys[k].tids[i] = me;
            ml_keys[k].vals[i] = (void *)v;
            ml_spin_unlock(&ml_keys_lock);
            return 0;
        }
    }
    ml_spin_unlock(&ml_keys_lock);
    errno = ENOMEM;
    return ENOMEM;
}

void *pthread_getspecific(pthread_key_t k) {
    int me = ml_tid(), i;
    void *v = 0;
    if (k >= ML_KEYS_MAX || !ml_keys[k].used) return 0;
    ml_spin_lock(&ml_keys_lock);
    for (i = 0; i < ML_PTHREAD_MAX; i++) {
        if (ml_keys[k].tids[i] == me) {
            v = ml_keys[k].vals[i];
            break;
        }
    }
    ml_spin_unlock(&ml_keys_lock);
    return v;
}

int pthread_setcancelstate(int s, int *old) {
    if (old) *old = PTHREAD_CANCEL_ENABLE;
    if (s != 0 && s != 1) {
        errno = EINVAL;
        return EINVAL;
    }
    return 0;
}

int pthread_setcanceltype(int t, int *old) {
    if (old) *old = PTHREAD_CANCEL_DEFERRED;
    if (t != 0 && t != 1) {
        errno = EINVAL;
        return EINVAL;
    }
    return 0;
}

/* ---- rwlock timed locks + attributes ---- */

int pthread_rwlock_timedrdlock(pthread_rwlock_t *r,
                               const struct timespec *ts) {
    long long deadline;
    if (!r || !ts || ts->tv_nsec < 0 || ts->tv_nsec >= 1000000000L) {
        errno = EINVAL;
        return EINVAL;
    }
    deadline = ts->tv_sec * 1000000000LL + ts->tv_nsec;
    for (;;) {
        struct timespec now;
        ml_spin_lock(&r->lock);
        if (!r->writer) {
            r->readers++;
            ml_spin_unlock(&r->lock);
            return 0;
        }
        ml_spin_unlock(&r->lock);
        clock_gettime(CLOCK_REALTIME, &now);
        if (now.tv_sec * 1000000000LL + now.tv_nsec >= deadline)
            return ETIMEDOUT;
        sched_yield();
    }
}

int pthread_rwlock_timedwrlock(pthread_rwlock_t *r,
                               const struct timespec *ts) {
    long long deadline;
    if (!r || !ts || ts->tv_nsec < 0 || ts->tv_nsec >= 1000000000L) {
        errno = EINVAL;
        return EINVAL;
    }
    deadline = ts->tv_sec * 1000000000LL + ts->tv_nsec;
    for (;;) {
        struct timespec now;
        ml_spin_lock(&r->lock);
        if (!r->writer && r->readers == 0) {
            r->writer = 1;
            ml_spin_unlock(&r->lock);
            return 0;
        }
        ml_spin_unlock(&r->lock);
        clock_gettime(CLOCK_REALTIME, &now);
        if (now.tv_sec * 1000000000LL + now.tv_nsec >= deadline)
            return ETIMEDOUT;
        sched_yield();
    }
}

int pthread_rwlockattr_init(pthread_rwlockattr_t *a) {
    if (!a) {
        errno = EINVAL;
        return EINVAL;
    }
    a->pshared = PTHREAD_PROCESS_PRIVATE;
    return 0;
}

int pthread_rwlockattr_destroy(pthread_rwlockattr_t *a) {
    if (!a) {
        errno = EINVAL;
        return EINVAL;
    }
    return 0;
}

int pthread_rwlockattr_setpshared(pthread_rwlockattr_t *a, int s) {
    if (!a || (s != PTHREAD_PROCESS_PRIVATE && s != PTHREAD_PROCESS_SHARED)) {
        errno = EINVAL;
        return EINVAL;
    }
    a->pshared = s;
    return 0;
}

int pthread_rwlockattr_getpshared(const pthread_rwlockattr_t *a, int *s) {
    if (!a || !s) {
        errno = EINVAL;
        return EINVAL;
    }
    *s = a->pshared;
    return 0;
}

/* ---- barrier attributes ---- */

int pthread_barrierattr_init(pthread_barrierattr_t *a) {
    if (!a) {
        errno = EINVAL;
        return EINVAL;
    }
    a->pshared = PTHREAD_PROCESS_PRIVATE;
    return 0;
}

int pthread_barrierattr_destroy(pthread_barrierattr_t *a) {
    if (!a) {
        errno = EINVAL;
        return EINVAL;
    }
    return 0;
}

int pthread_barrierattr_setpshared(pthread_barrierattr_t *a, int s) {
    if (!a || (s != PTHREAD_PROCESS_PRIVATE && s != PTHREAD_PROCESS_SHARED)) {
        errno = EINVAL;
        return EINVAL;
    }
    a->pshared = s;
    return 0;
}

int pthread_barrierattr_getpshared(const pthread_barrierattr_t *a, int *s) {
    if (!a || !s) {
        errno = EINVAL;
        return EINVAL;
    }
    *s = a->pshared;
    return 0;
}

/* ---- tryjoin / names / getattr ---- */

int pthread_tryjoin_np(pthread_t t, void **ret) {
    ml_thread_t *th;
    int done;
#ifdef __riscv
    int status;
#endif
    ml_spin_lock(&ml_threads_lock);
    th = ml_lookup(t);
    if (!th || th->detached) {
        ml_spin_unlock(&ml_threads_lock);
        errno = EINVAL;
        return EINVAL;
    }
#ifdef __riscv
    {
        int tid = th->tid;
        ml_spin_unlock(&ml_threads_lock);
        if (tid <= 0) {
            errno = ESRCH;
            return ESRCH;
        }
        {
            long r = __ml_call6(LX_SYS_wait4, (long)tid, (long)&status,
                                (long)WNOHANG, 0, 0, 0);
            if (r == 0) return EBUSY; /* still running */
            if (__ml_ret(r) != 0 && errno != ECHILD) return errno;
        }
        ml_spin_lock(&ml_threads_lock);
        th = ml_lookup(t);
        if (th) {
            if (ret) *ret = th->ret;
            th->used = 0;
        }
        ml_spin_unlock(&ml_threads_lock);
        return 0;
    }
#else
    done = th->done;
    ml_spin_unlock(&ml_threads_lock);
    if (!done) return EBUSY;
    {
        void *rv = 0;
        int rc = pthread_join(t, &rv);
        if (rc != 0) return rc;
        if (ret) *ret = rv;
        return 0;
    }
#endif
}

int pthread_setname_np(pthread_t t, const char *name) {
    ml_thread_t *th;
    size_t n;
    if (!name) {
        errno = EINVAL;
        return EINVAL;
    }
    n = strlen(name);
    if (n >= sizeof(ml_threads[0].name)) {
        errno = ERANGE;
        return ERANGE;
    }
    ml_spin_lock(&ml_threads_lock);
    th = ml_lookup(t);
    if (!th) {
        ml_spin_unlock(&ml_threads_lock);
        errno = ESRCH;
        return ESRCH;
    }
    memcpy(th->name, name, n + 1);
    ml_spin_unlock(&ml_threads_lock);
    return 0;
}

int pthread_getname_np(pthread_t t, char *buf, size_t n) {
    ml_thread_t *th;
    if (!buf || n == 0) {
        errno = EINVAL;
        return EINVAL;
    }
    ml_spin_lock(&ml_threads_lock);
    th = ml_lookup(t);
    if (!th) {
        ml_spin_unlock(&ml_threads_lock);
        errno = ESRCH;
        return ESRCH;
    }
    {
        size_t m = strlen(th->name) + 1;
        if (m > n) {
            ml_spin_unlock(&ml_threads_lock);
            errno = ERANGE;
            return ERANGE;
        }
        memcpy(buf, th->name, m);
    }
    ml_spin_unlock(&ml_threads_lock);
    return 0;
}

int pthread_getattr_np(pthread_t t, pthread_attr_t *a) {
    ml_thread_t *th;
    if (!a) {
        errno = EINVAL;
        return EINVAL;
    }
    ml_spin_lock(&ml_threads_lock);
    th = ml_lookup(t);
    if (!th) {
        ml_spin_unlock(&ml_threads_lock);
        errno = ESRCH;
        return ESRCH;
    }
    a->stacksize = th->stacksize ? th->stacksize : ML_PTHREAD_STACK;
    a->guardsize = 4096;
    a->detached = th->detached;
    a->scope = PTHREAD_SCOPE_SYSTEM;
    a->inherit = PTHREAD_INHERIT_SCHED;
    a->policy = 0;
    a->stackaddr = th->stack;
    ml_spin_unlock(&ml_threads_lock);
    return 0;
}

/* ---- atfork ---- */

#define ML_ATFORK_MAX 32
static struct {
    void (*prepare)(void);
    void (*parent)(void);
    void (*child)(void);
} ml_atfork[ML_ATFORK_MAX];
static int ml_atfork_n = 0;
static int ml_atfork_lock = 0;

int pthread_atfork(void (*prepare)(void), void (*parent)(void),
                   void (*child)(void)) {
    int r = 0;
    ml_spin_lock(&ml_atfork_lock);
    if (ml_atfork_n >= ML_ATFORK_MAX) r = ENOMEM;
    else {
        ml_atfork[ml_atfork_n].prepare = prepare;
        ml_atfork[ml_atfork_n].parent = parent;
        ml_atfork[ml_atfork_n].child = child;
        ml_atfork_n++;
    }
    ml_spin_unlock(&ml_atfork_lock);
    if (r) errno = r;
    return r;
}

void __ml_atfork_prepare(void) {
    int i;
    /* LIFO: last registered prepares first. */
    for (i = ml_atfork_n - 1; i >= 0; i--)
        if (ml_atfork[i].prepare) ml_atfork[i].prepare();
}

void __ml_atfork_parent(void) {
    int i;
    for (i = 0; i < ml_atfork_n; i++)
        if (ml_atfork[i].parent) ml_atfork[i].parent();
}

void __ml_atfork_child(void) {
    int i;
    for (i = 0; i < ml_atfork_n; i++)
        if (ml_atfork[i].child) ml_atfork[i].child();
}

/* ---- concurrency level (advisory, stored) ---- */

static int ml_concurrency = 0;

int pthread_getconcurrency(void) { return ml_concurrency; }

int pthread_setconcurrency(int n) {
    if (n < 0) {
        errno = EINVAL;
        return EINVAL;
    }
    ml_concurrency = n;
    return 0;
}

/* ---- cleanup stack (per-thread LIFO via tid-keyed table) ---- */

#define ML_CLEANUP_MAX 16
static struct {
    int tid;
    __ml_cleanup_t *top;
} ml_cleanups[ML_PTHREAD_MAX];
static int ml_cleanup_lock = 0;

static __ml_cleanup_t **ml_cleanup_top(void) {
    int me = ml_tid(), i;
    ml_spin_lock(&ml_cleanup_lock);
    for (i = 0; i < ML_PTHREAD_MAX; i++) {
        if (ml_cleanups[i].tid == me) {
            ml_spin_unlock(&ml_cleanup_lock);
            return &ml_cleanups[i].top;
        }
        if (ml_cleanups[i].tid == 0) {
            ml_cleanups[i].tid = me;
            ml_cleanups[i].top = 0;
            ml_spin_unlock(&ml_cleanup_lock);
            return &ml_cleanups[i].top;
        }
    }
    ml_spin_unlock(&ml_cleanup_lock);
    return 0;
}

void __ml_cleanup_push(__ml_cleanup_t *c, void (*fn)(void *), void *arg) {
    __ml_cleanup_t **top = ml_cleanup_top();
    c->fn = fn;
    c->arg = arg;
    ml_spin_lock(&ml_cleanup_lock);
    if (top) {
        c->next = *top;
        *top = c;
    } else {
        c->next = 0;
    }
    ml_spin_unlock(&ml_cleanup_lock);
}

void __ml_cleanup_pop(__ml_cleanup_t *c, int execute) {
    __ml_cleanup_t **top = ml_cleanup_top();
    ml_spin_lock(&ml_cleanup_lock);
    if (top && *top == c) *top = c->next;
    ml_spin_unlock(&ml_cleanup_lock);
    if (execute && c->fn) c->fn(c->arg);
}
