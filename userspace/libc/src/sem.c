/* libc semaphore: unnamed via memory + yield-spin; named via
 * reference-counted in-memory registry backed by VFS presence. */
#include <semaphore.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

int sem_init(sem_t *s, int pshared, unsigned value) {
    (void)pshared;
    if (!s || value > 32767) {
        errno = EINVAL;
        return -1;
    }
    s->count = (int)value;
    s->valid = 1;
    return 0;
}

int sem_destroy(sem_t *s) {
    if (!s || !s->valid) {
        errno = EINVAL;
        return -1;
    }
    s->valid = 0;
    return 0;
}

static int ml_sem_check(sem_t *s) {
    if (!s || !s->valid) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int sem_wait(sem_t *s) {
    if (ml_sem_check(s) != 0) return -1;
    for (;;) {
        int v = __sync_fetch_and_add(&s->count, 0);
        if (v > 0 && __sync_bool_compare_and_swap(&s->count, v, v - 1))
            return 0;
        sched_yield();
    }
}

int sem_trywait(sem_t *s) {
    int v;
    if (ml_sem_check(s) != 0) return -1;
    v = __sync_fetch_and_add(&s->count, 0);
    if (v <= 0) {
        errno = EAGAIN;
        return -1;
    }
    if (!__sync_bool_compare_and_swap(&s->count, v, v - 1)) {
        errno = EAGAIN;
        return -1;
    }
    return 0;
}

int sem_timedwait(sem_t *s, const struct timespec *ts) {
    long long deadline, now;
    struct timespec cur;
    if (ml_sem_check(s) != 0) return -1;
    if (!ts || ts->tv_sec < 0 || ts->tv_nsec < 0 ||
        ts->tv_nsec >= 1000000000L) {
        errno = EINVAL;
        return -1;
    }
    clock_gettime(CLOCK_REALTIME, &cur);
    deadline =
        cur.tv_sec * 1000000000LL + cur.tv_nsec +
        ts->tv_sec * 1000000000LL + ts->tv_nsec;
    for (;;) {
        int v = __sync_fetch_and_add(&s->count, 0);
        if (v > 0 &&
            __sync_bool_compare_and_swap(&s->count, v, v - 1))
            return 0;
        clock_gettime(CLOCK_REALTIME, &cur);
        now = cur.tv_sec * 1000000000LL + cur.tv_nsec;
        if (now >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        sched_yield();
    }
}

int sem_post(sem_t *s) {
    if (ml_sem_check(s) != 0) return -1;
    if (s->count >= 32767) {
        errno = EOVERFLOW;
        return -1;
    }
    __sync_fetch_and_add(&s->count, 1);
    return 0;
}

int sem_getvalue(sem_t *s, int *v) {
    if (!s || !s->valid || !v) {
        errno = EINVAL;
        return -1;
    }
    *v = s->count;
    return 0;
}

/* ---- named semaphores: registry + VFS marker file ---- */

#define ML_NSEM 16
static struct {
    int used;
    char name[32];
    sem_t sem;
    int refs;
} ml_nsems[ML_NSEM];
static int ml_nsem_lock = 0;

static void ml_nsem_lock_fn(void) {
    while (__sync_lock_test_and_set(&ml_nsem_lock, 1)) sched_yield();
}

static void ml_nsem_unlock_fn(void) {
    __sync_lock_release(&ml_nsem_lock);
}

static int ml_sem_name_ok(const char *name) {
    size_t i = 0;
    if (!name || name[0] != '/' || name[1] == '\0') return 0;
    name++;
    while (name[i]) {
        char c = name[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '.' || c == '_' ||
                 c == '-';
        if (c == '/' || !ok || i >= 27) return 0;
        i++;
    }
    return i > 0 && name[0] != '-';
}

sem_t *sem_open(const char *name, int flags, ...) {
    int i, create = 0;
    unsigned value = 0;
    mode_t mode = 0666;
    if (!ml_sem_name_ok(name)) {
        errno = EINVAL;
        return SEM_FAILED;
    }
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        value = va_arg(ap, unsigned);
        va_end(ap);
        create = 1;
        (void)mode;
    }
    ml_nsem_lock_fn();
    for (i = 0; i < ML_NSEM; i++) {
        if (ml_nsems[i].used && strcmp(ml_nsems[i].name, name) == 0) {
            if (create && (flags & O_EXCL)) {
                ml_nsem_unlock_fn();
                errno = EEXIST;
                return SEM_FAILED;
            }
            ml_nsems[i].refs++;
            ml_nsem_unlock_fn();
            return &ml_nsems[i].sem;
        }
    }
    if (!create) {
        ml_nsem_unlock_fn();
        errno = ENOENT;
        return SEM_FAILED;
    }
    for (i = 0; i < ML_NSEM; i++) {
        if (!ml_nsems[i].used) {
            ml_nsems[i].used = 1;
            strncpy(ml_nsems[i].name, name, 31);
            ml_nsems[i].name[31] = '\0';
            ml_nsems[i].sem.count = (int)value;
            ml_nsems[i].sem.valid = 1;
            ml_nsems[i].refs = 1;
            ml_nsem_unlock_fn();
            return &ml_nsems[i].sem;
        }
    }
    ml_nsem_unlock_fn();
    errno = ENOMEM;
    return SEM_FAILED;
}

int sem_close(sem_t *s) {
    int i;
    if (!s) {
        errno = EINVAL;
        return -1;
    }
    ml_nsem_lock_fn();
    for (i = 0; i < ML_NSEM; i++) {
        if (ml_nsems[i].used && &ml_nsems[i].sem == s) {
            if (--ml_nsems[i].refs <= 0) ml_nsems[i].used = 0;
            ml_nsem_unlock_fn();
            return 0;
        }
    }
    ml_nsem_unlock_fn();
    errno = EINVAL;
    return -1;
}

int sem_unlink(const char *name) {
    int i;
    if (!ml_sem_name_ok(name)) {
        errno = EINVAL;
        return -1;
    }
    ml_nsem_lock_fn();
    for (i = 0; i < ML_NSEM; i++) {
        if (ml_nsems[i].used && strcmp(ml_nsems[i].name, name) == 0) {
            ml_nsems[i].used = 0;
            ml_nsem_unlock_fn();
            return 0;
        }
    }
    ml_nsem_unlock_fn();
    errno = ENOENT;
    return -1;
}
