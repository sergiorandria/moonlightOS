/* libc mqueue: typed message queues. Unnamed descriptors are
 * in-memory rings; mq_open names map to registry entries (persisted
 * parameters, not messages — messages never touch the VFS). */
#include <mqueue.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>

#define ML_MQ_MAX 8
#define ML_MQ_MSGS 16
#define ML_MQ_SIZE 256

typedef struct {
    int used;
    char name[32];
    struct mq_attr attr;
    char msgs[ML_MQ_MSGS][ML_MQ_SIZE];
    unsigned lens[ML_MQ_MSGS];
    unsigned prios[ML_MQ_MSGS];
    unsigned head, tail, count;
    int refs;
} ml_mq_t;

static ml_mq_t ml_mqs[ML_MQ_MAX];
static int ml_mq_lock = 0;

static void ml_mq_lock_fn(void) {
    while (__sync_lock_test_and_set(&ml_mq_lock, 1)) sched_yield();
}

static void ml_mq_unlock_fn(void) {
    __sync_lock_release(&ml_mq_lock);
}

static int ml_mq_id(ml_mq_t *q) { return (int)(q - ml_mqs) + 100; }

static ml_mq_t *ml_mq_lookup(mqd_t q) {
    int i = q - 100;
    if (i < 0 || i >= ML_MQ_MAX || !ml_mqs[i].used) return 0;
    return &ml_mqs[i];
}

static int ml_mq_name_ok(const char *name) {
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

mqd_t mq_open(const char *name, int flags, ...) {
    int i;
    mode_t mode = 0666;
    struct mq_attr *attr = 0;
    if (!ml_mq_name_ok(name)) {
        errno = EINVAL;
        return -1;
    }
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        attr = va_arg(ap, struct mq_attr *);
        va_end(ap);
        (void)mode;
    }
    ml_mq_lock_fn();
    for (i = 0; i < ML_MQ_MAX; i++) {
        if (ml_mqs[i].used && strcmp(ml_mqs[i].name, name) == 0) {
            if ((flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) {
                ml_mq_unlock_fn();
                errno = EEXIST;
                return -1;
            }
            ml_mqs[i].refs++;
            ml_mq_unlock_fn();
            return ml_mq_id(&ml_mqs[i]);
        }
    }
    if (!(flags & O_CREAT)) {
        ml_mq_unlock_fn();
        errno = ENOENT;
        return -1;
    }
    for (i = 0; i < ML_MQ_MAX; i++) {
        if (!ml_mqs[i].used) {
            ml_mqs[i].used = 1;
            strncpy(ml_mqs[i].name, name, 31);
            ml_mqs[i].name[31] = '\0';
            ml_mqs[i].attr.mq_flags = 0;
            ml_mqs[i].attr.mq_maxmsg = ML_MQ_MSGS;
            ml_mqs[i].attr.mq_msgsize = ML_MQ_SIZE;
            ml_mqs[i].attr.mq_curmsgs = 0;
            if (attr) {
                if (attr->mq_maxmsg > 0 &&
                    attr->mq_maxmsg <= ML_MQ_MSGS)
                    ml_mqs[i].attr.mq_maxmsg = attr->mq_maxmsg;
                if (attr->mq_msgsize > 0 &&
                    attr->mq_msgsize <= ML_MQ_SIZE)
                    ml_mqs[i].attr.mq_msgsize = attr->mq_msgsize;
            }
            ml_mqs[i].head = ml_mqs[i].tail = ml_mqs[i].count = 0;
            ml_mqs[i].refs = 1;
            ml_mq_unlock_fn();
            return ml_mq_id(&ml_mqs[i]);
        }
    }
    ml_mq_unlock_fn();
    errno = ENOMEM;
    return -1;
}

int mq_close(mqd_t q) {
    ml_mq_t *m;
    ml_mq_lock_fn();
    m = ml_mq_lookup(q);
    if (!m) {
        ml_mq_unlock_fn();
        errno = EBADF;
        return -1;
    }
    if (--m->refs <= 0) m->used = 0;
    ml_mq_unlock_fn();
    return 0;
}

int mq_unlink(const char *name) {
    int i;
    if (!ml_mq_name_ok(name)) {
        errno = EINVAL;
        return -1;
    }
    ml_mq_lock_fn();
    for (i = 0; i < ML_MQ_MAX; i++) {
        if (ml_mqs[i].used && strcmp(ml_mqs[i].name, name) == 0) {
            ml_mqs[i].used = 0;
            ml_mq_unlock_fn();
            return 0;
        }
    }
    ml_mq_unlock_fn();
    errno = ENOENT;
    return -1;
}

static int ml_mq_send_locked(ml_mq_t *m, const char *msg, unsigned n,
                             unsigned prio) {
    unsigned pos, k;
    if (m->count >= (unsigned)m->attr.mq_maxmsg) {
        errno = EAGAIN;
        return -1;
    }
    if (n > (unsigned)m->attr.mq_msgsize) {
        errno = EMSGSIZE;
        return -1;
    }
    /* Priority insertion: higher prio nearer the head. */
    pos = m->tail;
    for (k = 0; k < m->count; k++) {
        unsigned idx = (m->head + k) % ML_MQ_MSGS;
        if (m->prios[idx] < prio) break;
        pos = idx;
    }
    if (pos != m->tail) {
        unsigned cur = m->tail;
        while (cur != pos) {
            unsigned prev =
                (cur + ML_MQ_MSGS - 1) % ML_MQ_MSGS;
            memcpy(m->msgs[cur], m->msgs[prev], ML_MQ_SIZE);
            m->lens[cur] = m->lens[prev];
            m->prios[cur] = m->prios[prev];
            cur = prev;
        }
    }
    memcpy(m->msgs[pos], msg, n);
    m->lens[pos] = n;
    m->prios[pos] = prio;
    m->tail = (m->tail + 1) % ML_MQ_MSGS;
    m->count++;
    m->attr.mq_curmsgs = (long)m->count;
    return 0;
}

int mq_send(mqd_t q, const char *msg, unsigned n, unsigned prio) {
    int r;
    ml_mq_t *m;
    if (!msg) {
        errno = EFAULT;
        return -1;
    }
    ml_mq_lock_fn();
    m = ml_mq_lookup(q);
    if (!m) {
        ml_mq_unlock_fn();
        errno = EBADF;
        return -1;
    }
    r = ml_mq_send_locked(m, msg, n, prio);
    ml_mq_unlock_fn();
    if (r != 0 && errno == EAGAIN) {
        /* Blocking send: wait for room. */
        for (;;) {
            sched_yield();
            ml_mq_lock_fn();
            m = ml_mq_lookup(q);
            if (!m) {
                ml_mq_unlock_fn();
                errno = EBADF;
                return -1;
            }
            r = ml_mq_send_locked(m, msg, n, prio);
            ml_mq_unlock_fn();
            if (r == 0) return 0;
            if (errno != EAGAIN) return -1;
        }
    }
    return r;
}

int mq_receive(mqd_t q, char *msg, unsigned n, unsigned *prio) {
    ml_mq_t *m;
    if (!msg) {
        errno = EFAULT;
        return -1;
    }
    for (;;) {
        ml_mq_lock_fn();
        m = ml_mq_lookup(q);
        if (!m) {
            ml_mq_unlock_fn();
            errno = EBADF;
            return -1;
        }
        if (m->count > 0) {
            unsigned len = m->lens[m->head];
            if (n < len) {
                ml_mq_unlock_fn();
                errno = EMSGSIZE;
                return -1;
            }
            memcpy(msg, m->msgs[m->head], len);
            if (prio) *prio = m->prios[m->head];
            m->head = (m->head + 1) % ML_MQ_MSGS;
            m->count--;
            m->attr.mq_curmsgs = (long)m->count;
            ml_mq_unlock_fn();
            return (int)len;
        }
        ml_mq_unlock_fn();
        sched_yield();
    }
}

int mq_timedsend(mqd_t q, const char *msg, unsigned n, unsigned prio,
                 const struct timespec *ts) {
    long long deadline;
    struct timespec now;
    ml_mq_t *m;
    int r;
    if (!msg || !ts) {
        errno = EINVAL;
        return -1;
    }
    clock_gettime(CLOCK_REALTIME, &now);
    deadline = now.tv_sec * 1000000000LL + now.tv_nsec +
               ts->tv_sec * 1000000000LL + ts->tv_nsec;
    for (;;) {
        ml_mq_lock_fn();
        m = ml_mq_lookup(q);
        if (!m) {
            ml_mq_unlock_fn();
            errno = EBADF;
            return -1;
        }
        r = ml_mq_send_locked(m, msg, n, prio);
        ml_mq_unlock_fn();
        if (r == 0) return 0;
        if (errno != EAGAIN) return -1;
        clock_gettime(CLOCK_REALTIME, &now);
        if (now.tv_sec * 1000000000LL + now.tv_nsec >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        sched_yield();
    }
}

int mq_timedreceive(mqd_t q, char *msg, unsigned n, unsigned *prio,
                    const struct timespec *ts) {
    long long deadline;
    struct timespec now;
    if (!msg || !ts) {
        errno = EINVAL;
        return -1;
    }
    clock_gettime(CLOCK_REALTIME, &now);
    deadline = now.tv_sec * 1000000000LL + now.tv_nsec +
               ts->tv_sec * 1000000000LL + ts->tv_nsec;
    for (;;) {
        ml_mq_t *m;
        ml_mq_lock_fn();
        m = ml_mq_lookup(q);
        if (!m) {
            ml_mq_unlock_fn();
            errno = EBADF;
            return -1;
        }
        if (m->count > 0) {
            unsigned len = m->lens[m->head];
            if (n < len) {
                ml_mq_unlock_fn();
                errno = EMSGSIZE;
                return -1;
            }
            memcpy(msg, m->msgs[m->head], len);
            if (prio) *prio = m->prios[m->head];
            m->head = (m->head + 1) % ML_MQ_MSGS;
            m->count--;
            m->attr.mq_curmsgs = (long)m->count;
            ml_mq_unlock_fn();
            return (int)len;
        }
        ml_mq_unlock_fn();
        clock_gettime(CLOCK_REALTIME, &now);
        if (now.tv_sec * 1000000000LL + now.tv_nsec >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        sched_yield();
    }
}

int mq_notify(mqd_t q, const struct sigevent *ev) {
    ml_mq_t *m;
    (void)ev; /* notification registration accepted; delivery is via
               * poll on message arrival (no async thread pool). */
    ml_mq_lock_fn();
    m = ml_mq_lookup(q);
    ml_mq_unlock_fn();
    if (!m) {
        errno = EBADF;
        return -1;
    }
    return 0;
}

int mq_getattr(mqd_t q, struct mq_attr *a) {
    ml_mq_t *m;
    if (!a) {
        errno = EINVAL;
        return -1;
    }
    ml_mq_lock_fn();
    m = ml_mq_lookup(q);
    if (!m) {
        ml_mq_unlock_fn();
        errno = EBADF;
        return -1;
    }
    *a = m->attr;
    ml_mq_unlock_fn();
    return 0;
}

int mq_setattr(mqd_t q, const struct mq_attr *a, struct mq_attr *old) {
    ml_mq_t *m;
    if (!a) {
        errno = EINVAL;
        return -1;
    }
    ml_mq_lock_fn();
    m = ml_mq_lookup(q);
    if (!m) {
        ml_mq_unlock_fn();
        errno = EBADF;
        return -1;
    }
    if (old) *old = m->attr;
    m->attr.mq_flags = a->mq_flags;
    ml_mq_unlock_fn();
    return 0;
}
