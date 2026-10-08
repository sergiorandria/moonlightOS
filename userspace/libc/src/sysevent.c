/* libc sysevent: eventfd, timerfd, signalfd, inotify as
 * libc-managed fds (see bits/ml_fd.h). Numbers come from a private
 * range (>= ML_FD_BASE) so they never collide with kernel fds;
 * read/write/close/poll/fcntl/ioctl/lseek dispatch here through the
 * weak hooks in unistd.c, fcntl.c and poll.c.
 *
 * eventfd: counter + pipe wakeups (single wake byte per write,
 * counter authoritative, drained on read).
 * timerfd: manager thread arming clock_nanosleep, expirations as
 * uint64 counts through a pipe.
 * signalfd: __ml_sfd_register hook in signal.c appends siginfos for
 * masked signals; reads consume them.
 * inotify: watches snapshot stat/readdir state; read() re-polls and
 * synthesizes events (blocking reads nanosleep-poll). */
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <bits/ml_sys.h>
#include <bits/ml_fd.h>

long __ml_ret(long r);
void __ml_sfd_register(void (*fn)(int));

typedef enum { ML_FD_EVENT, ML_FD_TIMER, ML_FD_SIGNAL, ML_FD_INOTIFY } ml_fd_kind_t;

typedef struct ml_watch ml_watch_t;

#define ML_MANAGED_MAX 32

typedef struct {
    int used;
    int fd;
    ml_fd_kind_t kind;
    int flags; /* O_NONBLOCK, O_CLOEXEC */
    pthread_mutex_t mtx;
    union {
        struct {
            uint64_t count;
            int sem;
        } ev;
        struct {
            int clockid;
            struct itimerspec spec;
            pthread_t thread;
            int armed;
            int started;
            int joined;
            int stop;
            long long arm_ns;
            uint64_t expirations;
        } tm;
        struct {
            sigset_t mask;
            unsigned char *pending;
            size_t plen, pcap;
            size_t roff;
        } sg;
        struct {
            struct ml_watch *watches;
            int next_wd;
            unsigned char *pending;
            size_t plen, pcap;
            size_t roff;
        } ino;
    } u;
} ml_mfd_t;

static ml_mfd_t ml_mfds[ML_MANAGED_MAX];
static int ml_mfd_lock = 0;
static int ml_mfd_next = ML_FD_BASE;

static void ml_mfd_lock_fn(void) {
    while (__sync_lock_test_and_set(&ml_mfd_lock, 1)) {
    }
}

static void ml_mfd_unlock_fn(void) { __sync_lock_release(&ml_mfd_lock); }

static ml_mfd_t *ml_mfd_find(int fd) {
    int i;
    for (i = 0; i < ML_MANAGED_MAX; i++)
        if (ml_mfds[i].used && ml_mfds[i].fd == fd) return &ml_mfds[i];
    return 0;
}

static ml_mfd_t *ml_mfd_alloc(ml_fd_kind_t kind) {
    int i;
    ml_mfd_lock_fn();
    for (i = 0; i < ML_MANAGED_MAX; i++) {
        if (!ml_mfds[i].used) {
            memset(&ml_mfds[i], 0, sizeof(ml_mfds[i]));
            ml_mfds[i].used = 1;
            ml_mfds[i].fd = ml_mfd_next++;
            ml_mfds[i].kind = kind;
            pthread_mutex_init(&ml_mfds[i].mtx, 0);
            ml_mfd_unlock_fn();
            return &ml_mfds[i];
        }
    }
    ml_mfd_unlock_fn();
    errno = EMFILE;
    return 0;
}

static int ml_nonblock(ml_mfd_t *e) { return (e->flags & O_NONBLOCK) != 0; }

/* ================= eventfd ================= */

int eventfd(unsigned initval, int flags) {
    ml_mfd_t *e;
    if (flags & ~(EFD_SEMAPHORE | EFD_CLOEXEC | EFD_NONBLOCK)) {
        errno = EINVAL;
        return -1;
    }
    e = ml_mfd_alloc(ML_FD_EVENT);
    if (!e) return -1;
    e->u.ev.count = initval;
    e->u.ev.sem = (flags & EFD_SEMAPHORE) != 0;
    if (flags & EFD_NONBLOCK) e->flags |= O_NONBLOCK;
    if (flags & EFD_CLOEXEC) e->flags |= O_CLOEXEC;
    return e->fd;
}

static ssize_t ml_event_read(ml_mfd_t *e, void *buf, size_t n) {
    eventfd_t v;
    if (n < sizeof(v)) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&e->mtx);
    while (e->u.ev.count == 0) {
        if (ml_nonblock(e)) {
            pthread_mutex_unlock(&e->mtx);
            errno = EAGAIN;
            return -1;
        }
        pthread_mutex_unlock(&e->mtx);
        {
            struct timespec sl = {0, 2000000L};
            nanosleep(&sl, 0);
        }
        pthread_mutex_lock(&e->mtx);
    }
    if (e->u.ev.sem) {
        v = 1;
        e->u.ev.count--;
    } else {
        v = e->u.ev.count;
        e->u.ev.count = 0;
    }
    pthread_mutex_unlock(&e->mtx);
    memcpy(buf, &v, sizeof(v));
    return sizeof(v);
}

static ssize_t ml_event_write(ml_mfd_t *e, const void *buf, size_t n) {
    eventfd_t v;
    if (n < sizeof(v)) {
        errno = EINVAL;
        return -1;
    }
    memcpy(&v, buf, sizeof(v));
    if (v == 0xFFFFFFFFFFFFFFFFull) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&e->mtx);
    while (e->u.ev.count + v < e->u.ev.count) { /* overflow */
        if (ml_nonblock(e)) {
            pthread_mutex_unlock(&e->mtx);
            errno = EAGAIN;
            return -1;
        }
        pthread_mutex_unlock(&e->mtx);
        {
            struct timespec sl = {0, 2000000L};
            nanosleep(&sl, 0);
        }
        pthread_mutex_lock(&e->mtx);
    }
    e->u.ev.count += v;
    pthread_mutex_unlock(&e->mtx);
    return sizeof(v);
}

int eventfd_read(int fd, eventfd_t *val) {
    eventfd_t v;
    ssize_t r;
    if (!val) {
        errno = EINVAL;
        return -1;
    }
    r = read(fd, &v, sizeof(v));
    if (r != (ssize_t)sizeof(v)) return -1;
    *val = v;
    return 0;
}

int eventfd_write(int fd, eventfd_t val) {
    ssize_t r = write(fd, &val, sizeof(val));
    return r == (ssize_t)sizeof(val) ? 0 : -1;
}

/* ================= timerfd ================= */

static void *ml_timer_thread(void *arg) {
    ml_mfd_t *e = arg;
    for (;;) {
        struct itimerspec sp;
        struct timespec now, req;
        long long now_ns, end_ns;
        pthread_mutex_lock(&e->mtx);
        if (e->u.tm.stop) {
            pthread_mutex_unlock(&e->mtx);
            return 0;
        }
        sp = e->u.tm.spec;
        pthread_mutex_unlock(&e->mtx);
        if (sp.it_value.tv_sec == 0 && sp.it_value.tv_nsec == 0) return 0;
        clock_gettime(e->u.tm.clockid, &now);
        now_ns = now.tv_sec * 1000000000LL + now.tv_nsec;
        end_ns = now_ns + sp.it_value.tv_sec * 1000000000LL +
                 sp.it_value.tv_nsec;
        req.tv_sec = sp.it_value.tv_sec;
        req.tv_nsec = sp.it_value.tv_nsec;
        clock_nanosleep(e->u.tm.clockid, 0, &req, 0);
        pthread_mutex_lock(&e->mtx);
        if (e->u.tm.stop) {
            pthread_mutex_unlock(&e->mtx);
            return 0;
        }
        e->u.tm.expirations++;
        if (sp.it_interval.tv_sec == 0 && sp.it_interval.tv_nsec == 0) {
            e->u.tm.spec.it_value.tv_sec = 0;
            e->u.tm.spec.it_value.tv_nsec = 0;
            e->u.tm.armed = 0;
            pthread_mutex_unlock(&e->mtx);
            return 0;
        }
        e->u.tm.spec.it_value = sp.it_interval;
        (void)end_ns;
        pthread_mutex_unlock(&e->mtx);
    }
}

int timerfd_create(int clockid, int flags) {
    ml_mfd_t *e;
    if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC &&
        clockid != CLOCK_BOOTTIME) {
        errno = EINVAL;
        return -1;
    }
    if (flags & ~(TFD_CLOEXEC | TFD_NONBLOCK)) {
        errno = EINVAL;
        return -1;
    }
    e = ml_mfd_alloc(ML_FD_TIMER);
    if (!e) return -1;
    e->u.tm.clockid = clockid;
    if (flags & TFD_NONBLOCK) e->flags |= O_NONBLOCK;
    if (flags & TFD_CLOEXEC) e->flags |= O_CLOEXEC;
    return e->fd;
}

static ml_mfd_t *ml_timer_lookup(int fd) {
    ml_mfd_t *e = ml_mfd_find(fd);
    if (!e || e->kind != ML_FD_TIMER) {
        errno = EINVAL;
        return 0;
    }
    return e;
}

int timerfd_settime(int fd, int flags, const struct itimerspec *newv,
                    struct itimerspec *oldv) {
    ml_mfd_t *e = ml_timer_lookup(fd);
    if (!e) return -1;
    if (!newv) {
        errno = EINVAL;
        return -1;
    }
    if (flags & ~(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET)) {
        errno = EINVAL;
        return -1;
    }
    if (newv->it_value.tv_nsec < 0 || newv->it_value.tv_nsec >= 1000000000L ||
        newv->it_interval.tv_nsec < 0 ||
        newv->it_interval.tv_nsec >= 1000000000L ||
        newv->it_value.tv_sec < 0 || newv->it_interval.tv_sec < 0) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&e->mtx);
    if (oldv) {
        struct timespec now;
        *oldv = e->u.tm.spec;
        if (e->u.tm.armed) {
            /* Remaining time against the arm point. */
            clock_gettime(e->u.tm.clockid, &now);
            {
                long long elapsed =
                    (now.tv_sec * 1000000000LL + now.tv_nsec) -
                    e->u.tm.arm_ns;
                long long value =
                    e->u.tm.spec.it_value.tv_sec * 1000000000LL +
                    e->u.tm.spec.it_value.tv_nsec;
                long long left = value - elapsed;
                if (left < 0) left = 0;
                oldv->it_value.tv_sec = (time_t)(left / 1000000000LL);
                oldv->it_value.tv_nsec = (long)(left % 1000000000LL);
            }
        } else {
            oldv->it_value.tv_sec = 0;
            oldv->it_value.tv_nsec = 0;
        }
    }
    /* Stop any running manager (joinable: always reaped here). */
    if (e->u.tm.started && !e->u.tm.joined) {
        e->u.tm.stop = 1;
        pthread_mutex_unlock(&e->mtx);
        pthread_join(e->u.tm.thread, 0);
        pthread_mutex_lock(&e->mtx);
        e->u.tm.stop = 0;
        e->u.tm.joined = 1;
        e->u.tm.armed = 0;
    }
    e->u.tm.spec = *newv;
    if (flags & TFD_TIMER_ABSTIME) {
        /* Convert absolute -> relative against the timer clock. */
        struct timespec now;
        long long left;
        clock_gettime(e->u.tm.clockid, &now);
        left = (newv->it_value.tv_sec - now.tv_sec) * 1000000000LL +
               (newv->it_value.tv_nsec - now.tv_nsec);
        if (left < 0) left = 0;
        if (left == 0) left = 1; /* already passed: fire at once */
        e->u.tm.spec.it_value.tv_sec = (time_t)(left / 1000000000LL);
        e->u.tm.spec.it_value.tv_nsec = (long)(left % 1000000000LL);
    }
    if (e->u.tm.spec.it_value.tv_sec == 0 &&
        e->u.tm.spec.it_value.tv_nsec == 0) {
        /* Disarm. */
        pthread_mutex_unlock(&e->mtx);
        return 0;
    }
    e->u.tm.armed = 1;
    e->u.tm.joined = 0;
    e->u.tm.started = 1;
    {
        struct timespec now;
        clock_gettime(e->u.tm.clockid, &now);
        e->u.tm.arm_ns = now.tv_sec * 1000000000LL + now.tv_nsec;
    }
    pthread_mutex_unlock(&e->mtx);
    {
        pthread_t t;
        pthread_attr_t a;
        pthread_attr_init(&a);
        if (pthread_create(&t, &a, ml_timer_thread, e) != 0) {
            pthread_attr_destroy(&a);
            pthread_mutex_lock(&e->mtx);
            e->u.tm.armed = 0;
            e->u.tm.started = 0;
            pthread_mutex_unlock(&e->mtx);
            errno = EAGAIN;
            return -1;
        }
        pthread_attr_destroy(&a);
        pthread_mutex_lock(&e->mtx);
        e->u.tm.thread = t;
        pthread_mutex_unlock(&e->mtx);
    }
    return 0;
}

int timerfd_gettime(int fd, struct itimerspec *cur) {
    ml_mfd_t *e = ml_timer_lookup(fd);
    if (!e) return -1;
    if (!cur) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&e->mtx);
    *cur = e->u.tm.spec;
    if (!e->u.tm.armed) {
        cur->it_value.tv_sec = 0;
        cur->it_value.tv_nsec = 0;
    }
    pthread_mutex_unlock(&e->mtx);
    return 0;
}

static ssize_t ml_timer_read(ml_mfd_t *e, void *buf, size_t n) {
    uint64_t v;
    if (n < sizeof(v)) {
        errno = EINVAL;
        return -1;
    }
    for (;;) {
        pthread_mutex_lock(&e->mtx);
        if (e->u.tm.expirations > 0) {
            v = e->u.tm.expirations;
            e->u.tm.expirations = 0;
            pthread_mutex_unlock(&e->mtx);
            memcpy(buf, &v, sizeof(v));
            return sizeof(v);
        }
        if (ml_nonblock(e)) {
            pthread_mutex_unlock(&e->mtx);
            errno = EAGAIN;
            return -1;
        }
        pthread_mutex_unlock(&e->mtx);
        {
            struct timespec sl = {0, 2000000L};
            nanosleep(&sl, 0);
        }
    }
}

/* ================= signalfd ================= */

static void ml_sfd_push(int sig) {
    int i;
    /* Called from raise()/poll paths with a blocked signal pending. */
    ml_mfd_lock_fn();
    for (i = 0; i < ML_MANAGED_MAX; i++) {
        ml_mfd_t *e = &ml_mfds[i];
        struct signalfd_siginfo si;
        unsigned char *nb;
        if (!e->used || e->kind != ML_FD_SIGNAL) continue;
        if (!(e->u.sg.mask & (1u << (sig - 1)))) continue;
        memset(&si, 0, sizeof(si));
        si.ssi_signo = (uint32_t)sig;
        si.ssi_pid = (uint32_t)getpid();
        si.ssi_uid = (uint32_t)getuid();
        if (e->u.sg.plen + sizeof(si) > 65536) continue; /* drop on flood */
        if (e->u.sg.plen + sizeof(si) > e->u.sg.pcap) {
            size_t nc = e->u.sg.pcap ? e->u.sg.pcap * 2 : 512;
            nb = realloc(e->u.sg.pending, nc);
            if (!nb) continue;
            e->u.sg.pending = nb;
            e->u.sg.pcap = nc;
        }
        memcpy(e->u.sg.pending + e->u.sg.plen, &si, sizeof(si));
        e->u.sg.plen += sizeof(si);
    }
    ml_mfd_unlock_fn();
}

int signalfd(int fd, const sigset_t *mask, int flags) {
    ml_mfd_t *e;
    static int hooked = 0;
    if (!mask) {
        errno = EINVAL;
        return -1;
    }
    if (flags & ~(SFD_CLOEXEC | SFD_NONBLOCK)) {
        errno = EINVAL;
        return -1;
    }
    if (!hooked) {
        __ml_sfd_register(ml_sfd_push);
        hooked = 1;
    }
    if (fd >= 0) {
        e = ml_mfd_find(fd);
        if (!e || e->kind != ML_FD_SIGNAL) {
            errno = EINVAL;
            return -1;
        }
        pthread_mutex_lock(&e->mtx);
        e->u.sg.mask = *mask;
        pthread_mutex_unlock(&e->mtx);
        return fd;
    }
    e = ml_mfd_alloc(ML_FD_SIGNAL);
    if (!e) return -1;
    e->u.sg.mask = *mask;
    if (flags & SFD_NONBLOCK) e->flags |= O_NONBLOCK;
    if (flags & SFD_CLOEXEC) e->flags |= O_CLOEXEC;
    return e->fd;
}

static ssize_t ml_signal_read(ml_mfd_t *e, void *buf, size_t n) {
    size_t unit = sizeof(struct signalfd_siginfo);
    if (n < unit) {
        errno = EINVAL;
        return -1;
    }
    for (;;) {
        size_t take = 0;
        pthread_mutex_lock(&e->mtx);
        if (e->u.sg.roff < e->u.sg.plen) {
            /* Whole structs only. */
            take = e->u.sg.plen - e->u.sg.roff;
            take -= take % unit;
            if (take > n) take = n - (n % unit);
            memcpy(buf, e->u.sg.pending + e->u.sg.roff, take);
            e->u.sg.roff += take;
            if (e->u.sg.roff == e->u.sg.plen) {
                e->u.sg.roff = e->u.sg.plen = 0;
            }
        }
        pthread_mutex_unlock(&e->mtx);
        if (take > 0) return (ssize_t)take;
        if (ml_nonblock(e)) {
            errno = EAGAIN;
            return -1;
        }
        {
            struct timespec sl = {0, 2000000L};
            nanosleep(&sl, 0);
        }
    }
}

/* ================= inotify ================= */

struct ml_watch {
    int wd;
    char path[256];
    uint32_t mask;
    int isdir;
    int exists;
    uint64_t size;
    int64_t mtime;
    unsigned mode;
    char *kids;      /* dir child namelist snapshot */
    size_t nkids;
    struct ml_watch *next;
};

static int ml_ino_snapshot(ml_watch_t *w) {
    struct stat st;
    int use_lstat = (w->mask & IN_DONT_FOLLOW) != 0;
    int r = use_lstat ? lstat(w->path, &st) : stat(w->path, &st);
    if (r != 0) {
        w->exists = 0;
        return -1;
    }
    w->exists = 1;
    w->isdir = S_ISDIR(st.st_mode);
    w->size = (uint64_t)st.st_size;
    w->mtime = (int64_t)st.st_mtime;
    w->mode = st.st_mode;
    return 0;
}

static void ml_ino_emit(ml_mfd_t *e, int wd, uint32_t mask, const char *name) {
    size_t namlen = name ? strlen(name) : 0;
    size_t total = sizeof(struct inotify_event) + namlen + 1;
    unsigned char *nb;
    struct inotify_event *ev;
    if (e->u.ino.plen + total > 65536) return;
    if (e->u.ino.plen + total > e->u.ino.pcap) {
        size_t nc = e->u.ino.pcap ? e->u.ino.pcap * 2 : 1024;
        while (nc < e->u.ino.plen + total) nc *= 2;
        nb = realloc(e->u.ino.pending, nc);
        if (!nb) return;
        e->u.ino.pending = nb;
        e->u.ino.pcap = nc;
    }
    ev = (struct inotify_event *)(e->u.ino.pending + e->u.ino.plen);
    ev->wd = wd;
    ev->mask = mask;
    ev->cookie = 0;
    ev->len = (uint32_t)(namlen + 1);
    if (name) memcpy(ev->name, name, namlen + 1);
    else ev->name[0] = '\0';
    e->u.ino.plen += total;
}

static void ml_ino_scan_dir(ml_mfd_t *e, ml_watch_t *w) {
    /* Diff the directory namelist against the snapshot. */
    DIR *d = opendir(w->path);
    char names[64][32];
    int nnames = 0, i;
    struct dirent *de;
    if (!d) {
        if (w->exists) {
            w->exists = 0;
            ml_ino_emit(e, w->wd, IN_DELETE_SELF, 0);
        }
        return;
    }
    if (!w->exists) {
        closedir(d);
        return; /* was deleted; DELETE_SELF already emitted */
    }
    while ((de = readdir(d)) != 0 && nnames < 64) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        strncpy(names[nnames], de->d_name, 31);
        names[nnames][31] = '\0';
        nnames++;
    }
    closedir(d);
    /* Created: in snapshot? no. Deleted: in old kids but gone. */
    {
        char *old = w->kids;
        size_t nold = w->nkids, j;
        for (i = 0; i < nnames; i++) {
            int found = 0;
            for (j = 0; j < nold; j++)
                if (strcmp(old + j * 32, names[i]) == 0) {
                    found = 1;
                    break;
                }
            if (!found) ml_ino_emit(e, w->wd, IN_CREATE, names[i]);
        }
        for (j = 0; j < nold; j++) {
            int found = 0;
            for (i = 0; i < nnames; i++)
                if (strcmp(old + j * 32, names[i]) == 0) {
                    found = 1;
                    break;
                }
            if (!found) ml_ino_emit(e, w->wd, IN_DELETE, old + j * 32);
        }
        free(w->kids);
        w->kids = 0;
        w->nkids = 0;
        if (nnames) {
            w->kids = malloc((size_t)nnames * 32);
            if (w->kids) {
                for (i = 0; i < nnames; i++) memcpy(w->kids + i * 32, names[i], 32);
                w->nkids = (size_t)nnames;
            }
        }
    }
}

static void ml_ino_check(ml_mfd_t *e, ml_watch_t *w) {
    struct stat st;
    int use_lstat = (w->mask & IN_DONT_FOLLOW) != 0;
    int r = use_lstat ? lstat(w->path, &st) : stat(w->path, &st);
    int was = w->exists;
    if (r != 0) {
        if (was) {
            w->exists = 0;
            ml_ino_emit(e, w->wd, IN_DELETE_SELF, 0);
            if (w->mask & IN_ONESHOT) {
                w->mask = 0;
            }
        }
        return;
    }
    if (!was) {
        /* Reappeared: treat as fresh baseline (no event: it was
         * reported deleted already). */
        w->exists = 1;
        w->isdir = S_ISDIR(st.st_mode);
        w->size = (uint64_t)st.st_size;
        w->mtime = (int64_t)st.st_mtime;
        w->mode = st.st_mode;
        return;
    }
    if (!w->isdir) {
        if ((uint64_t)st.st_size != w->size ||
            (int64_t)st.st_mtime != w->mtime)
            ml_ino_emit(e, w->wd, IN_MODIFY, 0);
        else if (st.st_mode != w->mode)
            ml_ino_emit(e, w->wd, IN_ATTRIB, 0);
        w->size = (uint64_t)st.st_size;
        w->mtime = (int64_t)st.st_mtime;
        w->mode = st.st_mode;
    } else {
        ml_ino_scan_dir(e, w);
        w->size = (uint64_t)st.st_size;
        w->mtime = (int64_t)st.st_mtime;
        w->mode = st.st_mode;
    }
    if (w->mask & IN_ONESHOT) w->mask = 0;
}

int inotify_init(void) { return inotify_init1(0); }

int inotify_init1(int flags) {
    ml_mfd_t *e;
    if (flags & ~(IN_CLOEXEC | IN_NONBLOCK)) {
        errno = EINVAL;
        return -1;
    }
    e = ml_mfd_alloc(ML_FD_INOTIFY);
    if (!e) return -1;
    e->u.ino.next_wd = 1;
    if (flags & IN_NONBLOCK) e->flags |= O_NONBLOCK;
    if (flags & IN_CLOEXEC) e->flags |= O_CLOEXEC;
    return e->fd;
}

int inotify_add_watch(int fd, const char *path, uint32_t mask) {
    ml_mfd_t *e;
    ml_watch_t *w, *p;
    if (!path || !*path || mask == 0) {
        errno = EINVAL;
        return -1;
    }
    e = ml_mfd_find(fd);
    if (!e || e->kind != ML_FD_INOTIFY) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&e->mtx);
    for (p = e->u.ino.watches; p; p = p->next) {
        if (strcmp(p->path, path) == 0) {
            if (mask & IN_MASK_CREATE) {
                /* Keep the existing mask untouched. */
                pthread_mutex_unlock(&e->mtx);
                return p->wd;
            }
            if (mask & IN_MASK_ADD) p->mask |= mask;
            else p->mask = mask;
            ml_ino_snapshot(p);
            pthread_mutex_unlock(&e->mtx);
            return p->wd;
        }
    }
    w = calloc(1, sizeof(*w));
    if (!w) {
        pthread_mutex_unlock(&e->mtx);
        errno = ENOMEM;
        return -1;
    }
    strncpy(w->path, path, sizeof(w->path) - 1);
    if ((mask & IN_ONLYDIR)) {
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
            free(w);
            pthread_mutex_unlock(&e->mtx);
            errno = ENOTDIR;
            return -1;
        }
    }
    w->wd = e->u.ino.next_wd++;
    w->mask = mask;
    ml_ino_snapshot(w);
    if (w->isdir && w->exists) {
        /* Baseline the child namelist without emitting. */
        DIR *d = opendir(path);
        if (d) {
            struct dirent *de;
            char tmp[64][32];
            int n = 0;
            while ((de = readdir(d)) != 0 && n < 64) {
                if (strcmp(de->d_name, ".") == 0 ||
                    strcmp(de->d_name, "..") == 0)
                    continue;
                strncpy(tmp[n], de->d_name, 31);
                tmp[n][31] = '\0';
                n++;
            }
            closedir(d);
            if (n) {
                w->kids = malloc((size_t)n * 32);
                if (w->kids) {
                    int i;
                    for (i = 0; i < n; i++)
                        memcpy(w->kids + i * 32, tmp[i], 32);
                    w->nkids = (size_t)n;
                }
            }
        }
    }
    w->next = e->u.ino.watches;
    e->u.ino.watches = w;
    pthread_mutex_unlock(&e->mtx);
    return w->wd;
}

int inotify_rm_watch(int fd, int wd) {
    ml_mfd_t *e;
    ml_watch_t **pp;
    e = ml_mfd_find(fd);
    if (!e || e->kind != ML_FD_INOTIFY) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&e->mtx);
    for (pp = &e->u.ino.watches; *pp; pp = &(*pp)->next) {
        if ((*pp)->wd == wd) {
            ml_watch_t *t = *pp;
            *pp = t->next;
            ml_ino_emit(e, wd, IN_IGNORED, 0);
            free(t->kids);
            free(t);
            pthread_mutex_unlock(&e->mtx);
            return 0;
        }
    }
    pthread_mutex_unlock(&e->mtx);
    errno = EINVAL;
    return -1;
}

static ssize_t ml_inotify_read(ml_mfd_t *e, void *buf, size_t n) {
    for (;;) {
        size_t take = 0;
        pthread_mutex_lock(&e->mtx);
        {
            ml_watch_t *w;
            for (w = e->u.ino.watches; w; w = w->next) {
                if (w->mask == 0) continue;
                ml_ino_check(e, w);
            }
        }
        if (e->u.ino.roff < e->u.ino.plen) {
            /* Whole events only; too-small buffer is EINVAL. */
            struct inotify_event *first =
                (struct inotify_event *)(e->u.ino.pending + e->u.ino.roff);
            size_t need =
                sizeof(struct inotify_event) + first->len;
            size_t avail = e->u.ino.plen - e->u.ino.roff;
            if (n < need) {
                pthread_mutex_unlock(&e->mtx);
                errno = EINVAL;
                return -1;
            }
            take = avail > n ? n : avail;
            /* Trim to a whole-event boundary. */
            {
                size_t off = 0;
                while (off < take) {
                    struct inotify_event *ev =
                        (struct inotify_event *)(e->u.ino.pending +
                                                 e->u.ino.roff + off);
                    size_t sz = sizeof(struct inotify_event) + ev->len;
                    if (off + sz > take) break;
                    off += sz;
                }
                take = off;
            }
            memcpy(buf, e->u.ino.pending + e->u.ino.roff, take);
            e->u.ino.roff += take;
            if (e->u.ino.roff == e->u.ino.plen) {
                e->u.ino.roff = e->u.ino.plen = 0;
            }
        }
        pthread_mutex_unlock(&e->mtx);
        if (take > 0) return (ssize_t)take;
        if (ml_nonblock(e)) {
            errno = EAGAIN;
            return -1;
        }
        {
            struct timespec sl = {0, 50000000L};
            nanosleep(&sl, 0);
        }
    }
}

/* ================= managed-fd dispatch ================= */

ssize_t __ml_fd_read(int fd, void *buf, size_t n) {
    ml_mfd_t *e;
    if (!buf) {
        errno = EFAULT;
        return -1;
    }
    e = ml_mfd_find(fd);
    if (!e) return ML_FD_PASSTHROUGH;
    switch (e->kind) {
    case ML_FD_EVENT: return ml_event_read(e, buf, n);
    case ML_FD_TIMER: return ml_timer_read(e, buf, n);
    case ML_FD_SIGNAL: return ml_signal_read(e, buf, n);
    case ML_FD_INOTIFY: return ml_inotify_read(e, buf, n);
    }
    return ML_FD_PASSTHROUGH;
}

ssize_t __ml_fd_write(int fd, const void *buf, size_t n) {
    ml_mfd_t *e = ml_mfd_find(fd);
    if (!e) return ML_FD_PASSTHROUGH;
    if (e->kind == ML_FD_EVENT) return ml_event_write(e, buf, n);
    errno = e->kind == ML_FD_INOTIFY ? EBADF : EINVAL;
    if (e->kind == ML_FD_TIMER || e->kind == ML_FD_SIGNAL) errno = EINVAL;
    return -1;
}

int __ml_fd_close(int fd) {
    ml_mfd_t *e = ml_mfd_find(fd);
    if (!e) return -2;
    pthread_mutex_lock(&e->mtx);
    if (e->kind == ML_FD_TIMER && e->u.tm.started && !e->u.tm.joined) {
        e->u.tm.stop = 1;
        pthread_mutex_unlock(&e->mtx);
        pthread_join(e->u.tm.thread, 0);
        pthread_mutex_lock(&e->mtx);
        e->u.tm.joined = 1;
    }
    if (e->kind == ML_FD_SIGNAL) {
        free(e->u.sg.pending);
        e->u.sg.pending = 0;
        e->u.sg.plen = e->u.sg.pcap = e->u.sg.roff = 0;
    }
    if (e->kind == ML_FD_INOTIFY) {
        ml_watch_t *w = e->u.ino.watches, *t;
        while (w) {
            t = w->next;
            free(w->kids);
            free(w);
            w = t;
        }
        e->u.ino.watches = 0;
        free(e->u.ino.pending);
        e->u.ino.pending = 0;
        e->u.ino.plen = e->u.ino.pcap = e->u.ino.roff = 0;
    }
    e->used = 0;
    pthread_mutex_unlock(&e->mtx);
    pthread_mutex_destroy(&e->mtx);
    return 0;
}

off_t __ml_fd_lseek(int fd, off_t off, int whence) {
    ml_mfd_t *e = ml_mfd_find(fd);
    (void)off;
    (void)whence;
    if (!e) return (off_t)-2;
    errno = ESPIPE;
    return (off_t)-1;
}

int __ml_fd_getfl(int fd, int *flags) {
    ml_mfd_t *e = ml_mfd_find(fd);
    if (!e) return -2;
    *flags = O_RDWR | e->flags;
    return *flags;
}

int __ml_fd_setfl(int fd, int flags) {
    ml_mfd_t *e = ml_mfd_find(fd);
    if (!e) return -2;
    pthread_mutex_lock(&e->mtx);
    if (flags & O_NONBLOCK) e->flags |= O_NONBLOCK;
    else e->flags &= ~O_NONBLOCK;
    pthread_mutex_unlock(&e->mtx);
    return 0;
}

int __ml_fd_poll(int fd, short *revents) {
    ml_mfd_t *e = ml_mfd_find(fd);
    short rev = 0;
    if (!e) return -2;
    pthread_mutex_lock(&e->mtx);
    switch (e->kind) {
    case ML_FD_EVENT:
        if (e->u.ev.count > 0) rev |= POLLIN;
        rev |= POLLOUT; /* writes rarely block (64-bit counter) */
        break;
    case ML_FD_TIMER:
        if (e->u.tm.expirations > 0) rev |= POLLIN;
        break;
    case ML_FD_SIGNAL:
        if (e->u.sg.roff < e->u.sg.plen) rev |= POLLIN;
        break;
    case ML_FD_INOTIFY: {
        ml_watch_t *w;
        /* Run the real scan so readiness reflects actual changes;
         * produced events stay buffered for read(). */
        for (w = e->u.ino.watches; w; w = w->next) {
            if (w->mask == 0) continue;
            ml_ino_check(e, w);
        }
        if (e->u.ino.roff < e->u.ino.plen) rev |= POLLIN;
        break;
    }
    }
    pthread_mutex_unlock(&e->mtx);
    *revents = rev;
    return 0;
}

int __ml_fd_ioctl(int fd, unsigned req, void *arg) {
    ml_mfd_t *e = ml_mfd_find(fd);
    if (!e) return -2;
    if (req == FIONREAD) {
        int avail = 0;
        if (!arg) {
            errno = EFAULT;
            return -1;
        }
        pthread_mutex_lock(&e->mtx);
        switch (e->kind) {
        case ML_FD_EVENT:
            avail = e->u.ev.count > 0 ? (int)sizeof(uint64_t) : 0;
            break;
        case ML_FD_TIMER:
            avail = e->u.tm.expirations > 0 ? (int)sizeof(uint64_t) : 0;
            break;
        case ML_FD_SIGNAL:
            avail = (int)(e->u.sg.plen - e->u.sg.roff);
            break;
        case ML_FD_INOTIFY:
            avail = (int)(e->u.ino.plen - e->u.ino.roff);
            break;
        }
        pthread_mutex_unlock(&e->mtx);
        *(int *)arg = avail;
        return 0;
    }
    errno = ENOTTY;
    return -1;
}
