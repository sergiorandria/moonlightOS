/* libc aio: POSIX async I/O over a worker thread pool.
 * Queue depth is bounded (64); workers run pread/pwrite/fsync and
 * mark completion, then fire the sigevent (NONE/THREAD/SIGNAL).
 * aio_suspend polls with nanosleep; aio_cancel drops queued items. */
#include <aio.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#define ML_AIO_DEPTH 64
#define ML_AIO_WORKERS 4

static struct aiocb *ml_aio_q[ML_AIO_DEPTH];
static int ml_aio_qn = 0;
static pthread_mutex_t ml_aio_mtx = {0, 0, 0, 0};
static pthread_cond_t ml_aio_cond = {0, 0, 0};
static int ml_aio_started = 0;

static void ml_aio_fire(struct aiocb *cb) {
    if (cb->aio_sigevent.sigev_notify == SIGEV_THREAD &&
        cb->aio_sigevent.sigev_notify_function) {
        /* Detached notifier thread runs the callback. */
        pthread_t t;
        pthread_attr_t a;
        pthread_attr_init(&a);
        pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&t, &a,
                           (void *(*)(void *))cb->aio_sigevent.sigev_notify_function,
                           cb->aio_sigevent.sigev_value.sival_ptr) != 0) {
            /* Thread birth failed: run inline (still delivers). */
            cb->aio_sigevent.sigev_notify_function(
                cb->aio_sigevent.sigev_value);
        }
        pthread_attr_destroy(&a);
    } else if (cb->aio_sigevent.sigev_notify == SIGEV_SIGNAL) {
        raise(cb->aio_sigevent.sigev_signo);
    }
}

static void *ml_aio_worker(void *arg) {
    (void)arg;
    for (;;) {
        struct aiocb *cb = 0;
        int i;
        pthread_mutex_lock(&ml_aio_mtx);
        while (ml_aio_qn == 0)
            pthread_cond_wait(&ml_aio_cond, &ml_aio_mtx);
        cb = ml_aio_q[0];
        for (i = 1; i < ml_aio_qn; i++) ml_aio_q[i - 1] = ml_aio_q[i];
        ml_aio_qn--;
        pthread_mutex_unlock(&ml_aio_mtx);
        if (cb->aio_lio_opcode == LIO_READ)
            cb->__ml_ret =
                pread(cb->aio_fildes, cb->aio_buf, cb->aio_nbytes,
                      cb->aio_offset);
        else if (cb->aio_lio_opcode == LIO_WRITE)
            cb->__ml_ret =
                pwrite(cb->aio_fildes, cb->aio_buf, cb->aio_nbytes,
                       cb->aio_offset);
        else
            cb->__ml_ret = fsync(cb->aio_fildes) == 0 ? 0 : -1;
        cb->__ml_err = cb->__ml_ret < 0 ? errno : 0;
        cb->__ml_done = 1;
        pthread_cond_broadcast(&ml_aio_cond);
        ml_aio_fire(cb);
    }
    return 0;
}

static int ml_aio_ensure(void) {
    int i;
    if (ml_aio_started) return 0;
    for (i = 0; i < ML_AIO_WORKERS; i++) {
        pthread_t t;
        pthread_attr_t a;
        pthread_attr_init(&a);
        pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&t, &a, ml_aio_worker, 0) != 0) {
            pthread_attr_destroy(&a);
            return -1;
        }
        pthread_attr_destroy(&a);
    }
    ml_aio_started = 1;
    return 0;
}

static int ml_aio_submit(struct aiocb *cb, int op) {
    if (!cb || !cb->aio_buf || cb->aio_nbytes == 0) {
        errno = EINVAL;
        return -1;
    }
    cb->aio_lio_opcode = op;
    cb->__ml_err = EINPROGRESS;
    cb->__ml_ret = 0;
    cb->__ml_done = 0;
    cb->__ml_queued = 1;
    pthread_mutex_lock(&ml_aio_mtx);
    if (!ml_aio_started) {
        pthread_mutex_unlock(&ml_aio_mtx);
        if (ml_aio_ensure() != 0) return -1;
        pthread_mutex_lock(&ml_aio_mtx);
    }
    if (ml_aio_qn >= ML_AIO_DEPTH) {
        pthread_mutex_unlock(&ml_aio_mtx);
        errno = EAGAIN;
        return -1;
    }
    ml_aio_q[ml_aio_qn++] = cb;
    pthread_cond_signal(&ml_aio_cond);
    pthread_mutex_unlock(&ml_aio_mtx);
    return 0;
}

int aio_read(struct aiocb *cb) { return ml_aio_submit(cb, LIO_READ); }
int aio_write(struct aiocb *cb) { return ml_aio_submit(cb, LIO_WRITE); }

int aio_fsync(int op, struct aiocb *cb) {
    (void)op; /* O_SYNC/DATASYNC alike: the store is write-through. */
    return ml_aio_submit(cb, LIO_NOP);
}

int aio_error(const struct aiocb *cb) {
    if (!cb) {
        errno = EINVAL;
        return EINVAL;
    }
    if (!cb->__ml_done && cb->__ml_queued) return EINPROGRESS;
    return cb->__ml_err;
}

ssize_t aio_return(struct aiocb *cb) {
    if (!cb) {
        errno = EINVAL;
        return -1;
    }
    if (!cb->__ml_done) {
        errno = EINPROGRESS;
        return -1;
    }
    cb->__ml_queued = 0;
    errno = cb->__ml_err;
    return cb->__ml_ret;
}

int aio_cancel(int fd, struct aiocb *cb) {
    int i, found = 0, running = 0;
    pthread_mutex_lock(&ml_aio_mtx);
    for (i = 0; i < ml_aio_qn; i++) {
        struct aiocb *c = ml_aio_q[i];
        if (c->aio_fildes != fd) continue;
        if (cb && c != cb) continue;
        c->__ml_queued = 0;
        c->__ml_done = 1;
        c->__ml_err = ECANCELED;
        c->__ml_ret = -1;
        found = 1;
        {
            int j;
            for (j = i + 1; j < ml_aio_qn; j++) ml_aio_q[j - 1] = ml_aio_q[j];
            ml_aio_qn--;
            i--;
        }
    }
    pthread_mutex_unlock(&ml_aio_mtx);
    (void)running;
    if (!found) {
        /* Not queued: either running or unknown. */
        if (cb && cb->__ml_queued && !cb->__ml_done) return AIO_NOTCANCELED;
        return AIO_ALLDONE;
    }
    pthread_cond_broadcast(&ml_aio_cond);
    return AIO_CANCELED;
}

int aio_suspend(const struct aiocb *const *list, int n,
                const struct timespec *timeout) {
    long long deadline = 0;
    int i;
    if (!list || n < 0) {
        errno = EINVAL;
        return -1;
    }
    if (timeout) {
        struct timespec now;
        if (timeout->tv_nsec < 0 || timeout->tv_nsec >= 1000000000L) {
            errno = EINVAL;
            return -1;
        }
        clock_gettime(CLOCK_REALTIME, &now);
        deadline = (now.tv_sec + timeout->tv_sec) * 1000000000LL +
                   now.tv_nsec + timeout->tv_nsec;
    }
    for (;;) {
        int alldone = 1;
        for (i = 0; i < n; i++) {
            const struct aiocb *cb = list[i];
            if (!cb) continue;
            if (!cb->__ml_done) {
                alldone = 0;
                break;
            }
        }
        if (alldone) return 0;
        if (timeout) {
            struct timespec now, sl = {0, 1000000L};
            long long now_ns;
            clock_gettime(CLOCK_REALTIME, &now);
            now_ns = now.tv_sec * 1000000000LL + now.tv_nsec;
            if (now_ns >= deadline) {
                errno = EAGAIN;
                return -1;
            }
            nanosleep(&sl, 0);
        } else {
            struct timespec sl = {0, 1000000L};
            nanosleep(&sl, 0);
        }
    }
}

int lio_listio(int mode, struct aiocb *const *list, int n,
               struct sigevent *sig) {
    int i, submitted = 0;
    if (!list || n < 0 || (mode != LIO_WAIT && mode != LIO_NOWAIT)) {
        errno = EINVAL;
        return -1;
    }
    for (i = 0; i < n; i++) {
        struct aiocb *cb = (struct aiocb *)list[i];
        int op, r;
        if (!cb) continue;
        if (cb->aio_lio_opcode == LIO_READ) op = LIO_READ;
        else if (cb->aio_lio_opcode == LIO_WRITE) op = LIO_WRITE;
        else op = LIO_NOP;
        r = ml_aio_submit(cb, op);
        if (r != 0) {
            errno = EIO;
            return -1;
        }
        submitted++;
    }
    if (mode == LIO_WAIT) {
        if (aio_suspend((const struct aiocb *const *)list, n, 0) != 0)
            return -1;
    }
    if (sig && sig->sigev_notify == SIGEV_SIGNAL && submitted)
        raise(sig->sigev_signo);
    return 0;
}
