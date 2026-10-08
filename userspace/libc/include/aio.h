/* Moonlight libc - aio.h (POSIX async I/O over a worker
 * thread pool; implemented in src/aio.c). */
#pragma once

#include <signal.h>
#include <sys/types.h>

struct aiocb {
    int aio_fildes;
    void *aio_buf;
    size_t aio_nbytes;
    off_t aio_offset;
    int aio_reqprio;
    struct sigevent aio_sigevent;
    int aio_lio_opcode;
    /* internal */
    int __ml_err;
    ssize_t __ml_ret;
    int __ml_done;
    int __ml_queued;
};

#define AIO_CANCELED 0
#define AIO_NOTCANCELED 1
#define AIO_ALLDONE 2
#define LIO_READ 0
#define LIO_WRITE 1
#define LIO_NOP 2
#define LIO_WAIT 0
#define LIO_NOWAIT 1

int aio_read(struct aiocb *cb);
int aio_write(struct aiocb *cb);
int aio_fsync(int op, struct aiocb *cb);
int aio_error(const struct aiocb *cb);
ssize_t aio_return(struct aiocb *cb);
int aio_cancel(int fd, struct aiocb *cb);
int aio_suspend(const struct aiocb *const *list, int n,
                const struct timespec *timeout);
int lio_listio(int mode, struct aiocb *const *list, int n,
               struct sigevent *sig);
