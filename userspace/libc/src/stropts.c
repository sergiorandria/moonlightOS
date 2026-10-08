/* libc stropts: STREAMS message compat over fd byte streams. No
 * STREAMS modules exist on this target, so there is no control channel:
 * isastream validates the fd and reports 0, the data part of every
 * message moves through read/write (short counts looped, nonblocking
 * EAGAIN passed through), control payloads are EINVAL, and attach
 * fails ENOSTR once the path itself checks out. */
#include <stropts.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>

int isastream(int fd) {
    /* The whole truth: validate the fd (errno from fcntl), then
     * report that no STREAMS module is pushed. */
    if (fcntl(fd, F_GETFD) != 0) return 0;
    return 0;
}

/* Validate one strbuf: NULL means "absent" (allowed); otherwise the
 * length must be >= 0 and a positive maxlen needs a buffer. */
static int ml_strbuf_ok(const struct strbuf *b) {
    if (!b) return 0;
    if (b->maxlen < 0 || b->len < 0) {
        errno = EINVAL;
        return -1;
    }
    if (b->maxlen > 0 && !b->buf) {
        errno = EFAULT;
        return -1;
    }
    return 0;
}

static int ml_fd_live(int fd) {
    if (fcntl(fd, F_GETFD) != 0) return -1; /* errno already set */
    return 0;
}

int getmsg(int fd, struct strbuf *ctl, struct strbuf *dat, int *flags) {
    ssize_t r;
    if (!flags) {
        errno = EFAULT;
        return -1;
    }
    if (ml_strbuf_ok(ctl) != 0 || ml_strbuf_ok(dat) != 0) return -1;
    if (ml_fd_live(fd) != 0) return -1;
    /* No control channel: report zero control bytes when asked. */
    if (ctl) ctl->len = 0;
    *flags = 0;
    if (!dat || !dat->buf || dat->maxlen == 0) {
        if (dat) dat->len = 0;
        return 0;
    }
    r = read(fd, dat->buf, (size_t)dat->maxlen);
    if (r < 0) {
        if (dat) dat->len = -1;
        return -1;
    }
    dat->len = (int)r;
    return 0;
}

int getpmsg(int fd, struct strbuf *ctl, struct strbuf *dat, int *band,
            int *flags) {
    if (!band) {
        errno = EFAULT;
        return -1;
    }
    if (getmsg(fd, ctl, dat, flags) != 0) return -1;
    *band = 0; /* single band on a byte stream */
    return 0;
}

int putmsg(int fd, const struct strbuf *ctl, const struct strbuf *dat,
           int flags) {
    size_t off = 0;
    if (ml_strbuf_ok(ctl) != 0 || ml_strbuf_ok(dat) != 0) return -1;
    /* A control payload has nowhere to go (no multiplexor below). */
    if (ctl && ctl->len > 0) {
        errno = EINVAL;
        return -1;
    }
    if (flags != 0 && flags != RS_HIPRI && flags != MSG_HIPRI) {
        errno = EINVAL;
        return -1;
    }
    if (ml_fd_live(fd) != 0) return -1;
    if (!dat || !dat->buf || dat->len <= 0) return 0;
    /* Byte streams have no message boundaries: loop the data part
     * through write until it is all accepted. */
    while (off < (size_t)dat->len) {
        ssize_t w =
            write(fd, dat->buf + off, (size_t)dat->len - off);
        if (w < 0) return -1;
        if (w == 0) {
            errno = EIO;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

int putpmsg(int fd, const struct strbuf *ctl, const struct strbuf *dat,
            int band, int flags) {
    if (band != 0) {
        errno = EINVAL;
        return -1;
    }
    return putmsg(fd, ctl, dat, flags);
}

int fattach(int fd, const char *path) {
    if (!path) {
        errno = EFAULT;
        return -1;
    }
    if (ml_fd_live(fd) != 0) return -1;
    if (path[0] == '\0' || strlen(path) >= 256) {
        errno = EINVAL;
        return -1;
    }
    /* The path must name something real before the STREAMS verdict. */
    if (access(path, F_OK) != 0) return -1;
    errno = ENOSTR; /* fd is not a STREAMS device */
    return -1;
}

int fdetach(const char *path) {
    if (!path) {
        errno = EFAULT;
        return -1;
    }
    if (path[0] == '\0' || strlen(path) >= 256) {
        errno = EINVAL;
        return -1;
    }
    if (access(path, F_OK) != 0) return -1;
    errno = ENOSTR; /* nothing attached (no STREAMS devices exist) */
    return -1;
}
