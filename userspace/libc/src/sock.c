/* libc sockets: BSD API over the kernel AF_UNIX/loopback-INET table.
 * send/recv map to sendto/recvfrom; sendmsg/recvmsg walk iovecs. */
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bits/ml_sys.h>

long __ml_ret(long r);

int socket(int domain, int type, int proto) {
    long r = __ml_call6(LX_SYS_socket, (long)domain, (long)type,
                        (long)proto, 0, 0, 0);
    return (int)__ml_ret(r);
}

int socketpair(int domain, int type, int proto, int sv[2]) {
    long r;
    if (!sv) {
        errno = EFAULT;
        return -1;
    }
    r = __ml_call6(LX_SYS_socketpair, (long)domain, (long)type,
                   (long)proto, (long)sv, 0, 0);
    return (int)__ml_ret(r);
}

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
    long r;
    if (!addr) {
        errno = EFAULT;
        return -1;
    }
    r = __ml_call6(LX_SYS_bind, (long)fd, (long)addr, (long)len, 0, 0,
                   0);
    return (int)__ml_ret(r);
}

int listen(int fd, int backlog) {
    long r = __ml_call6(LX_SYS_listen, (long)fd, (long)backlog, 0, 0, 0,
                        0);
    return (int)__ml_ret(r);
}

int accept(int fd, struct sockaddr *addr, socklen_t *len) {
    return accept4(fd, addr, len, 0);
}

int accept4(int fd, struct sockaddr *addr, socklen_t *len, int flags) {
    long r;
    unsigned alen = 0;
    if (flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) {
        errno = EINVAL;
        return -1;
    }
    if (addr && (!len || *len < sizeof(addr->sa_family))) {
        if (len && *len < sizeof(addr->sa_family)) {
            errno = EINVAL;
            return -1;
        }
    }
    if (len) alen = *len;
    r = __ml_call6(LX_SYS_accept, (long)fd, (long)addr,
                   (long)(addr ? &alen : 0), 0, 0, 0);
    if (__ml_ret(r) != 0) return -1;
    if (len) *len = alen;
    return (int)r;
}

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    long r;
    if (!addr) {
        errno = EFAULT;
        return -1;
    }
    r = __ml_call6(LX_SYS_connect, (long)fd, (long)addr, (long)len, 0,
                   0, 0);
    return (int)__ml_ret(r);
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
    long r;
    unsigned alen;
    if (!addr || !len) {
        errno = EFAULT;
        return -1;
    }
    alen = *len;
    r = __ml_call6(LX_SYS_getsockname, (long)fd, (long)addr, (long)&alen,
                   0, 0, 0);
    if (__ml_ret(r) != 0) return -1;
    *len = alen;
    return 0;
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *len) {
    long r;
    unsigned alen;
    if (!addr || !len) {
        errno = EFAULT;
        return -1;
    }
    alen = *len;
    r = __ml_call6(LX_SYS_getpeername, (long)fd, (long)addr,
                   (long)&alen, 0, 0, 0);
    if (__ml_ret(r) != 0) return -1;
    *len = alen;
    return 0;
}

ssize_t send(int fd, const void *buf, size_t n, int flags) {
    return sendto(fd, buf, n, flags, 0, 0);
}

ssize_t recv(int fd, void *buf, size_t n, int flags) {
    return recvfrom(fd, buf, n, flags, 0, 0);
}

ssize_t sendto(int fd, const void *buf, size_t n, int flags,
               const struct sockaddr *addr, socklen_t len) {
    long r = __ml_call6(LX_SYS_sendto, (long)fd, (long)buf, (long)n,
                        (long)flags, (long)addr, (long)len);
    return (ssize_t)__ml_ret(r);
}

ssize_t recvfrom(int fd, void *buf, size_t n, int flags,
                 struct sockaddr *addr, socklen_t *len) {
    long r;
    unsigned alen = 0;
    if (addr && len) alen = *len;
    r = __ml_call6(LX_SYS_recvfrom, (long)fd, (long)buf, (long)n,
                   (long)flags, (long)addr,
                   (long)((addr && len) ? &alen : 0));
    if (__ml_ret(r) < 0) return -1;
    if (addr && len) *len = alen;
    return (ssize_t)r;
}

ssize_t sendmsg(int fd, const struct msghdr *m, int flags) {
    size_t total = 0, i;
    if (!m) {
        errno = EFAULT;
        return -1;
    }
    for (i = 0; i < m->msg_iovlen; i++) {
        ssize_t r = sendto(fd, m->msg_iov[i].iov_base,
                           m->msg_iov[i].iov_len, flags, m->msg_name,
                           m->msg_namelen);
        if (r < 0) return total > 0 ? (ssize_t)total : -1;
        total += (size_t)r;
        if ((size_t)r < m->msg_iov[i].iov_len) break;
    }
    return (ssize_t)total;
}

ssize_t recvmsg(int fd, struct msghdr *m, int flags) {
    size_t total = 0, i;
    if (!m) {
        errno = EFAULT;
        return -1;
    }
    for (i = 0; i < m->msg_iovlen; i++) {
        ssize_t r;
        if (i == 0)
            r = recvfrom(fd, m->msg_iov[i].iov_base,
                         m->msg_iov[i].iov_len, flags, m->msg_name,
                         m->msg_namelen ? &m->msg_namelen : 0);
        else
            r = recv(fd, m->msg_iov[i].iov_base,
                     m->msg_iov[i].iov_len, flags);
        if (r < 0) return total > 0 ? (ssize_t)total : -1;
        total += (size_t)r;
        if ((size_t)r < m->msg_iov[i].iov_len) break;
        if ((size_t)r == 0) break;
    }
    return (ssize_t)total;
}

int setsockopt(int fd, int level, int name, const void *val,
               socklen_t len) {
    long r = __ml_call6(LX_SYS_setsockopt, (long)fd, (long)level,
                        (long)name, (long)val, (long)len, 0);
    return (int)__ml_ret(r);
}

int getsockopt(int fd, int level, int name, void *val, socklen_t *len) {
    long r;
    unsigned optlen;
    if (!val || !len) {
        errno = EFAULT;
        return -1;
    }
    optlen = *len;
    r = __ml_call6(LX_SYS_getsockopt, (long)fd, (long)level,
                   (long)name, (long)val, (long)&optlen, 0);
    if (__ml_ret(r) != 0) return -1;
    *len = optlen;
    return 0;
}

int shutdown(int fd, int how) {
    long r = __ml_call6(LX_SYS_shutdown, (long)fd, (long)how, 0, 0, 0,
                        0);
    return (int)__ml_ret(r);
}
