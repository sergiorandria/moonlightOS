/* Moonlight libc - sys/socket + netinet/in + arpa/inet + netdb.
 * AF_UNIX/AF_INET(loopback) stream+dgram over the kernel socket table. */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define AF_UNIX 1
#define AF_INET 2
#define AF_UNSPEC 0
#define PF_UNIX AF_UNIX
#define PF_INET AF_INET
#define PF_UNSPEC AF_UNSPEC

#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_NONBLOCK 04000
#define SOCK_CLOEXEC 02000000

#define SOL_SOCKET 1
#define SO_TYPE 3
#define SO_ERROR 4
#define SO_SNDBUF 7
#define SO_RCVBUF 8
#define SO_REUSEADDR 2
#define SO_KEEPALIVE 9
#define SO_RCVTIMEO 20
#define SO_SNDTIMEO 21

#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2

#define MSG_DONTWAIT 0x40
#define MSG_PEEK 0x2
#define MSG_WAITALL 0x100

typedef uint32_t socklen_t;
typedef uint16_t sa_family_t;

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};

struct sockaddr_un {
    sa_family_t sun_family;
    char sun_path[108];
};

struct sockaddr_in {
    sa_family_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    char sin_zero[8];
};

struct sockaddr_storage {
    sa_family_t ss_family;
    char __pad[126];
};

struct msghdr {
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    int msg_flags;
};

#ifndef __ML_IOVEC_DEFINED
#define __ML_IOVEC_DEFINED 1
struct iovec {
    void *iov_base;
    size_t iov_len;
};
#endif

struct linger {
    int l_onoff;
    int l_linger;
};

#ifndef __ML_TIMEVAL_DEFINED
#define __ML_TIMEVAL_DEFINED 1
struct timeval {
    long tv_sec;
    long tv_usec;
};
#endif

int socket(int domain, int type, int proto);
int socketpair(int domain, int type, int proto, int sv[2]);
int bind(int fd, const struct sockaddr *addr, socklen_t len);
int listen(int fd, int backlog);
int accept(int fd, struct sockaddr *addr, socklen_t *len);
int accept4(int fd, struct sockaddr *addr, socklen_t *len, int flags);
int connect(int fd, const struct sockaddr *addr, socklen_t len);
int getsockname(int fd, struct sockaddr *addr, socklen_t *len);
int getpeername(int fd, struct sockaddr *addr, socklen_t *len);
ssize_t send(int fd, const void *buf, size_t n, int flags);
ssize_t recv(int fd, void *buf, size_t n, int flags);
ssize_t sendto(int fd, const void *buf, size_t n, int flags,
               const struct sockaddr *addr, socklen_t len);
ssize_t recvfrom(int fd, void *buf, size_t n, int flags,
                 struct sockaddr *addr, socklen_t *len);
ssize_t sendmsg(int fd, const struct msghdr *m, int flags);
ssize_t recvmsg(int fd, struct msghdr *m, int flags);
int setsockopt(int fd, int level, int name, const void *val,
               socklen_t len);
int getsockopt(int fd, int level, int name, void *val, socklen_t *len);
int shutdown(int fd, int how);
