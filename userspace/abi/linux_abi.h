#pragma once
/* Linux rv64 personality ABI: syscall numbers, errnos, flags and structs.
 * Numbers are the asm-generic (riscv64/musl) table - verified against
 * musl arch/riscv64/bits/syscall.h.in. Only the subset implemented in
 * kernel/src/linux.c is listed here; anything else returns -ENOSYS.
 *
 * Dispatch rule (kernel/src/syscall.c): a7 <= SYS_MAX (7) runs the native
 * Moonlight capability path; a7 > 7 runs the Linux personality. Linux
 * numbers 0..7 (io_setup..fsetxattr) therefore stay -ENOSYS: no collision,
 * no ambiguity. Linux results use the Linux convention (a0 = -errno).
 */
#include <stdint.h>
#include <stddef.h>

/* ---- implemented syscalls (riscv64 numbers) ---- */
#define LX_SYS_getcwd 17
#define LX_SYS_dup 23
#define LX_SYS_dup3 24
#define LX_SYS_fcntl 25
#define LX_SYS_ioctl 29
#define LX_SYS_flock 32
#define LX_SYS_mknodat 33
#define LX_SYS_mkdirat 34
#define LX_SYS_unlinkat 35
#define LX_SYS_symlinkat 36
#define LX_SYS_linkat 37
#define LX_SYS_truncate 45
#define LX_SYS_ftruncate 46
#define LX_SYS_faccessat 48
#define LX_SYS_chdir 49
#define LX_SYS_fchdir 50
#define LX_SYS_fchmodat 53
#define LX_SYS_fchownat 54
#define LX_SYS_openat 56
#define LX_SYS_close 57
#define LX_SYS_pipe2 59
#define LX_SYS_getdents64 61
#define LX_SYS_lseek 62
#define LX_SYS_read 63
#define LX_SYS_write 64
#define LX_SYS_readv 65
#define LX_SYS_writev 66
#define LX_SYS_pread64 67
#define LX_SYS_pwrite64 68
#define LX_SYS_pselect6 72
#define LX_SYS_ppoll 73
#define LX_SYS_readlinkat 78
#define LX_SYS_newfstatat 79
#define LX_SYS_fstat 80
#define LX_SYS_exit 93
#define LX_SYS_exit_group 94
#define LX_SYS_set_tid_address 96
#define LX_SYS_futex 98
#define LX_SYS_nanosleep 101
#define LX_SYS_clock_gettime 113
#define LX_SYS_clock_getres 114
#define LX_SYS_clock_nanosleep 115
#define LX_SYS_sched_yield 124
#define LX_SYS_kill 129
#define LX_SYS_tgkill 131
#define LX_SYS_rt_sigpending 136
#define LX_SYS_rt_sigtimedwait 137
#define LX_SYS_uname 160
#define LX_SYS_gettimeofday 169
#define LX_SYS_getpid 172
#define LX_SYS_getppid 173
#define LX_SYS_getuid 174
#define LX_SYS_geteuid 175
#define LX_SYS_getgid 176
#define LX_SYS_getegid 177
#define LX_SYS_gettid 178
#define LX_SYS_socket 198
#define LX_SYS_socketpair 199
#define LX_SYS_bind 200
#define LX_SYS_listen 201
#define LX_SYS_accept 202
#define LX_SYS_connect 203
#define LX_SYS_getsockname 204
#define LX_SYS_getpeername 205
#define LX_SYS_sendto 206
#define LX_SYS_recvfrom 207
#define LX_SYS_setsockopt 208
#define LX_SYS_getsockopt 209
#define LX_SYS_shutdown 210
#define LX_SYS_brk 214
#define LX_SYS_munmap 215
#define LX_SYS_clone 220
#define LX_SYS_execve 221
#define LX_SYS_mmap 222
#define LX_SYS_mprotect 226
#define LX_SYS_madvise 233
#define LX_SYS_accept4 242
#define LX_SYS_wait4 260
#define LX_SYS_getrandom 278
#define LX_SYS_utimensat 280
#define LX_SYS_statx 291

/* ---- errnos (asm-generic errno-base.h) ---- */
#define LX_EPERM 1
#define LX_ENOENT 2
#define LX_ESRCH 3
#define LX_EINTR 4
#define LX_EIO 5
#define LX_ENXIO 6
#define LX_ENOEXEC 8
#define LX_EBADF 9
#define LX_ECHILD 10
#define LX_EAGAIN 11
#define LX_ENOMEM 12
#define LX_EACCES 13
#define LX_EFAULT 14
#define LX_EBUSY 16
#define LX_EEXIST 17
#define LX_ENODEV 19
#define LX_ENOTDIR 20
#define LX_EISDIR 21
#define LX_EINVAL 22
#define LX_EMFILE 24
#define LX_ENOSPC 28
#define LX_ESPIPE 29
#define LX_EROFS 30
#define LX_EMLINK 31
#define LX_EPIPE 32
#define LX_ERANGE 34
#define LX_ENAMETOOLONG 36
#define LX_ENOSYS 38
#define LX_ELOOP 40
#define LX_ENOMSG 42
#define LX_EIDRM 43
#define LX_ENOTSOCK 88
#define LX_EDESTADDRREQ 89
#define LX_EMSGSIZE 90
#define LX_EPROTOTYPE 91
#define LX_ENOPROTOOPT 92
#define LX_EPROTONOSUPPORT 93
#define LX_ESOCKTNOSUPPORT 94
#define LX_EOPNOTSUPP 95
#define LX_EAFNOSUPPORT 97
#define LX_EADDRINUSE 98
#define LX_EADDRNOTAVAIL 99
#define LX_ENETDOWN 100
#define LX_ENETUNREACH 101
#define LX_ECONNABORTED 103
#define LX_ECONNRESET 104
#define LX_ENOBUFS 105
#define LX_EISCONN 106
#define LX_ENOTCONN 107
#define LX_ETIMEDOUT 110
#define LX_ECONNREFUSED 111
#define LX_EINPROGRESS 115
#define LX_EALREADY 114
#define LX_EOVERFLOW 75
#define LX_ECHRNG 44
#define LX_EL2NSYNC 45

/* ---- openat/fcntl flags (asm-generic fcntl.h, octal) ---- */
#define LX_O_RDONLY 0
#define LX_O_WRONLY 01
#define LX_O_RDWR 02
#define LX_O_CREAT 0100
#define LX_O_EXCL 0200
#define LX_O_NOCTTY 0400
#define LX_O_TRUNC 01000
#define LX_O_APPEND 02000
#define LX_O_NONBLOCK 04000
#define LX_O_DIRECTORY 040000
#define LX_O_NOFOLLOW 0400000
#define LX_O_CLOEXEC 02000000
#define LX_O_ACCMODE 03

/* ---- at(2) flags ---- */
#define LX_AT_FDCWD (-100)
#define LX_AT_REMOVEDIR 0x200
#define LX_AT_EMPTY_PATH 0x1000
#define LX_AT_SYMLINK_NOFOLLOW 0x100
#define LX_AT_NO_AUTOMOUNT 0x800
#define LX_AT_STATX_SYNC_TYPE 0x6000

/* ---- waitid ---- */
#define LX_WEXITED 0x4
#define LX_WSTOPPED 0x2
#define LX_WNOWAIT 0x1000000

/* ---- seek ---- */
#define LX_SEEK_SET 0
#define LX_SEEK_CUR 1
#define LX_SEEK_END 2

/* ---- mmap ---- */
#define LX_PROT_NONE 0x0
#define LX_PROT_READ 0x1
#define LX_PROT_WRITE 0x2
#define LX_PROT_EXEC 0x4
#define LX_MAP_SHARED 0x01
#define LX_MAP_PRIVATE 0x02
#define LX_MAP_FIXED 0x10
#define LX_MAP_ANONYMOUS 0x20

/* ---- access modes ---- */
#define LX_F_OK 0
#define LX_X_OK 1
#define LX_W_OK 2
#define LX_R_OK 4

/* ---- clocks ---- */
#define LX_CLOCK_REALTIME 0
#define LX_CLOCK_MONOTONIC 1
#define LX_CLOCK_PROCESS_CPUTIME_ID 2

/* ---- file types ---- */
#define LX_S_IFREG 0100000
#define LX_S_IFDIR 0040000
#define LX_S_IFCHR 0020000
#define LX_S_IFIFO 0010000
#define LX_S_IFLNK 0120000
#define LX_S_IFSOCK 0140000
#define LX_S_IFMT 0170000

/* ---- dup/fcntl (asm-generic fcntl.h) ---- */
#define LX_F_DUPFD_CLOEXEC 1030
#define LX_F_DUPFD 0
#define LX_F_GETFD 1
#define LX_F_SETFD 2
#define LX_F_GETFL 3
#define LX_F_SETFL 4
#define LX_F_GETLK 5
#define LX_F_SETLK 6
#define LX_F_SETLKW 7
#define LX_FD_CLOEXEC 1
#define LX_O_CLOEXEC_EXTRA 02000000 /* == O_CLOEXEC, kept for F_* users */

/* ---- flock(2) ---- */
#define LX_LOCK_SH 1
#define LX_LOCK_EX 2
#define LX_LOCK_NB 4
#define LX_LOCK_UN 8

/* ---- ioctl ---- */
#define LX_FIONREAD 0x541B
#define LX_TIOCGWINSZ 0x5413
#define LX_TIOCSWINSZ 0x5414
#define LX_TCGETS 0x5401
#define LX_TCSETS 0x5402

/* ---- poll/select ---- */
#define LX_POLLIN 0x001
#define LX_POLLPRI 0x002
#define LX_POLLOUT 0x004
#define LX_POLLERR 0x008
#define LX_POLLHUP 0x010
#define LX_POLLNVAL 0x020

typedef struct {
    int fd;
    short events;
    short revents;
} lx_pollfd_t;

/* ---- getdents64 ---- */
typedef struct {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[32];
} lx_dirent64_t;
#define LX_DT_UNKNOWN 0
#define LX_DT_FIFO 1
#define LX_DT_CHR 2
#define LX_DT_DIR 4
#define LX_DT_REG 8
#define LX_DT_LNK 10
#define LX_DT_SOCK 12

/* ---- sockets ---- */
#define LX_AF_UNIX 1
#define LX_AF_INET 2
#define LX_SOCK_STREAM 1
#define LX_SOCK_DGRAM 2
#define LX_SOCK_NONBLOCK 04000
#define LX_SOCK_CLOEXEC 02000000
#define LX_SOL_SOCKET 1
#define LX_SO_RCVTIMEO_OLD 20
#define LX_SO_SNDTIMEO_OLD 21
#define LX_SO_ERROR 4
#define LX_SO_TYPE 3
#define LX_SO_REUSEADDR 2
#define LX_SO_KEEPALIVE 9
#define LX_SO_SNDBUF 7
#define LX_SO_RCVBUF 8
#define LX_SHUT_RD 0
#define LX_SHUT_WR 1
#define LX_SHUT_RDWR 2
#define LX_MSG_DONTWAIT 0x40
#define LX_MSG_PEEK 0x2
#define LX_MSG_WAITALL 0x100

typedef struct {
    uint16_t sun_family;
    char sun_path[108];
} lx_sockaddr_un_t;

typedef struct {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    char sin_zero[8];
} lx_sockaddr_in_t;

/* ---- clone ---- */
#define LX_CLONE_VM 0x100
#define LX_CLONE_FS 0x200
#define LX_CLONE_FILES 0x400
#define LX_CLONE_SIGHAND 0x800
#define LX_CLONE_VFORK 0x4000
#define LX_CLONE_PARENT_SETTID 0x100000
#define LX_CLONE_CHILD_CLEARTID 0x200000
#define LX_CLONE_CHILD_SETTID 0x1000000
#define LX_CSIGNAL 0xFF

/* ---- futex ---- */
#define LX_FUTEX_WAIT 0
#define LX_FUTEX_WAKE 1
#define LX_FUTEX_PRIVATE_FLAG 128

/* ---- wait ---- */
#define LX_WNOHANG 1
#define LX_WUNTRACED 2
#define LX_WCONTINUED 8

/* ---- statx ---- */
#define LX_STATX_BASIC_STATS 0x7FFu
typedef struct {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t __spare0[1];
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    int64_t stx_atime_sec;
    uint32_t stx_atime_nsec;
    int32_t __spare1;
    int64_t stx_mtime_sec;
    uint32_t stx_mtime_nsec;
    int32_t __spare2;
    int64_t stx_ctime_sec;
    uint32_t stx_ctime_nsec;
    int32_t __spare3;
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t __spare4[14];
} lx_statx_t;

/* ---- getrandom ---- */
#define LX_GRND_NONBLOCK 0x1
#define LX_GRND_RANDOM 0x2

/* rv64 Linux structs (LP64 layout). */

typedef struct {
    int64_t tv_sec;
    int64_t tv_nsec;
} lx_timespec_t;

typedef struct {
    int64_t tv_sec;
    int64_t tv_usec;
} lx_timeval_t;

typedef struct {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
} lx_utsname_t;

typedef struct {
    void *iov_base;
    size_t iov_len;
} lx_iovec_t;

/* 128-byte rv64 struct stat (glibc asm-generic layout: blksize is long,
 * blocks at offset 64). libc's struct stat mirrors this exactly. */
typedef struct {
    uint64_t st_dev;
    uint64_t st_ino;
    uint32_t st_mode;
    uint32_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    uint64_t st_rdev;
    uint64_t __pad1;
    int64_t st_size;
    int32_t st_blksize;
    int32_t __pad2;
    int64_t st_blocks;
    int64_t st_atime_sec;
    int64_t st_atime_nsec;
    int64_t st_mtime_sec;
    int64_t st_mtime_nsec;
    int64_t st_ctime_sec;
    int64_t st_ctime_nsec;
    int32_t __unused[2];
} lx_stat_t;
_Static_assert(sizeof(lx_stat_t) == 128, "lx_stat_t must be 128 bytes");
