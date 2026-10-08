/* Moonlight libc - sys/stat. */
#pragma once

#include <sys/types.h>

struct stat {
    dev_t st_dev;
    ino_t st_ino;
    mode_t st_mode;
    nlink_t st_nlink;
    uid_t st_uid;
    gid_t st_gid;
    dev_t st_rdev;
    unsigned long __pad1;
    off_t st_size;
    int st_blksize;
    int __pad2;
    blkcnt_t st_blocks;
    time_t st_atime;
    long st_atime_nsec;
    time_t st_mtime;
    long st_mtime_nsec;
    time_t st_ctime;
    long st_ctime_nsec;
    int __unused[2];
};

#define S_IFREG 0100000
#define S_IFCHR 0020000
#define S_IFDIR 0040000
#define S_IFIFO 0010000
#define S_IFLNK 0120000
#define S_IFSOCK 0140000
#define S_IFMT 0170000
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

/* Permission bits (accepted by open's mode arg; owner model ignores them). */
#define S_ISUID 04000
#define S_ISGID 02000
#define S_ISVTX 01000
#define S_IRUSR 0400
#define S_IWUSR 0200
#define S_IXUSR 0100
#define S_IRGRP 040
#define S_IWGRP 020
#define S_IXGRP 010
#define S_IROTH 04
#define S_IWOTH 02
#define S_IXOTH 01
#define S_IRWXU 0700
#define S_IRWXG 070
#define S_IRWXO 07

int stat(const char *path, struct stat *st);
int fstat(int fd, struct stat *st);
int lstat(const char *path, struct stat *st);
int fstatat(int dirfd, const char *path, struct stat *st, int flags);
/* Owner model: mode bits are accepted (files 0644, dirs 0755). */
int chmod(const char *path, mode_t mode);
int fchmod(int fd, mode_t mode);
int fchmodat(int dirfd, const char *path, mode_t mode, int flags);
mode_t umask(mode_t mask);
int chown(const char *path, uid_t uid, gid_t gid);
int fchown(int fd, uid_t uid, gid_t gid);
int lchown(const char *path, uid_t uid, gid_t gid);
int fchownat(int dirfd, const char *path, uid_t uid, gid_t gid, int flags);
int mkdir(const char *path, mode_t mode);
int rmdir(const char *path);
int symlink(const char *oldp, const char *newp);
int link(const char *oldp, const char *newp);
int mkfifo(const char *path, mode_t mode);
int mkfifoat(int dirfd, const char *path, mode_t mode);
int mknod(const char *path, mode_t mode, dev_t dev);
int mknodat(int dirfd, const char *path, mode_t mode, dev_t dev);

/* Extended stat (kernel statx; mask always BASIC_STATS there). */
struct statx_timestamp {
    long long tv_sec;
    unsigned tv_nsec;
    int __reserved;
};

struct statx {
    unsigned stx_mask;
    unsigned stx_blksize;
    unsigned long long stx_attributes;
    unsigned stx_nlink;
    unsigned stx_uid;
    unsigned stx_gid;
    unsigned short stx_mode;
    unsigned short __spare0[1];
    unsigned long long stx_ino;
    unsigned long long stx_size;
    unsigned long long stx_blocks;
    unsigned long long stx_attributes_mask;
    struct statx_timestamp stx_atime;
    struct statx_timestamp stx_mtime;
    struct statx_timestamp stx_ctime;
    /* NOTE: no stx_btime here — the kernel statx omits birth time and
     * packs rdev/dev immediately after ctime; the layout mirrors the
     * kernel lx_statx_t exactly. */
    unsigned stx_rdev_major;
    unsigned stx_rdev_minor;
    unsigned stx_dev_major;
    unsigned stx_dev_minor;
    unsigned long long __spare2[14];
};

#define STATX_TYPE 0x001
#define STATX_MODE 0x002
#define STATX_NLINK 0x004
#define STATX_UID 0x008
#define STATX_GID 0x010
#define STATX_ATIME 0x020
#define STATX_MTIME 0x040
#define STATX_CTIME 0x080
#define STATX_INO 0x100
#define STATX_SIZE 0x200
#define STATX_BLOCKS 0x400
#define STATX_BASIC_STATS 0x7FF
#define STATX_ALL 0xFFF
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif
#define AT_NO_AUTOMOUNT 0x800
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#define AT_STATX_SYNC_TYPE 0x6000
#define AT_STATX_SYNC_AS_STAT 0x0000
#define AT_STATX_FORCE_SYNC 0x2000
#define AT_STATX_DONT_SYNC 0x4000

int statx(int dirfd, const char *path, int flags, unsigned mask,
          struct statx *buf);
