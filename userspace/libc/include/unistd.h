/* Moonlight libc - unistd. */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifndef __ML_IOVEC_DEFINED
#define __ML_IOVEC_DEFINED 1
struct iovec {
    void *iov_base;
    size_t iov_len;
};
#endif

int close(int fd);
ssize_t read(int fd, void *buf, size_t n);
ssize_t write(int fd, const void *buf, size_t n);
off_t lseek(int fd, off_t off, int whence);
ssize_t readv(int fd, const struct iovec *v, int n);
ssize_t writev(int fd, const struct iovec *v, int n);
ssize_t pread(int fd, void *buf, size_t n, off_t off);
ssize_t pwrite(int fd, const void *buf, size_t n, off_t off);
int unlink(const char *path);
int access(const char *path, int mode);
int chdir(const char *path);
char *getcwd(char *buf, size_t n);
int ftruncate(int fd, off_t len);
int truncate(const char *path, off_t len);
int isatty(int fd);
int brk(void *addr);
void *sbrk(intptr_t inc);
int getpid(void);
int getppid(void);
int getuid(void);
int geteuid(void);
int getgid(void);
int getegid(void);
int gettid(void);
int gethostname(char *buf, size_t n);
int getpgid(int pid);
int getpgrp(void);
int setpgid(int pid, int pgid);
int setsid(void);
long getpagesize(void);
long sysconf(int name);
long pathconf(const char *path, int name);
long fpathconf(int fd, int name);
int fsync(int fd);
int fdatasync(int fd);
void sync(void);
int pause(void);
/* Process creation / exec / pipes / dup over real kernel objects
 * (clone/fork share the single address space, nommu semantics;
 * execve loads user ELFs from the VFS; pipes/sockets are kernel
 * rings). wait()/waitpid()/wait4() reap via the children table. */
int fork(void);
int vfork(void);
long clone(unsigned long flags, void *stack, int *ptid, void *tls,
           int *ctid);
int execve(const char *path, char *const argv[], char *const envp[]);
int execv(const char *path, char *const argv[]);
int execvp(const char *file, char *const argv[]);
int execvpe(const char *file, char *const argv[], char *const envp[]);
int execl(const char *path, const char *arg, ...);
int execlp(const char *file, const char *arg, ...);
int execle(const char *path, const char *arg, ...);
int eaccess(const char *path, int mode);
int euidaccess(const char *path, int mode);
int closefrom(int lowfd);
int getdtablesize(void);
ssize_t preadv(int fd, const struct iovec *v, int n, off_t off);
ssize_t pwritev(int fd, const struct iovec *v, int n, off_t off);
char *getusershell(void);
void setusershell(void);
void endusershell(void);
int pipe(int fd2[2]);
int pipe2(int fd2[2], int flags);
int dup(int fd);
int dup2(int oldfd, int newfd);
int dup3(int oldfd, int newfd, int flags);
int kill(int pid, int sig);
int tgkill(int tgid, int tid, int sig);
ssize_t readlink(const char *path, char *buf, size_t n);
int symlink(const char *oldp, const char *newp);
int link(const char *oldp, const char *newp);
ssize_t getrandom(void *buf, size_t n, unsigned flags);
int getentropy(void *buf, size_t n);
void swab(const void *from, void *to, ssize_t n);
unsigned sleep(unsigned s);
int usleep(unsigned us);
void _exit(int code) __attribute__((noreturn));
unsigned alarm(unsigned s);
int nice(int inc);
long confstr(int name, char *buf, size_t n);
char *ctermid(char *buf);
char *ttyname(int fd);
int ttyname_r(int fd, char *buf, size_t n);
char *getlogin(void);
int getlogin_r(char *buf, size_t n);
int getgroups(int n, gid_t grouplist[]);
int setgroups(size_t n, const gid_t *list);
int setuid(uid_t uid);
int setgid(gid_t gid);
int seteuid(uid_t uid);
int setegid(gid_t gid);
int fchdir(int fd);
int sethostname(const char *name, size_t n);

extern char *optarg;
extern int optind, opterr, optopt;
int getopt(int argc, char *const argv[], const char *optstring);

/* confstr names (the subset with true answers here). */
#define _CS_PATH 0
#define _CS_POSIX_V7_WIDTH_RESTRICTED_ENVS 5
#define _CS_POSIX_V7_ILP32_OFF32_CFLAGS 1116
#define _CS_POSIX_V7_LP64_OFF64_CFLAGS 1119
#define _CS_POSIX_V6_WIDTH_RESTRICTED_ENVS 5

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

/* access() modes (match LX_F_OK/R_OK/W_OK/X_OK). */
#define F_OK 0
#define X_OK 1
#define W_OK 2
#define R_OK 4

/* sysconf names (the subset with true answers here). */
#define _SC_PAGESIZE 30
#define _SC_PAGE_SIZE _SC_PAGESIZE
#define _SC_NPROCESSORS_ONLN 84
#define _SC_OPEN_MAX 11
#define _SC_IOV_MAX 60
#define _SC_GETPW_R_SIZE_MAX 70
#define _SC_CLK_TCK 2

/* pathconf names (static flat-VFS answers). */
#define _PC_NAME_MAX 3
#define _PC_PATH_MAX 4
#define _PC_PIPE_BUF 6
