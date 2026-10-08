/* Moonlight libc - spawn (vfork+exec over kernel TCBs). */
#pragma once

#include <sys/types.h>
#include <signal.h>

typedef struct {
    short flags;
    pid_t pgroup;
    sigset_t mask;
    sigset_t def;
    int fd_map[16];
    int fd_n;
} posix_spawnattr_t;

typedef struct {
    int fd_op[16];
    int fd_fd[16];
    int fd_map[16];
    int fd_flags[16];
    char fd_path[16][64];
    int fd_n;
} posix_spawn_file_actions_t;

#define POSIX_SPAWN_RESETIDS 1
#define POSIX_SPAWN_SETPGROUP 2
#define POSIX_SPAWN_SETSIGDEF 4
#define POSIX_SPAWN_SETSIGMASK 8

int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *fa,
                const posix_spawnattr_t *attr, char *const argv[],
                char *const envp[]);
int posix_spawnp(pid_t *pid, const char *file,
                 const posix_spawn_file_actions_t *fa,
                 const posix_spawnattr_t *attr, char *const argv[],
                 char *const envp[]);
int posix_spawnattr_init(posix_spawnattr_t *a);
int posix_spawnattr_destroy(posix_spawnattr_t *a);
int posix_spawnattr_setflags(posix_spawnattr_t *a, short f);
int posix_spawnattr_getflags(const posix_spawnattr_t *a, short *f);
int posix_spawnattr_setpgroup(posix_spawnattr_t *a, pid_t p);
int posix_spawnattr_getpgroup(const posix_spawnattr_t *a, pid_t *p);
int posix_spawnattr_setsigmask(posix_spawnattr_t *a, const sigset_t *m);
int posix_spawnattr_getsigmask(const posix_spawnattr_t *a, sigset_t *m);
int posix_spawnattr_setsigdefault(posix_spawnattr_t *a, const sigset_t *m);
int posix_spawnattr_getsigdefault(const posix_spawnattr_t *a, sigset_t *m);
int posix_spawn_file_actions_init(posix_spawn_file_actions_t *f);
int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *f);
int posix_spawn_file_actions_addopen(posix_spawn_file_actions_t *f, int fd,
                                     const char *path, int flags, mode_t mode);
int posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *f, int fd);
int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *f, int old,
                                     int newf);
