/* Moonlight libc - sys/ipc.h (System V IPC keys + perms). */
#pragma once

#include <sys/types.h>

struct ipc_perm {
    int __key;
    uid_t uid;
    gid_t gid;
    uid_t cuid;
    gid_t cgid;
    unsigned short mode;
    unsigned short __seq;
};

#define IPC_CREAT 01000
#define IPC_EXCL 02000
#define IPC_NOWAIT 04000
#define IPC_RMID 0
#define IPC_SET 1
#define IPC_STAT 2
#define IPC_INFO 3

#define IPC_PRIVATE 0

typedef int key_t;

key_t ftok(const char *path, int id);
