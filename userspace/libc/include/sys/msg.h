/* Moonlight libc - sys/msg.h (System V message queues;
 * process-shared tables, implemented in src/sysvipc.c). */
#pragma once

#include <stddef.h>
#include <sys/ipc.h>
#include <sys/types.h>

struct msqid_ds {
    struct ipc_perm msg_perm;
    size_t msg_qnum;
    size_t msg_qbytes;
    pid_t msg_lspid;
    pid_t msg_lrpid;
    time_t msg_stime;
    time_t msg_rtime;
    time_t msg_ctime;
};

#define MSG_NOERROR 010000
#define MSG_EXCEPT 020000

struct msgbuf {
    long mtype;
    char mtext[1];
};

int msgget(key_t key, int flags);
int msgsnd(int id, const void *msgp, size_t size, int flags);
ssize_t msgrcv(int id, void *msgp, size_t size, long type, int flags);
int msgctl(int id, int cmd, struct msqid_ds *buf);
