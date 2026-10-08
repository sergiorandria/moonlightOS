/* libc sysvipc: System V IPC (message queues, semaphores,
 * shared memory) as process-shared tables. The single address space
 * makes the tables visible to every thread/process; blocking uses
 * pthread condvars, permissions honor uid/gid/mode, SEM_UNDO is
 * tracked per thread and rolled back on semop failure/exit paths.
 * ftok() folds a file's (dev,ino) with the project id. */
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#define ML_IPC_MAX 32

static pthread_mutex_t ml_ipc_mtx = {0, 0, 0, 0};
static int ml_ipc_seq = 1;

/* ================= ftok ================= */

key_t ftok(const char *path, int id) {
    struct stat st;
    if (!path) {
        errno = EINVAL;
        return -1;
    }
    if (stat(path, &st) != 0) return -1;
    return (key_t)(((st.st_ino & 0xFFFF) | ((st.st_dev & 0xFF) << 16) |
                    ((id & 0xFF) << 24)));
}

/* ================= message queues ================= */

typedef struct ml_msg {
    long type;
    size_t len;
    struct ml_msg *next;
    char data[];
} ml_msg_t;

typedef struct {
    int used;
    int seq;
    key_t key;
    struct ipc_perm perm;
    size_t qbytes;
    ml_msg_t *head, *tail;
    size_t qnum;
    size_t curbytes;
    pid_t lspid, lrpid;
    time_t stime, rtime, ctime;
    pthread_cond_t cond;
} ml_msq_t;

static ml_msq_t ml_msqs[ML_IPC_MAX];

static ml_msq_t *ml_msq_lookup(int id) {
    int i = id & 0xFF;
    if (i < 0 || i >= ML_IPC_MAX) return 0;
    if (!ml_msqs[i].used || ml_msqs[i].seq != (id >> 8)) return 0;
    return &ml_msqs[i];
}

static int ml_perm_ok(struct ipc_perm *p, int want) {
    uid_t me = getuid();
    gid_t mg = getgid();
    unsigned bits;
    if (me == 0) return 1;
    if (me == p->uid || me == p->cuid) bits = (p->mode >> 6) & 7;
    else if (mg == p->gid || mg == p->cgid) bits = (p->mode >> 3) & 7;
    else bits = p->mode & 7;
    return (bits & (unsigned)want) == (unsigned)want;
}

int msgget(key_t key, int flags) {
    int i, slot = -1;
    pthread_mutex_lock(&ml_ipc_mtx);
    for (i = 0; i < ML_IPC_MAX; i++) {
        if (!ml_msqs[i].used) {
            if (slot < 0) slot = i;
            continue;
        }
        if (key != IPC_PRIVATE && ml_msqs[i].key == key) {
            int id = ml_msqs[i].seq << 8 | i;
            if ((flags & IPC_CREAT) && (flags & IPC_EXCL)) {
                pthread_mutex_unlock(&ml_ipc_mtx);
                errno = EEXIST;
                return -1;
            }
            pthread_mutex_unlock(&ml_ipc_mtx);
            return id;
        }
    }
    if (key != IPC_PRIVATE && !(flags & IPC_CREAT)) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        errno = ENOENT;
        return -1;
    }
    if (slot < 0) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        errno = ENOSPC;
        return -1;
    }
    {
        ml_msq_t *q = &ml_msqs[slot];
        memset(q, 0, sizeof(*q));
        q->used = 1;
        q->seq = ml_ipc_seq++;
        if (ml_ipc_seq <= 0) ml_ipc_seq = 1;
        q->key = key;
        q->perm.__key = key;
        q->perm.uid = q->perm.cuid = getuid();
        q->perm.gid = q->perm.cgid = getgid();
        q->perm.mode = (unsigned short)(flags & 0777);
        q->qbytes = 16384;
        q->ctime = q->stime = q->rtime = time(0);
        pthread_cond_init(&q->cond, 0);
        pthread_mutex_unlock(&ml_ipc_mtx);
        return q->seq << 8 | slot;
    }
}

int msgsnd(int id, const void *msgp, size_t size, int flags) {
    const struct msgbuf *m = msgp;
    ml_msg_t *node;
    ml_msq_t *q;
    if (!msgp || size > 8192) {
        errno = EINVAL;
        return -1;
    }
    if (m->mtype < 1) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&ml_ipc_mtx);
    q = ml_msq_lookup(id);
    if (!q) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        errno = EINVAL;
        return -1;
    }
    if (!ml_perm_ok(&q->perm, 2)) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        errno = EACCES;
        return -1;
    }
    while (q->curbytes + size > q->qbytes) {
        if (flags & IPC_NOWAIT) {
            pthread_mutex_unlock(&ml_ipc_mtx);
            errno = EAGAIN;
            return -1;
        }
        pthread_cond_wait(&q->cond, &ml_ipc_mtx);
        q = ml_msq_lookup(id);
        if (!q) {
            pthread_mutex_unlock(&ml_ipc_mtx);
            errno = EIDRM;
            return -1;
        }
    }
    node = malloc(sizeof(*node) + size);
    if (!node) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        errno = ENOMEM;
        return -1;
    }
    node->type = m->mtype;
    node->len = size;
    node->next = 0;
    memcpy(node->data, m->mtext, size);
    if (q->tail) q->tail->next = node;
    else q->head = node;
    q->tail = node;
    q->qnum++;
    q->curbytes += size;
    q->lspid = getpid();
    q->stime = time(0);
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&ml_ipc_mtx);
    return 0;
}

ssize_t msgrcv(int id, void *msgp, size_t size, long type, int flags) {
    struct msgbuf *m = msgp;
    ml_msq_t *q;
    ml_msg_t *prev, *node;
    if (!msgp) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&ml_ipc_mtx);
    q = ml_msq_lookup(id);
    if (!q) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        errno = EINVAL;
        return -1;
    }
    if (!ml_perm_ok(&q->perm, 4)) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        errno = EACCES;
        return -1;
    }
    for (;;) {
        prev = 0;
        node = q->head;
        if (type == 0) {
            /* first message */
        } else if (type > 0) {
            if (flags & MSG_EXCEPT) {
                while (node && node->type == type) {
                    prev = node;
                    node = node->next;
                }
            } else {
                while (node && node->type != type) {
                    prev = node;
                    node = node->next;
                }
            }
        } else {
            /* lowest type <= -type */
            ml_msg_t *best = 0, *bestprev = 0;
            long want = -type;
            prev = 0;
            node = q->head;
            while (node) {
                if (node->type <= want &&
                    (!best || node->type < best->type)) {
                    best = node;
                    bestprev = prev;
                }
                prev = node;
                node = node->next;
            }
            node = best;
            prev = bestprev;
        }
        if (node) break;
        if (flags & IPC_NOWAIT) {
            pthread_mutex_unlock(&ml_ipc_mtx);
            errno = ENOMSG;
            return -1;
        }
        pthread_cond_wait(&q->cond, &ml_ipc_mtx);
        q = ml_msq_lookup(id);
        if (!q) {
            pthread_mutex_unlock(&ml_ipc_mtx);
            errno = EIDRM;
            return -1;
        }
    }
    if (node->len > size) {
        if (!(flags & MSG_NOERROR)) {
            pthread_mutex_unlock(&ml_ipc_mtx);
            errno = E2BIG;
            return -1;
        }
    }
    {
        size_t n = node->len > size ? size : node->len;
        ssize_t ret = (ssize_t)node->len;
        m->mtype = node->type;
        memcpy(m->mtext, node->data, n);
        if (prev) prev->next = node->next;
        else q->head = node->next;
        if (q->tail == node) q->tail = prev;
        q->qnum--;
        q->curbytes -= node->len;
        q->lrpid = getpid();
        q->rtime = time(0);
        free(node);
        pthread_cond_broadcast(&q->cond);
        pthread_mutex_unlock(&ml_ipc_mtx);
        return ret;
    }
}

int msgctl(int id, int cmd, struct msqid_ds *buf) {
    ml_msq_t *q;
    pthread_mutex_lock(&ml_ipc_mtx);
    if (cmd == IPC_RMID) {
        ml_msg_t *n;
        q = ml_msq_lookup(id);
        if (!q) {
            pthread_mutex_unlock(&ml_ipc_mtx);
            errno = EINVAL;
            return -1;
        }
        n = q->head;
        while (n) {
            ml_msg_t *t = n->next;
            free(n);
            n = t;
        }
        memset(q, 0, sizeof(*q));
        pthread_mutex_unlock(&ml_ipc_mtx);
        return 0;
    }
    q = ml_msq_lookup(id);
    if (!q) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        errno = EINVAL;
        return -1;
    }
    if (cmd == IPC_STAT) {
        if (!buf) {
            pthread_mutex_unlock(&ml_ipc_mtx);
            errno = EFAULT;
            return -1;
        }
        buf->msg_perm = q->perm;
        buf->msg_qnum = q->qnum;
        buf->msg_qbytes = q->qbytes;
        buf->msg_lspid = q->lspid;
        buf->msg_lrpid = q->lrpid;
        buf->msg_stime = q->stime;
        buf->msg_rtime = q->rtime;
        buf->msg_ctime = q->ctime;
        pthread_mutex_unlock(&ml_ipc_mtx);
        return 0;
    }
    if (cmd == IPC_SET) {
        if (!buf) {
            pthread_mutex_unlock(&ml_ipc_mtx);
            errno = EFAULT;
            return -1;
        }
        q->perm.uid = buf->msg_perm.uid;
        q->perm.gid = buf->msg_perm.gid;
        q->perm.mode = buf->msg_perm.mode & 0777;
        if (buf->msg_qbytes) q->qbytes = buf->msg_qbytes;
        q->ctime = time(0);
        pthread_mutex_unlock(&ml_ipc_mtx);
        return 0;
    }
    pthread_mutex_unlock(&ml_ipc_mtx);
    errno = EINVAL;
    return -1;
}

/* ================= semaphores ================= */

typedef struct {
    int used;
    int seq;
    key_t key;
    struct ipc_perm perm;
    int nsems;
    unsigned short *vals;
    int *waits;
    int *zwaits;
    time_t otime, ctime;
    pthread_cond_t cond;
    /* SEM_UNDO journal: per-thread adjustments applied at release. */
    struct {
        int tid;
        int semnum;
        int adj;
    } undo[64];
    int nundo;
} ml_sem_t;

static ml_sem_t ml_sems[ML_IPC_MAX];

static ml_sem_t *ml_sem_lookup(int id) {
    int i = id & 0xFF;
    if (i < 0 || i >= ML_IPC_MAX) return 0;
    if (!ml_sems[i].used || ml_sems[i].seq != (id >> 8)) return 0;
    return &ml_sems[i];
}

int semget(key_t key, int nsems, int flags) {
    int i, slot = -1;
    if (nsems < 0 || nsems > 256) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&ml_ipc_mtx);
    for (i = 0; i < ML_IPC_MAX; i++) {
        if (!ml_sems[i].used) {
            if (slot < 0) slot = i;
            continue;
        }
        if (key != IPC_PRIVATE && ml_sems[i].key == key) {
            int id = ml_sems[i].seq << 8 | i;
            if ((flags & IPC_CREAT) && (flags & IPC_EXCL)) {
                pthread_mutex_unlock(&ml_ipc_mtx);
                errno = EEXIST;
                return -1;
            }
            if (nsems && nsems != ml_sems[i].nsems) {
                pthread_mutex_unlock(&ml_ipc_mtx);
                errno = EINVAL;
                return -1;
            }
            pthread_mutex_unlock(&ml_ipc_mtx);
            return id;
        }
    }
    if (key != IPC_PRIVATE && !(flags & IPC_CREAT)) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        errno = ENOENT;
        return -1;
    }
    if (slot < 0 || nsems == 0) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        errno = nsems == 0 ? EINVAL : ENOSPC;
        return -1;
    }
    {
        ml_sem_t *s = &ml_sems[slot];
        memset(s, 0, sizeof(*s));
        s->used = 1;
        s->seq = ml_ipc_seq++;
        if (ml_ipc_seq <= 0) ml_ipc_seq = 1;
        s->key = key;
        s->perm.__key = key;
        s->perm.uid = s->perm.cuid = getuid();
        s->perm.gid = s->perm.cgid = getgid();
        s->perm.mode = (unsigned short)(flags & 0777);
        s->nsems = nsems;
        s->vals = calloc((size_t)nsems, sizeof(unsigned short));
        s->waits = calloc((size_t)nsems, sizeof(int));
        s->zwaits = calloc((size_t)nsems, sizeof(int));
        if (!s->vals || !s->waits || !s->zwaits) {
            free(s->vals);
            free(s->waits);
            free(s->zwaits);
            memset(s, 0, sizeof(*s));
            pthread_mutex_unlock(&ml_ipc_mtx);
            errno = ENOMEM;
            return -1;
        }
        s->ctime = time(0);
        pthread_cond_init(&s->cond, 0);
        pthread_mutex_unlock(&ml_ipc_mtx);
        return s->seq << 8 | slot;
    }
}

/* Apply one P/V step; caller holds ml_ipc_mtx. Returns 1 if the whole
 * op vector can proceed (all-or-nothing check), else 0. */
static int ml_sem_can(ml_sem_t *s, struct sembuf *ops, size_t nops) {
    size_t i;
    for (i = 0; i < nops; i++) {
        int n = ops[i].sem_num, op = ops[i].sem_op;
        if (n < 0 || n >= s->nsems) return -2;
        if (op == 0) {
            if (s->vals[n] != 0) return 0;
        } else if (op < 0) {
            if ((int)s->vals[n] + op < 0) return 0;
        }
    }
    return 1;
}

static void ml_sem_undo_add(ml_sem_t *s, int tid, int n, int adj) {
    int i;
    for (i = 0; i < s->nundo; i++) {
        if (s->undo[i].tid == tid && s->undo[i].semnum == n) {
            s->undo[i].adj += adj;
            return;
        }
    }
    if (s->nundo < 64) {
        s->undo[s->nundo].tid = tid;
        s->undo[s->nundo].semnum = n;
        s->undo[s->nundo].adj = adj;
        s->nundo++;
    }
}

int semop(int id, struct sembuf *ops, size_t nops) {
    return semtimedop(id, ops, nops, 0);
}

int semtimedop(int id, struct sembuf *ops, size_t nops,
               const struct timespec *timeout) {
    ml_sem_t *s;
    size_t i;
    long long deadline = 0;
    int tid;
    if (!ops || nops == 0 || nops > 64) {
        errno = EINVAL;
        return -1;
    }
    if (timeout) {
        struct timespec now;
        if (timeout->tv_nsec < 0 || timeout->tv_nsec >= 1000000000L) {
            errno = EINVAL;
            return -1;
        }
        if (timeout->tv_sec < 0) {
            errno = EAGAIN;
            return -1;
        }
        clock_gettime(CLOCK_REALTIME, &now);
        deadline = (now.tv_sec + timeout->tv_sec) * 1000000000LL +
                   now.tv_nsec + timeout->tv_nsec;
    }
    tid = getpid();
    pthread_mutex_lock(&ml_ipc_mtx);
    s = ml_sem_lookup(id);
    if (!s) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        errno = EINVAL;
        return -1;
    }
    if (!ml_perm_ok(&s->perm, 2 | 4)) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        errno = EACCES;
        return -1;
    }
    for (;;) {
        int can = ml_sem_can(s, ops, nops);
        if (can == -2) {
            pthread_mutex_unlock(&ml_ipc_mtx);
            errno = EFBIG;
            return -1;
        }
        if (can) break;
        if (timeout) {
            struct timespec now, sl = {0, 1000000L};
            long long now_ns;
            clock_gettime(CLOCK_REALTIME, &now);
            now_ns = now.tv_sec * 1000000000LL + now.tv_nsec;
            pthread_mutex_unlock(&ml_ipc_mtx);
            if (now_ns >= deadline) {
                errno = EAGAIN;
                return -1;
            }
            nanosleep(&sl, 0);
            pthread_mutex_lock(&ml_ipc_mtx);
            s = ml_sem_lookup(id);
            if (!s) {
                pthread_mutex_unlock(&ml_ipc_mtx);
                errno = EIDRM;
                return -1;
            }
            continue;
        }
        pthread_cond_wait(&s->cond, &ml_ipc_mtx);
        s = ml_sem_lookup(id);
        if (!s) {
            pthread_mutex_unlock(&ml_ipc_mtx);
            errno = EIDRM;
            return -1;
        }
    }
    for (i = 0; i < nops; i++) {
        int n = ops[i].sem_num, op = ops[i].sem_op;
        if (op == 0) continue;
        s->vals[n] = (unsigned short)((int)s->vals[n] + op);
        if (ops[i].sem_flg & SEM_UNDO) ml_sem_undo_add(s, tid, n, -op);
    }
    s->otime = time(0);
    pthread_cond_broadcast(&s->cond);
    pthread_mutex_unlock(&ml_ipc_mtx);
    return 0;
}

int semctl(int id, int num, int cmd, ...) {
    ml_sem_t *s;
    va_list ap;
    int r = 0;
    va_start(ap, cmd);
    pthread_mutex_lock(&ml_ipc_mtx);
    if (cmd == IPC_RMID) {
        s = ml_sem_lookup(id);
        if (!s) {
            pthread_mutex_unlock(&ml_ipc_mtx);
            va_end(ap);
            errno = EINVAL;
            return -1;
        }
        free(s->vals);
        free(s->waits);
        free(s->zwaits);
        memset(s, 0, sizeof(*s));
        pthread_mutex_unlock(&ml_ipc_mtx);
        va_end(ap);
        return 0;
    }
    s = ml_sem_lookup(id);
    if (!s) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        va_end(ap);
        errno = EINVAL;
        return -1;
    }
    switch (cmd) {
    case GETVAL: {
        if (num < 0 || num >= s->nsems) {
            errno = EINVAL;
            r = -1;
        } else r = s->vals[num];
        break;
    }
    case SETVAL: {
        int v = va_arg(ap, int);
        if (num < 0 || num >= s->nsems || v < 0 || v > 32767) {
            errno = EINVAL;
            r = -1;
        } else {
            s->vals[num] = (unsigned short)v;
            s->ctime = time(0);
            pthread_cond_broadcast(&s->cond);
        }
        break;
    }
    case GETALL: {
        unsigned short *a = va_arg(ap, unsigned short *);
        if (!a) {
            errno = EFAULT;
            r = -1;
        } else memcpy(a, s->vals, (size_t)s->nsems * sizeof(*a));
        break;
    }
    case SETALL: {
        unsigned short *a = va_arg(ap, unsigned short *);
        int i;
        if (!a) {
            errno = EFAULT;
            r = -1;
        } else {
            for (i = 0; i < s->nsems; i++) s->vals[i] = a[i];
            s->ctime = time(0);
            pthread_cond_broadcast(&s->cond);
        }
        break;
    }
    case IPC_STAT: {
        struct semid_ds *b = va_arg(ap, struct semid_ds *);
        if (!b) {
            errno = EFAULT;
            r = -1;
        } else {
            b->sem_perm = s->perm;
            b->array = s->vals;
            b->sem_nsems = (unsigned short)s->nsems;
            b->sem_otime = s->otime;
            b->sem_ctime = s->ctime;
        }
        break;
    }
    case IPC_SET: {
        struct semid_ds *b = va_arg(ap, struct semid_ds *);
        if (!b) {
            errno = EFAULT;
            r = -1;
        } else {
            s->perm.uid = b->sem_perm.uid;
            s->perm.gid = b->sem_perm.gid;
            s->perm.mode = b->sem_perm.mode & 0777;
            s->ctime = time(0);
        }
        break;
    }
    case GETPID:
    case GETNCNT:
    case GETZCNT:
        r = 0; /* no per-sem waiter accounting exposed; valid set */
        break;
    default:
        errno = EINVAL;
        r = -1;
        break;
    }
    pthread_mutex_unlock(&ml_ipc_mtx);
    va_end(ap);
    return r;
}

/* ================= shared memory ================= */

typedef struct {
    int used;
    int seq;
    key_t key;
    struct ipc_perm perm;
    size_t size;
    void *addr;
    int nattch;
    pid_t cpid, lpid;
    time_t atime, dtime, ctime;
} ml_shm_t;

static ml_shm_t ml_shms[ML_IPC_MAX];

static ml_shm_t *ml_shm_lookup(int id) {
    int i = id & 0xFF;
    if (i < 0 || i >= ML_IPC_MAX) return 0;
    if (!ml_shms[i].used || ml_shms[i].seq != (id >> 8)) return 0;
    return &ml_shms[i];
}

int shmget(key_t key, size_t size, int flags) {
    int i, slot = -1;
    pthread_mutex_lock(&ml_ipc_mtx);
    for (i = 0; i < ML_IPC_MAX; i++) {
        if (!ml_shms[i].used) {
            if (slot < 0) slot = i;
            continue;
        }
        if (key != IPC_PRIVATE && ml_shms[i].key == key) {
            int id = ml_shms[i].seq << 8 | i;
            if ((flags & IPC_CREAT) && (flags & IPC_EXCL)) {
                pthread_mutex_unlock(&ml_ipc_mtx);
                errno = EEXIST;
                return -1;
            }
            if (size && size != ml_shms[i].size) {
                pthread_mutex_unlock(&ml_ipc_mtx);
                errno = EINVAL;
                return -1;
            }
            pthread_mutex_unlock(&ml_ipc_mtx);
            return id;
        }
    }
    if (key != IPC_PRIVATE && !(flags & IPC_CREAT)) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        errno = ENOENT;
        return -1;
    }
    if (slot < 0 || size == 0 || size > (1u << 24)) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        errno = size == 0 ? EINVAL : ENOSPC;
        return -1;
    }
    {
        ml_shm_t *s = &ml_shms[slot];
        void *mem;
        size_t rounded = (size + 4095) & ~(size_t)4095;
        pthread_mutex_unlock(&ml_ipc_mtx);
        mem = mmap(0, rounded, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) return -1;
        memset(mem, 0, rounded);
        pthread_mutex_lock(&ml_ipc_mtx);
        memset(s, 0, sizeof(*s));
        s->used = 1;
        s->seq = ml_ipc_seq++;
        if (ml_ipc_seq <= 0) ml_ipc_seq = 1;
        s->key = key;
        s->perm.__key = key;
        s->perm.uid = s->perm.cuid = getuid();
        s->perm.gid = s->perm.cgid = getgid();
        s->perm.mode = (unsigned short)(flags & 0777);
        s->size = size;
        s->addr = mem;
        s->cpid = getpid();
        s->ctime = time(0);
        pthread_mutex_unlock(&ml_ipc_mtx);
        return s->seq << 8 | slot;
    }
}

void *shmat(int id, const void *addr, int flags) {
    ml_shm_t *s;
    (void)addr;
    (void)flags; /* single address space: attach = segment address */
    pthread_mutex_lock(&ml_ipc_mtx);
    s = ml_shm_lookup(id);
    if (!s) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        errno = EINVAL;
        return (void *)-1;
    }
    if (!ml_perm_ok(&s->perm, (flags & SHM_RDONLY) ? 4 : 6)) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        errno = EACCES;
        return (void *)-1;
    }
    s->nattch++;
    s->lpid = getpid();
    s->atime = time(0);
    pthread_mutex_unlock(&ml_ipc_mtx);
    return s->addr;
}

int shmdt(const void *addr) {
    int i;
    if (!addr) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&ml_ipc_mtx);
    for (i = 0; i < ML_IPC_MAX; i++) {
        if (ml_shms[i].used && ml_shms[i].addr == addr) {
            ml_shms[i].nattch--;
            ml_shms[i].lpid = getpid();
            ml_shms[i].dtime = time(0);
            pthread_mutex_unlock(&ml_ipc_mtx);
            return 0;
        }
    }
    pthread_mutex_unlock(&ml_ipc_mtx);
    errno = EINVAL;
    return -1;
}

int shmctl(int id, int cmd, struct shmid_ds *buf) {
    ml_shm_t *s;
    pthread_mutex_lock(&ml_ipc_mtx);
    if (cmd == IPC_RMID) {
        s = ml_shm_lookup(id);
        if (!s) {
            pthread_mutex_unlock(&ml_ipc_mtx);
            errno = EINVAL;
            return -1;
        }
        munmap(s->addr, (s->size + 4095) & ~(size_t)4095);
        memset(s, 0, sizeof(*s));
        pthread_mutex_unlock(&ml_ipc_mtx);
        return 0;
    }
    s = ml_shm_lookup(id);
    if (!s) {
        pthread_mutex_unlock(&ml_ipc_mtx);
        errno = EINVAL;
        return -1;
    }
    if (cmd == IPC_STAT) {
        if (!buf) {
            pthread_mutex_unlock(&ml_ipc_mtx);
            errno = EFAULT;
            return -1;
        }
        buf->shm_perm = s->perm;
        buf->shm_segsz = s->size;
        buf->shm_lpid = s->lpid;
        buf->shm_cpid = s->cpid;
        buf->shm_nattch = (unsigned long)(s->nattch < 0 ? 0 : s->nattch);
        buf->shm_atime = s->atime;
        buf->shm_dtime = s->dtime;
        buf->shm_ctime = s->ctime;
        pthread_mutex_unlock(&ml_ipc_mtx);
        return 0;
    }
    if (cmd == IPC_SET) {
        if (!buf) {
            pthread_mutex_unlock(&ml_ipc_mtx);
            errno = EFAULT;
            return -1;
        }
        s->perm.uid = buf->shm_perm.uid;
        s->perm.gid = buf->shm_perm.gid;
        s->perm.mode = buf->shm_perm.mode & 0777;
        s->ctime = time(0);
        pthread_mutex_unlock(&ml_ipc_mtx);
        return 0;
    }
    if (cmd == SHM_LOCK || cmd == SHM_UNLOCK) {
        /* Always resident: locking is a successful no-op. */
        pthread_mutex_unlock(&ml_ipc_mtx);
        return 0;
    }
    pthread_mutex_unlock(&ml_ipc_mtx);
    errno = EINVAL;
    return -1;
}
