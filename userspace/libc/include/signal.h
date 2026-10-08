/* Moonlight libc - signal (C99 + POSIX sigaction/procmask).
 *
 * No kernel delivery exists (single-hart, no async interrupts to user
 * space): signal() registers a handler table, raise() invokes the
 * handler synchronously honoring the process mask (blocked signals
 * pend and deliver on unblock via sigprocmask), pause() yield-waits
 * for a pending unblocked signal. abort() raises SIGABRT first so a
 * handler runs before the exit_group park. All real in-process
 * semantics; cross-process kill() stays kernel-ENOSYS (see LINUX.md).
 */
#pragma once

#include <time.h>

typedef unsigned sigset_t;
typedef int sig_atomic_t;

#define SIGHUP 1
#define SIGINT 2
#define SIGQUIT 3
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGBUS 7
#define SIGFPE 8
#define SIGKILL 9
#define SIGUSR1 10
#define SIGSEGV 11
#define SIGUSR2 12
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15
#define SIGCHLD 17
#define SIGCONT 18
#define SIGSTOP 19
#define SIGTSTP 20
#define SIGTTIN 21
#define SIGTTOU 22
#define SIGURG 23
#define SIGXCPU 24
#define SIGXFSZ 25
#define SIGVTALRM 26
#define SIGPROF 27
#define SIGWINCH 28
#define SIGIO 29
#define SIGPWR 30
#define SIGSYS 31
#define NSIG 32

#define SIG_DFL ((void (*)(int))0)
#define SIG_IGN ((void (*)(int))1)
#define SIG_ERR ((void (*)(int))-1)

#define SIG_BLOCK 0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2

#define SA_NOCLDSTOP 1
#define SA_RESTART 0x10000000

struct sigaction {
    void (*sa_handler)(int);
    sigset_t sa_mask;
    int sa_flags;
};

union sigval {
    int sival_int;
    void *sival_ptr;
};

typedef struct {
    int si_signo;
    int si_errno;
    int si_code;
    union {
        int sival_int;
        void *sival_ptr;
        int sigchld_pid;
    } si_value;
} siginfo_t;

#define SI_USER 0
#define SI_KERNEL 128
#define SI_QUEUE -1
#define SI_TIMER -2
#define SI_MESGQ -3
#define SI_ASYNCIO -4
#define SI_SIGIO -5
#define SI_TKILL -6

#define CLD_EXITED 1
#define CLD_KILLED 2
#define CLD_DUMPED 3
#define CLD_TRAPPED 4
#define CLD_STOPPED 5
#define CLD_CONTINUED 6

struct sigevent {
    int sigev_notify;
    int sigev_signo;
    union sigval sigev_value;
    void (*sigev_notify_function)(union sigval);
    void *sigev_notify_attributes;
    int sigev_notify_thread_id;
};

#define SIGEV_NONE 0
#define SIGEV_SIGNAL 1
#define SIGEV_THREAD 2
#define SIGEV_THREAD_ID 4

void (*signal(int sig, void (*fn)(int)))(int);
int raise(int sig);
int killpg(int grp, int sig);
int sigaction(int sig, const struct sigaction *act, struct sigaction *old);
int sigprocmask(int how, const sigset_t *set, sigset_t *old);
int sigpending(sigset_t *set);
int sigsuspend(const sigset_t *mask);
int sigwait(const sigset_t *set, int *sig);
int sigwaitinfo(const sigset_t *set, void *info);
int sigtimedwait(const sigset_t *set, void *info,
                 const struct timespec *timeout);
int pause(void);
int pthread_sigmask(int how, const sigset_t *set, sigset_t *old);
void psignal(int sig, const char *msg);
void psiginfo(const siginfo_t *info, const char *msg);
int sigemptyset(sigset_t *set);
int sigfillset(sigset_t *set);
int sigaddset(sigset_t *set, int sig);
int sigdelset(sigset_t *set, int sig);
int sigismember(const sigset_t *set, int sig);
