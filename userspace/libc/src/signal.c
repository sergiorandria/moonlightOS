/* libc signal: in-process handler table + synchronous raise +
 * cross-thread delivery.
 *
 * raise() runs the installed handler immediately when the signal is
 * unblocked, otherwise marks it pending; sigprocmask unblocking flushes
 * pending handlers in signal order. kill() targets another thread's
 * kernel pending set; the target collects it at its next yield boundary
 * (__ml_poll_signals, called from sched_yield) and delivers locally.
 * SIGKILL/SIGSTOP are uncatchable. abort() raises SIGABRT first. */
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <unistd.h>
#include <time.h>
#include <bits/ml_sys.h>

#define LX_SYS_rt_sigpending 136
#define LX_SYS_rt_sigtimedwait 137
static void (*ml_handlers[NSIG])(int);
static unsigned ml_mask;    /* blocked set, bit (sig-1) */
static unsigned ml_pending; /* raised-while-blocked set */

/* signalfd delivery hook (registered by sysevent.c; NULL when absent). */
static void (*ml_sfd_hook)(int);

/* Full sigset mask without UB shifts (NSIG may equal the word width). */
#define ML_SIG_ALL ((unsigned)(NSIG >= 32 ? 0xFFFFFFFFull : ((1ull << NSIG) - 1ull)))

static void ml_deliver(int sig) {
    void (*h)(int) = ml_handlers[sig];
    if (h == SIG_IGN) return;
    if (!h || h == SIG_DFL) {
        switch (sig) {
        case SIGABRT:
        case SIGFPE:
        case SIGILL:
        case SIGSEGV:
        case SIGBUS:
        case SIGTRAP:
        case SIGSYS:
            _Exit(128 + sig);
        default:
            return;
        }
    }
    h(sig);
}

/* Drain the kernel's per-thread pending set into the local table
 * (delivering whatever is unblocked). Runs at yield boundaries. */
void __ml_poll_signals(void) {
    int sig, guard = 0;
    for (;;) {
        long r = __ml_raw6(LX_SYS_rt_sigtimedwait, 0, 0, 0, 0, 0, 0);
        if (r <= 0 || r >= NSIG) return; /* empty (or host-sim ENOSYS) */
        if (++guard > 32) return;
        sig = (int)r;
        if (sig == 9) _Exit(128 + 9); /* SIGKILL: uncatchable */
        if (sig == 19) continue; /* SIGSTOP: no job control; drop */
        if (ml_mask & (1u << (sig - 1))) {
            ml_pending |= 1u << (sig - 1);
            if (ml_sfd_hook) ml_sfd_hook(sig);
        } else ml_deliver(sig);
    }
}

static int ml_sig_ok(int sig) { return sig > 0 && sig < NSIG; }

unsigned __ml_sigmask_get(void) { return ml_mask; }

void __ml_sigmask_set(unsigned m) {
    unsigned newly;
    ml_mask = m & ML_SIG_ALL;
    /* Deliver signals unblocked by the restore, in order. */
    newly = ml_pending & ~ml_mask;
    while (newly) {
        int sig = 1;
        while (sig < NSIG && !(newly & (1u << (sig - 1)))) sig++;
        if (sig >= NSIG) break;
        newly &= ~(1u << (sig - 1));
        ml_pending &= ~(1u << (sig - 1));
        if (ml_handlers[sig] && ml_handlers[sig] != SIG_IGN)
            ml_handlers[sig](sig);
    }
}

void (*signal(int sig, void (*fn)(int)))(int) {
    void (*old)(int);
    if (!ml_sig_ok(sig) || sig == SIGKILL || sig == SIGSTOP) {
        errno = EINVAL;
        return SIG_ERR;
    }
    old = ml_handlers[sig];
    ml_handlers[sig] = fn;
    return old ? old : SIG_DFL;
}

int raise(int sig) {
    void (*h)(int);
    if (!ml_sig_ok(sig)) {
        errno = EINVAL;
        return -1;
    }
    h = ml_handlers[sig];
    if (h == SIG_IGN) return 0;
    if ((ml_mask & (1u << (sig - 1))) && sig != SIGKILL) {
        ml_pending |= 1u << (sig - 1);
        if (ml_sfd_hook) ml_sfd_hook(sig);
        return 0;
    }
    if (!h || h == SIG_DFL) {
        /* Default dispositions with no handler: fatal ones park the
         * thread (like exit_group); benign ones are ignored. */
        switch (sig) {
        case SIGABRT:
        case SIGFPE:
        case SIGILL:
        case SIGSEGV:
        case SIGBUS:
        case SIGTRAP:
        case SIGSYS:
            _Exit(128 + sig);
        default:
            return 0;
        }
    }
    h(sig);
    return 0;
}

int sigaction(int sig, const struct sigaction *act, struct sigaction *old) {
    if (!ml_sig_ok(sig) || sig == SIGKILL || sig == SIGSTOP) {
        errno = EINVAL;
        return -1;
    }
    if (old) {
        old->sa_handler = ml_handlers[sig] ? ml_handlers[sig] : SIG_DFL;
        old->sa_mask = 0;
        old->sa_flags = 0;
    }
    if (act) ml_handlers[sig] = act->sa_handler;
    return 0;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *old) {
    if (old) *old = ml_mask;
    if (!set) return 0;
    switch (how) {
    case SIG_BLOCK:
        __ml_sigmask_set(ml_mask | *set);
        break;
    case SIG_UNBLOCK:
        __ml_sigmask_set(ml_mask & ~*set);
        break;
    case SIG_SETMASK:
        __ml_sigmask_set(*set);
        break;
    default:
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int sigpending(sigset_t *set) {
    unsigned long kpend = 0;
    if (!set) {
        errno = EINVAL;
        return -1;
    }
    *set = ml_pending;
    if (__ml_raw6(LX_SYS_rt_sigpending, (long)&kpend, 0, 0, 0, 0, 0) ==
        0)
        *set |= (sigset_t)kpend;
    return 0;
}

int sigsuspend(const sigset_t *mask) {    unsigned saved = ml_mask;
    if (mask) ml_mask = *mask;
    /* Wait for an unblocked pending signal, then restore. */
    for (;;) {
        unsigned ready = ml_pending & ~ml_mask;
        if (ready) {
            int sig = 1;
            while (sig < NSIG && !(ready & (1u << (sig - 1)))) sig++;
            ml_mask = saved;
            ml_pending &= ~(1u << (sig - 1));
            if (ml_handlers[sig] && ml_handlers[sig] != SIG_IGN &&
                ml_handlers[sig] != SIG_DFL)
                ml_handlers[sig](sig);
            errno = EINTR;
            return -1;
        }
        sched_yield();
    }
}

int pause(void) {
    for (;;) {
        unsigned ready = ml_pending & ~ml_mask;
        if (ready) {
            int sig = 1;
            while (sig < NSIG && !(ready & (1u << (sig - 1)))) sig++;
            ml_pending &= ~(1u << (sig - 1));
            if (ml_handlers[sig] && ml_handlers[sig] != SIG_IGN &&
                ml_handlers[sig] != SIG_DFL)
                ml_handlers[sig](sig);
            errno = EINTR;
            return -1;
        }
        sched_yield();
    }
}

/* Synchronously take one signal from the waited set: local pending
 * first, then the kernel queue, then yield-spin until the deadline. */
static int ml_sigwait_once(const sigset_t *set, unsigned long *kmask) {
    unsigned want = set ? *set : 0xFFFFFFFFu;
    unsigned ready = ml_pending & want;
    int sig;
    if (ready) {
        sig = 1;
        while (sig < NSIG && !(ready & (1u << (sig - 1)))) sig++;
        ml_pending &= ~(1u << (sig - 1));
        return sig;
    }
    if (kmask) {
        long r = __ml_raw6(LX_SYS_rt_sigtimedwait, (long)kmask, 0, 0, 0,
                           0, 0);
        if (r > 0 && r < NSIG) return (int)r;
    }
    return 0;
}

int sigwait(const sigset_t *set, int *sig) {
    unsigned long km;
    if (!set || !sig) {
        errno = EINVAL;
        return EINVAL;
    }
    km = *set;
    for (;;) {
        int s = ml_sigwait_once(set, &km);
        if (s > 0) {
            *sig = s;
            return 0;
        }
        sched_yield();
    }
}

int sigwaitinfo(const sigset_t *set, void *info) {
    int sig;
    (void)info;
    return sigwait(set, &sig) == 0 ? sig : -1;
}

int sigtimedwait(const sigset_t *set, void *info,
                 const struct timespec *timeout) {
    unsigned long km;
    long long deadline = -1;
    (void)info;
    if (!set) {
        errno = EINVAL;
        return -1;
    }
    km = *set;
    if (timeout) {
        struct timespec now;
        if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 ||
            timeout->tv_nsec >= 1000000000L) {
            errno = EINVAL;
            return -1;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        deadline = (now.tv_sec * 1000000000LL + now.tv_nsec) +
                   timeout->tv_sec * 1000000000LL + timeout->tv_nsec;
    }
    for (;;) {
        int s = ml_sigwait_once(set, &km);
        if (s > 0) return s;
        if (timeout) {
            struct timespec now;
            long long left;
            clock_gettime(CLOCK_MONOTONIC, &now);
            left =
                deadline - (now.tv_sec * 1000000000LL + now.tv_nsec);
            if (left <= 0) {
                errno = EAGAIN;
                return -1;
            }
        }
        sched_yield();
    }
}

int sigemptyset(sigset_t *set) {
    if (!set) {
        errno = EINVAL;
        return -1;
    }
    *set = 0;
    return 0;
}

int sigfillset(sigset_t *set) {
    if (!set) {
        errno = EINVAL;
        return -1;
    }
    *set = ML_SIG_ALL;
    return 0;
}

int sigaddset(sigset_t *set, int sig) {
    if (!set || !ml_sig_ok(sig)) {
        errno = EINVAL;
        return -1;
    }
    *set |= 1u << (sig - 1);
    return 0;
}

int sigdelset(sigset_t *set, int sig) {
    if (!set || !ml_sig_ok(sig)) {
        errno = EINVAL;
        return -1;
    }
    *set &= ~(1u << (sig - 1));
    return 0;
}

int sigismember(const sigset_t *set, int sig) {
    if (!set || !ml_sig_ok(sig)) {
        errno = EINVAL;
        return -1;
    }
    return (*set & (1u << (sig - 1))) ? 1 : 0;
}

/* ---- signalfd delivery hook (storage declared at top) ---- */

void __ml_sfd_register(void (*fn)(int)) { ml_sfd_hook = fn; }

/* ---- psignal / psiginfo / pthread_sigmask ---- */

#include <stdio.h>

int pthread_sigmask(int how, const sigset_t *set, sigset_t *old) {
    return sigprocmask(how, set, old);
}

void psignal(int sig, const char *msg) {
    const char *desc = strsignal(sig);
    if (msg && *msg) dprintf(2, "%s: %s\n", msg, desc ? desc : "Unknown signal");
    else dprintf(2, "%s\n", desc ? desc : "Unknown signal");
}

void psiginfo(const siginfo_t *info, const char *msg) {
    psignal(info ? info->si_signo : 0, msg);
}
