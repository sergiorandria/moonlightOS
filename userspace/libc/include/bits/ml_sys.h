/* Raw Linux-ecall layer (private to libc). riscv64: a7=nr, a0-a5 args,
 * result in a0 (negative errno on failure). Host builds get stubs so
 * libc unit tests link (pure functions only; syscalls untested on host).
 */
#pragma once

/* Resolved via -I abi (frozen userspace ABI headers). */
#include "linux_abi.h"

#ifdef __riscv

static inline long __ml_raw6(long nr, long a0, long a1, long a2, long a3,
                             long a4, long a5) {
    register long r_a0 __asm__("a0") = a0;
    register long r_a1 __asm__("a1") = a1;
    register long r_a2 __asm__("a2") = a2;
    register long r_a3 __asm__("a3") = a3;
    register long r_a4 __asm__("a4") = a4;
    register long r_a5 __asm__("a5") = a5;
    register long r_a7 __asm__("a7") = nr;
    __asm__ volatile("ecall"
                     : "+r"(r_a0)
                     : "r"(r_a1), "r"(r_a2), "r"(r_a3), "r"(r_a4),
                       "r"(r_a5), "r"(r_a7)
                     : "memory");
    return r_a0;
}

#define __ML_SYS0(nr) __ml_call6(nr, 0, 0, 0, 0, 0, 0)
#define __ML_SYS1(nr, a) __ml_call6(nr, (long)(a), 0, 0, 0, 0, 0)
#define __ML_SYS2(nr, a, b) __ml_call6(nr, (long)(a), (long)(b), 0, 0, 0, 0)
#define __ML_SYS3(nr, a, b, c) \
    __ml_call6(nr, (long)(a), (long)(b), (long)(c), 0, 0, 0)
#define __ML_SYS4(nr, a, b, c, d) \
    __ml_call6(nr, (long)(a), (long)(b), (long)(c), (long)(d), 0, 0)
#define __ML_SYS6(nr, a, b, c, d, e, f) \
    __ml_call6(nr, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), \
              (long)(f))

#else /* host: link-only stubs (never called by unit-tested code) */

static inline long __ml_raw6(long nr, long a0, long a1, long a2, long a3,
                             long a4, long a5) {
    (void)nr;
    (void)a0;
    (void)a1;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;
    return -38; /* -ENOSYS */
}

#define __ML_SYS0(nr) __ml_raw6(nr, 0, 0, 0, 0, 0, 0)
#define __ML_SYS1(nr, a) __ml_raw6(nr, (long)(a), 0, 0, 0, 0, 0)
#define __ML_SYS2(nr, a, b) __ml_raw6(nr, (long)(a), (long)(b), 0, 0, 0, 0)
#define __ML_SYS3(nr, a, b, c) \
    __ml_raw6(nr, (long)(a), (long)(b), (long)(c), 0, 0, 0)
#define __ML_SYS4(nr, a, b, c, d) \
    __ml_raw6(nr, (long)(a), (long)(b), (long)(c), (long)(d), 0, 0)
#define __ML_SYS6(nr, a, b, c, d, e, f) \
    __ml_raw6(nr, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), \
              (long)(f))

#endif

/* Fold -errno into errno; returns -1 on failure, value otherwise. */
long __ml_ret(long r);

/* Ecall with bounded EAGAIN retry: gated syscalls fail transiently when
 * the caller's tick budget is exhausted (replenished every period). Yield
 * between tries so time advances; 8 tries keep stdin-poll latency small
 * while covering normal dips. NOT for exit (parks) or stdin fast-poll
 * callers that pre-check. Returns the final raw result. */
long __ml_call6(long nr, long a0, long a1, long a2, long a3, long a4,
                long a5);

/* Collect kernel-queued cross-thread signals into local delivery
 * (signal.c). Called on yield boundaries. */
void __ml_poll_signals(void);
