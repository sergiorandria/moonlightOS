/* Moonlight libc - setjmp (C99, real context capture).
 *
 * setjmp/longjmp are raw context switches over callee-saved state
 * (see setjmp.S): setjmp stores ra/sp/s0-s11 (rv64) or
 * rbx/rbp/rsp/r12-r15/rip (x86_64 host) and returns 0; longjmp
 * restores them and returns val (0 becomes 1). sigsetjmp is a macro
 * so the capture runs in the caller's frame; siglongjmp restores the
 * soft signal mask first (see signal.c). FP data regs are
 * caller-saved per both ABIs (soft-float on rv64imac anyway), so
 * integer state is the complete context, like musl.
 */
#pragma once

#include <signal.h>

typedef struct __ml_jmp {
    unsigned long regs[16];
    int mask_saved;
    unsigned mask;
} jmp_buf[1];

typedef struct __ml_jmp sigjmp_buf[1];

unsigned __ml_sigmask_get(void);
void __ml_sigmask_set(unsigned m);

int setjmp(jmp_buf env);
void longjmp(jmp_buf env, int val) __attribute__((noreturn));
void siglongjmp(sigjmp_buf env, int val) __attribute__((noreturn));

#define sigsetjmp(env, savemask)                                           \
    ((env)->mask_saved = (savemask),                                      \
     ((savemask) ? ((env)->mask = __ml_sigmask_get(), 0) : 0),            \
     setjmp(env))
