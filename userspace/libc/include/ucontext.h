/* Moonlight libc - ucontext (real contexts over sigjmp_buf layout).
 * get/set/swapcontext save and restore integer state; makecontext
 * crafts a context that starts on a fresh stack at a trampoline. */
#pragma once

#include <signal.h>

typedef struct {
    unsigned long regs[16];
    int mask_saved;
    unsigned mask;
} mcontext_t;

typedef struct __ml_ucontext {
    struct __ml_ucontext *uc_link;
    sigset_t uc_sigmask;
    mcontext_t uc_mcontext;
    char *uc_stack_base;
    unsigned uc_stack_size;
} ucontext_t;

int getcontext(ucontext_t *uc);
int setcontext(const ucontext_t *uc);
int swapcontext(ucontext_t *ou, const ucontext_t *nu);
void makecontext(ucontext_t *uc, void (*fn)(void), int argc, ...);
