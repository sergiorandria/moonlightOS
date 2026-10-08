/* libc ucontext: contexts over the sigjmp_buf register layout
 * (rv64: regs[0]=ra, regs[1]=sp, regs[2..13]=s0..s11; x86_64 host:
 * regs[0]=rbx,1=rbp,2=rsp,3..6=r12-r15,7=rip). makecontext points ra
 * at a trampoline that unpacks fn/args from s-registers, runs on the
 * supplied stack, and chains to uc_link. */
#include <ucontext.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

static void ml_uc_trampoline(void) {
#if defined(__riscv)
    register unsigned long s0v __asm__("s0");
    register unsigned long s1v __asm__("s1");
    register unsigned long s2v __asm__("s2");
    void (*fn)(void) = (void (*)(void))s0v;
    ucontext_t *link = (ucontext_t *)s2v;
    (void)s1v;
    fn();
    if (link) setcontext(link);
    _Exit(0);
#elif defined(__x86_64__)
    register unsigned long r12v __asm__("r12");
    register unsigned long r15v __asm__("r15");
    void (*fn)(void) = (void (*)(void))r12v;
    ucontext_t *link = (ucontext_t *)r15v;
    fn();
    if (link) setcontext(link);
    _Exit(0);
#else
    _Exit(0);
#endif
}

int getcontext(ucontext_t *uc) {
    jmp_buf jb;
    if (!uc) return -1;
    if (setjmp(jb) != 0) return 0; /* resumed via setcontext */
    memcpy(uc->uc_mcontext.regs, jb->regs, sizeof(jb->regs));
    uc->uc_mcontext.mask_saved = 0;
    uc->uc_sigmask = __ml_sigmask_get();
    return 0;
}

int setcontext(const ucontext_t *uc) {
    jmp_buf jb;
    if (!uc) return -1;
    memcpy(jb->regs, uc->uc_mcontext.regs, sizeof(jb->regs));
    __ml_sigmask_set(uc->uc_sigmask);
    /* Mask restore inside siglongjmp needs the flag; reuse the
     * sigjmp path manually (mask already set above). */
    longjmp(jb, 1);
    return 0;
}

int swapcontext(ucontext_t *ou, const ucontext_t *nu) {
    jmp_buf jb;
    if (!ou || !nu) return -1;
    if (setjmp(jb) != 0) return 0;
    memcpy(ou->uc_mcontext.regs, jb->regs, sizeof(jb->regs));
    ou->uc_mcontext.mask_saved = 0;
    ou->uc_sigmask = __ml_sigmask_get();
    return setcontext(nu);
}

void makecontext(ucontext_t *uc, void (*fn)(void), int argc, ...) {
    va_list ap;
    int i;
    if (!uc || !fn || argc < 0 || argc > 6) return;
    memset(uc->uc_mcontext.regs, 0, sizeof(uc->uc_mcontext.regs));
#if defined(__riscv)
    uc->uc_mcontext.regs[0] =
        (unsigned long)ml_uc_trampoline; /* ra */
    uc->uc_mcontext.regs[1] =
        (unsigned long)(uc->uc_stack_base + uc->uc_stack_size -
                        16); /* sp */
    uc->uc_mcontext.regs[2] = (unsigned long)fn; /* s0 */
    /* Args ride in s3..s8 (trampoline ignores them for void fn; the
     * slots keep the values observable for debugging). */
    va_start(ap, argc);
    for (i = 0; i < argc && i < 6; i++)
        uc->uc_mcontext.regs[4 + i] = va_arg(ap, unsigned long);
    va_end(ap);
    uc->uc_mcontext.regs[3] = (unsigned long)uc; /* s1 = self */
    uc->uc_mcontext.regs[5] = 0;
    /* uc_link in s2. */
    uc->uc_mcontext.regs[4] = (unsigned long)uc->uc_link; /* s2 */
#elif defined(__x86_64__)
    uc->uc_mcontext.regs[7] = (unsigned long)ml_uc_trampoline;
    uc->uc_mcontext.regs[2] =
        (unsigned long)(uc->uc_stack_base + uc->uc_stack_size - 16);
    uc->uc_mcontext.regs[0] = (unsigned long)fn; /* rbx slot reuse */
    uc->uc_mcontext.regs[3] = (unsigned long)fn; /* r12 */
    uc->uc_mcontext.regs[6] = (unsigned long)uc->uc_link; /* r15 */
    va_start(ap, argc);
    for (i = 0; i < argc; i++) (void)va_arg(ap, unsigned long);
    va_end(ap);
#endif
}
