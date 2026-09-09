/* moonlight.c - userspace syscall stubs. Freestanding, no libc.
 *
 * RISC-V: real ecall with the kernel convention (a7=sysno, a0=cap/arg,
 * a1/a2=args, result in a0). Host-sim (unit tests): harmless stubs so
 * userspace logic links and runs on the build machine.
 */
#include "moonlight.h"

#ifdef __riscv

static inline long raw_ecall(long sys, long a0, long a1, long a2) {
    register long r_a0 asm("a0") = a0;
    register long r_a1 asm("a1") = a1;
    register long r_a2 asm("a2") = a2;
    register long r_a7 asm("a7") = sys;
    asm volatile("ecall"
                 : "+r"(r_a0)
                 : "r"(r_a1), "r"(r_a2), "r"(r_a7)
                 : "memory");
    return r_a0;
}

int moonlight_call(uint32_t ep_cptr, void *msg) {
    return (int)raw_ecall(MOONLIGHT_SYS_CALL, ep_cptr, (long)msg, 0);
}

int moonlight_recv(uint32_t ep_cptr, void *msg) {
    /* REPLY_RECV delivers into the TCB buffer; payload copy-out to *msg
     * needs the kernel copy-out half (TODO) - today returns status only. */
    return (int)raw_ecall(MOONLIGHT_SYS_REPLY_RECV, ep_cptr, (long)msg, 0);
}

int moonlight_send(uint32_t ep_cptr, void *msg) {
    return (int)raw_ecall(MOONLIGHT_SYS_SEND, ep_cptr, (long)msg, 0);
}

int moonlight_yield(void) {
    return (int)raw_ecall(MOONLIGHT_SYS_YIELD, 0, 0, 0);
}

int moonlight_retype(uint32_t untyped_cptr, uint32_t type, size_t size, uint32_t dest_cptr) {
    /* INV_UNTYPED_RETYPE (0): arg1 = op | dest<<8, arg2 = type, arg3 = size.
     * handle_invoke takes (cap, op, arg1, arg2, arg3); frame->a3 carries size. */
    register long r_a0 asm("a0") = 0; /* root retype path */
    register long r_a1 asm("a1") = (0 | (dest_cptr << 8));
    register long r_a2 asm("a2") = type;
    register long r_a3 asm("a3") = (long)size;
    register long r_a7 asm("a7") = MOONLIGHT_SYS_INVOKE;
    (void)untyped_cptr;
    asm volatile("ecall"
                 : "+r"(r_a0)
                 : "r"(r_a1), "r"(r_a2), "r"(r_a3), "r"(r_a7)
                 : "memory");
    return (int)r_a0;
}

int moonlight_cnode_copy(uint32_t dst, uint32_t src, uint32_t rights) {
    (void)rights;
    register long r_a0 asm("a0") = 0;
    register long r_a1 asm("a1") = 2; /* INV_CNODE_MINT */
    register long r_a2 asm("a2") = src;
    register long r_a3 asm("a3") = dst;
    register long r_a7 asm("a7") = MOONLIGHT_SYS_INVOKE;
    asm volatile("ecall"
                 : "+r"(r_a0)
                 : "r"(r_a1), "r"(r_a2), "r"(r_a3), "r"(r_a7)
                 : "memory");
    return (int)r_a0;
}

int moonlight_putc(char c) {
    return (int)raw_ecall(MOONLIGHT_SYS_DEBUG_PUTC, (long)(unsigned char)c, 0, 0);
}

int moonlight_getc(void) {
    return (int)raw_ecall(MOONLIGHT_SYS_DEBUG_GETC, 0, 0, 0);
}

#else /* host-sim: linkable no-ops for unit tests */
#include <stdio.h>

int moonlight_call(uint32_t ep_cptr, void *msg) { (void)ep_cptr; (void)msg; return 0; }
int moonlight_recv(uint32_t ep_cptr, void *msg) { (void)ep_cptr; (void)msg; return 0; }
int moonlight_send(uint32_t ep_cptr, void *msg) { (void)ep_cptr; (void)msg; return 0; }
int moonlight_yield(void) { return 0; }
int moonlight_retype(uint32_t untyped_cptr, uint32_t type, size_t size, uint32_t dest_cptr) {
    (void)untyped_cptr; (void)type; (void)size; (void)dest_cptr; return 0;
}
int moonlight_cnode_copy(uint32_t dst, uint32_t src, uint32_t rights) {
    (void)dst; (void)src; (void)rights; return 0;
}

/* Host-sim console reroutes to stdio so shell logic runs in unit tests.
 * Weak so tests can override with scripted input/output buffers. */
__attribute__((weak)) int moonlight_putc(char c) { return putchar(c); }
__attribute__((weak)) int moonlight_getc(void) { return -1; }

#endif
