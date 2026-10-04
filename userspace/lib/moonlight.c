/* moonlight.c - userspace syscall stubs. Freestanding, no libc.
 *
 * RISC-V: real ecall with the kernel convention (a7=sysno, a0=cap/arg,
 * a1/a2=args, result in a0). Host-sim (unit tests): harmless stubs so
 * userspace logic links and runs on the build machine.
 */
#include "moonlight.h"

#ifdef __riscv

static inline long raw_ecall(long sys, long a0, long a1, long a2)
{
    register long r_a0 asm("a0") = a0;
    register long r_a1 asm("a1") = a1;
    register long r_a2 asm("a2") = a2;
    register long r_a7 asm("a7") = sys;
    asm volatile("ecall" : "+r"(r_a0) : "r"(r_a1), "r"(r_a2), "r"(r_a7) : "memory");
    return r_a0;
}

/* raw_ecall variant that captures both a0 and a1 for RECV */
static inline void raw_ecall_recv(long sys, long a0, long a1, long a2, long *out_a0, long *out_a1)
{
    register long r_a0 asm("a0") = a0;
    register long r_a1 asm("a1") = a1;
    register long r_a2 asm("a2") = a2;
    register long r_a7 asm("a7") = sys;
    asm volatile("ecall" : "+r"(r_a0), "+r"(r_a1) : "r"(r_a2), "r"(r_a7) : "memory");
    *out_a0 = r_a0;
    *out_a1 = r_a1;
}

/* V2 wire view of a moonlight_msg_t: leading words only, capped at
 * MOONLIGHT_SEND_WORDS (== V2_MSG_MAX; longer spans fail INVALID). */
static inline uint64_t *msg_words(void *msg)
{
    return ((moonlight_msg_t *)msg)->words;
}

int moonlight_call(uint32_t ep_cptr, void *msg)
{
    /* V2 has no combined call: SEND then RECV (blocking rendezvous both
     * legs; NOT atomic — can deadlock without a waiter + replier).
     * Only used by host-linked servers; no shipping ELF calls this
     * (V2 servers drive u_ecall directly). */
    long rc = raw_ecall(MOONLIGHT_SYS_SEND, ep_cptr, (long)msg_words(msg), (long)MOONLIGHT_SEND_WORDS);
    if (rc != 0)
        return (int)rc;
    return (int)raw_ecall(MOONLIGHT_SYS_RECV, ep_cptr, (long)msg_words(msg), (long)MOONLIGHT_SEND_WORDS);
}

int moonlight_recv(uint32_t ep_cptr, void *msg)
{
    moonlight_msg_t *m = (moonlight_msg_t *)msg;
    long ret_a0, ret_a1;
    raw_ecall_recv(MOONLIGHT_SYS_RECV, ep_cptr, (long)msg_words(msg), (long)MOONLIGHT_SEND_WORDS, &ret_a0, &ret_a1);
    
    /* Kernel returns: a0 = word count (or negative error), a1 = sender TID */
    m->sender_tcb = (uint32_t)ret_a1;
    m->length = (uint32_t)ret_a0;
    
    return (int)ret_a0;
}

int moonlight_send(uint32_t ep_cptr, void *msg)
{
    return (int)raw_ecall(MOONLIGHT_SYS_SEND, ep_cptr, (long)msg_words(msg), (long)MOONLIGHT_SEND_WORDS);
}

int moonlight_yield(void)
{
    return (int)raw_ecall(MOONLIGHT_SYS_YIELD, 0, 0, 0);
}

int moonlight_retype(uint32_t untyped_cptr, uint32_t type, size_t size, uint32_t dest_cptr)
{
    /* V1 Untyped-retype has no V2 equivalent: PT_ALLOC mints a zeroed frame
     * cap for the caller (the V2 way to acquire memory). type/size select
     * nothing; dest slot is the caller's to manage. Only used by
     * host-linked code; no shipping ELF calls this. */
    register long r_a0 asm("a0") = MOONLIGHT_INV_PT_ALLOC;
    register long r_a1 asm("a1") = 0;
    register long r_a2 asm("a2") = 0;
    register long r_a3 asm("a3") = 0;
    register long r_a7 asm("a7") = MOONLIGHT_SYS_INVOKE;
    (void)untyped_cptr;
    (void)type;
    (void)size;
    (void)dest_cptr;
    asm volatile("ecall" : "+r"(r_a0) : "r"(r_a1), "r"(r_a2), "r"(r_a3), "r"(r_a7) : "memory");
    return (int)r_a0;
}

int moonlight_cnode_copy(uint32_t dst, uint32_t src, uint32_t rights)
{
    /* V2 MINT (op 1): v2_mint(st, caller, src=a1, rights=a2, dst=a3). */
    register long r_a0 asm("a0") = MOONLIGHT_INV_MINT;
    register long r_a1 asm("a1") = (long)src;
    register long r_a2 asm("a2") = (long)rights;
    register long r_a3 asm("a3") = (long)dst;
    register long r_a7 asm("a7") = MOONLIGHT_SYS_INVOKE;
    asm volatile("ecall" : "+r"(r_a0) : "r"(r_a1), "r"(r_a2), "r"(r_a3), "r"(r_a7) : "memory");
    return (int)r_a0;
}

int moonlight_putc(char c)
{
    return (int)raw_ecall(MOONLIGHT_SYS_PUTC, (long)(unsigned char)c, 0, 0);
}

int moonlight_getc(void)
{
    /* No V2 console-input ecall exists (input arrives via virtio-input IRQ
     * -> NOTIFY, consumed by the input server, not by raw ecalls). Never
     * trap: report RX-empty (-1, never blocks) per the header contract. */
    return -1;
}

#else /* host-sim: linkable no-ops for unit tests */
#include <stdio.h>

int moonlight_call(uint32_t ep_cptr, void *msg)
{
    (void)ep_cptr;
    (void)msg;
    return 0;
}
int moonlight_recv(uint32_t ep_cptr, void *msg)
{
    (void)ep_cptr;
    (void)msg;
    return 0;
}
int moonlight_send(uint32_t ep_cptr, void *msg)
{
    (void)ep_cptr;
    (void)msg;
    return 0;
}
int moonlight_yield(void)
{
    return 0;
}
int moonlight_retype(uint32_t untyped_cptr, uint32_t type, size_t size, uint32_t dest_cptr)
{
    (void)untyped_cptr;
    (void)type;
    (void)size;
    (void)dest_cptr;
    return 0;
}
int moonlight_cnode_copy(uint32_t dst, uint32_t src, uint32_t rights)
{
    (void)dst;
    (void)src;
    (void)rights;
    return 0;
}

/* Host-sim console reroutes to stdio so shell logic runs in unit tests.
 * Weak so tests can override with scripted input/output buffers. */
__attribute__((weak)) int moonlight_putc(char c)
{
    return putchar(c);
}
__attribute__((weak)) int moonlight_getc(void)
{
    return -1;
}

#endif
