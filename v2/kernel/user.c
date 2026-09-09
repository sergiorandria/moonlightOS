/* v2 U-mode threads (Stage 1). Freestanding, linked into .utext/.udata.
 * CONSTRAINT (Stage-1, documented): no string literals, no globals here.
 * Literals would land in kernel .rodata (U=0, fault on U access) and gp
 * points at the kernel small-data area. Everything below is immediates +
 * stack locals, so code runs with any gp. Stage 3 (ELF loader) lifts this
 * with per-process gp + private rodata. */
#include <stdint.h>

#define V2_YIELD 0
#define V2_PUTC 1
#define V2_PARK 2

static long u_ecall(long sys, long arg) {
    register long r_a0 asm("a0") = arg;
    register long r_a7 asm("a7") = sys;
    asm volatile("ecall" : "+r"(r_a0) : "r"(r_a7) : "memory");
    return r_a0;
}

static void uputc(char c) {
    u_ecall(V2_PUTC, (long)(unsigned char)c);
}

static void uyield(void) {
    u_ecall(V2_YIELD, 0);
}

static void upark(void) {
    u_ecall(V2_PARK, 0);
    for (;;)
        u_ecall(V2_YIELD, 0); /* unreachable: park never returns */
}

/* Thread A: counts with yields, then parks so B can run (lowest-Runnable
 * would otherwise run A forever). */
__attribute__((section(".utext"), noinline)) void user_a_main(void) {
    uputc('A');
    for (long i = 0; i < 5; i++) {
        uputc('0' + (char)i);
        uputc('\n');
        uyield();
    }
    upark();
}

/* Thread B: greets, then executes an illegal instruction. The kernel must
 * park B with a message while A keeps running (fault containment demo). */
__attribute__((section(".utext"), noinline)) void user_b_main(void) {
    uputc('B');
    uputc('\n');
    uyield();
    uputc('!');
    uputc('\n');
    asm volatile(".4byte 0x0"); /* illegal: must trap, never return */
    uputc('X'); /* unreachable if containment works */
    for (;;)
        uyield();
}

static uint8_t ustack_a[4096] __attribute__((section(".ustack"), aligned(16)));
static uint8_t ustack_b[4096] __attribute__((section(".ustack"), aligned(16)));

uintptr_t ustack_a_top __attribute__((section(".udata"))) = 0;
uintptr_t ustack_b_top __attribute__((section(".udata"))) = 0;

__attribute__((section(".utext"))) void user_stacks_init(void) {
    ustack_a_top = (uintptr_t)(ustack_a + sizeof(ustack_a));
    ustack_b_top = (uintptr_t)(ustack_b + sizeof(ustack_b));
}
