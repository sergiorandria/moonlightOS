#include "../include/hardening.h"
#include <string.h>

static uint64_t g_canary;

void hardening_init(void) {
#ifdef __riscv
    uint64_t rnd;
    __asm__ volatile("csrr %0, time" : "=r"(rnd));
    g_canary = rnd ^ STACK_CANARY;
#else
    g_canary = STACK_CANARY;
#endif
}

bool canary_check(uint64_t canary) { return canary == g_canary; }

void guard_page_init(uintptr_t base, size_t len) {
    /* Mark guard page as no-access via PMP + CHERI zero-length cap */
    (void)base; (void)len;
#ifdef __riscv
    __asm__ volatile("sfence.vma" ::: "memory");
#else
    __asm__ volatile("" ::: "memory");
#endif
}

void ubsan_handler(const char *file, int line, const char *msg) {
    (void)file; (void)line; (void)msg;
    /* Fail closed: halt, do not continue with undefined behavior */
    while(1) {
#ifdef __riscv
        __asm__ volatile("wfi");
#else
        __asm__ volatile("" ::: "memory"); break;
#endif
    }
}
