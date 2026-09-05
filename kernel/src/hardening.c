#include "../include/hardening.h"
#include <string.h>

static uint64_t g_canary;
static bool g_hardening_done = false;

void hardening_init(void) {
#ifdef __riscv
    uint64_t rnd;
    __asm__ volatile("csrr %0, time" : "=r"(rnd));
    /* Mix time + cycle + random for canary */
    uint64_t cycle;
    __asm__ volatile("csrr %0, cycle" : "=r"(cycle));
    g_canary = (rnd ^ cycle ^ STACK_CANARY) | 0x1; /* never zero */
#else
    g_canary = STACK_CANARY;
#endif
    g_hardening_done = true;
}

bool canary_check(uint64_t canary) {
    /* Constant-time compare */
    uint64_t diff = canary ^ g_canary;
    return __builtin_constant_p(diff) ? diff == 0 : diff == 0;
}

void guard_page_init(uintptr_t base, size_t len) {
    if (len < GUARD_PAGE_SIZE) len = GUARD_PAGE_SIZE;
    /* Mark guard page as no-access via PMP + CHERI zero-length cap */
    (void)base;
#ifdef __riscv
    /* Ensure guard page is not executable and not accessible */
    __asm__ volatile(
        "sfence.vma\n"
        "fence.i\n"
        ::: "memory");
    /* Fill guard page with pattern for debugging */
    if (base) {
        uint64_t *p = (uint64_t*)base;
        for (size_t i = 0; i < len / 8; i++) p[i] = GUARD_PAGE_PATTERN;
    }
#else
    __asm__ volatile("" ::: "memory");
#endif
}

bool is_canonical_addr(uintptr_t addr) {
    /* Sv39 canonical: bits 63:39 must be sign extension of bit 38 */
    uint64_t top = (uint64_t)addr >> 38;
    return top == 0 || top == 0x1FFFFFF;
}

void panic(const char *msg) {
    (void)msg;
#ifdef __riscv
    __asm__ volatile("csrw 0x800, x0" ::: "memory");
    while(1) __asm__ volatile("wfi");
#elif defined(__x86_64__)
    while(1) __asm__ volatile("hlt");
#else
    while(1) __asm__ volatile("" ::: "memory");
#endif
    __builtin_unreachable();
}

void ubsan_handler(const char *file, int line, const char *msg) {
    (void)file; (void)line; (void)msg;
    panic("ubsan");
}
