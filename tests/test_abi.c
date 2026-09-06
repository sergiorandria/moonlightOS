#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/* Regression for PLAN 3: ensures cross-build did not pull host glibc
 * bits/wordsize.h which makes uintptr_t 4 bytes under
 * --target=riscv64-unknown-elf -mabi=lp64.
 * Freestanding clang -I/usr/lib/clang/22/include must be used, not -I/usr/include.
 */
_Static_assert(sizeof(uintptr_t) == 8, "uintptr_t must be 8 bytes for rv64 lp64");
_Static_assert(sizeof(void *) == 8, "void* must be 8 bytes");
_Static_assert(sizeof(size_t) == 8, "size_t must be 8 bytes");
_Static_assert(sizeof(uint64_t) == 8, "uint64_t must be 8 bytes");

int main(void) {
    printf("ABI check: uintptr_t=%zu void*=%zu size_t=%zu\n",
           sizeof(uintptr_t), sizeof(void*), sizeof(size_t));
    if (sizeof(uintptr_t) != 8) {
        printf("FAIL: uintptr_t is %zu, not 8 — truncated build\n", sizeof(uintptr_t));
        return 1;
    }
    printf("PASS: ABI 64-bit intact (no 32-bit truncation)\n");
    return 0;
}
