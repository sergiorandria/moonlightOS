#include "../kernel/include/hardening.h"
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

int main(){
    printf("=== test_hardening ===\n");
    hardening_init();
    assert(canary_check(0) == false);
    printf("canary 0 fails OK\n");
    // guard_page should not crash, and on RISC-V fills pattern
    uint64_t page[512];
    for(int i=0;i<512;i++) page[i]=0;
    guard_page_init((uintptr_t)page, sizeof(page));
#ifdef __riscv
    bool filled = false;
    for(int i=0;i<512;i++) if(page[i]==GUARD_PAGE_PATTERN) filled=true;
    assert(filled);
    printf("guard_page fill OK (riscv)\n");
#else
    printf("guard_page init OK (x86 host, no fill expected)\n");
#endif
    // is_canonical_addr: Sv39 canonical: bits 63:39 sign extension of bit 38
    assert(is_canonical_addr(0x0000000000000000)==true);
    assert(is_canonical_addr(0xFFFFFFFFFFFFFFFF)==true);
    assert(is_canonical_addr(0x0000008000000000)==false);
    assert(is_canonical_addr(0xFFFFFF8000000000)==false);
    printf("is_canonical_addr OK\n");
    printf("PASS: hardening\n");
    return 0;
}
