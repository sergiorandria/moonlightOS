// minilib - freestanding memset/memcpy for RISC-V (host-sim compatible)
#include <stddef.h>
#include <stdint.h>
void *memset(void *s, int c, size_t n){
    unsigned char *p = s;
    while(n--) *p++ = (unsigned char)c;
    return s;
}
void *memcpy(void *d, const void *s, size_t n){
    unsigned char *dd = d;
    const unsigned char *ss = s;
    while(n--) *dd++ = *ss++;
    return d;
}
int memcmp(const void *a, const void *b, size_t n){
    const unsigned char *aa=a, *bb=b;
    while(n--) if(*aa!=*bb) return *aa-*bb; else {aa++;bb++;}
    return 0;
}
uintptr_t __stack_chk_guard = 0xDEADBEEF;
void __stack_chk_fail(void){
    while(1) {
#ifdef __riscv
        __asm__ volatile("wfi");
#else
        /* Host-sim: trap instead of privileged halt/wfi */
        __builtin_trap();
#endif
    }
}
