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
/* Bounded string helpers for in-image userspace (vfs_server/shell): the
 * VFS validates names (≤31 chars, NUL-terminated by construction), so these
 * never run off the end on valid inputs; they still stop at NUL anyway. */
size_t strlen(const char *s){
    size_t n = 0;
    while(s[n]) n++;
    return n;
}
int strcmp(const char *a, const char *b){
    while(*a && *a==*b){a++;b++;}
    return (unsigned char)*a - (unsigned char)*b;
}
int strncmp(const char *a, const char *b, size_t n){
    while(n > 0 && *a && *a==*b){a++;b++;n--;}
    if(n == 0) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}
char *strncpy(char *d, const char *s, size_t n){
    size_t i = 0;
    while(i < n && s[i]){ d[i] = s[i]; i++; }
    while(i < n){ d[i] = '\0'; i++; }
    return d;
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
