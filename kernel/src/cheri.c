#include "../include/cheri.h"
#include <string.h>

#ifndef __CHERI_PURE_CAPABILITY__
int cheri_cap_is_valid(CHERI_CAP cap, uintptr_t base, size_t len, uint32_t perms) {
    if (!cap.tag) return 0;
    if (cap.sealed) return 0;
    if (cap.base != base) return 0;
    if (cap.top != base + len) return 0;
    if ((cap.perms & perms) != perms) return 0;
    return 1;
}
void *cheri_memcpy_capped(CHERI_CAP dst, const void *src, size_t len) {
    if (!dst.tag || dst.sealed) return NULL;
    if (dst.addr + len > dst.top) return NULL;
    if (dst.addr < dst.base) return NULL;
    void *d = (void*)dst.addr;
    memcpy(d, src, len);
    return d;
}
#else
int cheri_cap_is_valid(CHERI_CAP cap, uintptr_t base, size_t len, uint32_t perms) {
    if (!cheri_tag_get(cap)) return 0;
    if (cheri_base_get(cap) != base) return 0;
    if (cheri_length_get(cap) != len) return 0;
    if ((cheri_perms_get(cap) & perms) != perms) return 0;
    return 1;
}
void *cheri_memcpy_capped(CHERI_CAP cap, const void *src, size_t len) {
    if (!cheri_tag_get(cap)) return NULL;
    if (cheri_length_get(cap) < len) return NULL;
    void *d = (void*)cheri_address_get(cap);
    __builtin_memcpy(d, src, len);
    return d;
}
void cheri_init_ddc(void) {
    /* Validate PCC/DDC tags on purecap HW; hybrid traps if no CHERI */
    __capability void *pcc;
    __capability void *ddc;
    __asm__ volatile ("cgetpcc %0" : "=C"(pcc));
    __asm__ volatile ("cgetddc %0" : "=C"(ddc));
    if (!cheri_tag_get(pcc) || !cheri_tag_get(ddc)) {
        while(1) __asm__ volatile("wfi");
    }
    /* Restrict DDC to kernel range 0x80000000-0x90000000 for demo */
    ddc = cheri_bounds_set(ddc, 0x10000000);
    __asm__ volatile ("csetddc %0" :: "C"(ddc));
}
bool cheri_is_purecap(void) { return true; }
#endif
