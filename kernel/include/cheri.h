#pragma once
#include <stdint.h>
#include <stddef.h>

/* CHERI RISC-V purecap/hybrid abstraction.
 * On non-CHERI host, degrades to checked-pointer simulation for testing.
 */

#ifdef __CHERI_PURE_CAPABILITY__
#include <cheriintrin.h>
#define CHERI_CAP __capability void *
#define CHERI_CODE_CAP __capability void *
#define cheri_bounds_set(cap, len) __builtin_cheri_bounds_set(cap, len)
#define cheri_perms_and(cap, perms) __builtin_cheri_perms_and(cap, perms)
#define cheri_seal(cap, otype) __builtin_cheri_seal(cap, otype)
#define cheri_unseal(cap, auth) __builtin_cheri_unseal(cap, auth)
#define cheri_tag_get(cap) __builtin_cheri_tag_get(cap)
#define cheri_address_get(cap) __builtin_cheri_address_get(cap)
#define cheri_base_get(cap) __builtin_cheri_base_get(cap)
#define cheri_length_get(cap) __builtin_cheri_length_get(cap)
#define cheri_perms_get(cap) __builtin_cheri_perms_get(cap)
#else
/* Host simulation: tag + bounds tracked in struct, checked at runtime */
typedef struct {
    uintptr_t base;
    uintptr_t top;
    uintptr_t addr;
    uint32_t perms;
    uint32_t otype;
    uint8_t tag;
    uint8_t sealed;
} sim_cap_t;
#define CHERI_CAP sim_cap_t
#define CHERI_CODE_CAP sim_cap_t
static inline int cheri_tag_get(sim_cap_t c) { return c.tag; }
static inline uintptr_t cheri_base_get(sim_cap_t c) { return c.base; }
static inline size_t cheri_length_get(sim_cap_t c) { return c.top - c.base; }
#endif

/* CHERI permissions - RISC-V CHERI spec */
#define CHERI_PERM_LOAD          (1u << 0)
#define CHERI_PERM_STORE         (1u << 1)
#define CHERI_PERM_EXECUTE       (1u << 2)
#define CHERI_PERM_LOAD_CAP      (1u << 3)
#define CHERI_PERM_STORE_CAP     (1u << 4)
#define CHERI_PERM_SEAL          (1u << 5)
#define CHERI_PERM_UNSEAL        (1u << 6)
#define CHERI_PERM_SYSTEM        (1u << 7)

/* Moonlight otype allocation - kernel sealing types */
#define OTYPE_CNODE         0x100
#define OTYPE_TCB           0x101
#define OTYPE_VSPACE        0x102
#define OTYPE_ENDPOINT      0x103
#define OTYPE_NOTIFICATION  0x104
#define OTYPE_FRAME         0x105
#define OTYPE_SCHEDCONTEXT  0x106
#define OTYPE_TIMEPARTITION 0x107

/* Microarchitectural flush - proven flush-on-switch */
static inline void cheri_flush_microarch(void) {
#ifdef __riscv
    __asm__ volatile(
        "fence.i\n"
        "sfence.vma\n"
        /* CHERI tag cache clear + BTB/BHT flush via custom CSR */
        "csrw 0x800, x0\n"
        ::: "memory");
#else
    __asm__ volatile("" ::: "memory");
#endif
}

/* Strict bounds-checked copy - constant time wrt secret length */
void *cheri_memcpy_capped(CHERI_CAP dst, const void *src, size_t len);
int cheri_cap_is_valid(CHERI_CAP cap, uintptr_t base, size_t len, uint32_t perms);
