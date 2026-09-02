#include "../../include/vspace.h"
#include <string.h>
#include <stdint.h>

// x86-64 PML4 4-level paging, 4K pages, PCID per ASID
static uint8_t pml4_pool[64 * 4096] __attribute__((aligned(4096)));
static uint32_t pml4_next = 0;

static uint64_t* alloc_pml_page(void){
    if(pml4_next >= 64) return NULL;
    uint64_t *p = (uint64_t*)&pml4_pool[pml4_next*4096];
    memset(p,0,4096);
    pml4_next++;
    return p;
}

// x86-64 PTE flags
#define X86_PTE_P  (1ULL<<0)
#define X86_PTE_W  (1ULL<<1)
#define X86_PTE_U  (1ULL<<2)
#define X86_PTE_A  (1ULL<<5)
#define X86_PTE_D  (1ULL<<6)
#define X86_PTE_PS (1ULL<<7)
#define X86_PTE_G  (1ULL<<8)

// Override weak vspace functions for x86-64 when compiled with -DARCH_X86_64
#ifdef __x86_64__
kerror_t vspace_init_arch(vspace_t *vs, asid_t asid, uint32_t part){
    if(!vs) return ERR_INVALID_ARG;
    vs->root = (pte_t*)alloc_pml_page();
    if(!vs->root) return ERR_NO_MEM;
    vs->asid = asid;
    vs->partition_id = part;
    return ERR_OK;
}
#endif
