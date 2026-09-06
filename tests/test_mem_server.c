#include "../kernel/include/cap.h"
#include "../kernel/include/cnode.h"
#include "../kernel/include/types.h"
#include <stdio.h>
#include <assert.h>

extern void mem_server_init(uintptr_t *bases, size_t *sizes, uint16_t *colors, uint32_t n);
extern int mem_alloc(uint32_t partition, size_t size, uintptr_t *out_paddr, uint16_t *out_color);

// Stubs
int moonlight_call(uint32_t ep, void *msg){ (void)ep; (void)msg; return 0; }
int moonlight_recv(uint32_t ep, void *msg){ (void)ep; (void)msg; return 0; }
int moonlight_retype(uint32_t cptr, uint32_t type, size_t size, uint32_t dest){
    extern cnode_t g_root_cnode;
    cap_t *ut = cnode_lookup(&g_root_cnode, cptr);
    if(!ut) return -1;
    cap_t new_cap = cap_retype(*ut, type, ut->u.untyped.paddr, size);
    if(!new_cap.is_valid) return -1;
    if(dest >= 256) return -1;
    if(g_root_cnode.slots[dest].is_valid) return -1;
    g_root_cnode.slots[dest]=new_cap;
    g_root_cnode.used++;
    return 0;
}
int moonlight_cnode_copy(uint32_t dst, uint32_t src, uint32_t rights){ (void)dst;(void)src;(void)rights; return 0; }

cnode_t g_root_cnode;

int main(){
    printf("=== test_mem_server ===\n");
    uintptr_t bases[2] = {0x90000000, 0x91000000};
    size_t sizes[2] = {4096, 4096};
    uint16_t colors[2] = {0, 2};
    mem_server_init(bases, sizes, colors, 2);
    cnode_init(&g_root_cnode, 0, 8);
    cap_t ut0={0}; ut0.type=CAP_UNTYPED; ut0.is_valid=1; ut0.hw_cap.tag=1; ut0.u.untyped.paddr=0x90000000; ut0.u.untyped.size=4096; ut0.rights=0xFF; ut0.hw_cap.base=0x90000000; ut0.hw_cap.top=0x90001000; ut0.hw_cap.addr=0x90000000;
    cap_t ut1={0}; ut1.type=CAP_UNTYPED; ut1.is_valid=1; ut1.hw_cap.tag=1; ut1.u.untyped.paddr=0x91000000; ut1.u.untyped.size=4096; ut1.rights=0xFF; ut1.hw_cap.base=0x91000000; ut1.hw_cap.top=0x91001000; ut1.hw_cap.addr=0x91000000;
    g_root_cnode.slots[0]=ut0; g_root_cnode.slots[1]=ut1; g_root_cnode.used=2;
    uintptr_t paddr; uint16_t color;
    int err = mem_alloc(0, 4096, &paddr, &color);
    printf("alloc part0 %d paddr %lx color %u\n", err, paddr, color);
    assert(err==0 && color==0);
    err = mem_alloc(0, 4096, &paddr, &color);
    printf("alloc part0 second should fail %d\n", err);
    assert(err==-1);
    err = mem_alloc(1, 4096, &paddr, &color);
    printf("alloc part1 %d color %u\n", err, color);
    assert(err==0 && color==2);
    assert(g_root_cnode.slots[10].is_valid && g_root_cnode.slots[10].type==CAP_FRAME);
    printf("PASS: mem_server\n");
    return 0;
}
