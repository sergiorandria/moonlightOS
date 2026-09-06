/* mem_server - userspace memory manager, purecap compartment
 * Holds Untyped caps, services alloc/free via IPC. Micro-rebootable: state is caps, not heap.
 * Policy: partition color check, mechanism: kernel retype/mint via moonlight_call.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

typedef struct { uint32_t label, length, caps; uint64_t words[30]; uint32_t cap_ptrs[3]; } ipc_msg_t;
extern int moonlight_call(uint32_t ep, ipc_msg_t *msg);
extern int moonlight_recv(uint32_t ep, ipc_msg_t *msg);

#define PAGE_SIZE 4096
#define MAX_UNTYPED 32

typedef struct {
    uintptr_t paddr;
    size_t size;
    uint32_t cptr;
    bool free;
    uint16_t color;
} untyped_t;

static untyped_t untypeds[MAX_UNTYPED];
static uint32_t untyped_count;
static uint32_t next_frame_slot = 10;

void mem_server_init(uintptr_t *bases, size_t *sizes, uint16_t *colors, uint32_t n) {
    for (uint32_t i=0;i<n && i<MAX_UNTYPED;i++) {
        untypeds[i].paddr = bases[i];
        untypeds[i].size = sizes[i];
        untypeds[i].cptr = i;
        untypeds[i].free = true;
        untypeds[i].color = colors[i];
    }
    untyped_count = n;
    next_frame_slot = 10;
}

int mem_alloc(uint32_t partition, size_t size, uintptr_t *out_paddr, uint16_t *out_color) {
    for (uint32_t i=0;i<untyped_count;i++) {
        if (!untypeds[i].free) continue;
        if (untypeds[i].size < size) continue;
        uint16_t expected = (partition * 2) % 16;
        if (untypeds[i].color != expected && untypeds[i].color != expected+1) continue;
        // Real: invoke UntypedRetype to create Frame cap
        // Use moonlight_retype helper which does SYS_INVOKE
        extern int moonlight_retype(uint32_t untyped_cptr, uint32_t type, size_t size, uint32_t dest_cptr);
        int err = moonlight_retype(untypeds[i].cptr, 5 /*CAP_FRAME*/, size, next_frame_slot);
        if (err != 0) continue;
        untypeds[i].free = false;
        *out_paddr = untypeds[i].paddr;
        *out_color = untypeds[i].color;
        next_frame_slot++;
        return 0;
    }
    return -1;
}

void mem_server_run(void) {
    ipc_msg_t msg;
    uint32_t ep = 1; // fixed endpoint for mem_server
    while (1) {
        moonlight_recv(ep, &msg);
        if (msg.label == 1) {
            uint32_t part = (uint32_t)msg.words[0];
            size_t sz = (size_t)msg.words[1];
            uintptr_t paddr; uint16_t color;
            int err = mem_alloc(part, sz, &paddr, &color);
            msg.words[0] = err;
            msg.words[1] = paddr;
            msg.words[2] = color;
            if (err==0) {
                msg.cap_ptrs[0] = next_frame_slot-1;
                msg.caps = 1;
            }
            msg.length = 3;
            moonlight_call(ep, &msg);
        } else if (msg.label == 2) {
            uintptr_t p = (uintptr_t)msg.words[0];
            for (uint32_t i=0;i<untyped_count;i++) if (untypeds[i].paddr==p) untypeds[i].free=true;
            msg.words[0]=0; msg.length=1;
            moonlight_call(ep, &msg);
        }
    }
}
