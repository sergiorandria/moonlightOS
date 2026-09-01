/* mem_server - userspace memory manager, purecap compartment
 * Holds Untyped caps, services alloc/free via IPC. Micro-rebootable: state is caps, not heap.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/* Simulated kernel IPC ABI for host testing */
typedef struct { uint32_t label, length, caps; uint64_t words[30]; uint32_t cap_ptrs[3]; } ipc_msg_t;
extern int moonlight_call(uint32_t ep, ipc_msg_t *msg);
extern int moonlight_recv(uint32_t ep, ipc_msg_t *msg);

#define PAGE_SIZE 4096
#define MAX_UNTYPED 32

typedef struct {
    uintptr_t paddr;
    size_t size;
    uint32_t cptr; /* kernel cap ptr */
    bool free;
    uint16_t color;
} untyped_t;

static untyped_t untypeds[MAX_UNTYPED];
static uint32_t untyped_count;

void mem_server_init(uintptr_t *bases, size_t *sizes, uint16_t *colors, uint32_t n) {
    for (uint32_t i=0;i<n && i<MAX_UNTYPED;i++) {
        untypeds[i].paddr = bases[i];
        untypeds[i].size = sizes[i];
        untypeds[i].free = true;
        untypeds[i].color = colors[i];
    }
    untyped_count = n;
}

/* Allocate 4K frame with partition color - enforces cache coloring invariant */
int mem_alloc(uint32_t partition, size_t size, uintptr_t *out_paddr, uint16_t *out_color) {
    for (uint32_t i=0;i<untyped_count;i++) {
        if (!untypeds[i].free) continue;
        if (untypeds[i].size < size) continue;
        /* Color check: partition must get its own colors */
        uint16_t expected = (partition * 2) % 16;
        if (untypeds[i].color != expected && untypeds[i].color != expected+1) continue;
        untypeds[i].free = false;
        *out_paddr = untypeds[i].paddr;
        *out_color = untypeds[i].color;
        /* In real system: invoke UntypedRetype to create Frame cap, then mint to caller */
        return 0;
    }
    return -1;
}

void mem_server_run(uint32_t ep) {
    ipc_msg_t msg;
    while (1) {
        moonlight_recv(ep, &msg);
        if (msg.label == 1) { /* alloc */
            uint32_t part = (uint32_t)msg.words[0];
            size_t sz = (size_t)msg.words[1];
            uintptr_t paddr; uint16_t color;
            int err = mem_alloc(part, sz, &paddr, &color);
            msg.words[0] = err;
            msg.words[1] = paddr;
            msg.words[2] = color;
            msg.length = 3;
            moonlight_call(ep, &msg);
        } else if (msg.label == 2) { /* free */
            uintptr_t p = (uintptr_t)msg.words[0];
            for (uint32_t i=0;i<untyped_count;i++) if (untypeds[i].paddr==p) untypeds[i].free=true;
            msg.words[0]=0; msg.length=1;
            moonlight_call(ep, &msg);
        }
    }
}
