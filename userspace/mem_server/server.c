/* mem_server - userspace memory manager, purecap compartment
 * Holds Untyped caps, services alloc/free via IPC. Micro-rebootable: state is caps, not heap.
 *
 * Microkernel split: the kernel (alloc.c) owns only its own pool mechanics
 * (PT pages, stacks). All *policy* — which partition gets what, splitting,
 * coalescing, pressure response, and the OOM victim choice — lives here.
 * The kernel OOM ledger (kernel/src/oom.c) enforces the same 4GB
 * per-process limit as a backstop; this server mirrors it so clients get
 * -ENOMEM before the kernel has to kill anyone.
 *
 * Any-RAM-size: the Untyped list is whatever boot hands over (one region
 * per RAM chunk, any size). Best-fit across regions keeps arbitrary sizes
 * usable; allocation granularity is one whole region (see mem_alloc).
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
#define MAX_PARTITIONS 8
/* Per-partition (== per-process-class here) cap. Mirrors the kernel's
 * OOM_PER_PROCESS_LIMIT so policy and mechanism agree: no client grows
 * past 4GB; the biggest consumer is the OOM victim. */
#define MEM_PROC_LIMIT (0x100000000ULL)

typedef struct {
    uintptr_t paddr;
    size_t size;
    uint32_t cptr;
    bool free;
    uint16_t color;
    uint32_t owner; /* partition id when !free, 0xFFFFFFFF when free */
} untyped_t;

static untyped_t untypeds[MAX_UNTYPED];
static uint32_t untyped_count;
static uint32_t next_frame_slot = 10;
static uint64_t part_bytes[MAX_PARTITIONS];

#define OWNER_FREE 0xFFFFFFFFu

static size_t round_page(size_t n) {
    return (n + PAGE_SIZE - 1) & ~(size_t)(PAGE_SIZE - 1);
}

void mem_server_init(uintptr_t *bases, size_t *sizes, uint16_t *colors, uint32_t n) {
    for (uint32_t i=0;i<n && i<MAX_UNTYPED;i++) {
        untypeds[i].paddr = bases[i];
        untypeds[i].size = sizes[i];
        untypeds[i].cptr = i;
        untypeds[i].free = true;
        untypeds[i].color = colors[i];
        untypeds[i].owner = OWNER_FREE;
    }
    untyped_count = n < MAX_UNTYPED ? n : MAX_UNTYPED;
    next_frame_slot = 10;
    memset(part_bytes, 0, sizeof(part_bytes));
}

/* Bytes currently held by a partition (0 for bad id). */
uint64_t mem_usage(uint32_t partition) {
    if (partition >= MAX_PARTITIONS) return 0;
    return part_bytes[partition];
}

/* 0..100 pressure across all managed Untypeds (by bytes). */
uint32_t mem_pressure(void) {
    uint64_t total = 0, used = 0;
    for (uint32_t i=0;i<untyped_count;i++) {
        total += (uint64_t)untypeds[i].size;
        if (!untypeds[i].free) used += (uint64_t)untypeds[i].size;
    }
    if (total == 0) return 100;
    return (uint32_t)((used * 100) / total);
}

/* OOM policy: largest consumer is the victim (or -1 when idle).
 * Deterministic, no syscalls: the kernel backstop (oom_pick_victim) uses
 * the same rule, so host tests and target agree. */
int mem_oom_victim(void) {
    int best = -1;
    uint64_t most = 0;
    for (uint32_t p=0;p<MAX_PARTITIONS;p++) {
        if (part_bytes[p] > most) { most = part_bytes[p]; best = (int)p; }
    }
    return best;
}

int mem_free(uintptr_t paddr);

int mem_alloc(uint32_t partition, size_t size, uintptr_t *out_paddr, uint16_t *out_color) {
    uint32_t best = MAX_UNTYPED;
    uint16_t expected;
    size_t want;
    if (partition >= MAX_PARTITIONS || !out_paddr || !out_color) return -1;
    if (size == 0) return -1;
    want = round_page(size);
    if (want == 0) return -1; /* wrapped */
    /* 4GB per-partition limit: refuse before touching caps. */
    if ((uint64_t)want > MEM_PROC_LIMIT) return -12; /* -ENOMEM */
    if (part_bytes[partition] + (uint64_t)want > MEM_PROC_LIMIT) return -12;
    expected = (partition * 2) % 16;
    /* Best-fit: smallest free Untyped of a valid color that fits. */
    for (uint32_t i=0;i<untyped_count;i++) {
        if (!untypeds[i].free) continue;
        if (untypeds[i].size < want) continue;
        if (untypeds[i].color != expected && untypeds[i].color != expected+1) continue;
        if (best == MAX_UNTYPED || untypeds[i].size < untypeds[best].size)
            best = i;
    }
    if (best == MAX_UNTYPED) return -1;
    {
        extern int moonlight_retype(uint32_t untyped_cptr, uint32_t type, size_t size, uint32_t dest_cptr);
        /* Whole-region retype. The retype ABI carves from the Untyped base
         * with no offset or watermark (syscall.c retypes at
         * cap->u.untyped.paddr), so a sub-size retype would leave the
         * remainder retypable at the SAME base: a second Frame aliasing the
         * first, invisible to this bookkeeping — a complete-mediation
         * break. Retyping the full region keeps exactly one live kernel
         * Frame per Untyped (1:1 cap-to-bookkeeping). Subdividing a region
         * would need an offset/watermark in the invoke ABI; until then,
         * boot sizes Untypeds for efficiency (one region per RAM chunk)
         * and small requests hold their whole best-fit region (accounted
         * at full size below — honest, not fragmented). */
        size_t whole = untypeds[best].size;
        int err;
        if (part_bytes[partition] + (uint64_t)whole > MEM_PROC_LIMIT)
            return -12; /* holding the whole region would exceed 4GB */
        err = moonlight_retype(untypeds[best].cptr, 5 /*CAP_FRAME*/, whole, next_frame_slot);
        if (err != 0) return -1;
        *out_paddr = untypeds[best].paddr;
        *out_color = untypeds[best].color;
        untypeds[best].free = false;
        untypeds[best].owner = partition;
        part_bytes[partition] += (uint64_t)whole;
        next_frame_slot++;
        return 0;
    }
}

int mem_free(uintptr_t paddr) {
    for (uint32_t i=0;i<untyped_count;i++) {
        if (untypeds[i].free || untypeds[i].paddr != paddr) continue;
        untypeds[i].free = true;
        if (untypeds[i].owner < MAX_PARTITIONS) {
            uint64_t sz = (uint64_t)untypeds[i].size;
            if (sz >= part_bytes[untypeds[i].owner])
                part_bytes[untypeds[i].owner] = 0;
            else
                part_bytes[untypeds[i].owner] -= sz;
        }
        untypeds[i].owner = OWNER_FREE;
        /* No coalescing: regions are never split (one live Frame per
         * Untyped, see mem_alloc), so entries are stable and free is just
         * a release. */
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
            uintptr_t paddr = 0; uint16_t color = 0;
            int err = mem_alloc(part, sz, &paddr, &color);
            msg.words[0] = (uint64_t)(int64_t)err;
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
            /* Single accounting-correct path: mem_free releases the owner's
             * bytes. (No legacy inline fallback — an unsynced mark-free
             * would leak the charge and blind the OOM victim pick.) */
            int rc = mem_free(p);
            msg.words[0]=(uint64_t)(int64_t)rc; msg.length=1;
            moonlight_call(ep, &msg);
        } else if (msg.label == 3) {
            /* OOM query: words[0] = victim partition or -1. */
            int v = mem_oom_victim();
            msg.words[0] = (uint64_t)(int64_t)v;
            msg.words[1] = mem_pressure();
            msg.length = 2;
            moonlight_call(ep, &msg);
        } else if (msg.label == 4) {
            /* ELF frame request: words[0] = index of ELF in initrd (0=first).
             * Returns frame ID in words[0] or error in words[0]. */
            uint32_t idx = (uint32_t)msg.words[0];
            /* For now, initrd is a simple array of ELF frames starting at frame 1.
             * Frame 0 is reserved, frame 1 = first ELF, etc. */
            uint32_t frame_id = idx + 1;
            if (frame_id >= 8) { /* V2_FRAMES_MAX = 8 */
                msg.words[0] = (uint64_t)(int64_t)-1;
            } else {
                msg.words[0] = (uint64_t)frame_id;
                /* Cap is already in next_frame_slot-1 from alloc, but ELF frames
                 * are pre-allocated. For simplicity, we return the frame ID
                 * and the caller must have the cap. In a real impl, we'd
                 * retype the initrd frame here. */
                msg.caps = 1;
                msg.cap_ptrs[0] = frame_id;
            }
            msg.length = 1;
            moonlight_call(ep, &msg);
        }
    }
}
