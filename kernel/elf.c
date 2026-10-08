/* kernel/elf.c - ELF64 loader (frames + caps side). Validation lives in
 * elf.h (v2_elf_plan); this file only executes an already-validated plan.
 *
 * Host-testable: tests/test_elf.c includes this file with V2_FRAME_PTR
 * pointed at a host array and its own frame_alloc_slot/frame_release, so
 * the copy bounds and the rollback path run under ASan/UBSan. */
#include "elf.h"
#include "caps.h"
#include "ipc.h"

/* Writable view of a pool frame. Kernel: the S-only identity map of the
 * pool (VA == PA). Overridable for the host test. */
#ifndef V2_FRAME_PTR
#define V2_FRAME_PTR(f) ((volatile uint8_t *)(V2_FRAME_PHYS_BASE + (unsigned long)(f) * PAGE_SIZE))
#endif

/* One page the loader has allocated, kept so a failed load can undo it. */
typedef struct
{
    unsigned long vpn;
    unsigned long slot;
    unsigned long frame;
} v2_elf_page_t;

/* Allocate a frame, specialize its fresh RW cap to the segment rights
 * (the kernel is the allocator authority; minting X from RW would fail
 * closed, so attenuation is not used), and map it at vpn. On success the
 * page is recorded in *pg for rollback. */
static int v2_elf_map_page(v2_caps_t *caps, unsigned long tid, unsigned long vpn, unsigned long rights,
                           v2_elf_page_t *pg)
{
    int slot;

    if (!caps || !pg)
        return V2_ERR_INVALID;
    if (rights == 0 || (rights & ~V2_RIGHT_MEM_MASK) != 0)
        return V2_ERR_INVALID;
    if ((rights & V2_RIGHT_W) && (rights & V2_RIGHT_X))
        return V2_ERR_INVALID; /* W^X */
    if (vpn >= (unsigned long)V2_VPN_SLOTS)
        return V2_ERR_INVALID;
    if (v2_vm_find(caps, tid, vpn) >= 0)
        return V2_ERR_INVALID; /* duplicate vpn: fail before allocating */

    slot = frame_alloc_slot(caps, tid);
    if (slot < 0)
        return slot;
    if (slot >= V2_CAP_SLOTS)
    {
        /* Allocator contract broken: no slot to drop, nothing to name the
         * frame by. Fail closed (the frame stays with its owner and is
         * reclaimed when that thread's qube is destroyed). */
        return V2_ERR_OVERFLOW;
    }
    caps->caps[tid][slot].rights = rights;
    pg->vpn = vpn;
    pg->slot = (unsigned long)slot;
    pg->frame = caps->caps[tid][slot].obj;

    if (v2_map(caps, tid, (unsigned long)slot, vpn) != V2_OK)
    {
        /* Mapping table full: drop the cap and give the frame back so no
         * half-mapped state and no leaked frame survive. */
        caps->caps[tid][slot].valid = 0;
        frame_release(pg->frame);
        return V2_ERR_OVERFLOW;
    }
    return V2_OK;
}

/* Undo the first n recorded pages: unmap, drop the cap, free the frame. */
static void v2_elf_rollback(v2_caps_t *caps, unsigned long tid, const v2_elf_page_t *pages, unsigned long n)
{
    unsigned long i;
    for (i = 0; i < n; i++)
    { /* bound: V2_VPN_SLOTS */
        (void)v2_unmap(caps, tid, pages[i].vpn);
        caps->caps[tid][pages[i].slot].valid = 0;
        frame_release(pages[i].frame);
    }
}

int v2_elf_load(const uint8_t *elf_data, size_t elf_size, v2_caps_t *caps, unsigned long cur_tid, uint64_t *out_entry,
                uint64_t *out_brk)
{
    v2_elf_plan_t plan;
    /* Non-reentrant by design: function-static scratch (32x24 B = 768 B
     * would fit the trap stack, but reentrancy is excluded by a stronger
     * invariant — single hart + handlers run with SIE=0 + halt never
     * returns into the epilogue (see halt-context guard), so no nested
     * trap can re-enter the loader. If the burst-race work ever opens an
     * in-handler SIE window, convert this to caller-provided storage
     * first (burst spec H1/H2). Host tests are single-threaded. */
    static v2_elf_page_t pages[V2_VPN_SLOTS];
    unsigned long npages_done = 0;
    unsigned long i, k;
    int rc;

    if (!caps || !out_entry || !out_brk || !v2_cap_holder_ok(caps, cur_tid))
        return V2_ERR_INVALID;
    rc = v2_elf_plan(elf_data, elf_size, &plan);
    if (rc != V2_OK)
        return rc;

    for (i = 0; i < plan.nseg; i++)
    { /* bound: V2_ELF_MAX_PHNUM */
        const v2_elf_seg_t *s = &plan.seg[i];
        unsigned long rights = v2_elf_rights(s->flags);

        for (k = 0; k < s->npages; k++)
        { /* bound: V2_VPN_SLOTS */
            volatile uint8_t *dst;
            uint64_t page_off = k * PAGE_SIZE;
            uint64_t avail = s->filesz > page_off ? s->filesz - page_off : 0;
            unsigned long n = avail < PAGE_SIZE ? (unsigned long)avail : (unsigned long)PAGE_SIZE;
            unsigned long b;

            /* npages_done < V2_VPN_SLOTS: plan guarantees disjoint pages
             * inside the V2_VPN_SLOTS window. */
            rc = v2_elf_map_page(caps, cur_tid, s->vpn + k, rights, &pages[npages_done]);
            if (rc != V2_OK)
            {
                v2_elf_rollback(caps, cur_tid, pages, npages_done);
                return rc;
            }
            dst = V2_FRAME_PTR(pages[npages_done].frame);
            npages_done++;

            /* Zero the page (BSS tail, padding), then copy this page's
             * slice of the file range. The slice is bounded by filesz,
             * which the plan checked against the image size. */
            for (b = 0; b < PAGE_SIZE; b++)
                dst[b] = 0;
            for (b = 0; b < n; b++)
                dst[b] = elf_data[s->offset + page_off + b];
        }
    }

    *out_entry = plan.entry;
    *out_brk = plan.brk;
    return V2_OK;
}
