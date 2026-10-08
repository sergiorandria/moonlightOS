/* syscall_mem.c - frame content lifecycle (release/teardown) + word-model INVOKE ops: WRITE/READ/FRAME_PA.
 *
 * Split out of syscall.c (SOLID Sprint 1b, production-ready): one file per
 * INVOKE operation class, mirroring seL4's src/object organization.
 * Operation classes are disjoint; syscall.c dispatches via handles(). */
#include <stdint.h>

#include "caps.h"
#include "kinternal.h"

/* frame_release: kernel-authority teardown of one frame (satisfies the
 * caps.h contract). Revoke every non-root cap + every mapping
 * system-wide, clear any hardware PTE still naming the frame, scrub the
 * page and return it to the pool. No-op on frame 0 / out-of-range /
 * already-free frames (fail-closed: never double-frees, never scrubs a
 * live frame). EVERY free path funnels through here (ELF rollback, EXEC,
 * REVOKE-adjacent teardown) so a freed frame is never reachable via a
 * stale cap, mapping, or PTE: use-after-free across fork+exec would be
 * an isolation break, while a leak would only exhaust the pool.
 * NOTE: intentionally NOT owner-checked: the kernel is the authority
 * (mirrors v2_revoke_frame, not v2_revoke). Ownership audits use
 * v2_frames_next_owned on the frames.h side.
 * ROOTS SURVIVE: v2_revoke_frame preserves thread-0 root caps by design
 * (allocator authority, so the mem_server can re-issue). A root still
 * names a freed+reallocated frame — roots are authority, NOT ownership:
 * thread 0 must never be attacker-controlled, and no path may hand a
 * root cap to an untrusted thread (MINT clears root on every copy).
 * SHARED FRAMES: frame_release is system-wide and must ONLY be called
 * for frames with no other live references (fresh loader pages). For
 * frames that may be COW-shared, use frame_teardown_owned below, which
 * drops one thread's side and frees only when unshared. */
void frame_release(unsigned long frame)
{
    unsigned long u;
    int i;
    if (frame >= (unsigned long)V2_FRAME_TOTAL)
        return;
    if (frame == 0 || frame_bitmap[frame] != 0)
        return; /* kernel-reserved / already free: no state change */
    /* Clear every hardware PTE still naming this frame BEFORE the model
     * forgets the (thread, vpn) pairs. bound: threads x vpn slots. */
    for (u = 0; u < (unsigned long)NTHREADS; u++)
    {
        for (i = 0; i < V2_VPN_SLOTS; i++)
        {
            if (caps.vm[u][i].valid && caps.vm[u][i].frame == frame)
                v2_pte_clear(u, caps.vm[u][i].vpn);
        }
    }
    v2_revoke_frame(&caps, frame); /* drops non-root caps + all mappings */
    v2_sfence_all();
    frame_free((int)frame); /* bitmap was 0 (used): zeroes, no double-free warn */
}

/* frame_teardown_owned: drop ONE thread's side of a frame, freeing the
 * frame only when nothing references it anymore. The revoke in
 * frame_release is system-wide: calling it on a COW-shared frame would
 * destroy live siblings' mappings (then free under their stale PTEs).
 * So: drop owner's mappings + PTEs + non-root caps first, then free only
 * if no valid mapping AND no valid non-root cap survives anywhere (a
 * granted-but-unmapped live cap must also block the free, or a later
 * realloc lets it map somebody else's page). Dead co-owners are handled
 * by processing order (each dead side drops in turn; the last one frees).
 * Roots are never cleared here (mirror v2_revoke). No-op on frame 0 /
 * out-of-range / already-free / bad owner (fail closed). */

void frame_teardown_owned(unsigned long owner, unsigned long frame)
{
    unsigned long u;
    int i, live;
    if (owner >= (unsigned long)NTHREADS)
        return;
    if (frame >= (unsigned long)V2_FRAME_TOTAL)
        return;
    if (frame == 0 || frame_bitmap[frame] != 0)
        return; /* kernel-reserved / already free: no state change */
    /* Drop owner's mappings + PTEs for this frame. bound: V2_VPN_SLOTS. */
    for (i = 0; i < V2_VPN_SLOTS; i++)
    {
        if (caps.vm[owner][i].valid && caps.vm[owner][i].frame == frame)
        {
            v2_pte_clear(owner, caps.vm[owner][i].vpn);
            caps.vm[owner][i].valid = 0;
        }
    }
    /* Drop owner's non-root caps for this frame. bound: V2_CAP_SLOTS. */
    for (i = 0; i < V2_CAP_SLOTS; i++)
    {
        v2_capslot_t *c = &caps.caps[owner][i];
        if (c->valid && !c->root && c->obj == frame)
            c->valid = 0;
    }
    /* Free only when no valid mapping AND no valid non-root cap survives
     * anywhere (roots exempt: allocator authority). bound: threads x slots. */
    live = 0;
    for (u = 0; u < (unsigned long)NTHREADS && !live; u++)
    {
        for (i = 0; i < V2_VPN_SLOTS; i++)
        {
            if (caps.vm[u][i].valid && caps.vm[u][i].frame == frame)
            {
                live = 1;
                break;
            }
        }
        for (i = 0; i < V2_CAP_SLOTS && !live; i++)
        {
            const v2_capslot_t *c = &caps.caps[u][i];
            if (c->valid && !c->root && c->obj == frame)
                live = 1;
        }
    }
    if (!live)
        frame_release(frame); /* full revoke (stragglers) + scrub + free */
    else
        v2_sfence_all(); /* owner's PTE clears above need fencing */
}
int syscall_mem_handles(uint64_t op)
{
    switch (op)
    {
    case V2_INV_WRITE:
        return 1;
    case V2_INV_READ:
        return 1;
    case V2_INV_FRAME_PA:
        return 1;
    default:
        return 0;
    }
}

long syscall_mem_invoke(uint64_t op, uint64_t a1, uint64_t a2, uint64_t a3)
{
    long rc = V2_ERR_INVALID;
    (void)a1;
    (void)a2;
    (void)a3;
    switch (op)
    {
    case V2_INV_WRITE: {
        /* WRITE (a1=vpn, a2=u_src): one 8-byte word. Range-check +
         * copy the user word into a kernel temp, run the model
         * write on fdata (rights gate + shadow), then — only on
         * V2_OK — store that same word into the real frame PA
         * (Write-Through Mirror: real memory and fdata stay
         * identical). FAIL CLOSED: real memory is never touched
         * on model error. */
        uint64_t kbuf[1];
        if (a1 >= (uint64_t)V2_VPN_SLOTS)
        {
            rc = V2_ERR_INVALID;
            break;
        }
        if (!v2_send_range_ok((uintptr_t)a2, 1))
        {
            rc = V2_ERR_INVALID;
            break;
        }
        u_copy_in(kbuf, (uintptr_t)a2, 1);
        rc = v2_write(&caps, (unsigned long)cur, a1, kbuf[0]);
        if (rc == V2_OK)
        {
            int m = v2_vm_find(&caps, (unsigned long)cur, a1);
            if (m >= 0) /* model wrote it: mapping must be findable */
                v2_real_write(caps.vm[cur][m].frame, (const uint8_t *)kbuf, V2_WORD_BYTES);
        }
        break;
    }
    case V2_INV_READ: {
        /* READ (a1=vpn, a2=u_dst): mirror of WRITE. Run the model
         * read first (rights gate + shadow), then — only on V2_OK —
         * load the real 8-byte word from the frame PA into a kernel
         * temp and copy it out to the validated user destination.
         * FAIL CLOSED: the user destination is touched only on
         * model + range success. */
        uint64_t kbuf[1];
        if (a1 >= (uint64_t)V2_VPN_SLOTS)
        {
            rc = V2_ERR_INVALID;
            break;
        }
        if (!v2_recv_range_ok((uintptr_t)a2, 1))
        {
            rc = V2_ERR_INVALID;
            break;
        }
        rc = v2_read(&caps, (unsigned long)cur, a1, &kbuf[0]);
        if (rc == V2_OK)
        {
            int m = v2_vm_find(&caps, (unsigned long)cur, a1);
            if (m < 0)
            { /* model read succeeded: must be findable */
                rc = V2_ERR_INVALID;
                break;
            }
            v2_real_read(caps.vm[cur][m].frame, (uint8_t *)kbuf, V2_WORD_BYTES);
            u_copy_out((uintptr_t)a2, kbuf, 1);
        }
        break;
    }
    case V2_INV_FRAME_PA: {
        /* FRAME_PA (a1=vpn, a2/a3 reserved=0): return the physical
         * address of the frame mapped at vpn in the caller's VSpace.
         * Pure address math (V2_FRAME_PHYS_BASE + frame*4096): no
         * state change, no copy. Miss or nonzero reserved -> INVALID. */
        int m; /* bound: V2_VPN_SLOTS (v2_vm_find scan) */
        if (a2 != 0 || a3 != 0)
        {
            rc = V2_ERR_INVALID;
            break;
        }
        m = v2_vm_find(&caps, (unsigned long)cur, a1);
        if (m < 0)
        {
            rc = V2_ERR_INVALID;
            break;
        }
        rc = (long)(V2_FRAME_PHYS_BASE + caps.vm[cur][m].frame * 4096UL);
        break;
    }
    default:
        rc = V2_ERR_INVALID;
        break;
    }
    return rc;
}
