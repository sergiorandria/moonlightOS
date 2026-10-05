/* syscall_proc.c - loader + process lifecycle INVOKE ops: ELF_CHECK/ELF_MAP/SPAWN/FORK/EXEC.
 *
 * Split out of syscall.c (SOLID Sprint 1b, production-ready): one file per
 * INVOKE operation class, mirroring seL4's src/object organization.
 * Operation classes are disjoint; syscall.c dispatches via handles(). */
#include <stdint.h>

#include "caps.h"
#include "kinternal.h"
#include "elf.h"
#include "initrd.h"

int syscall_proc_handles(uint64_t op)
{
    switch (op)
    {
    case V2_INV_ELF_CHECK:
        return 1;
    case V2_INV_ELF_MAP:
        return 1;
    case V2_INV_SPAWN:
        return 1;
    case V2_INV_FORK:
        return 1;
    case V2_INV_EXEC:
        return 1;
    default:
        return 0;
    }
}

long syscall_proc_invoke(uint64_t op, uint64_t a1, uint64_t a2, uint64_t a3)
{
    long rc = V2_ERR_INVALID;
    (void)a1;
    (void)a2;
    (void)a3;
    switch (op)
    {
    case V2_INV_ELF_CHECK:
        rc = v2_elf_ok((int)a1, (const v2_phdr_t *)a2, a3) ? V2_OK : V2_ERR_INVALID;
        break;
    case V2_INV_ELF_MAP: {
        /* ELF_MAP (a1=initrd index, a2/a3 reserved):
         * Load an initrd ELF into the caller's VSpace.
         * a1 = initrd index (0 = mem_server.elf, see mkinitrd.sh)
         * a2/a3 are reserved and must be zero (unused).
         * Returns entry point in rc (a0 on return).
         * FAIL CLOSED: any validation error -> V2_ERR_INVALID. */
        const uint8_t *elf_data;
        uint32_t elf_size;
        uint64_t entry, brk = 0;
        if (!((a2 == 0 && a3 == 0) || v2_recv_range_ok((uintptr_t)a2, a3)))
        {
            rc = V2_ERR_INVALID;
            break;
        }
        if (initrd_lookup((uint32_t)a1, &elf_data, &elf_size) != 0)
        {
            rc = V2_ERR_INVALID;
            break;
        }
        rc = v2_elf_load(elf_data, (size_t)elf_size, &caps, (unsigned long)cur, &entry, &brk);
        if (rc == V2_OK)
        {
            v2_pte_sync((unsigned long)cur);
            rc = (int)entry; /* return entry point as rc */
        }
        break;
    }
    case V2_INV_SPAWN: {
        /* SPAWN (a1=initrd index, a2/a3 reserved):
         * Create a new thread, allocate its VSpace, load an
         * initrd ELF into it.
         * a1 = initrd index (0 = mem_server.elf, see mkinitrd.sh)
         * a2/a3 are reserved and must be zero (unused).
         * Returns child tid in rc on success.
         * FAIL CLOSED: any validation error -> V2_ERR_INVALID. */
        const uint8_t *elf_data;
        uint32_t elf_size;
        uint64_t entry, brk = 0;
        if (initrd_lookup((uint32_t)a1, &elf_data, &elf_size) != 0)
        {
            rc = V2_ERR_INVALID;
            break;
        }
        if (!((a2 == 0 && a3 == 0) || v2_recv_range_ok((uintptr_t)a2, a3)))
        {
            rc = V2_ERR_INVALID;
            break;
        }
        /* Find a free thread slot (threads[] has NTHREADS entries;
         * V2_CAP_THREADS is the model's bound, not ours). */
        int child = -1;
        for (int t = 0; t < NTHREADS; t++)
        { /* bound: NTHREADS */
            /* deferred-C: T_DEAD is distinct; state alone frees the slot */
            if (threads[t].state == T_DEAD)
            {
                child = t;
                break;
            }
        }
        if (child < 0)
        {
            rc = V2_ERR_OVERFLOW;
            break;
        }
        /* A reused slot may hold a previous life's caps/mappings:
         * clear them so the load starts fresh (fail closed). The
         * child inherits the spawner's qube: without this a slot
         * recycled by QDESTROY (label cleared to 0) silently lands
         * the new thread in the ambient qube — or keeps a stale
         * non-zero label — and the raw gate decides on the wrong
         * labels. Set before any failure break below. */
        qube_of[child] = qube_of[cur];
        /* Reclaim the previous life's frames first: dropping caps
         * without freeing leaks the pool into OVERFLOW over spawn
         * cycles. Snapshot-then-teardown (EXEC precedent): shared
         * frames are unmapped on this slot's side only, never
         * freed under a live sibling. */
        {
            unsigned long reuse_frames[V2_VPN_SLOTS];
            int reuse_n = 0;
            for (int i = 0; i < V2_VPN_SLOTS; i++)
            {
                if (caps.vm[child][i].valid)
                    reuse_frames[reuse_n++] = caps.vm[child][i].frame;
            }
            for (int i = 0; i < reuse_n; i++)
                frame_teardown_owned((unsigned long)child, reuse_frames[i]);
        }
        for (int s = 0; s < V2_CAP_SLOTS; s++)
            caps.caps[child][s].valid = 0;
        for (int i = 0; i < V2_VPN_SLOTS; i++)
            caps.vm[child][i].valid = 0;
        /* Build child's VSpace: copy current thread's page tables for kernel mappings,
         * allocate fresh l0_u for user mappings */
        unsigned long child_root = build_child_vspace((unsigned long)cur, (unsigned long)child);
        if (!child_root)
        {
            rc = V2_ERR_OVERFLOW;
            break;
        }
        threads[child].vspace_root_ppn = child_root;
        /* Fresh IPC/notify state: a reused slot must not inherit
         * the previous life's blocked sends or pending signals. */
        threads[child].ipc_ptr = 0;
        threads[child].ipc_cap = 0;
        threads[child].notify = 0;
        threads[child].wait_kind = V2_WK_NONE;
        /* Fresh registers: no stale-word leak into the new image. */
        for (int r = 0; r < 32; r++)
            threads[child].regs[r] = 0;
        threads[child].state = T_RUNNABLE;

        /* Load ELF into child's VSpace */
        rc = v2_elf_load(elf_data, (size_t)elf_size, &caps, (unsigned long)child, &entry, &brk);
        if (rc == V2_OK && entry != 0)
        {
            v2_pte_sync((unsigned long)child);
            threads[child].regs[2] = u_sp[child];
            threads[child].sepc = entry;
            rc = child; /* return child tid */
        }
        else
        {
            threads[child].state = T_DEAD; /* cleanup on failure */
            if (rc == V2_OK)
                rc = V2_ERR_INVALID;
        }
        break;
    }
    case V2_INV_FORK: {
        /* FORK (no args):
         * Create a child thread with a COW copy of the parent's
         * VSpace and caps. The caps model keeps full rights on
         * both sides (it stays the authority); only the hardware
         * PTEs lose W (see v2_cow_write_protect), so the first
         * store to a shared page faults and the handler breaks
         * the share for the faulting thread only.
         * Returns child tid to parent, 0 to child.
         * FAIL CLOSED: any error -> V2_ERR_INVALID/V2_ERR_OVERFLOW. */
        int child = -1;
        for (int t = 0; t < NTHREADS; t++)
        { /* bound: NTHREADS */
            /* deferred-C: T_DEAD is distinct; state alone frees the slot */
            if (threads[t].state == T_DEAD)
            {
                child = t;
                break;
            }
        }
        if (child < 0)
        {
            rc = V2_ERR_OVERFLOW;
            break;
        }
        /* The child inherits the parent's qube (same reason as
         * SPAWN above: a recycled T_DEAD slot must not keep a
         * cleared (0) or stale label). Set before any failure
         * break below. */
        qube_of[child] = qube_of[cur];
        /* Reclaim the slot's previous life first (same leak as
         * SPAWN-reuse had: overwriting caps/vm orphans frames).
         * Shared frames are spared by teardown_owned. */
        {
            unsigned long fork_frames[V2_VPN_SLOTS + V2_CAP_SLOTS];
            int fork_n = 0;
            for (int i = 0; i < V2_VPN_SLOTS; i++)
            {
                if (caps.vm[child][i].valid)
                    fork_frames[fork_n++] = caps.vm[child][i].frame;
            }
            for (int s = 0; s < V2_CAP_SLOTS; s++)
            {
                if (caps.caps[child][s].valid && !caps.caps[child][s].root)
                    fork_frames[fork_n++] = caps.caps[child][s].obj;
            }
            for (int i = 0; i < fork_n; i++)
                frame_teardown_owned((unsigned long)child, fork_frames[i]);
        }
        /* Copy parent's caps table. The child must not inherit
         * allocator authority: root bits stay with the parent. */
        for (int s = 0; s < V2_CAP_SLOTS; s++)
        {
            caps.caps[child][s] = caps.caps[cur][s];
            caps.caps[child][s].root = 0;
        }
        /* Copy parent's mappings verbatim (rights intact: the
         * model is the COW authority, not a rights bit). */
        for (int i = 0; i < V2_VPN_SLOTS; i++)
            caps.vm[child][i] = caps.vm[cur][i];
        /* Build child tables, install the shared mappings, then
         * write-protect both sides in hardware. */
        unsigned long child_root = build_child_vspace((unsigned long)cur, (unsigned long)child);
        if (!child_root)
        {
            rc = V2_ERR_OVERFLOW;
            break;
        }
        threads[child].vspace_root_ppn = child_root;
        for (int i = 0; i < V2_VPN_SLOTS; i++)
        {
            if (caps.vm[child][i].valid)
                v2_pte_install((unsigned long)child, caps.vm[child][i].vpn, caps.vm[child][i].frame,
                               caps.vm[child][i].rights);
        }
        v2_cow_write_protect((unsigned long)cur, (unsigned long)child);
        /* Fresh IPC/notify state for the new life. */
        threads[child].ipc_ptr = 0;
        threads[child].ipc_cap = 0;
        threads[child].notify = 0;
        threads[child].wait_kind = V2_WK_NONE;
        threads[child].state = T_RUNNABLE;
        threads[child].regs[2] = u_sp[child];
        threads[child].sepc = threads[cur].sepc + 4; /* return after ecall */
        /* Copy registers (parent's a0..a7, sp, etc.) */
        for (int r = 0; r < 32; r++)
            threads[child].regs[r] = threads[cur].regs[r];
        threads[child].regs[10] = 0;   /* child returns 0 in a0 */
        threads[child].regs[11] = cur; /* child gets parent tid in a1 */
        rc = child;                    /* parent returns child tid in a0 */
        break;
    }
    case V2_INV_EXEC: {
        /* EXEC (a1=initrd index, a2/a3 reserved):
         * Replace current thread's image: unmap all user mappings, free frames,
         * clear user caps, load a new initrd ELF.
         * a1 = initrd index (0 = mem_server.elf, see mkinitrd.sh)
         * a2/a3 are reserved and must be zero (unused).
         * Returns 0 on success.
         * FAIL CLOSED: any validation error -> V2_ERR_INVALID. */
        const uint8_t *elf_data;
        uint32_t elf_size;
        if (initrd_lookup((uint32_t)a1, &elf_data, &elf_size) != 0)
        {
            rc = V2_ERR_INVALID;
            break;
        }
        if (!((a2 == 0 && a3 == 0) || v2_recv_range_ok((uintptr_t)a2, a3)))
        {
            rc = V2_ERR_INVALID;
            break;
        }
        /* Tear down all user mappings and reclaim their frames.
         * Snapshot first (teardown mutates later aliasing slots).
         * Shared-with-sibling frames (COW fork child) are unmapped
         * on our side only and NOT freed — a system-wide release
         * here would destroy the sibling's live mappings. */
        unsigned long exec_frames[V2_VPN_SLOTS];
        int exec_nframes = 0;
        for (int i = 0; i < V2_VPN_SLOTS; i++)
        {
            if (caps.vm[cur][i].valid)
                exec_frames[exec_nframes++] = caps.vm[cur][i].frame;
        }
        for (int i = 0; i < exec_nframes; i++)
            frame_teardown_owned((unsigned long)cur, exec_frames[i]);
        v2_sfence_all();
        /* Clear user caps (slots 0..V2_CAP_SLOTS-1, keep root caps) */
        for (int s = 0; s < V2_CAP_SLOTS; s++)
        {
            if (!caps.caps[cur][s].root)
                caps.caps[cur][s].valid = 0;
        }
        /* Load new ELF into current VSpace */
        {
            uint64_t entry = 0, brk = 0;
            rc = v2_elf_load(elf_data, (size_t)elf_size, &caps, (unsigned long)cur, &entry, &brk);
            if (rc == V2_OK && entry != 0)
            {
                v2_pte_sync((unsigned long)cur);
                threads[cur].regs[2] = u_sp[cur];
                threads[cur].sepc = entry;
                /* Reset registers to clean state */
                for (int r = 0; r < 32; r++)
                    threads[cur].regs[r] = 0;
                threads[cur].regs[2] = u_sp[cur];
                rc = 0; /* return 0 on success */
            }
            else if (rc == V2_OK)
            {
                rc = V2_ERR_INVALID;
            }
        }
        break;
    }
    default:
        rc = V2_ERR_INVALID;
        break;
    }
    return rc;
}
