/* syscall_qube.c - qube lifecycle INVOKE ops: QCREATE/QDESTROY.
 *
 * Split out of syscall.c (SOLID Sprint 1b, production-ready): one file per
 * INVOKE operation class, mirroring seL4's src/object organization.
 * Operation classes are disjoint; syscall.c dispatches via handles(). */
#include <stdint.h>

#include "caps.h"
#include "kinternal.h"
#include "elf.h"
#include "initrd.h"
#include "qube.h"

int syscall_qube_handles(uint64_t op)
{
    switch (op)
    {
    case V2_INV_QCREATE:
        return 1;
    case V2_INV_QDESTROY:
        return 1;
    default:
        return 0;
    }
}

long syscall_qube_invoke(uint64_t op, uint64_t a1, uint64_t a2, uint64_t a3)
{
    long rc = V2_ERR_INVALID;
    (void)a1;
    (void)a2;
    (void)a3;
    switch (op)
    {
    case V2_INV_QCREATE: {
        /* QCREATE (a1=initrd index, a2/a3 reserved=0): new thread
         * in a fresh qube label. Mirrors SPAWN's slot setup, then
         * stamps the fresh label. FAIL CLOSED: any validation
         * error -> V2_ERR_INVALID/OVERFLOW with no partial state. */
        const uint8_t *elf_data;
        uint32_t elf_size;
        uint64_t entry = 0, brk = 0;
        int child = -1;
        if (!(a2 == 0 && a3 == 0))
        {
            rc = V2_ERR_INVALID;
            break;
        }
        if (qube_next >= (unsigned long)V2_QUBES_MAX)
        {
            rc = V2_ERR_OVERFLOW;
            break;
        }
        if (initrd_lookup((uint32_t)a1, &elf_data, &elf_size) != 0)
        {
            rc = V2_ERR_INVALID;
            break;
        }
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
         * reclaim frames first (same leak SPAWN-reuse had), then
         * clear so the load starts fresh (fail closed). Shared
         * frames are spared by teardown_owned. */
        {
            unsigned long qc_frames[V2_VPN_SLOTS + V2_CAP_SLOTS];
            int qc_n = 0;
            for (int i = 0; i < V2_VPN_SLOTS; i++)
            {
                if (caps.vm[child][i].valid)
                    qc_frames[qc_n++] = caps.vm[child][i].frame;
            }
            for (int s = 0; s < V2_CAP_SLOTS; s++)
            {
                if (caps.caps[child][s].valid && !caps.caps[child][s].root)
                    qc_frames[qc_n++] = caps.caps[child][s].obj;
            }
            for (int i = 0; i < qc_n; i++)
                frame_teardown_owned((unsigned long)child, qc_frames[i]);
        }
        for (int s = 0; s < V2_CAP_SLOTS; s++) /* bound: V2_CAP_SLOTS */
            caps.caps[child][s].valid = 0;
        for (int i = 0; i < V2_VPN_SLOTS; i++) /* bound: V2_VPN_SLOTS */
            caps.vm[child][i].valid = 0;
        {
            unsigned long child_root = build_child_vspace((unsigned long)cur, (unsigned long)child);
            if (!child_root)
            {
                rc = V2_ERR_OVERFLOW;
                break;
            }
            threads[child].vspace_root_ppn = child_root;
        }
        /* Fresh IPC/notify state: a reused slot must not inherit
         * the previous life's blocked sends or pending signals. */
        threads[child].ipc_ptr = 0;
        threads[child].ipc_cap = 0;
        threads[child].notify = 0;
        threads[child].wait_kind = V2_WK_NONE;
        /* Fresh registers: no stale-word leak into the new image. */
        for (int r = 0; r < 32; r++) /* bound: 32 */
            threads[child].regs[r] = 0;
        rc = v2_elf_load(elf_data, (size_t)elf_size, &caps, (unsigned long)child, &entry, &brk);
        if (rc == V2_OK && entry != 0)
        {
            threads[child].state = T_RUNNABLE;
            v2_pte_sync((unsigned long)child);
            threads[child].regs[2] = u_sp[child];
            threads[child].sepc = entry;
            qube_of[child] = (uint8_t)qube_next++;
            kputs("QUB: qube");
            kputdec((unsigned long)qube_of[child]);
            kputs(" up\n");
            rc = V2_OK;
        }
        else
        {
            threads[child].state = T_DEAD; /* cleanup on failure */
            if (rc == V2_OK)
                rc = V2_ERR_INVALID;
        }
        break;
    }
    case V2_INV_QDESTROY: {
        /* QDESTROY (a1=label, a2/a3 reserved=0): park every thread
         * in the qube, drop their queued IPC, revoke-drain their
         * caps + clear hardware PTEs, reclaim unshared frames.
         * Label 0 (base system) can never be destroyed. FAIL CLOSED.
         * POLICY (deliberate, not an oversight):
         * - No caller-authority check: V2 has no privilege levels.
         *   QCREATE/QDESTROY/SPAWN are all unprivileged by design;
         *   isolation comes from qube labels on the data plane,
         *   management is cooperative. Revisit if threat model grows.
         * - Live BLOCKED survivors stay blocked: a live SENDer queued
         *   for a dead waiter (or RECV waiter for dead senders) keeps
         *   T_BLOCKED with its queue entry intact. Waking them with
         *   an error would break open-ended rendezvous (a future
         *   peer may still arrive), so park-forever is the policy
         *   until timeouts/cancellation land. */
        unsigned long label = (unsigned long)a1;
        int found = 0;
        if (!(a2 == 0 && a3 == 0))
        {
            rc = V2_ERR_INVALID;
            break;
        }
        if (label == 0 || label >= (unsigned long)V2_QUBES_MAX)
        {
            rc = V2_ERR_INVALID;
            break;
        }
        for (int t = 0; t < NTHREADS; t++)
        { /* bound: NTHREADS */
            if (qube_of[t] == (uint8_t)label)
                found = 1;
        }
        if (!found)
        {
            rc = V2_ERR_INVALID;
            break;
        }
        /* Drop queued IPC entries owned by the qube (compact both
         * queues in place; other qubes' entries are preserved). */
        {
            for (int e = 0; e < V2_NEP; e++)
            { /* bound: V2_NEP (11) */
                v2_ep_t *ep = &eps[e];
                int w = 0;
                for (int i = 0; i < ep->send_len; i++)
                { /* bound: V2_IPC_Q */
                    int idx = (ep->send_head + i) % V2_IPC_Q;
                    unsigned long s = ep->sendq[idx].sender;
                    if (s < (unsigned long)NTHREADS && qube_of[s] == (uint8_t)label)
                        continue; /* drop: sender dies below */
                    if (w != i)
                    {
                        int dst = (ep->send_head + w) % V2_IPC_Q;
                        ep->sendq[dst] = ep->sendq[idx];
                    }
                    w++;
                }
                ep->send_len = w;
                w = 0;
                for (int i = 0; i < ep->recv_len; i++)
                { /* bound: V2_IPC_Q */
                    int idx = (ep->recv_head + i) % V2_IPC_Q;
                    unsigned long tid = ep->recvq[idx];
                    if (tid < (unsigned long)NTHREADS && qube_of[tid] == (uint8_t)label)
                        continue; /* drop: waiter dies below */
                    if (w != i)
                    {
                        int dst = (ep->recv_head + w) % V2_IPC_Q;
                        ep->recvq[dst] = ep->recvq[idx];
                    }
                    w++;
                }
                ep->recv_len = w;
            }
        }
        /* Tear down each dying thread via frame_teardown_owned:
         * SHARED frames (COW sibling in a live qube) lose only the
         * dead side — the old code called v2_revoke per slot,
         * which is system-wide and destroyed live siblings'
         * mappings before the live-check could see them (then freed
         * under their stale PTEs). UNSHARED frames are fully
         * revoked + scrubbed + freed (no QCREATE/QDESTROY pool
         * leak). Dead co-owners resolve by processing order. */
        for (int t = 0; t < NTHREADS; t++)
        { /* bound: NTHREADS */
            unsigned long dying_frames[V2_VPN_SLOTS + V2_CAP_SLOTS];
            int dying_n = 0;
            int s;
            if (qube_of[t] != (uint8_t)label)
                continue;
            /* Snapshot every frame this thread names (mappings +
             * caps; teardown is idempotent so no dedupe needed). */
            for (int i = 0; i < V2_VPN_SLOTS; i++)
            { /* bound: V2_VPN_SLOTS */
                if (caps.vm[t][i].valid)
                    dying_frames[dying_n++] = caps.vm[t][i].frame;
            }
            for (s = 0; s < V2_CAP_SLOTS; s++)
            { /* bound: V2_CAP_SLOTS */
                if (caps.caps[t][s].valid && !caps.caps[t][s].root)
                    dying_frames[dying_n++] = caps.caps[t][s].obj;
            }
            for (int i = 0; i < dying_n; i++)
                frame_teardown_owned((unsigned long)t, dying_frames[i]);
            for (int vpn = 0; vpn < V2_VPN_SLOTS; vpn++) /* bound: V2_VPN_SLOTS */
                v2_pte_clear((unsigned long)t, (unsigned long)vpn);
            threads[t].state = T_DEAD;
            threads[t].wait_kind = V2_WK_NONE;
            threads[t].ipc_ptr = 0;
            threads[t].ipc_cap = 0;
            threads[t].notify = 0;
            qube_of[t] = 0;
        }
        v2_sfence_all();
        kputs("QUB: qube");
        kputdec(label);
        kputs(" dead\n");
        rc = V2_OK;
        break;
    }
    default:
        rc = V2_ERR_INVALID;
        break;
    }
    return rc;
}
