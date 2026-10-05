/* syscall_cap.c - capability rights/topology INVOKE ops: MINT/GRANT/MAP/UNMAP/REVOKE/PT_ALLOC.
 *
 * Split out of syscall.c (SOLID Sprint 1b, production-ready): one file per
 * INVOKE operation class, mirroring seL4's src/object organization.
 * Operation classes are disjoint; syscall.c dispatches via handles(). */
#include <stdint.h>

#include "caps.h"
#include "kinternal.h"
int syscall_cap_handles(uint64_t op)
{
    switch (op)
    {
    case V2_INV_MINT:
        return 1;
    case V2_INV_GRANT:
        return 1;
    case V2_INV_MAP:
        return 1;
    case V2_INV_UNMAP:
        return 1;
    case V2_INV_REVOKE:
        return 1;
    case V2_INV_PT_ALLOC:
        return 1;
    default:
        return 0;
    }
}

long syscall_cap_invoke(uint64_t op, uint64_t a1, uint64_t a2, uint64_t a3)
{
    long rc = V2_ERR_INVALID;
    (void)a1;
    (void)a2;
    (void)a3;
    switch (op)
    {
    case V2_INV_MINT:
        rc = v2_mint(&caps, (unsigned long)cur, a1, a2, a3);
        break;
    case V2_INV_GRANT:
        rc = v2_grant(&caps, (unsigned long)cur, a1, a2, a3);
        break;
    case V2_INV_MAP: {
        /* vpn must index a real l0_u_t[t][vpn] slot: guard before
         * the model call so rc stays V2_ERR_INVALID for vpn >=
         * V2_VPN_SLOTS (the model itself does not bound vpn). The
         * model call stays authoritative: on V2_OK the mapping is
         * recorded in caps.vm, then we install the real leaf PTE. */
        int m; /* bound: vpn < V2_VPN_SLOTS (checked below) */
        if (a2 < (uint64_t)V2_VPN_SLOTS)
            rc = v2_map(&caps, (unsigned long)cur, a1, a2);
        if (rc == V2_OK)
        {
            m = v2_vm_find(&caps, (unsigned long)cur, a2);
            if (m >= 0)
            { /* model recorded it: must be findable */
                v2_pte_install((unsigned long)cur, a2, caps.vm[cur][m].frame, caps.vm[cur][m].rights);
                v2_sfence_all();
            }
        }
        break;
    }
    case V2_INV_UNMAP:
        rc = v2_unmap(&caps, (unsigned long)cur, a1);
        if (rc == V2_OK)
        { /* model validated the mapping exists */
            v2_pte_clear((unsigned long)cur, a1);
            v2_sfence_all();
        }
        break;
    case V2_INV_REVOKE: {
        /* Revoke drops every mapping to the frame system-wide; the
         * model clears caps.vm but not hardware PTEs. Capture the
         * affected (t, vpn) pairs BEFORE the model destroys them,
         * clear them only if the model approves (fail closed). */
        unsigned long f = 0;
        unsigned long npair = 0;
        int have_f = 0;
        if (a1 < (uint64_t)V2_CAP_SLOTS && caps.caps[cur][a1].valid)
        {
            f = caps.caps[cur][a1].obj;
            have_f = 1;
        }
        if (have_f)
        {
            for (unsigned long u = 0; u < caps.nthreads; u++)
                /* bound: V2_CAP_THREADS */
                for (int i = 0; i < V2_VPN_SLOTS; i++)
                {
                    /* bound: V2_VPN_SLOTS */
                    if (caps.vm[u][i].valid && caps.vm[u][i].frame == f &&
                        npair < (unsigned long)(V2_CAP_THREADS * V2_VPN_SLOTS))
                    {
                        v2_revoke_pairs[npair].t = u;
                        v2_revoke_pairs[npair].vpn = caps.vm[u][i].vpn;
                        npair++;
                    }
                }
        }
        rc = v2_revoke(&caps, (unsigned long)cur, a1);
        if (rc == V2_OK)
        {
            for (unsigned long i = 0; i < npair; i++)
            {
                /* bound: V2_CAP_THREADS * V2_VPN_SLOTS */
                if (v2_revoke_pairs[i].t < (unsigned long)NTHREADS)
                    v2_pte_clear(v2_revoke_pairs[i].t, v2_revoke_pairs[i].vpn);
            }
            v2_sfence_all();
        }
        break;
    }
    case V2_INV_PT_ALLOC:
        rc = frame_alloc_slot(&caps, (unsigned long)cur);
        break;
    default:
        rc = V2_ERR_INVALID;
        break;
    }
    return rc;
}
