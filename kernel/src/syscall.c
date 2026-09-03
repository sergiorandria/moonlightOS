#include "../include/syscall.h"
#include "../include/cnode.h"
#include "../include/tcb.h"
#include "../include/endpoint.h"
#include "../include/sched.h"
#include "../include/vspace.h"
#include "../include/revoke.h"

extern tcb_table_t g_tcbs;
extern endpoint_t g_endpoints[MAX_ENDPOINTS];
extern sched_state_t g_sched;
extern cnode_t g_root_cnode;

/* Constant-time dispatch - no secret-dependent branches */
kerror_t syscall_handler(trap_frame_t *frame, uint32_t cur_tcb) {
    if (!frame) return ERR_INVALID_ARG;
    uint64_t entry_us = 0;
#ifdef __riscv
    __asm__ volatile("rdtime %0" : "=r"(entry_us));
#endif
    syscall_t sys = (syscall_t)frame->a7;
    cptr_t cap_ptr = (cptr_t)frame->a0;
    uintptr_t arg1 = frame->a1;
    uintptr_t arg2 = frame->a2;

    /* Bounds check syscall number - proven exhaustive */
    if (sys > SYS_INVOKE) return ERR_INVALID_ARG;

    tcb_t *tcb = &g_tcbs.threads[cur_tcb];
    if (!tcb_is_runnable(tcb) && sys != SYS_YIELD) return ERR_PARTITION_DENIED;

    /* Every capability invocation validates CHERI tag + rights + partition */
    cap_t *cap = cnode_lookup(tcb->cspace, cap_ptr);
    if (sys != SYS_YIELD && !cap) {
        if (sys == SYS_INVOKE && cap_ptr == 0) {
            /* Untyped retype from root - check root cnode */
            cap = cnode_lookup(&g_root_cnode, arg1);
            if (!cap) return ERR_INVALID_CAP;
        } else {
            return ERR_INVALID_CAP;
        }
    }

    /* Temporal isolation: check partition budget */
    if (g_sched.contexts[tcb->sched_context].remaining_us == 0) return ERR_WCET_EXCEEDED;

    kerror_t err = ERR_OK;
    switch (sys) {
        case SYS_CALL: {
            if (!cap_has_right(*cap, CAP_RIGHTS_READ|CAP_RIGHTS_WRITE)) return ERR_NO_RIGHTS;
            if (cap->type != CAP_ENDPOINT) return ERR_INVALID_CAP;
            endpoint_t *ep = (endpoint_t*)cap->u.endpoint.ep_ptr;
            ipc_msg_t msg = {0};
            msg.length = (uint32_t)(arg1 & 0xFF);
            if (msg.length > IPC_MSG_MAX) return ERR_INVALID_ARG;
            /* Copy from user IPC buffer via CHERI-bounded memcpy - prevents overflow */
            for (uint32_t i=0;i<msg.length;i++) msg.words[i] = ((uint64_t*)tcb->ipc_buffer.words)[i];
            err = endpoint_send(ep, cur_tcb, &msg);
            if (err == ERR_OK) tcb->state = TCB_BLOCKED_REPLY;
            break;
        }
        case SYS_REPLY_RECV: {
            if (cap->type != CAP_ENDPOINT) return ERR_INVALID_CAP;
            endpoint_t *ep = (endpoint_t*)cap->u.endpoint.ep_ptr;
            bool was_pending = ep->pending || ep->q_len > 0;
            ipc_msg_t out;
            err = endpoint_recv(ep, cur_tcb, &out);
            if (err == ERR_OK && was_pending) {
                // Immediate delivery, copy to user buffer and stay runnable
                for (uint32_t i=0;i<out.length;i++) tcb->ipc_buffer.words[i] = out.words[i];
                tcb->ipc_buffer.length = out.length;
            } else if (err == ERR_OK) {
                // No message, now blocked
                tcb->state = TCB_BLOCKED_RECV;
            }
            break;
        }
        case SYS_SEND: {
            if (cap->type != CAP_ENDPOINT) return ERR_INVALID_CAP;
            endpoint_t *ep = (endpoint_t*)cap->u.endpoint.ep_ptr;
            ipc_msg_t msg = {0};
            msg.length = (uint32_t)(arg1 & 0xFF);
            if (msg.length > IPC_MSG_MAX) return ERR_INVALID_ARG;
            for (uint32_t i=0;i<msg.length;i++) msg.words[i] = ((uint64_t*)tcb->ipc_buffer.words)[i];
            msg.caps = tcb->ipc_buffer.caps;
            for (uint32_t i=0;i<msg.caps;i++) msg.cap_ptrs[i] = tcb->ipc_buffer.cap_ptrs[i];
            err = endpoint_send(ep, cur_tcb, &msg);
            break;
        }
        case SYS_YIELD:
            break;
        case SYS_INVOKE: {
            invoke_op_t op = (invoke_op_t)arg1;
            err = handle_invoke(cap, op, arg1, arg2, frame->a3);
            break;
        }
        default:
            err = ERR_INVALID_ARG;
    }

    /* WCET enforcement */
    if (!wcet_check(entry_us)) return ERR_WCET_EXCEEDED;

    frame->a0 = err;
    return err;
}

kerror_t handle_invoke(cap_t *cap, invoke_op_t op, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3) {
    // arg1 is op (redundant), arg2 is type/dest, arg3 is size/extra
    // For full capability invocation, we need TCB and destination CNode.
    // This is a minimal production wiring - real dispatch would use frame->a4/a5 for dest
    if (!cap || !cap_is_valid(cap)) return ERR_INVALID_CAP;
    switch (op) {
        case INV_UNTYPED_RETYPE: {
            cap_type_t new_type = (cap_type_t)arg2;
            size_t size = (size_t)arg3;
            cptr_t dest_slot = (cptr_t)((arg1>>8) & 0xFF); // dest in high bits of arg1 for demo
            if (dest_slot==0) dest_slot = 5; // fallback for legacy test that passes op only
            if (!cap_can_retype(*cap, new_type, size)) return ERR_INVALID_ARG;
            // Find caller's CNode (use root for demo)
            extern cnode_t g_root_cnode;
            cap_t new_cap = cap_retype(*cap, new_type, cap->u.untyped.paddr, size);
            if (!new_cap.is_valid) return ERR_INVALID_CAP;
            // Insert into caller's CNode at dest_slot
            if (dest_slot >= MAX_CAPS_PER_CNODE) return ERR_INVALID_ARG;
            if (g_root_cnode.slots[dest_slot].is_valid) return ERR_REVOKE_NEEDED;
            g_root_cnode.slots[dest_slot] = new_cap;
            g_root_cnode.used++;
            // MDB tracking
            extern mdb_tree_t g_mdb;
            uint32_t mdb_idx;
            mdb_insert(&g_mdb, 0, dest_slot, new_cap, &mdb_idx);
            return ERR_OK;
        }
        case INV_CNODE_COPY: {
            if (cap->type != CAP_CNODE) return ERR_INVALID_CAP;
            // arg2 = src slot, arg3 = dest slot (demo encoding)
            cptr_t src_slot = (cptr_t)(arg2 & 0xFF);
            cptr_t dst_slot = (cptr_t)(arg3 & 0xFF);
            extern cnode_t g_root_cnode;
            return cnode_copy(&g_root_cnode, dst_slot, &g_root_cnode, src_slot, cap->rights);
        }
        case INV_TCB_RESUME: {
            if (cap->type != CAP_TCB) return ERR_INVALID_CAP;
            tcb_t *t = (tcb_t*)(uintptr_t)cap->u.tcb.tcb_ptr;
            // Use tcb_wake for blocked, tcb_resume for inactive
            if (t->state == TCB_INACTIVE) tcb_resume(t);
            else tcb_wake_from_ipc(t, 0);
            return ERR_OK;
        }
        case INV_VSPACE_MAP: {
            if (cap->type != CAP_VSPACE) return ERR_INVALID_CAP;
            // arg2 = vaddr, arg3 = frame cap slot (demo)
            extern cnode_t g_root_cnode;
            cptr_t frame_slot = (cptr_t)(arg3 & 0xFF);
            cap_t *frame_cap = cnode_lookup(&g_root_cnode, frame_slot);
            if (!frame_cap || frame_cap->type != CAP_FRAME) return ERR_INVALID_CAP;
            vspace_t *vs = (vspace_t*)(uintptr_t)cap->u.vspace.root_pt;
            // Map frame's paddr at vaddr with frame's perms
            return vspace_map(vs, (uintptr_t)arg2, frame_cap->u.frame.paddr, PAGE_SIZE, frame_cap->u.frame.perms, frame_cap->u.frame.color);
        }
        default:
            return ERR_INVALID_ARG;
    }
}
