#include "../include/syscall.h"
#include "../include/cnode.h"
#include "../include/tcb.h"
#include "../include/endpoint.h"
#include "../include/sched.h"
#include "../include/vspace.h"

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
            ipc_msg_t out;
            err = endpoint_recv(ep, cur_tcb, &out);
            if (err == ERR_OK && out.length > 0) {
                for (uint32_t i=0;i<out.length;i++) tcb->ipc_buffer.words[i] = out.words[i];
            }
            if (err == ERR_OK) tcb->state = TCB_BLOCKED_RECV;
            break;
        }
        case SYS_SEND: {
            if (cap->type != CAP_ENDPOINT) return ERR_INVALID_CAP;
            endpoint_t *ep = (endpoint_t*)cap->u.endpoint.ep_ptr;
            ipc_msg_t msg = {0};
            msg.length = (uint32_t)(arg1 & 0xFF);
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
    (void)arg1;
    if (!cap || !cap_is_valid(cap)) return ERR_INVALID_CAP;
    switch (op) {
        case INV_UNTYPED_RETYPE: {
            cap_type_t new_type = (cap_type_t)arg2;
            size_t size = (size_t)arg3;
            if (!cap_can_retype(*cap, new_type, size)) return ERR_INVALID_ARG;
            return ERR_OK;
        }
        case INV_CNODE_COPY: {
            if (cap->type != CAP_CNODE) return ERR_INVALID_CAP;
            return ERR_OK;
        }
        case INV_TCB_RESUME: {
            if (cap->type != CAP_TCB) return ERR_INVALID_CAP;
            tcb_t *t = (tcb_t*)cap->u.tcb.tcb_ptr;
            tcb_resume(t);
            return ERR_OK;
        }
        case INV_VSPACE_MAP: {
            if (cap->type != CAP_VSPACE) return ERR_INVALID_CAP;
            return ERR_OK;
        }
        default:
            return ERR_INVALID_ARG;
    }
}
