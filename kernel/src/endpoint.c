#include "../include/endpoint.h"
#include "../include/tcb.h"
#include "../include/cheri.h"
#include <string.h>

extern tcb_table_t g_tcbs;

kerror_t endpoint_send(endpoint_t *ep, uint32_t sender, ipc_msg_t *msg) {
    if (!ep || !msg) return ERR_INVALID_ARG;
    if (msg->length > IPC_MSG_MAX) return ERR_INVALID_ARG;
    if (msg->caps > IPC_CAPS_MAX) return ERR_INVALID_ARG;

    // Rendezvous: direct copy if receiver waiting, wake it
    if (ep->has_receiver) {
        ep->pending_msg = *msg;
        ep->pending = true;
        uint32_t recvr = ep->receiver_tcb;
        ep->has_receiver = false;
        // Wake blocked receiver
        if (recvr < MAX_TCBS) {
            tcb_t *rtcb = &g_tcbs.threads[recvr];
            tcb_wake_from_ipc(rtcb, sender);
        }
        return ERR_OK;
    }
    if (ep->q_len >= 16) return ERR_OVERFLOW;
    ep->queue[ep->q_tail] = sender;
    ep->queue_msgs[ep->q_tail] = *msg;
    ep->q_tail = (ep->q_tail+1)%16;
    ep->q_len++;
    ep->pending_msg = *msg;
    ep->pending = true;
    return ERR_OK;
}

kerror_t endpoint_recv(endpoint_t *ep, uint32_t receiver, ipc_msg_t *out) {
    if (!ep || !out) return ERR_INVALID_ARG;
    if (ep->q_len > 0) {
        *out = ep->queue_msgs[ep->q_head];
        uint32_t sender = ep->queue[ep->q_head];
        ep->q_head = (ep->q_head+1)%16;
        ep->q_len--;
        if (ep->q_len == 0) ep->pending = false;
        else ep->pending_msg = ep->queue_msgs[ep->q_head];
        // Wake queued sender if it was blocked
        if (sender < MAX_TCBS) {
            tcb_t *stcb = &g_tcbs.threads[sender];
            if (stcb->state == TCB_BLOCKED_SEND) tcb_resume(stcb);
        }
        return ERR_OK;
    }
    if (ep->pending) {
        *out = ep->pending_msg;
        ep->pending = false;
        ep->has_receiver = false;
        return ERR_OK;
    }
    ep->has_receiver = true;
    ep->receiver_tcb = receiver;
    return ERR_OK;
}

kerror_t endpoint_call(endpoint_t *ep, uint32_t caller, ipc_msg_t *msg, ipc_msg_t *reply) {
    if (!ep || !msg || !reply) return ERR_INVALID_ARG;
    // Production: endpoint_call is deprecated, use SYS_CALL which does proper block/wake
    // For compatibility, just forward to send and let caller handle reply blocking
    return endpoint_send(ep, caller, msg);
}
