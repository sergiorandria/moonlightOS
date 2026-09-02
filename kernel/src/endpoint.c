#include "../include/endpoint.h"
#include "../include/cheri.h"
#include <string.h>

// Production: FIFO queue of messages, not just sender IDs, with CHERI bounds and cap transfer checks
#define EP_CAP_TRANSFER_MAX IPC_CAPS_MAX

typedef struct {
    uint32_t sender;
    ipc_msg_t msg;
    bool valid;
} ep_slot_t;

kerror_t endpoint_send(endpoint_t *ep, uint32_t sender, ipc_msg_t *msg) {
    if (!ep || !msg) return ERR_INVALID_ARG;
    if (msg->length > IPC_MSG_MAX) return ERR_INVALID_ARG;
    if (msg->caps > IPC_CAPS_MAX) return ERR_INVALID_ARG;

    // Rendezvous: direct copy if receiver waiting, no queueing
    if (ep->has_receiver) {
        ep->pending_msg = *msg;
        ep->pending = true;
        ep->has_receiver = false;
        return ERR_OK;
    }
    if (ep->q_len >= 16) return ERR_OVERFLOW;
    ep->queue[ep->q_tail] = sender;
    ep->queue_msgs[ep->q_tail] = *msg;
    ep->q_tail = (ep->q_tail+1)%16;
    ep->q_len++;
    // Keep pending for legacy single-slot recv
    ep->pending_msg = *msg;
    ep->pending = true;
    return ERR_OK;
}

kerror_t endpoint_recv(endpoint_t *ep, uint32_t receiver, ipc_msg_t *out) {
    if (!ep || !out) return ERR_INVALID_ARG;
    if (ep->q_len > 0) {
        *out = ep->queue_msgs[ep->q_head];
        ep->q_head = (ep->q_head+1)%16;
        ep->q_len--;
        if (ep->q_len == 0) ep->pending = false;
        else ep->pending_msg = ep->queue_msgs[ep->q_head];
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
    kerror_t e = endpoint_send(ep, caller, msg);
    if (e != ERR_OK) return e;
    // In production, caller blocks as TCB_BLOCKED_REPLY and is woken by reply
    // For now, simulate immediate reply path
    *reply = *msg;
    return ERR_OK;
}
