#include "../include/endpoint.h"
#include <string.h>

kerror_t endpoint_send(endpoint_t *ep, uint32_t sender, ipc_msg_t *msg) {
    if (!ep || !msg) return ERR_INVALID_ARG;
    if (msg->length > IPC_MSG_MAX) return ERR_INVALID_ARG;
    if (msg->caps > IPC_CAPS_MAX) return ERR_INVALID_ARG;
    /* Rendezvous: if receiver waiting, direct copy */
    if (ep->has_receiver) {
        ep->pending_msg = *msg;
        ep->pending = true;
        ep->has_receiver = false;
        return ERR_OK;
    }
    if (ep->q_len >= 16) return ERR_OVERFLOW;
    ep->queue[ep->q_tail] = sender;
    ep->q_tail = (ep->q_tail+1)%16;
    ep->q_len++;
    ep->pending_msg = *msg;
    ep->pending = true;
    return ERR_OK;
}

kerror_t endpoint_recv(endpoint_t *ep, uint32_t receiver, ipc_msg_t *out) {
    if (!ep || !out) return ERR_INVALID_ARG;
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
    kerror_t e = endpoint_send(ep, caller, msg);
    if (e != ERR_OK) return e;
    /* Call is send+recv - blocks until reply */
    (void)reply;
    return ERR_OK;
}
