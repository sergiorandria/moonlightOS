#pragma once
#include "types.h"
#include "cap.h"

typedef struct endpoint {
    bool has_sender;
    bool has_receiver;
    uint32_t sender_tcb;
    uint32_t receiver_tcb;
    ipc_msg_t pending_msg;
    bool pending;
    uint32_t queue[16];
    ipc_msg_t queue_msgs[16]; // per-slot messages for FIFO
    uint8_t q_head, q_tail, q_len;
    uint64_t badge; // for demux
} endpoint_t;

#define MAX_ENDPOINTS 64
kerror_t endpoint_send(endpoint_t *ep, uint32_t sender, ipc_msg_t *msg);
kerror_t endpoint_recv(endpoint_t *ep, uint32_t receiver, ipc_msg_t *out);
kerror_t endpoint_call(endpoint_t *ep, uint32_t caller, ipc_msg_t *msg, ipc_msg_t *reply);
