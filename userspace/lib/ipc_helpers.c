/*
 * ipc_helpers.c - IPC helper function implementations
 *
 * Uses the V2 IPC ABI with moonlight_msg_t structures.
 * ALL messages are sent inline (≤ 4 words = 32 bytes).
 * The shared memory path at 0x80700000 is removed — the kernel never
 * mapped that region, so any access would page-fault.
 *
 * Callers must ensure all IPC structs fit in 32 bytes by using
 * TTY_BUF_SIZE = 16 and chunking larger transfers across multiple sends.
 */

#include "services/ipc_helpers.h"
#include "services/ipc_protocol.h"
#include "moonlight.h"
#include <stdint.h>

/* Simple memset implementation (freestanding) */
void *memset(void *s, int c, unsigned long n) {
    unsigned char *p = (unsigned char *)s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

/* Per-thread message ID counter for request-response matching */
static uint32_t ipc_msg_id_counter = 1;

/**
 * Send a message to a service and wait for response.
 * Uses moonlight_send + moonlight_recv under the hood.
 *
 * @param sender_tid  This thread's TID (receive endpoint)
 * @param target_tid  Target service TID
 * @param msg         Message to send (must be ≤ 32 bytes)
 * @param msg_size    Size of message
 * @param resp        Response buffer (NULL if no response needed)
 * @param resp_size   Size of response buffer
 * @return Bytes copied to resp, or negative on error
 */
int ipc_send_sync(uint32_t sender_tid, uint32_t target_tid, const void *msg, uint32_t msg_size,
                  void *resp, uint32_t resp_size) {
    moonlight_msg_t ipc_msg = {0};
    uint32_t req_msg_id;

    /* Generate message ID */
    req_msg_id = ipc_msg_id_counter++;
    if (ipc_msg_id_counter == 0) ipc_msg_id_counter = 1;

    /* Copy message struct to words (must fit in 32 bytes) */
    uint64_t msg_copy[4] = {0};
    const uint8_t *src_bytes = (const uint8_t *)msg;
    uint8_t *dst_bytes = (uint8_t *)msg_copy;
    uint32_t copy_len = msg_size > 32 ? 32 : msg_size;
    for (uint32_t i = 0; i < copy_len; i++) {
        dst_bytes[i] = src_bytes[i];
    }

    /* Inject msg_id at bytes 4-7 (after msg_type in every request struct) */
    msg_copy[0] = (msg_copy[0] & 0x00000000FFFFFFFFUL) | ((uint64_t)req_msg_id << 32);

    ipc_msg.label  = (uint32_t)(msg_copy[0] & 0xFFFFFFFFUL);
    ipc_msg.length = 4;  /* Always send 4 words */

    for (uint32_t i = 0; i < 4; i++) {
        ipc_msg.words[i] = msg_copy[i];
    }

    /* Send message */
    int send_ret = moonlight_send(target_tid, &ipc_msg);
    if (send_ret < 0) {
        return send_ret;
    }

    /* Wait for response if requested */
    if (resp && resp_size > 0) {
        moonlight_msg_t resp_msg = {0};

        /* Block until we get a message from the target */
        while (1) {
            int recv_ret = moonlight_recv(sender_tid, &resp_msg);
            if (recv_ret < 0) {
                return recv_ret;
            }

            /* Accept the first message from our target service */
            if (resp_msg.sender_tcb == target_tid) {
                break;
            }
            /* Discard spurious messages from other senders */
        }

        /* Copy inline response to caller's buffer */
        uint32_t resp_copy = 32;  /* 4 words */
        if (resp_copy > resp_size) resp_copy = resp_size;
        const uint8_t *resp_src = (const uint8_t *)resp_msg.words;
        uint8_t *resp_dst = (uint8_t *)resp;
        for (uint32_t i = 0; i < resp_copy; i++) {
            resp_dst[i] = resp_src[i];
        }
        return (int)resp_copy;
    }

    return 0;
}

/**
 * Send a message to a service without waiting for response (fire-and-forget).
 *
 * @param target_tid  Target service TID
 * @param msg         Message to send (must be ≤ 32 bytes)
 * @param msg_size    Size of message
 * @return 0 on success, negative on error
 */
int ipc_send_async(uint32_t target_tid, const void *msg, uint32_t msg_size) {
    moonlight_msg_t ipc_msg = {0};

    ipc_msg.label  = ((const ipc_message_t *)msg)->msg_type;
    ipc_msg.length = 4;  /* Always send 4 words */

    /* Copy message bytes to words */
    const uint8_t *src = (const uint8_t *)msg;
    uint8_t *dst = (uint8_t *)ipc_msg.words;
    uint32_t copy_len = msg_size > 32 ? 32 : msg_size;
    for (uint32_t i = 0; i < copy_len; i++) {
        dst[i] = src[i];
    }

    return moonlight_send(target_tid, &ipc_msg);
}

/**
 * Wait for incoming message from any service.
 *
 * @param my_tid     This thread's TID (receive endpoint)
 * @param msg        Buffer to receive message
 * @param msg_size   Size of receive buffer
 * @param sender     Output: sender's TID
 * @return Number of bytes received, or negative on error
 */
int ipc_recv(uint32_t my_tid, void *msg, uint32_t msg_size, uint32_t *sender) {
    moonlight_msg_t ipc_msg = {0};

    /* Receive on our own endpoint */
    int ret = moonlight_recv(my_tid, &ipc_msg);
    if (ret < 0) return ret;

    /* Fill sender TID */
    if (sender) *sender = ipc_msg.sender_tcb;

    /* Copy inline words to output buffer */
    uint32_t copy_size = 32;  /* 4 words */
    if (copy_size > msg_size) copy_size = msg_size;

    uint8_t *dst = (uint8_t *)msg;
    const uint8_t *src = (const uint8_t *)ipc_msg.words;
    for (uint32_t i = 0; i < copy_size; i++) {
        dst[i] = src[i];
    }

    return (int)copy_size;
}

/**
 * Reply to a received message (fire-and-forget).
 */
int ipc_reply(uint32_t target_tid, const void *resp, uint32_t resp_size) {
    return ipc_send_async(target_tid, resp, resp_size);
}

/**
 * Check flow control status (placeholder).
 */
uint32_t ipc_check_flow_control(uint32_t my_tid) {
    (void)my_tid;
    return 0;
}
