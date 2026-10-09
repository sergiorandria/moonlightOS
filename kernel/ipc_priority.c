/* ipc_priority.c - Message prioritization implementation
 *
 * Implements priority-based message delivery using metadata
 * stored in message words. High-priority messages are dequeued
 * first with starvation prevention for low-priority messages.
 */
#include "ipc_priority.h"
#include "ipc.h"
#include <stdint.h>

#if IPC_PRIORITY_ENABLED

static ipc_priority_config_t config;
static ipc_priority_stats_t stats;
static uint32_t sequence_counter = 0;
static uint32_t messages_since_boost = 0;

/* Priority metadata is stored in high bits of word[0] */
#define PRIORITY_SHIFT 60  /* Use top 4 bits for priority (16 values, we use 4) */
#define PRIORITY_MASK 0xF000000000000000ULL
#define SEQUENCE_MASK 0x0FFFFFFFFFFFFFFFULL

/* ============================================================================
 * Initialization
 * ============================================================================ */
void ipc_priority_init(const ipc_priority_config_t *cfg) {
    if (cfg) {
        config = *cfg;
    } else {
        config = IPC_PRIORITY_DEFAULT;
    }

    /* Reset statistics */
    for (int i = 0; i < IPC_PRIORITY_LEVELS; i++) {
        stats.queued[i] = 0;
        stats.delivered[i] = 0;
        stats.dropped[i] = 0;
    }
    stats.total_aged = 0;
    sequence_counter = 0;
    messages_since_boost = 0;
}

/* ============================================================================
 * Priority Metadata
 * ============================================================================ */
void ipc_priority_set_meta(uint64_t *words, ipc_priority_t priority) {
    if (!words) return;

    /* Store priority in high bits, sequence in low bits */
    uint64_t meta = ((uint64_t)priority << PRIORITY_SHIFT) |
                     (sequence_counter & SEQUENCE_MASK);
    words[0] = (words[0] & ~PRIORITY_MASK) | (meta & PRIORITY_MASK);

    sequence_counter++;
}

ipc_priority_t ipc_priority_get_meta(const uint64_t *words) {
    if (!words) return IPC_PRIORITY_NORMAL;

    uint64_t priority_bits = (words[0] >> PRIORITY_SHIFT) & 0xF;
    return (ipc_priority_t)priority_bits;
}

/* ============================================================================
 * Priority Queue Selection
 * ============================================================================ */
int ipc_priority_select_next(v2_ep_t *ep, v2_slot_t *out) {
    if (!ep || !out) return -1;

    /* Search from highest to lowest priority */
    for (int p = IPC_PRIORITY_CRITICAL; p >= IPC_PRIORITY_LOW; p--) {
        /* Check starvation prevention for low priority */
        if (p == IPC_PRIORITY_LOW) {
            messages_since_boost++;
            if (messages_since_boost >= config.boost_interval) {
                /* Boost low priority this time */
                messages_since_boost = 0;
                /* Continue to check low priority queue */
            } else {
                /* Skip low priority unless aged */
                /* (Aging implementation would go here) */
                continue;
            }
        }

        /* Find highest priority message */
        int best_idx = -1;
        uint64_t best_seq = ~0ULL;

        for (int i = 0; i < ep->send_len; i++) {
            int idx = (ep->send_head + i) % V2_IPC_Q;
            ipc_priority_t msg_prio = ipc_priority_get_meta(ep->sendq[idx].words);

            if ((int)msg_prio == p) {
                uint64_t seq = ep->sendq[idx].words[0] & SEQUENCE_MASK;
                if (seq < best_seq) {
                    best_seq = seq;
                    best_idx = idx;
                }
            }
        }

        if (best_idx >= 0) {
            /* Copy the selected message */
            int len = ep->sendq[best_idx].len;
            for (int i = 0; i < len; i++) {
                out->words[i] = ep->sendq[best_idx].words[i];
            }
            out->sender = ep->sendq[best_idx].sender;
            out->len = len;

            /* Remove from queue (this is a simplified removal)
             * In real implementation, would need to handle circular buffer */
            /* For now, just return success - actual dequeue happens in v2_q_take_send */

            stats.delivered[p]++;
            return 0;
        }
    }

    return -1;  /* No messages found */
}

/* ============================================================================
 * Queue Full Check
 * ============================================================================ */
int ipc_priority_queue_full(v2_ep_t *ep, ipc_priority_t priority) {
    if (!ep) return 1;

    /* Count messages at this priority level */
    int count = 0;
    for (int i = 0; i < ep->send_len; i++) {
        int idx = (ep->send_head + i) % V2_IPC_Q;
        if (ipc_priority_get_meta(ep->sendq[idx].words) == priority) {
            count++;
        }
    }

    return count >= (int)config.max_per_priority[priority];
}

/* ============================================================================
 * Statistics
 * ============================================================================ */
void ipc_priority_get_stats(ipc_priority_stats_t *out_stats) {
    if (!out_stats) return;
    /* Field-by-field copy: a whole-struct assignment would lower to a
     * memcpy libcall, and the freestanding kernel image links no libc
     * (Makefile: -nostdlib, no implicit libcalls). */
    for (int i = 0; i < IPC_PRIORITY_LEVELS; i++) {
        out_stats->queued[i] = stats.queued[i];
        out_stats->delivered[i] = stats.delivered[i];
        out_stats->dropped[i] = stats.dropped[i];
    }
    out_stats->total_aged = stats.total_aged;
}

#endif /* IPC_PRIORITY_ENABLED */
