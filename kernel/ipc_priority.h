/* ipc_priority.h - Message prioritization for IPC
 *
 * Provides priority-based message delivery:
 * - Priority levels (CRITICAL, HIGH, NORMAL, LOW)
 * - Priority queue (high-priority messages delivered first)
 * - Starvation prevention (fairness for low-priority)
 *
 * Priority levels ensure critical system messages (alerts, shutdowns)
 * are delivered ahead of normal traffic without complex changes
 * to the core IPC mechanism.
 */
#ifndef IPC_PRIORITY_H
#define IPC_PRIORITY_H

#include <stdint.h>

/* v2_ep_t / v2_slot_t are the core IPC queue ABI (kernel/ipc.h). This
 * module is a policy layer over those queues, so it depends on that
 * header rather than redeclaring the types (seL4 src/object precedent:
 * a policy file includes the object header it operates on). */
#include "ipc.h"

/* Compile-time enable/disable for priority */
#define IPC_PRIORITY_ENABLED 1

/* Priority levels */
typedef enum
{
    IPC_PRIORITY_LOW = 0,     /* Background, logging */
    IPC_PRIORITY_NORMAL = 1,  /* Normal traffic */
    IPC_PRIORITY_HIGH = 2,    /* Important but not critical */
    IPC_PRIORITY_CRITICAL = 3 /* Alerts, shutdowns, security events */
} ipc_priority_t;

/* Number of priority levels */
#define IPC_PRIORITY_LEVELS 4

/* Priority queue configuration */
typedef struct
{
    /* Per-priority queue limits */
    uint32_t max_per_priority[IPC_PRIORITY_LEVELS];
    uint32_t total_capacity;

    /* Starvation prevention */
    uint32_t aging_threshold; /* Messages age after this count */
    uint32_t boost_interval;  /* Boost low-priority every N messages */
} ipc_priority_config_t;

/* Default configuration */
#define IPC_PRIORITY_DEFAULT                                                                       \
    (ipc_priority_config_t){                                                                       \
        .max_per_priority = {8, 16, 6, 2}, /* 32 total: 8 low, 16 normal, 6 high, 2 critical */    \
        .total_capacity = 32,                                                                      \
        .aging_threshold = 50,                                                                     \
        .boost_interval = 10}

/* Priority message metadata */
typedef struct
{
    ipc_priority_t priority;
    uint32_t age;      /* Age counter for starvation prevention */
    uint32_t sequence; /* Sequence for FIFO within priority */
} ipc_priority_meta_t;

/* ============================================================================
 * Priority Queue API
 * ============================================================================ */

#if IPC_PRIORITY_ENABLED

/* Initialize priority queue */
void ipc_priority_init(const ipc_priority_config_t *config);

/* Set message priority (called before SEND) */
void ipc_priority_set_meta(uint64_t *words, ipc_priority_t priority);

/* Get message priority (called during dequeue) */
ipc_priority_t ipc_priority_get_meta(const uint64_t *words);

/* Select next message from priority queue */
int ipc_priority_select_next(v2_ep_t *ep, v2_slot_t *out);

/* Check if priority queue is full for a given priority */
int ipc_priority_queue_full(v2_ep_t *ep, ipc_priority_t priority);

/* Get priority statistics */
typedef struct
{
    uint32_t queued[IPC_PRIORITY_LEVELS];
    uint32_t delivered[IPC_PRIORITY_LEVELS];
    uint32_t dropped[IPC_PRIORITY_LEVELS];
    uint32_t total_aged; /* Messages boosted due to aging */
} ipc_priority_stats_t;

void ipc_priority_get_stats(ipc_priority_stats_t *stats);

#else /* IPC_PRIORITY_ENABLED */

/* No-op stubs when disabled */
static inline void ipc_priority_init(const ipc_priority_config_t *config)
{
}
static inline void ipc_priority_set_meta(uint64_t *words, ipc_priority_t priority)
{
}
static inline ipc_priority_t ipc_priority_get_meta(const uint64_t *words)
{
    return IPC_PRIORITY_NORMAL;
}
static inline int ipc_priority_select_next(v2_ep_t *ep, v2_slot_t *out)
{
    return -1;
}
static inline int ipc_priority_queue_full(v2_ep_t *ep, ipc_priority_t priority)
{
    return 0;
}
static inline void ipc_priority_get_stats(ipc_priority_stats_t *stats)
{
}

#endif /* IPC_PRIORITY_ENABLED */

/* ============================================================================
 * Priority Guidelines
 * ============================================================================ */

/*
 * Priority Usage Guidelines:
 *
 * CRITICAL (3):
 * - Security alerts (intrusion detection, compromise)
 * - System shutdown/reboot commands
 * - Critical hardware events (thermal shutdown, power failure)
 * - Deadlock recovery notifications
 *
 * HIGH (2):
 * - User input (keyboard, mouse for GUI)
 * - Real-time data (network packets for firewall)
 * - Timer callbacks for time-sensitive operations
 * - Resource exhaustion warnings
 *
 * NORMAL (1):
 * - Regular application messages
 * - File I/O operations
 * - Log messages
 * - Configuration changes
 *
 * LOW (0):
 * - Background telemetry
 * - Statistics collection
 * - Non-critical diagnostics
 * - Performance monitoring
 *
 * Starvation Prevention:
 * - Low-priority messages age over time
 * - After aging_threshold, priority is boosted
 * - Every boost_interval messages, low-priority gets chance
 * - Ensures no priority level is completely starved
 */

#endif /* IPC_PRIORITY_H */
