/* ipc_monitor.h - IPC monitoring and observability hooks
 *
 * Provides production-grade monitoring for the IPC subsystem:
 * - Queue depth tracking per endpoint
 * - Message rate counters (sent/received/dropped)
 * - Error rate tracking
 * - Latency percentiles
 * - Flow control event logging
 *
 * These hooks are designed to be low-overhead and can be
 * enabled/disabled at compile time for production use.
 */
#ifndef IPC_MONITOR_H
#define IPC_MONITOR_H

#include <stdint.h>

/* Compile-time enable/disable for monitoring overhead */
#define IPC_MONITOR_ENABLED 1

/* Maximum number of monitored endpoints */
#define IPC_MONITOR_MAX_EPS V2_NEP

/* Per-endpoint statistics */
typedef struct {
    /* Queue depth tracking */
    uint32_t current_depth;        /* Current queue depth */
    uint32_t max_depth;            /* Maximum observed depth */
    uint32_t depth_samples;        /* Number of depth samples taken */

    /* Message counters */
    uint64_t messages_sent;        /* Total messages sent to this EP */
    uint64_t messages_received;    /* Total messages received from this EP */
    uint64_t messages_dropped;     /* Messages dropped (overflow) */

    /* Error counters */
    uint64_t errors_invalid_ep;    /* Invalid endpoint errors */
    uint64_t errors_invalid_range; /* Invalid address range errors */
    uint64_t errors_overflow;      /* Queue overflow errors */
    uint64_t errors_truncation;    /* Message truncation events */

    /* Flow control events */
    uint64_t flow_control_trigger; /* Times flow control triggered */
    uint64_t flow_control_clear;   /* Times flow control cleared */

    /* Latency tracking (in microseconds) */
    uint64_t latency_sum;          /* Sum of latencies */
    uint64_t latency_count;        /* Number of latency samples */
    uint64_t latency_min;          /* Minimum latency */
    uint64_t latency_max;          /* Maximum latency */

    /* Waiter tracking */
    uint32_t waiters_queued;       /* Current waiters in queue */
    uint32_t max_waiters;          /* Maximum waiters observed */
} ipc_ep_stats_t;

/* Global IPC statistics */
typedef struct {
    uint64_t total_syscalls;       /* Total IPC syscalls */
    uint64_t syscalls_send;        /* SEND syscalls */
    uint64_t syscalls_recv;        /* RECV syscalls */
    uint64_t syscalls_notify;      /* NOTIFY syscalls */
    uint64_t syscalls_wait;        /* WAIT syscalls */

    uint64_t direct_deliveries;    /* Messages delivered directly (bypass queue) */
    uint64_t queued_deliveries;    /* Messages delivered via queue */

    uint64_t blocking_waits;       /* Number of blocking WAIT calls */
    uint64_t nonblocking_waits;    /* Number of non-blocking WAIT calls */
} ipc_global_stats_t;

/* ============================================================================
 * Monitoring API
 * ============================================================================ */

#if IPC_MONITOR_ENABLED

/* Initialize monitoring structures */
void ipc_monitor_init(void);

/* Update queue depth for an endpoint */
void ipc_monitor_queue_depth(int ep, int depth);

/* Record a message sent to an endpoint */
void ipc_monitor_message_sent(int ep);

/* Record a message received from an endpoint */
void ipc_monitor_message_received(int ep);

/* Record a message dropped (overflow) */
void ipc_monitor_message_dropped(int ep);

/* Record an error */
void ipc_monitor_error(int ep, int error_type);

/* Record flow control trigger */
void ipc_monitor_flow_control_trigger(int ep);

/* Record flow control clear */
void ipc_monitor_flow_control_clear(int ep);

/* Record latency sample (in microseconds) */
void ipc_monitor_latency_sample(int ep, uint64_t latency_us);

/* Record waiter queued */
void ipc_monitor_waiter_queued(int ep);

/* Record waiter dequeued */
void ipc_monitor_waiter_dequeued(int ep);

/* Record direct delivery */
void ipc_monitor_direct_delivery(void);

/* Record queued delivery */
void ipc_monitor_queued_delivery(void);

/* Record syscall type */
void ipc_monitor_syscall(int syscall_type);

/* Get statistics for an endpoint */
const ipc_ep_stats_t *ipc_monitor_get_ep_stats(int ep);

/* Get global statistics */
const ipc_global_stats_t *ipc_monitor_get_global_stats(void);

/* Print statistics summary */
void ipc_monitor_print_summary(void);

/* Reset statistics (for testing) */
void ipc_monitor_reset(void);

#else /* IPC_MONITOR_ENABLED */

/* No-op stubs when monitoring disabled */
static inline void ipc_monitor_init(void) {}
static inline void ipc_monitor_queue_depth(int ep, int depth) {}
static inline void ipc_monitor_message_sent(int ep) {}
static inline void ipc_monitor_message_received(int ep) {}
static inline void ipc_monitor_message_dropped(int ep) {}
static inline void ipc_monitor_error(int ep, int error_type) {}
static inline void ipc_monitor_flow_control_trigger(int ep) {}
static inline void ipc_monitor_flow_control_clear(int ep) {}
static inline void ipc_monitor_latency_sample(int ep, uint64_t latency_us) {}
static inline void ipc_monitor_waiter_queued(int ep) {}
static inline void ipc_monitor_waiter_dequeued(int ep) {}
static inline void ipc_monitor_direct_delivery(void) {}
static inline void ipc_monitor_queued_delivery(void) {}
static inline void ipc_monitor_syscall(int syscall_type) {}
static inline const ipc_ep_stats_t *ipc_monitor_get_ep_stats(int ep) { return NULL; }
static inline const ipc_global_stats_t *ipc_monitor_get_global_stats(void) { return NULL; }
static inline void ipc_monitor_print_summary(void) {}
static inline void ipc_monitor_reset(void) {}

#endif /* IPC_MONITOR_ENABLED */

/* Error type constants */
#define IPC_ERROR_INVALID_EP 1
#define IPC_ERROR_INVALID_RANGE 2
#define IPC_ERROR_OVERFLOW 3
#define IPC_ERROR_TRUNCATION 4

/* Syscall type constants */
#define IPC_SYSCALL_SEND 1
#define IPC_SYSCALL_RECV 2
#define IPC_SYSCALL_NOTIFY 3
#define IPC_SYSCALL_WAIT 4

#endif /* IPC_MONITOR_H */
