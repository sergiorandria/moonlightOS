/* ipc_monitor.c - IPC monitoring implementation
 *
 * Low-overhead monitoring hooks for production observability.
 * Statistics are kept in kernel memory and can be queried via
 * a monitoring syscall or debug interface.
 */
#include "ipc_monitor.h"
#include "ipc.h"
#include <stddef.h>
#include <stdint.h>

#if IPC_MONITOR_ENABLED

/* Per-endpoint statistics array */
static ipc_ep_stats_t ep_stats[IPC_MONITOR_MAX_EPS];

/* Global statistics */
static ipc_global_stats_t global_stats;

/* ============================================================================
 * Initialization
 * ============================================================================ */
void ipc_monitor_init(void) {
    for (int i = 0; i < IPC_MONITOR_MAX_EPS; i++) {
        ep_stats[i].current_depth = 0;
        ep_stats[i].max_depth = 0;
        ep_stats[i].depth_samples = 0;
        ep_stats[i].messages_sent = 0;
        ep_stats[i].messages_received = 0;
        ep_stats[i].messages_dropped = 0;
        ep_stats[i].errors_invalid_ep = 0;
        ep_stats[i].errors_invalid_range = 0;
        ep_stats[i].errors_overflow = 0;
        ep_stats[i].errors_truncation = 0;
        ep_stats[i].flow_control_trigger = 0;
        ep_stats[i].flow_control_clear = 0;
        ep_stats[i].latency_sum = 0;
        ep_stats[i].latency_count = 0;
        ep_stats[i].latency_min = ~0ULL;  /* Max uint64 */
        ep_stats[i].latency_max = 0;
        ep_stats[i].waiters_queued = 0;
        ep_stats[i].max_waiters = 0;
    }

    global_stats.total_syscalls = 0;
    global_stats.syscalls_send = 0;
    global_stats.syscalls_recv = 0;
    global_stats.syscalls_notify = 0;
    global_stats.syscalls_wait = 0;
    global_stats.direct_deliveries = 0;
    global_stats.queued_deliveries = 0;
    global_stats.blocking_waits = 0;
    global_stats.nonblocking_waits = 0;
}

/* ============================================================================
 * Queue Depth Tracking
 * ============================================================================ */
void ipc_monitor_queue_depth(int ep, int depth) {
    if (ep < 0 || ep >= IPC_MONITOR_MAX_EPS)
        return;

    ep_stats[ep].current_depth = (uint32_t)depth;

    if (depth > (int)ep_stats[ep].max_depth) {
        ep_stats[ep].max_depth = (uint32_t)depth;
    }

    ep_stats[ep].depth_samples++;
}

/* ============================================================================
 * Message Counters
 * ============================================================================ */
void ipc_monitor_message_sent(int ep) {
    if (ep < 0 || ep >= IPC_MONITOR_MAX_EPS)
        return;

    ep_stats[ep].messages_sent++;
}

void ipc_monitor_message_received(int ep) {
    if (ep < 0 || ep >= IPC_MONITOR_MAX_EPS)
        return;

    ep_stats[ep].messages_received++;
}

void ipc_monitor_message_dropped(int ep) {
    if (ep < 0 || ep >= IPC_MONITOR_MAX_EPS)
        return;

    ep_stats[ep].messages_dropped++;
}

/* ============================================================================
 * Error Tracking
 * ============================================================================ */
void ipc_monitor_error(int ep, int error_type) {
    if (ep < 0 || ep >= IPC_MONITOR_MAX_EPS)
        return;

    switch (error_type) {
        case IPC_ERROR_INVALID_EP:
            ep_stats[ep].errors_invalid_ep++;
            break;
        case IPC_ERROR_INVALID_RANGE:
            ep_stats[ep].errors_invalid_range++;
            break;
        case IPC_ERROR_OVERFLOW:
            ep_stats[ep].errors_overflow++;
            break;
        case IPC_ERROR_TRUNCATION:
            ep_stats[ep].errors_truncation++;
            break;
    }
}

/* ============================================================================
 * Flow Control Tracking
 * ============================================================================ */
void ipc_monitor_flow_control_trigger(int ep) {
    if (ep < 0 || ep >= IPC_MONITOR_MAX_EPS)
        return;

    ep_stats[ep].flow_control_trigger++;
}

void ipc_monitor_flow_control_clear(int ep) {
    if (ep < 0 || ep >= IPC_MONITOR_MAX_EPS)
        return;

    ep_stats[ep].flow_control_clear++;
}

/* ============================================================================
 * Latency Tracking
 * ============================================================================ */
void ipc_monitor_latency_sample(int ep, uint64_t latency_us) {
    if (ep < 0 || ep >= IPC_MONITOR_MAX_EPS)
        return;

    ep_stats[ep].latency_sum += latency_us;
    ep_stats[ep].latency_count++;

    if (latency_us < ep_stats[ep].latency_min) {
        ep_stats[ep].latency_min = latency_us;
    }

    if (latency_us > ep_stats[ep].latency_max) {
        ep_stats[ep].latency_max = latency_us;
    }
}

/* ============================================================================
 * Waiter Tracking
 * ============================================================================ */
void ipc_monitor_waiter_queued(int ep) {
    if (ep < 0 || ep >= IPC_MONITOR_MAX_EPS)
        return;

    ep_stats[ep].waiters_queued++;

    if (ep_stats[ep].waiters_queued > ep_stats[ep].max_waiters) {
        ep_stats[ep].max_waiters = ep_stats[ep].waiters_queued;
    }
}

void ipc_monitor_waiter_dequeued(int ep) {
    if (ep < 0 || ep >= IPC_MONITOR_MAX_EPS)
        return;

    if (ep_stats[ep].waiters_queued > 0) {
        ep_stats[ep].waiters_queued--;
    }
}

/* ============================================================================
 * Delivery Type Tracking
 * ============================================================================ */
void ipc_monitor_direct_delivery(void) {
    global_stats.direct_deliveries++;
}

void ipc_monitor_queued_delivery(void) {
    global_stats.queued_deliveries++;
}

/* ============================================================================
 * Syscall Tracking
 * ============================================================================ */
void ipc_monitor_syscall(int syscall_type) {
    global_stats.total_syscalls++;

    switch (syscall_type) {
        case IPC_SYSCALL_SEND:
            global_stats.syscalls_send++;
            break;
        case IPC_SYSCALL_RECV:
            global_stats.syscalls_recv++;
            break;
        case IPC_SYSCALL_NOTIFY:
            global_stats.syscalls_notify++;
            break;
        case IPC_SYSCALL_WAIT:
            global_stats.syscalls_wait++;
            break;
    }
}

/* ============================================================================
 * Statistics Access
 * ============================================================================ */
const ipc_ep_stats_t *ipc_monitor_get_ep_stats(int ep) {
    if (ep < 0 || ep >= IPC_MONITOR_MAX_EPS)
        return NULL;

    return &ep_stats[ep];
}

const ipc_global_stats_t *ipc_monitor_get_global_stats(void) {
    return &global_stats;
}

/* ============================================================================
 * Statistics Summary
 * ============================================================================ */
void ipc_monitor_print_summary(void) {
    extern void kputs(const char *s);
    extern void kputdec(unsigned long v);
    extern void kputhex(uint64_t v);

    kputs("\n=== IPC Monitoring Summary ===\n");

    /* Global statistics */
    kputs("Total syscalls: ");
    kputdec(global_stats.total_syscalls);
    kputs("\n");

    kputs("  SEND: ");
    kputdec(global_stats.syscalls_send);
    kputs("\n");

    kputs("  RECV: ");
    kputdec(global_stats.syscalls_recv);
    kputs("\n");

    kputs("  NOTIFY: ");
    kputdec(global_stats.syscalls_notify);
    kputs("\n");

    kputs("  WAIT: ");
    kputdec(global_stats.syscalls_wait);
    kputs("\n");

    kputs("Direct deliveries: ");
    kputdec(global_stats.direct_deliveries);
    kputs("\n");

    kputs("Queued deliveries: ");
    kputdec(global_stats.queued_deliveries);
    kputs("\n");

    /* Per-endpoint statistics */
    for (int i = 0; i < IPC_MONITOR_MAX_EPS; i++) {
        if (ep_stats[i].messages_sent == 0 && ep_stats[i].messages_received == 0)
            continue;  /* Skip unused endpoints */

        kputs("\n--- EP ");
        kputdec((unsigned long)i);
        kputs(" ---\n");

        kputs("  Messages sent: ");
        kputdec(ep_stats[i].messages_sent);
        kputs("\n");

        kputs("  Messages received: ");
        kputdec(ep_stats[i].messages_received);
        kputs("\n");

        kputs("  Messages dropped: ");
        kputdec(ep_stats[i].messages_dropped);
        kputs("\n");

        kputs("  Max queue depth: ");
        kputdec(ep_stats[i].max_depth);
        kputs("\n");

        kputs("  Max waiters: ");
        kputdec(ep_stats[i].max_waiters);
        kputs("\n");

        if (ep_stats[i].errors_invalid_ep > 0 ||
            ep_stats[i].errors_invalid_range > 0 ||
            ep_stats[i].errors_overflow > 0 ||
            ep_stats[i].errors_truncation > 0) {
            kputs("  Errors:\n");
            if (ep_stats[i].errors_invalid_ep > 0) {
                kputs("    Invalid EP: ");
                kputdec(ep_stats[i].errors_invalid_ep);
                kputs("\n");
            }
            if (ep_stats[i].errors_invalid_range > 0) {
                kputs("    Invalid range: ");
                kputdec(ep_stats[i].errors_invalid_range);
                kputs("\n");
            }
            if (ep_stats[i].errors_overflow > 0) {
                kputs("    Overflow: ");
                kputdec(ep_stats[i].errors_overflow);
                kputs("\n");
            }
            if (ep_stats[i].errors_truncation > 0) {
                kputs("    Truncation: ");
                kputdec(ep_stats[i].errors_truncation);
                kputs("\n");
            }
        }

        if (ep_stats[i].latency_count > 0) {
            kputs("  Latency (us):\n");
            kputs("    Avg: ");
            kputdec(ep_stats[i].latency_sum / ep_stats[i].latency_count);
            kputs("\n");
            kputs("    Min: ");
            kputdec(ep_stats[i].latency_min);
            kputs("\n");
            kputs("    Max: ");
            kputdec(ep_stats[i].latency_max);
            kputs("\n");
        }
    }

    kputs("\n=== End IPC Summary ===\n");
}

/* ============================================================================
 * Reset Statistics
 * ============================================================================ */
void ipc_monitor_reset(void) {
    ipc_monitor_init();
}

#endif /* IPC_MONITOR_ENABLED */
