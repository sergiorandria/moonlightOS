/* ipc_flow_control.h - Adaptive flow control for IPC
 *
 * Provides dynamic flow control tuning:
 * - Adaptive thresholds based on traffic patterns
 * - Backpressure signaling
 * - Queue depth prediction
 * - Congestion avoidance
 *
 * Flow control prevents queue overflow and ensures fair
 * resource allocation across services.
 */
#ifndef IPC_FLOW_CONTROL_H
#define IPC_FLOW_CONTROL_H

#include <stdint.h>

/* V2_IPC_Q / V2_NEP (queue capacity + endpoint count) are the core IPC
 * ABI; this policy layer reads them, so it includes the queue header. */
#include "ipc.h"

/* Compile-time enable/disable for adaptive flow control */
#define IPC_FLOW_CONTROL_ADAPTIVE 1

/* Current flow control configuration */
#define V2_FLOW_CONTROL_THRESHOLD (V2_IPC_Q / 2)  /* 50% capacity */

/* Flow control modes */
typedef enum {
    IPC_FC_STATIC,          /* Fixed threshold (current behavior) */
    IPC_FC_ADAPTIVE,        /* Dynamic threshold based on patterns */
    IPC_FC_PREDICTIVE       /* Predictive based on trends */
} ipc_fc_mode_t;

/* Flow control state per endpoint */
typedef struct {
    /* Configuration */
    ipc_fc_mode_t mode;
    uint32_t threshold;      /* Current threshold */
    uint32_t min_threshold;  /* Minimum threshold (prevent starvation) */
    uint32_t max_threshold;  /* Maximum threshold (prevent overflow) */

    /* Statistics */
    uint32_t send_rate;      /* Messages per second */
    uint32_t recv_rate;      /* Messages per second */
    uint32_t avg_depth;      /* Average queue depth */
    uint32_t peak_depth;     /* Peak queue depth */
    uint32_t overflow_count;  /* Number of overflows */

    /* Adaptive parameters. Factors are integer permille (1000 == 1.0):
     * the S-mode kernel is built -march=rv64imac (no F/D), so any float
     * arithmetic would emit __mulsf3/__fixunssfsi libcalls that the
     * freestanding image does not link. Integer fixed-point keeps the
     * adaptive path self-contained and deterministic. */
    uint32_t increase_interval;  /* Increase threshold every N messages */
    uint32_t decrease_interval;  /* Decrease threshold every N messages */
    uint32_t increase_permille;  /* Threshold increase factor (permille) */
    uint32_t decrease_permille;  /* Threshold decrease factor (permille) */

    /* Backpressure state */
    int backpressure_active;    /* Backpressure currently applied */
    uint64_t backpressure_start; /* When backpressure started */
} ipc_fc_state_t;

/* Global flow control configuration */
typedef struct {
    ipc_fc_mode_t default_mode;
    uint32_t sample_interval_ms;  /* How often to sample statistics */
    uint32_t adaptation_interval_ms;  /* How often to adapt thresholds */
    uint32_t backpressure_timeout_ms;  /* Max backpressure duration */
} ipc_fc_config_t;

/* Default configuration */
#define IPC_FC_CONFIG_DEFAULT (ipc_fc_config_t){ \
    .default_mode = IPC_FC_ADAPTIVE, \
    .sample_interval_ms = 100, \
    .adaptation_interval_ms = 1000, \
    .backpressure_timeout_ms = 5000 \
}

/* ============================================================================
 * Flow Control API
 * ============================================================================ */

#if IPC_FLOW_CONTROL_ADAPTIVE

/* Initialize flow control */
void ipc_flow_control_init(const ipc_fc_config_t *config);

/* Initialize per-endpoint flow control state */
void ipc_flow_control_ep_init(int ep, ipc_fc_mode_t mode);

/* Record message sent (for rate tracking) */
void ipc_flow_control_record_send(int ep);

/* Record message received (for rate tracking) */
void ipc_flow_control_record_recv(int ep);

/* Update queue depth sample */
void ipc_flow_control_record_depth(int ep, uint32_t depth);

/* Record a queue overflow (V2_ERR_OVERFLOW). Feeds the adaptive decrease
 * branch on the next ipc_flow_control_adapt(); without this the overflow
 * counter is never advanced and the decrease path is dead code. */
void ipc_flow_control_record_overflow(int ep);

/* Check if flow control should trigger */
int ipc_flow_control_should_trigger(int ep, uint32_t current_depth);

/* Check if flow control should clear */
int ipc_flow_control_should_clear(int ep, uint32_t current_depth);

/* Adapt thresholds based on statistics */
void ipc_flow_control_adapt(int ep);

/* Get current threshold for endpoint */
uint32_t ipc_flow_control_get_threshold(int ep);

/* Set backpressure state */
void ipc_flow_control_set_backpressure(int ep, int active);

/* Check if backpressure is active */
int ipc_flow_control_backpressure_active(int ep);

/* Get flow control statistics */
typedef struct {
    uint32_t current_threshold;
    uint32_t send_rate;
    uint32_t recv_rate;
    uint32_t avg_depth;
    uint32_t overflow_count;
    int backpressure_active;
} ipc_fc_stats_t;

void ipc_flow_control_get_stats(int ep, ipc_fc_stats_t *stats);

/* Tick callback (called periodically) */
void ipc_flow_control_tick(void);

#else /* IPC_FLOW_CONTROL_ADAPTIVE */

/* No-op stubs using static threshold */
static inline void ipc_flow_control_init(const ipc_fc_config_t *config) {}
static inline void ipc_flow_control_ep_init(int ep, ipc_fc_mode_t mode) {}
static inline void ipc_flow_control_record_send(int ep) {}
static inline void ipc_flow_control_record_recv(int ep) {}
static inline void ipc_flow_control_record_depth(int ep, uint32_t depth) {}
static inline void ipc_flow_control_record_overflow(int ep) {}
static inline int ipc_flow_control_should_trigger(int ep, uint32_t current_depth) {
    return current_depth >= V2_FLOW_CONTROL_THRESHOLD;
}
static inline int ipc_flow_control_should_clear(int ep, uint32_t current_depth) {
    return current_depth < V2_FLOW_CONTROL_THRESHOLD;
}
static inline void ipc_flow_control_adapt(int ep) {}
static inline uint32_t ipc_flow_control_get_threshold(int ep) {
    return V2_FLOW_CONTROL_THRESHOLD;
}
static inline void ipc_flow_control_set_backpressure(int ep, int active) {}
static inline int ipc_flow_control_backpressure_active(int ep) { return 0; }
static inline void ipc_flow_control_get_stats(int ep, ipc_fc_stats_t *stats) {}
static inline void ipc_flow_control_tick(void) {}

#endif /* IPC_FLOW_CONTROL_ADAPTIVE */

/* ============================================================================
 * Flow Control Guidelines
 * ============================================================================ */

/*
 * Flow Control Tuning Guidelines:
 *
 * Threshold Selection:
 * - 50% (current): Conservative, ensures headroom
 * - 75%: Aggressive, higher throughput, higher overflow risk
 * - 25%: Very conservative, lowest overflow risk
 *
 * Adaptive Behavior:
 * - Increase threshold when send rate consistently high
 * - Decrease threshold when overflows occur
 * - Keep within min/max bounds to prevent starvation/overflow
 *
 * Backpressure:
 * - Trigger when queue exceeds threshold
 * - Clear when queue drops below threshold
 * - Timeout to prevent indefinite backpressure
 *
 * Monitoring:
 * - Track send/recv rates to detect imbalance
 * - Monitor overflow count to detect congestion
 * - Track backpressure duration to detect fairness issues
 *
 * Service-Specific Tuning:
 * - High-throughput services (network): higher threshold
 * - Latency-sensitive services (GUI): lower threshold
 * - Low-traffic services (vault): default threshold
 */

#endif /* IPC_FLOW_CONTROL_H */
