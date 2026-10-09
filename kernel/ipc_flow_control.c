/* ipc_flow_control.c - Adaptive flow control implementation
 *
 * Implements dynamic threshold adjustment and backpressure
 * management based on traffic patterns and statistics.
 */
#include "ipc_flow_control.h"
#include "ipc.h"
#include <stdint.h>

#if IPC_FLOW_CONTROL_ADAPTIVE

static ipc_fc_config_t global_config;
static ipc_fc_state_t ep_states[V2_NEP];
static uint64_t tick_counter = 0;

/* ============================================================================
 * Initialization
 * ============================================================================ */
void ipc_flow_control_init(const ipc_fc_config_t *config) {
    if (config) {
        global_config = *config;
    } else {
        global_config = IPC_FC_CONFIG_DEFAULT;
    }

    /* Initialize all endpoints */
    for (int i = 0; i < V2_NEP; i++) {
        ipc_flow_control_ep_init(i, global_config.default_mode);
    }
}

void ipc_flow_control_ep_init(int ep, ipc_fc_mode_t mode) {
    if (ep < 0 || ep >= V2_NEP) return;

    ep_states[ep].mode = mode;
    ep_states[ep].threshold = V2_FLOW_CONTROL_THRESHOLD;
    ep_states[ep].min_threshold = V2_IPC_Q / 4;  /* 25% */
    ep_states[ep].max_threshold = (V2_IPC_Q * 3) / 4;  /* 75% */
    ep_states[ep].send_rate = 0;
    ep_states[ep].recv_rate = 0;
    ep_states[ep].avg_depth = 0;
    ep_states[ep].peak_depth = 0;
    ep_states[ep].overflow_count = 0;
    ep_states[ep].increase_interval = 100;
    ep_states[ep].decrease_interval = 10;
    ep_states[ep].increase_permille = 1100;  /* +10% (integer fixed-point) */
    ep_states[ep].decrease_permille = 900;   /* -10% */
    ep_states[ep].backpressure_active = 0;
    ep_states[ep].backpressure_start = 0;
}

/* ============================================================================
 * Statistics Recording
 * ============================================================================ */
void ipc_flow_control_record_send(int ep) {
    if (ep < 0 || ep >= V2_NEP) return;
    ep_states[ep].send_rate++;
}

void ipc_flow_control_record_recv(int ep) {
    if (ep < 0 || ep >= V2_NEP) return;
    ep_states[ep].recv_rate++;
}

void ipc_flow_control_record_depth(int ep, uint32_t depth) {
    if (ep < 0 || ep >= V2_NEP) return;

    /* Update average (exponential moving average) */
    ep_states[ep].avg_depth = (ep_states[ep].avg_depth * 7 + depth) / 8;

    /* Update peak */
    if (depth > ep_states[ep].peak_depth) {
        ep_states[ep].peak_depth = depth;
    }
}

void ipc_flow_control_record_overflow(int ep) {
    if (ep < 0 || ep >= V2_NEP) return;
    ep_states[ep].overflow_count++;
}

/* ============================================================================
 * Flow Control Decisions
 * ============================================================================ */
int ipc_flow_control_should_trigger(int ep, uint32_t current_depth) {
    if (ep < 0 || ep >= V2_NEP) return 0;

    return current_depth >= ep_states[ep].threshold;
}

int ipc_flow_control_should_clear(int ep, uint32_t current_depth) {
    if (ep < 0 || ep >= V2_NEP) return 0;

    /* Clear when below 75% of threshold */
    return current_depth < (ep_states[ep].threshold * 3) / 4;
}

/* ============================================================================
 * Adaptive Threshold Adjustment
 * ============================================================================ */
void ipc_flow_control_adapt(int ep) {
    if (ep < 0 || ep >= V2_NEP) return;

    ipc_fc_state_t *state = &ep_states[ep];

    if (state->mode == IPC_FC_STATIC) {
        return;  /* No adaptation in static mode */
    }

    /* Increase threshold if high send rate and low overflow count */
    if (state->send_rate > state->recv_rate * 2 &&
        state->overflow_count == 0 &&
        state->avg_depth < state->threshold) {
        /* High throughput, low congestion - increase threshold (permille). */
        state->threshold = (uint32_t)(((uint64_t)state->threshold *
                                       state->increase_permille) / 1000u);
        if (state->threshold > state->max_threshold) {
            state->threshold = state->max_threshold;
        }
    }

    /* Decrease threshold if overflows occurring */
    if (state->overflow_count > 0) {
        state->threshold = (uint32_t)(((uint64_t)state->threshold *
                                       state->decrease_permille) / 1000u);
        if (state->threshold < state->min_threshold) {
            state->threshold = state->min_threshold;
        }
        state->overflow_count = 0;  /* Reset after adjustment */
    }

    /* Reset rates for next interval */
    state->send_rate = 0;
    state->recv_rate = 0;
}

/* ============================================================================
 * Threshold Access
 * ============================================================================ */
uint32_t ipc_flow_control_get_threshold(int ep) {
    if (ep < 0 || ep >= V2_NEP) return V2_FLOW_CONTROL_THRESHOLD;
    return ep_states[ep].threshold;
}

/* ============================================================================
 * Backpressure Management
 * ============================================================================ */
void ipc_flow_control_set_backpressure(int ep, int active) {
    if (ep < 0 || ep >= V2_NEP) return;

    if (active && !ep_states[ep].backpressure_active) {
        ep_states[ep].backpressure_active = 1;
        ep_states[ep].backpressure_start = tick_counter;
    } else if (!active && ep_states[ep].backpressure_active) {
        ep_states[ep].backpressure_active = 0;
    }
}

int ipc_flow_control_backpressure_active(int ep) {
    if (ep < 0 || ep >= V2_NEP) return 0;
    return ep_states[ep].backpressure_active;
}

/* ============================================================================
 * Statistics Access
 * ============================================================================ */
void ipc_flow_control_get_stats(int ep, ipc_fc_stats_t *stats) {
    if (ep < 0 || ep >= V2_NEP || !stats) return;

    stats->current_threshold = ep_states[ep].threshold;
    stats->send_rate = ep_states[ep].send_rate;
    stats->recv_rate = ep_states[ep].recv_rate;
    stats->avg_depth = ep_states[ep].avg_depth;
    stats->overflow_count = ep_states[ep].overflow_count;
    stats->backpressure_active = ep_states[ep].backpressure_active;
}

/* ============================================================================
 * Tick Callback
 * ============================================================================ */
void ipc_flow_control_tick(void) {
    tick_counter++;

    /* Adapt thresholds periodically */
    if (tick_counter % 10 == 0) {  /* Every 10 ticks */
        for (int i = 0; i < V2_NEP; i++) {
            ipc_flow_control_adapt(i);
        }
    }

    /* Check backpressure timeout */
    for (int i = 0; i < V2_NEP; i++) {
        if (ep_states[i].backpressure_active) {
            uint64_t duration = tick_counter - ep_states[i].backpressure_start;
            if (duration > 100) {  /* Timeout after 100 ticks */
                ipc_flow_control_set_backpressure(i, 0);
            }
        }
    }
}

#endif /* IPC_FLOW_CONTROL_ADAPTIVE */
