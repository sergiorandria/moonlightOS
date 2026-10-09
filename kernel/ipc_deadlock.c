/* ipc_deadlock.c - Deadlock detection implementation
 *
 * Implements wait-for graph tracking and cycle detection.
 * Uses DFS-based cycle detection with timeout-based recovery.
 */
#include "ipc_deadlock.h"
#include <stdint.h>

#if IPC_DEADLOCK_ENABLED

static ipc_deadlock_state_t state;

/* ============================================================================
 * Initialization
 * ============================================================================ */
void ipc_deadlock_init(void) {
    for (int i = 0; i < IPC_DEADLOCK_MAX_THREADS * IPC_DEADLOCK_MAX_THREADS; i++) {
        state.edges[i].waiter = -1;
        state.edges[i].target = -1;
        state.edges[i].start = 0;
        state.edges[i].active = 0;
    }
    state.edge_count = 0;
    state.tick = 0;
    state.deadlock_detected = 0;
    state.cycle_length = 0;
    for (int i = 0; i < IPC_DEADLOCK_MAX_THREADS; i++) {
        state.deadlock_cycle[i] = -1;
    }
}

/* ============================================================================
 * Wait-for Graph Management
 * ============================================================================ */
void ipc_deadlock_wait_begin(int waiter, int target) {
    if (waiter < 0 || waiter >= IPC_DEADLOCK_MAX_THREADS ||
        target < 0 || target >= IPC_DEADLOCK_MAX_THREADS) {
        return;
    }

    /* Find existing edge or allocate new one */
    for (int i = 0; i < state.edge_count; i++) {
        if (state.edges[i].waiter == waiter && state.edges[i].target == target) {
            /* Re-activate existing edge */
            state.edges[i].active = 1;
            state.edges[i].start = state.tick;
            return;
        }
    }

    /* Allocate new edge */
    if (state.edge_count < IPC_DEADLOCK_MAX_THREADS * IPC_DEADLOCK_MAX_THREADS) {
        state.edges[state.edge_count].waiter = waiter;
        state.edges[state.edge_count].target = target;
        state.edges[state.edge_count].start = state.tick;
        state.edges[state.edge_count].active = 1;
        state.edge_count++;
    }
}

void ipc_deadlock_wait_end(int waiter) {
    if (waiter < 0 || waiter >= IPC_DEADLOCK_MAX_THREADS) {
        return;
    }

    /* Deactivate all edges where this thread is the waiter */
    for (int i = 0; i < state.edge_count; i++) {
        if (state.edges[i].waiter == waiter) {
            state.edges[i].active = 0;
        }
    }
}

/* ============================================================================
 * Tick Counter
 * ============================================================================ */
void ipc_deadlock_tick(void) {
    state.tick++;
}

/* ============================================================================
 * Cycle Detection (DFS-based)
 * ============================================================================ */
static int visited[IPC_DEADLOCK_MAX_THREADS];
static int recursion_stack[IPC_DEADLOCK_MAX_THREADS];
static int stack_depth;

static int dfs_cycle_detection(int node, int start_node) {
    if (visited[node]) {
        if (node == start_node) {
            /* Found cycle back to start */
            return 1;
        }
        return 0;
    }

    visited[node] = 1;
    recursion_stack[stack_depth++] = node;

    /* Find all edges from this node */
    for (int i = 0; i < state.edge_count; i++) {
        if (state.edges[i].active && state.edges[i].waiter == node) {
            int target = state.edges[i].target;
            if (dfs_cycle_detection(target, start_node)) {
                return 1;
            }
        }
    }

    stack_depth--;
    return 0;
}

/* ============================================================================
 * Deadlock Check
 * ============================================================================ */
int ipc_deadlock_check(void) {
    /* Check for timeout deadlocks first */
    uint64_t current_tick = state.tick;

    for (int i = 0; i < state.edge_count; i++) {
        if (state.edges[i].active) {
            uint64_t wait_duration = current_tick - state.edges[i].start;
            if (wait_duration > IPC_DEADLOCK_TIMEOUT_TICKS) {
                /* Timeout detected - likely deadlock */
                state.deadlock_detected = 1;
                state.deadlock_cycle[0] = state.edges[i].waiter;
                state.deadlock_cycle[1] = state.edges[i].target;
                state.cycle_length = 2;
                return 1;
            }
        }
    }

    /* Check for circular wait (cycle detection) */
    for (int i = 0; i < IPC_DEADLOCK_MAX_THREADS; i++) {
        /* Reset visited array */
        for (int j = 0; j < IPC_DEADLOCK_MAX_THREADS; j++) {
            visited[j] = 0;
        }
        stack_depth = 0;

        /* Start DFS from each thread */
        if (dfs_cycle_detection(i, i)) {
            /* Cycle found */
            state.deadlock_detected = 1;
            state.cycle_length = stack_depth;
            for (int j = 0; j < stack_depth; j++) {
                state.deadlock_cycle[j] = recursion_stack[j];
            }
            return 1;
        }
    }

    return 0;
}

/* ============================================================================
 * Cycle Information
 * ============================================================================ */
int ipc_deadlock_get_cycle(int *cycle, int *length) {
    if (!state.deadlock_detected) {
        return 0;
    }

    if (cycle && length) {
        for (int i = 0; i < state.cycle_length; i++) {
            cycle[i] = state.deadlock_cycle[i];
        }
        *length = state.cycle_length;
    }

    return 1;
}

/* ============================================================================
 * Clear Deadlock State
 * ============================================================================ */
void ipc_deadlock_clear(void) {
    state.deadlock_detected = 0;
    state.cycle_length = 0;
    for (int i = 0; i < IPC_DEADLOCK_MAX_THREADS; i++) {
        state.deadlock_cycle[i] = -1;
    }
}

/* ============================================================================
 * Print Deadlock Report
 * ============================================================================ */
void ipc_deadlock_print_report(void) {
    extern void kputs(const char *s);
    extern void kputdec(unsigned long v);

    kputs("\n=== DEADLOCK DETECTED ===\n");

    if (state.deadlock_detected) {
        kputs("Deadlock cycle: ");
        for (int i = 0; i < state.cycle_length; i++) {
            kputdec((unsigned long)state.deadlock_cycle[i]);
            if (i < state.cycle_length - 1) {
                kputs(" -> ");
            }
        }
        kputs(" -> ");
        kputdec((unsigned long)state.deadlock_cycle[0]);
        kputs("\n");

        kputs("Active wait-for edges:\n");
        for (int i = 0; i < state.edge_count; i++) {
            if (state.edges[i].active) {
                kputs("  Thread ");
                kputdec((unsigned long)state.edges[i].waiter);
                kputs(" waits for thread ");
                kputdec((unsigned long)state.edges[i].target);
                kputs(" (duration: ");
                kputdec(state.tick - state.edges[i].start);
                kputs(" ticks)\n");
            }
        }
    } else {
        kputs("No deadlock detected\n");
    }

    kputs("=== END DEADLOCK REPORT ===\n");
}

#endif /* IPC_DEADLOCK_ENABLED */
