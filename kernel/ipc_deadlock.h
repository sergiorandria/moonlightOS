/* ipc_deadlock.h - Deadlock detection and prevention for IPC
 *
 * Provides runtime deadlock detection for the IPC subsystem:
 * - Wait-for graph tracking
 * - Cycle detection (waits-for chain)
 * - Timeout-based deadlock recovery
 * - Prevention guidelines
 *
 * Deadlock scenarios in IPC:
 * 1. Circular wait: A waits for B, B waits for A
 * 2. Resource ordering: A holds lock L1, waits for L2; B holds L2, waits for L1
 * 3. Starvation: Thread continuously bypassed in scheduling
 */
#ifndef IPC_DEADLOCK_H
#define IPC_DEADLOCK_H

#include <stdint.h>

/* Compile-time enable/disable for deadlock detection */
#define IPC_DEADLOCK_ENABLED 1

/* Maximum number of threads (matches NTHREADS) */
#define IPC_DEADLOCK_MAX_THREADS 11

/* Deadlock detection timeout (in ticks) */
#define IPC_DEADLOCK_TIMEOUT_TICKS 1000  /* 100 seconds at 100ms/tick */

/* Wait-for graph edge */
typedef struct {
    int waiter;      /* Thread waiting */
    int target;      /* Thread being waited for */
    uint64_t start;  /* Tick when wait started */
    int active;      /* Edge is active */
} ipc_deadlock_edge_t;

/* Deadlock detection state */
typedef struct {
    ipc_deadlock_edge_t edges[IPC_DEADLOCK_MAX_THREADS * IPC_DEADLOCK_MAX_THREADS];
    int edge_count;
    uint64_t tick;
    int deadlock_detected;
    int deadlock_cycle[IPC_DEADLOCK_MAX_THREADS];
    int cycle_length;
} ipc_deadlock_state_t;

/* ============================================================================
 * Deadlock Detection API
 * ============================================================================ */

#if IPC_DEADLOCK_ENABLED

/* Initialize deadlock detection */
void ipc_deadlock_init(void);

/* Record a wait relationship (thread waits for target) */
void ipc_deadlock_wait_begin(int waiter, int target);

/* Record wait end (thread stopped waiting) */
void ipc_deadlock_wait_end(int waiter);

/* Update tick counter (called from timer interrupt) */
void ipc_deadlock_tick(void);

/* Check for deadlock (call periodically) */
int ipc_deadlock_check(void);

/* Get deadlock cycle information */
int ipc_deadlock_get_cycle(int *cycle, int *length);

/* Clear deadlock state (after recovery) */
void ipc_deadlock_clear(void);

/* Print deadlock report */
void ipc_deadlock_print_report(void);

#else /* IPC_DEADLOCK_ENABLED */

/* No-op stubs when disabled */
static inline void ipc_deadlock_init(void) {}
static inline void ipc_deadlock_wait_begin(int waiter, int target) {}
static inline void ipc_deadlock_wait_end(int waiter) {}
static inline void ipc_deadlock_tick(void) {}
static inline int ipc_deadlock_check(void) { return 0; }
static inline int ipc_deadlock_get_cycle(int *cycle, int *length) { return 0; }
static inline void ipc_deadlock_clear(void) {}
static inline void ipc_deadlock_print_report(void) {}

#endif /* IPC_DEADLOCK_ENABLED */

/* ============================================================================
 * Deadlock Prevention Guidelines
 * ============================================================================ */

/*
 * To prevent deadlocks in IPC:
 *
 * 1. Always acquire resources in a fixed order
 *    - If you need multiple endpoints, always acquire EP 0 before EP 1, etc.
 *    - Establish a global ordering of resources
 *
 * 2. Use timeouts for all blocking operations
 *    - Never block indefinitely
 *    - Set reasonable timeouts based on expected operation time
 *
 * 3. Avoid circular dependencies
 *    - Don't have A wait for B while B waits for A
 *    - Design service hierarchies to avoid cycles
 *
 * 4. Release resources promptly
 *    - RECV as soon as possible after SEND
 *    - Don't hold resources while doing unrelated work
 *
 * 5. Use non-blocking patterns when possible
 *    - Poll with WAIT instead of blocking RECV
 *    - Use NOTIFY for one-shot signals
 *
 * 6. Test with deadlock detection enabled
 *    - Enable IPC_DEADLOCK_ENABLED in production
 *    - Monitor deadlock detection logs
 *    - Fix any detected cycles immediately
 */

#endif /* IPC_DEADLOCK_H */
