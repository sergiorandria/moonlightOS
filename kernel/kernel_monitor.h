/* kernel_monitor.h - Unified kernel monitoring and observability
 *
 * Provides production-grade monitoring for all kernel subsystems:
 * - Device discovery and initialization
 * - IRQ handling and dispatch
 * - Memory management and allocation
 * - Capability system operations
 * - Scheduler and thread management
 * - ELF loading and spawning
 * - Qube security and isolation
 *
 * This unified system provides consistent metrics across all subsystems.
 */
#ifndef KERNEL_MONITOR_H
#define KERNEL_MONITOR_H

#include <stdint.h>

/* Compile-time enable/disable for monitoring */
#define KERNEL_MONITOR_ENABLED 1

/* Maximum number of monitored subsystems */
#define KERNEL_MONITOR_MAX_SUBSYSTEMS 16

/* Subsystem identifiers */
typedef enum {
    KERNEL_SUBSYS_DEVICE = 0,
    KERNEL_SUBSYS_IRQ = 1,
    KERNEL_SUBSYS_MEMORY = 2,
    KERNEL_SUBSYS_CAPS = 3,
    KERNEL_SUBSYS_SCHED = 4,
    KERNEL_SUBSYS_ELF = 5,
    KERNEL_SUBSYS_QUBE = 6,
    KERNEL_SUBSYS_CONSOLE = 7,
    KERNEL_SUBSYS_PCI = 8,
    KERNEL_SUBSYS_VIRTIO = 9,
    KERNEL_SUBSYS_MAX
} kernel_subsys_t;

/* Subsystem statistics */
typedef struct {
    /* Operation counters */
    uint64_t ops_total;
    uint64_t ops_success;
    uint64_t ops_failed;
    uint64_t ops_timeout;

    /* Timing (in microseconds) */
    uint64_t time_total;
    uint64_t time_min;
    uint64_t time_max;
    uint64_t time_samples;

    /* Resource usage */
    uint64_t bytes_processed;
    uint64_t bytes_allocated;
    uint64_t bytes_freed;

    /* Error breakdown */
    uint64_t errors_invalid;
    uint64_t errors_overflow;
    uint64_t errors_permission;
    uint64_t errors_timeout;
    uint64_t errors_other;

    /* Subsystem-specific metrics */
    union {
        struct {
            uint64_t devices_discovered;
            uint64_t devices_initialized;
            uint64_t devices_failed;
        } device;

        struct {
            uint64_t irq_total;
            uint64_t irq_handled;
            uint64_t irq_spurious;
            uint64_t irq_nested;
        } irq;

        struct {
            uint64_t frames_allocated;
            uint64_t frames_freed;
            uint64_t frames_leaked;
            uint64_t allocation_failures;
        } memory;

        struct {
            uint64_t caps_created;
            uint64_t caps_deleted;
            uint64_t caps_revoked;
            uint64_t cap_derivation_failures;
        } caps;

        struct {
            uint64_t switches_total;
            uint64_t switches_preemptive;
            uint64_t switches_voluntary;
            uint64_t threads_blocked;
        } sched;

        struct {
            uint64_t elfs_loaded;
            uint64_t elfs_failed;
            uint64_t spawns_total;
            uint64_t spawns_failed;
        } elf;

        struct {
            uint64_t qube_creates;
            uint64_t qube_destroys;
            uint64_t xcross_allowed;
            uint64_t xcross_denied;
        } qube;
    };
} kernel_subsys_stats_t;

/* Global kernel statistics */
typedef struct {
    uint64_t uptime_ticks;
    uint64_t uptime_ms;
    uint64_t total_operations;
    uint64_t total_errors;
    uint64_t boot_time;
} kernel_global_stats_t;

/* ============================================================================
 * Monitoring API
 * ============================================================================ */

#if KERNEL_MONITOR_ENABLED

/* Initialize kernel monitoring */
void kernel_monitor_init(void);

/* Record operation start (returns start time) */
uint64_t kernel_monitor_op_start(kernel_subsys_t subsys);

/* Record operation end (calculates duration) */
void kernel_monitor_op_end(kernel_subsys_t subsys, uint64_t start, int success);

/* Record operation success */
void kernel_monitor_op_success(kernel_subsys_t subsys);

/* Record operation failure */
void kernel_monitor_op_failure(kernel_subsys_t subsys, int error_type);

/* Device-specific metrics */
void kernel_monitor_device_discovered(kernel_subsys_t subsys);
void kernel_monitor_device_initialized(kernel_subsys_t subsys);
void kernel_monitor_device_failed(kernel_subsys_t subsys);

/* Record bytes processed */
void kernel_monitor_bytes(kernel_subsys_t subsys, uint64_t bytes);

/* Get subsystem statistics */
const kernel_subsys_stats_t *kernel_monitor_get_subsys_stats(kernel_subsys_t subsys);

/* Get global statistics */
const kernel_global_stats_t *kernel_monitor_get_global_stats(void);

/* Print monitoring summary */
void kernel_monitor_print_summary(void);

/* Reset statistics (for testing) */
void kernel_monitor_reset(void);

/* Update uptime (called from timer interrupt) */
void kernel_monitor_tick(void);

#else /* KERNEL_MONITOR_ENABLED */

/* No-op stubs */
static inline void kernel_monitor_init(void) {}
static inline uint64_t kernel_monitor_op_start(kernel_subsys_t subsys) { return 0; }
static inline void kernel_monitor_op_end(kernel_subsys_t subsys, uint64_t start, int success) {}
static inline void kernel_monitor_op_success(kernel_subsys_t subsys) {}
static inline void kernel_monitor_op_failure(kernel_subsys_t subsys, int error_type) {}
static inline void kernel_monitor_bytes(kernel_subsys_t subsys, uint64_t bytes) {}
static inline void kernel_monitor_device_discovered(kernel_subsys_t subsys) {}
static inline void kernel_monitor_device_initialized(kernel_subsys_t subsys) {}
static inline void kernel_monitor_device_failed(kernel_subsys_t subsys) {}
static inline const kernel_subsys_stats_t *
kernel_monitor_get_subsys_stats(kernel_subsys_t subsys) { return NULL; }
static inline const kernel_global_stats_t *kernel_monitor_get_global_stats(void) { return NULL; }
static inline void kernel_monitor_print_summary(void) {}
static inline void kernel_monitor_reset(void) {}
static inline void kernel_monitor_tick(void) {}

#endif /* KERNEL_MONITOR_ENABLED */

/* Error type constants */
#define KERNEL_ERROR_INVALID 1
#define KERNEL_ERROR_OVERFLOW 2
#define KERNEL_ERROR_PERMISSION 3
#define KERNEL_ERROR_TIMEOUT 4
#define KERNEL_ERROR_OTHER 5

/* ============================================================================
 * Helper Macros for Easy Instrumentation
 * ============================================================================ */

#define MONITOR_OP_START(subsys) \
    uint64_t _mon_start = kernel_monitor_op_start(subsys)

#define MONITOR_OP_END(subsys, success) \
    kernel_monitor_op_end(subsys, _mon_start, success)

#define MONITOR_OP_SUCCESS(subsys) \
    kernel_monitor_op_success(subsys)

#define MONITOR_OP_FAILURE(subsys, error) \
    kernel_monitor_op_failure(subsys, error)

#define MONITOR_BYTES(subsys, bytes) \
    kernel_monitor_bytes(subsys, bytes)

#endif /* KERNEL_MONITOR_H */
