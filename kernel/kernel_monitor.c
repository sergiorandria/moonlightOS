/* kernel_monitor.c - Unified kernel monitoring implementation
 *
 * Provides production-grade monitoring for all kernel subsystems.
 * This is the foundation for observability across the kernel.
 */
#include "kernel_monitor.h"
#include "kinternal.h"
#include <stddef.h> /* NULL (freestanding header; no libc dependency) */
#include <stdint.h>

#if KERNEL_MONITOR_ENABLED

static kernel_subsys_stats_t subsys_stats[KERNEL_MONITOR_MAX_SUBSYSTEMS];
static kernel_global_stats_t global_stats;
static uint64_t tick_counter = 0;

/* ============================================================================
 * Initialization
 * ============================================================================ */
void kernel_monitor_init(void) {
    /* Verification marker: confirms monitoring subsystem initialized */
    kputs("[monitor] init\n");
    for (int i = 0; i < KERNEL_MONITOR_MAX_SUBSYSTEMS; i++) {
        subsys_stats[i].ops_total = 0;
        subsys_stats[i].ops_success = 0;
        subsys_stats[i].ops_failed = 0;
        subsys_stats[i].ops_timeout = 0;
        subsys_stats[i].time_total = 0;
        subsys_stats[i].time_min = ~0ULL;
        subsys_stats[i].time_max = 0;
        subsys_stats[i].time_samples = 0;
        subsys_stats[i].bytes_processed = 0;
        subsys_stats[i].bytes_allocated = 0;
        subsys_stats[i].bytes_freed = 0;
        subsys_stats[i].errors_invalid = 0;
        subsys_stats[i].errors_overflow = 0;
        subsys_stats[i].errors_permission = 0;
        subsys_stats[i].errors_timeout = 0;
        subsys_stats[i].errors_other = 0;

        /* Initialize subsystem-specific stats */
        subsys_stats[i].device.devices_discovered = 0;
        subsys_stats[i].device.devices_initialized = 0;
        subsys_stats[i].device.devices_failed = 0;

        subsys_stats[i].irq.irq_total = 0;
        subsys_stats[i].irq.irq_handled = 0;
        subsys_stats[i].irq.irq_spurious = 0;
        subsys_stats[i].irq.irq_nested = 0;

        subsys_stats[i].memory.frames_allocated = 0;
        subsys_stats[i].memory.frames_freed = 0;
        subsys_stats[i].memory.frames_leaked = 0;
        subsys_stats[i].memory.allocation_failures = 0;

        subsys_stats[i].caps.caps_created = 0;
        subsys_stats[i].caps.caps_deleted = 0;
        subsys_stats[i].caps.caps_revoked = 0;
        subsys_stats[i].caps.cap_derivation_failures = 0;

        subsys_stats[i].sched.switches_total = 0;
        subsys_stats[i].sched.switches_preemptive = 0;
        subsys_stats[i].sched.switches_voluntary = 0;
        subsys_stats[i].sched.threads_blocked = 0;

        subsys_stats[i].elf.elfs_loaded = 0;
        subsys_stats[i].elf.elfs_failed = 0;
        subsys_stats[i].elf.spawns_total = 0;
        subsys_stats[i].elf.spawns_failed = 0;

        subsys_stats[i].qube.qube_creates = 0;
        subsys_stats[i].qube.qube_destroys = 0;
        subsys_stats[i].qube.xcross_allowed = 0;
        subsys_stats[i].qube.xcross_denied = 0;
    }

    global_stats.uptime_ticks = 0;
    global_stats.uptime_ms = 0;
    global_stats.total_operations = 0;
    global_stats.total_errors = 0;
    global_stats.boot_time = tick_counter;
}

/* ============================================================================
 * Operation Tracking
 * ============================================================================ */
uint64_t kernel_monitor_op_start(kernel_subsys_t subsys) {
    if (subsys < 0 || subsys >= KERNEL_MONITOR_MAX_SUBSYSTEMS) {
        return 0;
    }
    subsys_stats[subsys].ops_total++;
    global_stats.total_operations++;
    return tick_counter;  /* Simplified time source */
}

void kernel_monitor_op_end(kernel_subsys_t subsys, uint64_t start, int success) {
    if (subsys < 0 || subsys >= KERNEL_MONITOR_MAX_SUBSYSTEMS) {
        return;
    }

    uint64_t duration = tick_counter - start;
    subsys_stats[subsys].time_total += duration;
    subsys_stats[subsys].time_samples++;

    if (duration < subsys_stats[subsys].time_min) {
        subsys_stats[subsys].time_min = duration;
    }
    if (duration > subsys_stats[subsys].time_max) {
        subsys_stats[subsys].time_max = duration;
    }

    if (success) {
        subsys_stats[subsys].ops_success++;
    } else {
        subsys_stats[subsys].ops_failed++;
        global_stats.total_errors++;
    }
}

void kernel_monitor_op_success(kernel_subsys_t subsys) {
    if (subsys < 0 || subsys >= KERNEL_MONITOR_MAX_SUBSYSTEMS) {
        return;
    }
    subsys_stats[subsys].ops_success++;
}

void kernel_monitor_op_failure(kernel_subsys_t subsys, int error_type) {
    if (subsys < 0 || subsys >= KERNEL_MONITOR_MAX_SUBSYSTEMS) {
        return;
    }

    subsys_stats[subsys].ops_failed++;
    global_stats.total_errors++;

    switch (error_type) {
        case KERNEL_ERROR_INVALID:
            subsys_stats[subsys].errors_invalid++;
            break;
        case KERNEL_ERROR_OVERFLOW:
            subsys_stats[subsys].errors_overflow++;
            break;
        case KERNEL_ERROR_PERMISSION:
            subsys_stats[subsys].errors_permission++;
            break;
        case KERNEL_ERROR_TIMEOUT:
            subsys_stats[subsys].errors_timeout++;
            break;
        default:
            subsys_stats[subsys].errors_other++;
            break;
    }
}

void kernel_monitor_bytes(kernel_subsys_t subsys, uint64_t bytes) {
    if (subsys < 0 || subsys >= KERNEL_MONITOR_MAX_SUBSYSTEMS) {
        return;
    }
    subsys_stats[subsys].bytes_processed += bytes;
}

/* Device-specific metrics */
void kernel_monitor_device_discovered(kernel_subsys_t subsys) {
    if (subsys < 0 || subsys >= KERNEL_MONITOR_MAX_SUBSYSTEMS) {
        return;
    }
    subsys_stats[subsys].device.devices_discovered++;
}

void kernel_monitor_device_initialized(kernel_subsys_t subsys) {
    if (subsys < 0 || subsys >= KERNEL_MONITOR_MAX_SUBSYSTEMS) {
        return;
    }
    subsys_stats[subsys].device.devices_initialized++;
}

void kernel_monitor_device_failed(kernel_subsys_t subsys) {
    if (subsys < 0 || subsys >= KERNEL_MONITOR_MAX_SUBSYSTEMS) {
        return;
    }
    subsys_stats[subsys].device.devices_failed++;
}

/* ============================================================================
 * Statistics Access
 * ============================================================================ */
const kernel_subsys_stats_t *kernel_monitor_get_subsys_stats(kernel_subsys_t subsys) {
    if (subsys < 0 || subsys >= KERNEL_MONITOR_MAX_SUBSYSTEMS) {
        return NULL;
    }
    return &subsys_stats[subsys];
}

const kernel_global_stats_t *kernel_monitor_get_global_stats(void) {
    return &global_stats;
}

/* ============================================================================
 * Print Summary
 * ============================================================================ */
void kernel_monitor_print_summary(void) {
    kputs("\n=== Kernel Monitoring Summary ===\n");

    kputs("Uptime: ");
    kputdec(global_stats.uptime_ticks);
    kputs(" ticks\n");

    kputs("Total operations: ");
    kputdec(global_stats.total_operations);
    kputs("\n");

    kputs("Total errors: ");
    kputdec(global_stats.total_errors);
    kputs("\n");

    kputs("\n--- Subsystem Statistics ---\n");

    const char *subsys_names[] = {
        "Device", "IRQ", "Memory", "Caps", "Sched",
        "ELF", "Qube", "Console", "PCI", "Virtio"
    };

    for (int i = 0; i < KERNEL_MONITOR_MAX_SUBSYSTEMS; i++) {
        if (subsys_stats[i].ops_total == 0) {
            continue;  /* Skip unused subsystems */
        }

        kputs("\n");
        kputs(subsys_names[i]);
        kputs(":\n");

        kputs("  Operations: ");
        kputdec(subsys_stats[i].ops_total);
        kputs(" (success: ");
        kputdec(subsys_stats[i].ops_success);
        kputs(", failed: ");
        kputdec(subsys_stats[i].ops_failed);
        kputs(")\n");

        if (subsys_stats[i].time_samples > 0) {
            kputs("  Avg time: ");
            kputdec(subsys_stats[i].time_total / subsys_stats[i].time_samples);
            kputs(" ticks\n");
        }

        if (subsys_stats[i].errors_invalid > 0 ||
            subsys_stats[i].errors_overflow > 0 ||
            subsys_stats[i].errors_permission > 0 ||
            subsys_stats[i].errors_timeout > 0) {
            kputs("  Errors:\n");
            if (subsys_stats[i].errors_invalid > 0) {
                kputs("    Invalid: ");
                kputdec(subsys_stats[i].errors_invalid);
                kputs("\n");
            }
            if (subsys_stats[i].errors_overflow > 0) {
                kputs("    Overflow: ");
                kputdec(subsys_stats[i].errors_overflow);
                kputs("\n");
            }
            if (subsys_stats[i].errors_permission > 0) {
                kputs("    Permission: ");
                kputdec(subsys_stats[i].errors_permission);
                kputs("\n");
            }
            if (subsys_stats[i].errors_timeout > 0) {
                kputs("    Timeout: ");
                kputdec(subsys_stats[i].errors_timeout);
                kputs("\n");
            }
        }

        /* Subsystem-specific metrics */
        if (i == KERNEL_SUBSYS_DEVICE) {
            kputs("  Devices discovered: ");
            kputdec(subsys_stats[i].device.devices_discovered);
            kputs("\n");
            kputs("  Devices initialized: ");
            kputdec(subsys_stats[i].device.devices_initialized);
            kputs("\n");
            kputs("  Devices failed: ");
            kputdec(subsys_stats[i].device.devices_failed);
            kputs("\n");
        }
    }

    kputs("\n=== End Monitoring Summary ===\n");
}

/* ============================================================================
 * Reset
 * ============================================================================ */
void kernel_monitor_reset(void) {
    kernel_monitor_init();
}

/* ============================================================================
 * Tick Counter
 * ============================================================================ */
void kernel_monitor_tick(void) {
    tick_counter++;
    global_stats.uptime_ticks++;
    /* Simplified: assume 1 tick = 1 ms */
    global_stats.uptime_ms++;
}

#endif /* KERNEL_MONITOR_ENABLED */
