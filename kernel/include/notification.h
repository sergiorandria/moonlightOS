#pragma once
#include "types.h"
#include <stdbool.h>
#include <stdint.h>

// Async notification - seL4-style, 64-bit badge, no queue, coalescing
typedef struct notification {
    uint64_t badge;          // pending badge bits (ORed)
    bool has_waiter;
    uint32_t waiter_tcb;     // TCB blocked in recv
    uint32_t bound_tcb;      // for IRQ binding
} notification_t;

#define MAX_NOTIFICATIONS 64

kerror_t notification_init(notification_t *ntfn);
kerror_t notification_signal(notification_t *ntfn, uint64_t badge);
kerror_t notification_wait(notification_t *ntfn, uint32_t waiter, uint64_t *out_badge);
kerror_t notification_bind(notification_t *ntfn, uint32_t tcb_id);
kerror_t notification_poll(notification_t *ntfn, uint64_t *out_badge);
