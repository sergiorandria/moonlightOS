/*
 * virtio_input.c - VirtIO input device driver (keyboard and mouse)
 * 
 * Implements VirtIO-input protocol (VirtIO v1.1 spec section 5.8) for
 * keyboard and mouse event delivery. Minimal implementation with statically
 * allocated flat rings (16 slots each). Production microkernel version.
 */

#include <stdint.h>
#include "virtio_input.h"

/* V2 syscalls */
#define V2_INVOKE 7
#define V2_INV_FRAME_PA 16

/* GUI U-image base (v2_user.ld) */
#define GUI_U_BASE 0x80800000UL

/* Syscall helpers */
static long u_ecall4(long sys, long a0, long a1, long a2, long a3) {
#ifdef __riscv
    register long r_a0 asm("a0") = a0;
    register long r_a1 asm("a1") = a1;
    register long r_a2 asm("a2") = a2;
    register long r_a3 asm("a3") = a3;
    register long r_a7 asm("a7") = sys;
    asm volatile("ecall"
                 : "+r"(r_a0), "+r"(r_a1), "+r"(r_a2), "+r"(r_a3)
                 : "r"(r_a7)
                 : "memory");
    return r_a0;
#else
    (void)sys; (void)a0; (void)a1; (void)a2; (void)a3;
    return -1;
#endif
}

static long u_invoke(long op, long a1, long a2, long a3) {
    return u_ecall4(V2_INVOKE, op, a1, a2, a3);
}

/* Memory fence for MMIO ordering */
static inline void virtio_fence(void) {
#ifdef __riscv
    asm volatile("fence rw,rw" ::: "memory");
#else
    __asm__ volatile("" ::: "memory");
#endif
}

/*
 * Translate a U VA range to guest-physical for virtio queue programming.
 * Returns 0 on failure (unmapped, below BASE, or straddles pages).
 */
static uint64_t virtio_va_to_pa(uintptr_t va, unsigned long len) {
    unsigned long vpn;
    unsigned long off;
    long pa_base;
    
    if (va < GUI_U_BASE || len == 0 || len > 4096UL)
        return 0;
    
    vpn = (unsigned long)((va - GUI_U_BASE) >> 12);
    off = (unsigned long)(va & 0xFFFUL);
    
    if (off > 4096UL - len)
        return 0; /* Straddles pages: no single PA */
    
    pa_base = u_invoke((long)V2_INV_FRAME_PA, (long)vpn, 0, 0);
    if (pa_base < 0)
        return 0;
    
    return (uint64_t)pa_base + (uint64_t)off;
}

/*
 * Initialize one VirtIO input device: reset, feature negotiation, queue setup.
 * 
 * Parameters:
 *   mmio: MMIO base address for VirtIO transport
 *   ring: Pre-allocated ring structure
 *   queue_size: Number of descriptors (must be <= 16)
 * 
 * Returns:
 *   1 on success, 0 on failure (device not responding or malformed)
 */
int virtio_input_init(volatile uint32_t *mmio, virtio_input_ring_t *ring, int queue_size) {
    uint32_t status;
    uint32_t device_features;
    uint64_t desc_pa;
    uint64_t avail_pa;
    uint64_t used_pa;
    if (!mmio || !ring || queue_size <= 0 || queue_size > 16 ||
        (queue_size & (queue_size - 1)) != 0)
        return 0;
    
    /* Step 0: Presence probe (reads only - no STATUS write yet) */
    if (mmio[VIRTIO_MMIO_MAGIC / 4] != 0x74726976u)
        return 0; /* No VirtIO transport here */
    if (mmio[VIRTIO_MMIO_VERSION / 4] != 2u)
        return 0; /* Legacy transport unsupported */
    if (mmio[VIRTIO_MMIO_DEVICE_ID / 4] != 18u)
        return 0; /* Not an input device */
    
    /* Reset is asynchronous on some transports; don't negotiate until clear. */
    mmio[VIRTIO_MMIO_STATUS / 4] = 0;
    virtio_fence();
    for (uint32_t tries = 0; tries < 100000u; tries++) {
        if (mmio[VIRTIO_MMIO_STATUS / 4] == 0)
            break;
        if (tries == 99999u)
            return 0;
    }
    
    /* Acknowledge, then declare the driver present. */
    mmio[VIRTIO_MMIO_STATUS / 4] = VIRTIO_STATUS_ACKNOWLEDGE;
    virtio_fence();
    mmio[VIRTIO_MMIO_STATUS / 4] = VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER;
    virtio_fence();
    
    /* Modern transports require VIRTIO_F_VERSION_1 (feature bit 32). */
    mmio[VIRTIO_MMIO_DEVICE_FEATURES_SEL / 4] = 1;
    device_features = mmio[VIRTIO_MMIO_DEVICE_FEATURES / 4];
    if (!(device_features & 1u)) {
        mmio[VIRTIO_MMIO_STATUS / 4] = VIRTIO_STATUS_ACKNOWLEDGE |
                                       VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FAILED;
        return 0;
    }
    mmio[VIRTIO_MMIO_DRIVER_FEATURES_SEL / 4] = 1;
    mmio[VIRTIO_MMIO_DRIVER_FEATURES / 4] = 1u;
    mmio[VIRTIO_MMIO_DRIVER_FEATURES_SEL / 4] = 0;
    mmio[VIRTIO_MMIO_DRIVER_FEATURES / 4] = 0;
    mmio[VIRTIO_MMIO_STATUS / 4] = VIRTIO_STATUS_ACKNOWLEDGE |
                                   VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK;
    virtio_fence();
    if ((mmio[VIRTIO_MMIO_STATUS / 4] & VIRTIO_STATUS_FEATURES_OK) == 0)
        goto fail;
    
    /* Step 6: Queue setup (queue 0 = eventq) */
    mmio[VIRTIO_MMIO_QUEUE_SEL / 4] = 0;
    if (mmio[VIRTIO_MMIO_QUEUE_READY / 4] != 0)
        goto fail;
    
    uint32_t qmax = mmio[VIRTIO_MMIO_QUEUE_NUM_MAX / 4];
    if (qmax < (uint32_t)queue_size)
        goto fail;
    
    mmio[VIRTIO_MMIO_QUEUE_NUM / 4] = (uint32_t)queue_size;
    for (int i = 0; i < 16; i++) {
        ring->desc[i].addr = 0;
        ring->desc[i].len = 0;
        ring->desc[i].flags = 0;
        ring->desc[i].next = 0;
        ring->avail.ring[i] = 0;
        ring->used.ring[i].id = 0;
        ring->used.ring[i].len = 0;
        ring->events[i].type = 0;
        ring->events[i].code = 0;
        ring->events[i].value = 0;
    }
    ring->avail.flags = 0;
    ring->avail.idx = 0;
    ring->used.flags = 0;
    ring->used.idx = 0;
    ring->last_used_idx = 0;
    desc_pa = virtio_va_to_pa((uintptr_t)ring->desc, sizeof(ring->desc));
    avail_pa = virtio_va_to_pa((uintptr_t)&ring->avail, sizeof(ring->avail));
    used_pa = virtio_va_to_pa((uintptr_t)&ring->used, sizeof(ring->used));
    if (desc_pa == 0 || avail_pa == 0 || used_pa == 0)
        goto fail;
    if ((desc_pa & 0xFu) != 0 || (avail_pa & 0x1u) != 0 || (used_pa & 0x3u) != 0)
        goto fail;
    
    mmio[VIRTIO_MMIO_QUEUE_DESC_LOW / 4] = (uint32_t)desc_pa;
    mmio[VIRTIO_MMIO_QUEUE_DESC_HIGH / 4] = (uint32_t)(desc_pa >> 32);
    mmio[VIRTIO_MMIO_QUEUE_DRIVER_LOW / 4] = (uint32_t)avail_pa;
    mmio[VIRTIO_MMIO_QUEUE_DRIVER_HIGH / 4] = (uint32_t)(avail_pa >> 32);
    mmio[VIRTIO_MMIO_QUEUE_DEVICE_LOW / 4] = (uint32_t)used_pa;
    mmio[VIRTIO_MMIO_QUEUE_DEVICE_HIGH / 4] = (uint32_t)(used_pa >> 32);
    
    /* Initialize descriptor ring: all slots point to event buffers */
    for (int i = 0; i < queue_size; i++) {
        uint64_t ev_pa = virtio_va_to_pa((uintptr_t)&ring->events[i],
                                         sizeof(ring->events[i]));
        if (ev_pa == 0)
            goto fail;
        
        ring->desc[i].addr = ev_pa;
        ring->desc[i].len = sizeof(struct virtio_input_event);
        ring->desc[i].flags = VIRTQ_DESC_F_WRITE; /* Device writes */
        ring->desc[i].next = 0;
    }
    
    /* Initialize available ring: make all descriptors available */
    ring->avail.flags = 0;
    ring->avail.idx = 0;
    
    for (int i = 0; i < queue_size; i++) {
        ring->avail.ring[i] = (uint16_t)i;
    }
    
    virtio_fence(); /* Fence after populating ring, before updating idx */
    ring->avail.idx = (uint16_t)queue_size; /* Make all descriptors visible */
    
    /* Initialize used ring tracking */
    ring->last_used_idx = 0;
    
    /* Queue ready */
    mmio[VIRTIO_MMIO_QUEUE_READY / 4] = 1;
    virtio_fence();
    if (mmio[VIRTIO_MMIO_QUEUE_READY / 4] != 1)
        goto fail;
    
    /* Step 7: Driver OK */
    mmio[VIRTIO_MMIO_STATUS / 4] = VIRTIO_STATUS_ACKNOWLEDGE |
                                   VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK |
                                   VIRTIO_STATUS_DRIVER_OK;
    virtio_fence();
    status = mmio[VIRTIO_MMIO_STATUS / 4];
    if ((status & (VIRTIO_STATUS_DRIVER_OK | VIRTIO_STATUS_FEATURES_OK)) !=
        (VIRTIO_STATUS_DRIVER_OK | VIRTIO_STATUS_FEATURES_OK))
        goto fail;
    return 1;

fail:
    mmio[VIRTIO_MMIO_STATUS / 4] = VIRTIO_STATUS_ACKNOWLEDGE |
                                   VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FAILED;
    virtio_fence();
    return 0;
}

/*
 * Poll VirtIO input eventq: process all pending events in used ring.
 * 
 * This is a SIMPLIFIED version that ONLY updates the ring state.
 * The CALLER is responsible for processing events from ring->events[].
 * 
 * Parameters:
 *   mmio: MMIO base address
 *   ring: Ring structure
 *   kbd_mods: UNUSED (kept for API compatibility)
 *   mouse: UNUSED (kept for API compatibility)
 *   unused: UNUSED
 * 
 * Returns:
 *   Number of new events available (caller should process ring->events[])
 */
void virtio_input_ack(volatile uint32_t *mmio)
{
    uint32_t isr;
    if (!mmio)
        return;
    isr = mmio[VIRTIO_MMIO_INTERRUPT_STATUS / 4];
    if (isr != 0) {
        mmio[VIRTIO_MMIO_INTERRUPT_ACK / 4] = isr;
        virtio_fence();
    }
}

void virtio_input_notify(volatile uint32_t *mmio)
{
    if (!mmio)
        return;
    virtio_fence();
    mmio[VIRTIO_MMIO_QUEUE_NOTIFY / 4] = 0;
    virtio_fence();
    virtio_input_ack(mmio);
}
