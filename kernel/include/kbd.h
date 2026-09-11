#pragma once
/* kbd - keyboard driver: virtio-input (MMIO) + UART merged into one ring.
 *
 * QEMU riscv-virt has no PS/2; the graphical window only feeds a
 * virtio-keyboard-device (virtio-mmio transport at 0x10001000+i*0x1000).
 * Serial input still arrives via the 16550 UART. This driver drains both
 * sources in kbd_poll() so SYS_DEBUG_GETC / moonsh see a single stream
 * regardless of where the user types.
 *
 * No interrupts yet (M-mode polling, like the UART): kbd_poll() is called
 * from the SYS_DEBUG_GETC path and drains a bounded number of events per
 * call (WCET-friendly). IRQ/PLIC binding stays on the roadmap - the virtio
 * used-ring + InterruptStatus/ACK handshake is already in place, so moving
 * to irq_bind() + Notification later needs no queue rework.
 *
 * The event core (kbd_put_event: press/release, shift/caps/ctrl tracking,
 * EV_KEY code -> ASCII/ANSI translation, ring push) is pure C and
 * host-testable (tests/test_kbd.c). Only the MMIO transport behind
 * kbd_virtio_init() is __riscv-only.
 */
#include "types.h"
#include "vspace.h"

/* virtio-input event types (virtio spec, LE) */
#define KBD_EV_SYN 0x00
#define KBD_EV_KEY 0x01
#define KBD_EV_LED 0x11
#define KBD_EV_REP 0x14

/* EV_KEY values */
#define KBD_KEY_RELEASE 0
#define KBD_KEY_PRESS   1
#define KBD_KEY_REPEAT  2

/* Subset of Linux KEY_* codes we translate (input-event-codes.h) */
#define KBD_KEY_ESC        1
#define KBD_KEY_BACKSPACE  14
#define KBD_KEY_TAB        15
#define KBD_KEY_ENTER      28
#define KBD_KEY_LEFTCTRL   29
#define KBD_KEY_LEFTSHIFT  42
#define KBD_KEY_RIGHTSHIFT 54
#define KBD_KEY_LEFTALT    56
#define KBD_KEY_SPACE      57
#define KBD_KEY_CAPSLOCK   58
#define KBD_KEY_DELETE     111
#define KBD_KEY_UP         103
#define KBD_KEY_DOWN       108
#define KBD_KEY_LEFT       105
#define KBD_KEY_RIGHT      106
#define KBD_KEY_HOME       102
#define KBD_KEY_END        107
#define KBD_KEY_PAGEUP     104
#define KBD_KEY_PAGEDOWN   109

#define KBD_RING_BITS 8
#define KBD_RING_SIZE (1u << KBD_RING_BITS)

typedef struct {
    uint8_t present;        /* 1 once a virtio-input device negotiated queues */
    uint8_t transport;      /* virtio-mmio slot that bound (0..7) */
    uint16_t device_id;     /* expect 18 (virtio input) */
    uint32_t ev_total;      /* EV_KEY triples fed to the translator */
    uint32_t ascii_total;   /* bytes pushed to the ring (virtio + uart) */
    uint32_t drops;         /* bytes lost to a full ring */
    uint16_t last_code;     /* last EV_KEY code seen */
    int16_t last_value;     /* its value (-1 = none yet) */
    uint16_t ring_used;     /* bytes currently buffered */
} kbd_status_t;

/* Reset ring + modifier state + stats. Safe to call before MMIO exists. */
void kbd_init(void);
/* Target-only: map 0x10001000 (8 transports) and negotiate a virtio-input
 * device (queues, event buffers, DRIVER_OK). Returns ERR_OK with
 * status.present=1, or ERR_NO_MEM when no keyboard is attached (UART-only
 * fallback - not a boot failure). Host-sim always returns ERR_NO_MEM. */
kerror_t kbd_virtio_init(vspace_t *vs);
/* Drain virtio used ring + UART RX into the ring (bounded work). */
void kbd_poll(void);
/* Poll, then pop one byte. Returns 0-255, or -1 when empty (never blocks). */
int kbd_getc(void);
/* Core translator: feed one (type, code, value) triple. Testable on host. */
void kbd_put_event(uint16_t type, uint16_t code, int32_t value);
/* Push one raw serial byte (UART path). Counts drops on overflow. */
void kbd_push_ascii(char c);
void kbd_status(kbd_status_t *out);
/* 1 once virtio-input bound (window typing works), 0 for UART-only. */
int kbd_is_present(void);
