#pragma once

/* Polled 16550A UART on QEMU virt (0x10000000). Implemented in src/flush.c.
 * These back SYS_DEBUG_PUTC/SYS_DEBUG_GETC; boot.c keeps its own
 * VGA-mirroring putc and does not use this header. */
void uart_putc(char c);
/* Non-blocking: 0-255, or -1 when RX empty. Host-sim always returns -1. */
int uart_getc(void);
void print_flush(void);
void print_boot_spawning(void);
