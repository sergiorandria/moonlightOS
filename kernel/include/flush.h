#pragma once

/* Polled 16550A UART on QEMU virt (0x10000000). Implemented in src/flush.c.
 * uart_putc always hits the UART (and mirrors to the VGA console once
 * vga_init() has run). The SYS_DEBUG_PUTC path should use console_putc()
 * (console.h) instead, so the window-split shell does not spam serial.
 * boot.c keeps its own early-boot putc and does not use this header. */
void uart_putc(char c);
/* Non-blocking: 0-255, or -1 when RX empty. Host-sim always returns -1. */
int uart_getc(void);
void print_flush(void);
void print_boot_spawning(void);
