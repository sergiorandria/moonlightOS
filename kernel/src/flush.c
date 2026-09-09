#include "../include/cheri.h"
#include "../include/flush.h"
/* RISC-V-only UART (QEMU virt 0x10000000 MMIO). Host-sim falls back to putchar. */
#ifdef __riscv
#define UART0 0x10000000
#define UART_LSR ((volatile uint8_t *)0x10000005)
#define UART_RBR ((volatile uint8_t *)0x10000000)
void uart_putc(char c) {
    while ((*UART_LSR & 0x20) == 0) {} /* wait TX ready: no FIFO drops */
    *(volatile char *)UART0 = c;
}
/* Non-blocking RX: char 0-255, or -1 if empty. QEMU -serial mon:stdio feeds stdin. */
int uart_getc(void) {
    if ((*UART_LSR & 0x01) == 0) return -1;
    return *UART_RBR;
}
#else
extern int putchar(int);
void uart_putc(char c) { putchar(c); }
/* Host-sim: never block a unit test on stdin. Target-only input path. */
int uart_getc(void) { return -1; }
#endif
void print_flush(void) {
  uart_putc('[');
  uart_putc('F');
  uart_putc('L');
  uart_putc('U');
  uart_putc('S');
  uart_putc('H');
  uart_putc(']');
  uart_putc(' ');
  uart_putc('m');
  uart_putc('i');
  uart_putc('c');
  uart_putc('r');
  uart_putc('o');
  uart_putc('a');
  uart_putc('r');
  uart_putc('c');
  uart_putc('h');
  uart_putc(' ');
  uart_putc('o');
  uart_putc('k');
  uart_putc(' ');
  uart_putc('-');
  uart_putc(' ');
  uart_putc('d');
  uart_putc('o');
  uart_putc('n');
  uart_putc('e');
  uart_putc('\n');
}

void print_boot_spawning(void) {
  uart_putc('[');
  uart_putc('B');
  uart_putc('O');
  uart_putc('O');
  uart_putc('T');
  uart_putc(']');
  uart_putc(' ');
  uart_putc('A');
  uart_putc('L');
  uart_putc('L');
  uart_putc(' ');
  uart_putc('O');
  uart_putc('K');
  uart_putc(' ');
  uart_putc('-');
  uart_putc(' ');
  uart_putc('s');
  uart_putc('p');
  uart_putc('a');
  uart_putc('w');
  uart_putc('n');
  uart_putc('i');
  uart_putc('n');
  uart_putc('g');
  uart_putc(' ');
  uart_putc('u');
  uart_putc('s');
  uart_putc('e');
  uart_putc('r');
  uart_putc('s');
  uart_putc('p');
  uart_putc('a');
  uart_putc('c');
  uart_putc('e');
  uart_putc('\n');
}
