#include "../include/cheri.h"
#ifdef __x86_64__
#define UART0 0x3F8
static inline void outb(uint16_t port, uint8_t v) {
  __asm__ volatile("outb %0,%1" ::"a"(v), "Nd"(port));
}
static inline uint8_t inb(uint16_t port) {
  uint8_t r;
  __asm__ volatile("inb %1,%0" : "=a"(r) : "Nd"(port));
  return r;
}
static void uart_putc(char c) {
  while ((inb(UART0 + 5) & 0x20) == 0) {
  }
  outb(UART0, c);
}
#else
#define UART0 0x10000000
static void uart_putc(char c) { *(volatile char *)UART0 = c; }
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
