/* userspace/example/hello_main.c - Simple test program for shell execution.
 * Demonstrates basic ELF loading and userspace execution.
 * Builds as hello.elf and can be spawned via shell_spawn_program("hello").
 */

#include "../lib/moonlight.h"

static void hello_putc(char c)
{
    moonlight_putc(c);
}

static void hello_puts(const char *s)
{
    while (*s)
        hello_putc(*s++);
}

void hello_main(void)
{
    hello_puts("Hello from userspace ELF!\n");
    hello_puts("Program counter: 0x");

    /* Print program counter (return address) */
    unsigned long pc;
    asm("auipc %0, 0" : "=r"(pc));
    for (int i = 15; i >= 0; i--)
    {
        unsigned d = (pc >> (i * 4)) & 0xF;
        hello_putc(d < 10 ? '0' + d : 'a' + d - 10);
    }
    hello_puts("\n");

    hello_puts("Calling V2_PARK to exit gracefully...\n");

    /* Park the thread (yield forever) via ecall */
    register long a0 asm("a0") = 0;
    register long a7 asm("a7") = 2; /* V2_PARK */
    asm volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");

    /* Should not reach here */
    while (1)
    {
    }
}

/* v2 entry shim: v2_start.S jumps here (SPAWN/EXEC zero all regs, so the
 * old start.S `jalr a0` convention faults). hello_main PARKs and never
 * returns; the loop below is unreachable backup. */
void mem_server_main(void)
{
    hello_main();
    while (1)
    {
    }
}
