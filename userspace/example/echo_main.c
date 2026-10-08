/* userspace/example/echo_main.c - Simple echo utility for testing shell execution.
 * Demonstrates program argument handling and text output.
 * For this MVP: prints a fixed message (argv parsing requires IPC/shared memory).
 */

#include "../lib/moonlight.h"

static void echo_putc(char c)
{
    moonlight_putc(c);
}

static void echo_puts(const char *s)
{
    while (*s)
        echo_putc(*s++);
}

void echo_main(void)
{
    echo_puts("echo utility: Hello from userspace!\n");
    echo_puts("Program arguments not yet supported (requires IPC integration)\n");
    echo_puts("Current implementation: fixed output only\n");
    echo_puts("Next step: add argv[] via SPAWN/FORK/EXEC parameter passing\n");

    /* Park the thread */
    register long a0 asm("a0") = 0;
    register long a7 asm("a7") = 2; /* V2_PARK */
    asm volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");

    while (1)
    {
    }
}

/* v2 entry shim: v2_start.S jumps here (SPAWN/EXEC zero all regs, so the
 * old start.S `jalr a0` convention faults). echo_main PARKs and never
 * returns; the loop below is unreachable backup. */
void mem_server_main(void)
{
    echo_main();
    while (1)
    {
    }
}
