/* userspace/example/cat_main.c - Simple cat utility for testing shell execution.
 * Reads and displays text, demonstrating basic I/O and ELF loading.
 * For this MVP: just print a test message (actual file I/O requires VFS).
 */

#include "../lib/moonlight.h"

static void cat_putc(char c)
{
    moonlight_putc(c);
}

static void cat_puts(const char *s)
{
    while (*s)
        cat_putc(*s++);
}

void cat_main(void)
{
    cat_puts("cat utility loaded successfully\n");
    cat_puts("Note: File I/O requires VFS integration\n");
    cat_puts("For now, this is a test stub.\n\n");
    cat_puts("Available programs can be discovered via shell 'help' command.\n");
    cat_puts("To implement full cat: add VFS read syscall\n");

    /* Park the thread */
    register long a0 asm("a0") = 0;
    register long a7 asm("a7") = 2; /* V2_PARK */
    asm volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");

    while (1)
    {
    }
}

/* v2 entry shim: v2_start.S jumps here (SPAWN/EXEC zero all regs, so the
 * old start.S `jalr a0` convention faults). cat_main PARKs and never
 * returns; the loop below is unreachable backup. */
void mem_server_main(void)
{
    cat_main();
    while (1)
    {
    }
}
