/* userspace/example/ls_main.c - Simple ls utility for testing shell execution.
 * Lists available programs in the initrd.
 * Demonstrates discovery API and iteration patterns.
 */

#include "../lib/moonlight.h"

static void ls_putc(char c)
{
    moonlight_putc(c);
}

static void ls_puts(const char *s)
{
    while (*s)
        ls_putc(*s++);
}

__attribute__((unused)) static void ls_print_ulong(unsigned long v)
{
    char buf[24];
    int i = 0;
    if (v == 0)
    {
        ls_putc('0');
        return;
    }
    while (v > 0 && i < 23)
    {
        buf[i++] = '0' + (v % 10);
        v /= 10;
    }
    while (i-- > 0)
        ls_putc(buf[i]);
}

void ls_main(void)
{
    ls_puts("ls: Available Programs\n");
    ls_puts("======================\n\n");

    ls_puts("System Services (kernel-managed):\n");
    ls_puts("  [0] mem_server.elf\n");
    ls_puts("  [1] qrexec_server.elf\n");
    ls_puts("  [2] adminvm.elf\n");
    ls_puts("  [3] firewall.elf\n");
    ls_puts("  [4] net.elf\n");
    ls_puts("  [5] moonsh.elf\n");
    ls_puts("  [6] ls.elf\n");
    ls_puts("  [7] cat.elf\n");
    ls_puts("  [8] vault.elf\n");
    ls_puts("  [9] cryptblk.elf\n");
    ls_puts("  [10] gui.elf\n\n");

    ls_puts("User Programs (accessible via shell):\n");
    ls_puts("  ls      - list programs (you are here)\n");
    ls_puts("  cat     - file reader (VFS integration pending)\n");
    ls_puts("  echo    - text output utility\n");
    ls_puts("  hello   - hello world test program\n\n");

    ls_puts("Usage:\n");
    ls_puts("  help                 # list all commands\n");
    ls_puts("  exec <name>          # run program\n");
    ls_puts("  spawn <name>         # background job\n\n");

    ls_puts("Discovery API:\n");
    ls_puts("  shell_lookup_program(name)    -> index\n");
    ls_puts("  shell_spawn_program(name)     -> child_tid\n");
    ls_puts("  shell_fork_and_exec(name)     -> child_tid (parent) / replaced (child)\n");

    /* Park the thread */
    register long a0 asm("a0") = 0;
    register long a7 asm("a7") = 2; /* V2_PARK */
    asm volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");

    while (1)
    {
    }
}

/* v2 entry shim: v2_start.S jumps here (SPAWN/EXEC zero all regs, so the
 * old start.S `jalr a0` convention faults). ls_main PARKs and never
 * returns; the loop below is unreachable backup. */
void mem_server_main(void)
{
    ls_main();
    while (1)
    {
    }
}
