/* moonsh - minimal shell above MoonlightOS. Freestanding, no libc.
 *
 * Runs as a cooperative thread (own stack, see kernel thread_enter):
 * reads lines from SYS_DEBUG_GETC, runs builtins, writes via
 * SYS_DEBUG_PUTC. Everything is synchronous; blocking waits yield.
 *
 * Honest stubs: `ps`/`mem` need a kernel INFO path (scheduler dispatch +
 * per-thread state query) that does not exist yet - they say so instead
 * of printing fake data.
 */
#include "../lib/moonlight.h"

#define SHELL_LINE_MAX 128

static void shell_puts(const char *s) {
    while (*s) moonlight_putc(*s++);
}

static int shell_streq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static int shell_strncmp(const char *a, const char *b, int n) {
    for (int i = 0; i < n; i++) {
        if (a[i] != b[i] || a[i] == '\0') return (unsigned char)a[i] - (unsigned char)b[i];
    }
    return 0;
}

static unsigned long shell_rdtime(void) {
#ifdef __riscv
    unsigned long t;
    asm volatile("rdtime %0" : "=r"(t));
    return t;
#else
    static unsigned long tick;
    return ++tick;
#endif
}

static void shell_print_ulong(unsigned long v) {
    char buf[24];
    int i = 0;
    if (v == 0) { moonlight_putc('0'); return; }
    while (v > 0 && i < 23) { buf[i++] = '0' + (v % 10); v /= 10; }
    while (i-- > 0) moonlight_putc(buf[i]);
}

/* Testable core: parse + dispatch one line. No static state. */
void shell_exec_line(const char *line) {
    while (*line == ' ') line++;
    if (*line == '\0') return;
    if (shell_streq(line, "help")) {
        shell_puts("moonsh builtins:\n");
        shell_puts("  help            this list\n");
        shell_puts("  echo <text>     print text\n");
        shell_puts("  clear           clear screen\n");
        shell_puts("  yield           yield the CPU (ecall test)\n");
        shell_puts("  uptime          timer ticks since boot\n");
        shell_puts("  ps              process list (needs scheduler dispatch)\n");
        shell_puts("  mem             memory map (needs INFO syscall)\n");
    } else if (shell_strncmp(line, "echo ", 5) == 0) {
        shell_puts(line + 5);
        moonlight_putc('\n');
    } else if (shell_streq(line, "echo")) {
        moonlight_putc('\n');
    } else if (shell_streq(line, "clear")) {
        shell_puts("\x1b[2J\x1b[H");
    } else if (shell_streq(line, "yield")) {
        moonlight_yield();
        shell_puts("yielded OK\n");
    } else if (shell_streq(line, "uptime")) {
        shell_puts("ticks: ");
        shell_print_ulong(shell_rdtime());
        moonlight_putc('\n');
    } else if (shell_streq(line, "ps")) {
        shell_puts("STATE         THREAD\n");
        shell_puts("RUNNING       this shell (hart0, cooperative)\n");
        shell_puts("note: TCB table needs scheduler dispatch (TODO)\n");
    } else if (shell_streq(line, "mem")) {
        shell_puts("needs INFO syscall for allocator state (TODO)\n");
    } else {
        shell_puts("moonsh: unknown command: ");
        shell_puts(line);
        shell_puts("\ntype 'help'\n");
    }
}

void shell_main(void) {
    shell_puts("\nmoonsh 0.1 on MoonlightOS (type 'help')\n");
    char line[SHELL_LINE_MAX];
    int len = 0;
    for (;;) {
        shell_puts("moonsh> ");
        len = 0;
        for (;;) {
            int c = moonlight_getc();
            if (c < 0) { moonlight_yield(); continue; }
            if (c == '\r') c = '\n';
            if (c == '\n') {
                moonlight_putc('\n');
                break;
            }
            if (c == 0x7f || c == 0x08) { /* backspace */
                if (len > 0) {
                    len--;
                    shell_puts("\b \b");
                }
                continue;
            }
            if (len < SHELL_LINE_MAX - 1) {
                line[len++] = (char)c;
                moonlight_putc((char)c); /* echo */
            }
        }
        line[len] = '\0';
        shell_exec_line(line);
    }
}
