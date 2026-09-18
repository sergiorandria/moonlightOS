/* moonsh - minimal shell above MoonlightOS. Freestanding, no libc.
 *
 * Runs as a cooperative thread (own stack, see kernel thread_enter):
 * reads lines from SYS_DEBUG_GETC (virtio-keyboard + UART merged ring in
 * kernel/src/kbd.c), runs builtins, writes via SYS_DEBUG_PUTC. Everything
 * is synchronous; blocking waits yield.
 *
 * Input arrives already translated: virtio EV_KEY arrows come down as the
 * same ESC [ A..D sequences a serial terminal sends, so one parser serves
 * both the graphical window and the serial console. Only VGA-safe output
 * is used for editing (printables, \b, \r, \n): the framebuffer console
 * has no ANSI parser.
 *
 * Optional kernel hooks (weak: the userspace moonsh.elf build has none):
 *   moonsh_kbd_status()  one-line virtio-input status for `kbd`
 *   moonsh_system_reset() SiFive test-finisher for poweroff/reboot
 *   moonsh_console_clear() clear the visible console(s) for `clear`
 *   moonsh_console_mode() 1 = split (window shell) for `console`
 *
 * `ps` lists the TCB table via the moonsh_ps_line hook (kernel) with the
 * dispatcher's next pick; `mem` dumps allocator stats via moonsh_mem_status.
 * Without the hooks (userspace build) both print their honest TODO stubs.
 */
#include "../lib/moonlight.h"

#define SHELL_LINE_MAX 128
#define SHELL_HIST_MAX 8

/* Weak kernel hooks (see above). NULL when linked as userspace ELF. */
__attribute__((weak)) int moonsh_kbd_status(char *buf, unsigned len);
__attribute__((weak)) void moonsh_system_reset(int do_reset);
__attribute__((weak)) void moonsh_console_clear(void);
__attribute__((weak)) int moonsh_console_mode(void);
__attribute__((weak)) int moonsh_ps_line(char *buf, unsigned len, unsigned *cursor);
__attribute__((weak)) int moonsh_mem_status(char *buf, unsigned len);
__attribute__((weak)) int moonsh_kill_tid(long tid, int op);
__attribute__((weak)) int moonsh_nice_tid(long tid, int prio);

/* VFS (userspace/vfs_server/server.c), linked into the kernel image but
 * absent from the bare userspace ELF: weak like the moonsh_* hooks. The
 * shell is just another client (reserved id, own fd table); all isolation
 * and validation still apply. Backing frames for shell-created files come
 * from a tiny demo pool below (production: Untyped retype via invoke). */
__attribute__((weak)) int vfs_create(unsigned caller, const char *name, unsigned cap, unsigned size, unsigned short color, unsigned short omode);
__attribute__((weak)) int vfs_open(unsigned caller, const char *name, unsigned rights);
__attribute__((weak)) int vfs_read(unsigned caller, int fd, void *buf, unsigned long len);
__attribute__((weak)) int vfs_write(unsigned caller, int fd, const void *buf, unsigned long len);
__attribute__((weak)) int vfs_close(unsigned caller, int fd);
__attribute__((weak)) int vfs_unlink(unsigned caller, const char *name);
__attribute__((weak)) int vfs_stat(unsigned caller, const char *name, unsigned *size_out, unsigned *used_out);
__attribute__((weak)) int vfs_list(int *cursor, char *name_out, unsigned *size_out, unsigned *used_out);
__attribute__((weak)) void vfs_server_init(void);
#define VFS_SHELL_CLIENT 128u
#define VFS_R 1u
#define VFS_W 2u
static unsigned char vfs_shell_frames[2][4096];
static unsigned vfs_shell_nframes;

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

/* Like shell_atoul but reports where the number ended (multi-arg commands).
 * Caps at 10 digits (fits in 64 bits, no wrap); more digits => invalid. */
static int shell_atoul_end(const char *s, unsigned long *out, const char **end) {
    unsigned long v = 0;
    int digits = 0;
    const char *p = s;
    while (*p == ' ') p++;
    s = p;
    while (*p >= '0' && *p <= '9') {
        if (digits < 10) v = v * 10u + (unsigned long)(*p - '0');
        digits++;
        p++;
    }
    if (!digits || digits > 10) return 0;
    *out = v;
    *end = p;
    return 1;
}

/* Decimal only. Returns 1 on success (at least one digit, nothing else). */
static int shell_atoul(const char *s, unsigned long *out) {
    unsigned long v = 0;
    int digits = 0;
    while (*s == ' ') s++;
    while (*s >= '0' && *s <= '9') {
        v = v * 10u + (unsigned long)(*s - '0');
        digits++;
        s++;
    }
    while (*s == ' ') s++;
    if (!digits || *s != '\0') return 0;
    *out = v;
    return 1;
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

static void shell_put_hex(unsigned v, int width) {
    int i;
    for (i = width - 1; i >= 0; i--) {
        unsigned d = (v >> (i * 4)) & 0xF;
        moonlight_putc(d < 10 ? (char)('0' + d) : (char)('a' + d - 10));
    }
}

/* Classic hexdump of a byte range: offset, hex, ASCII. */
static void shell_hexdump(const char *data, int len) {
    int off = 0;
    while (off < len) {
        int row = len - off > 16 ? 16 : len - off;
        int i;
        shell_put_hex((unsigned)off, 4);
        shell_puts(": ");
        for (i = 0; i < 16; i++) {
            if (i < row) {
                shell_put_hex((unsigned char)data[off + i], 2);
            } else {
                shell_puts("  ");
            }
            moonlight_putc(i == 7 ? '-' : ' ');
        }
        shell_puts(" |");
        for (i = 0; i < row; i++) {
            char c = data[off + i];
            moonlight_putc(c >= 0x20 && c < 0x7f ? c : '.');
        }
        shell_puts("|\n");
        off += row;
    }
}

/* ---- history + input stats (shared by exec + line reader) ---- */
static char shell_hist[SHELL_HIST_MAX][SHELL_LINE_MAX];
static int shell_hist_count;
static unsigned long shell_stat_lines;
static unsigned long shell_stat_chars;

void shell_test_reset(void) {
    int i, j;
    for (i = 0; i < SHELL_HIST_MAX; i++)
        for (j = 0; j < SHELL_LINE_MAX; j++) shell_hist[i][j] = '\0';
    shell_hist_count = 0;
    shell_stat_lines = 0;
    shell_stat_chars = 0;
}

static void shell_history_add(const char *line) {
    int i, j;
    if (!line || *line == '\0') return;
    if (shell_hist_count > 0) {
        const char *prev = shell_hist[(shell_hist_count - 1) % SHELL_HIST_MAX];
        int k = 0;
        while (line[k] && prev[k] && line[k] == prev[k]) k++;
        if (line[k] == '\0' && prev[k] == '\0') return; /* consecutive dup */
    }
    if (shell_hist_count < 1000000) shell_hist_count++;
    if (shell_hist_count <= SHELL_HIST_MAX) {
        for (j = 0; line[j] && j < SHELL_LINE_MAX - 1; j++)
            shell_hist[shell_hist_count - 1][j] = line[j];
        shell_hist[shell_hist_count - 1][j] = '\0';
    } else {
        for (i = 0; i < SHELL_HIST_MAX - 1; i++)
            for (j = 0; j < SHELL_LINE_MAX; j++)
                shell_hist[i][j] = shell_hist[i + 1][j];
        for (j = 0; line[j] && j < SHELL_LINE_MAX - 1; j++)
            shell_hist[SHELL_HIST_MAX - 1][j] = line[j];
        shell_hist[SHELL_HIST_MAX - 1][j] = '\0';
    }
}

/* 1-based index as shown by `history`. Returns NULL when out of range. */
static const char *shell_history_get(int n) {
    int entries = shell_hist_count < SHELL_HIST_MAX ? shell_hist_count : SHELL_HIST_MAX;
    if (n < 1 || n > entries) return NULL;
    return shell_hist[n - 1];
}

static void shell_history_show(void) {
    int entries = shell_hist_count < SHELL_HIST_MAX ? shell_hist_count : SHELL_HIST_MAX;
    int i;
    for (i = 0; i < entries; i++) {
        shell_print_ulong((unsigned long)(i + 1));
        shell_puts("  ");
        shell_puts(shell_hist[i]);
        moonlight_putc('\n');
    }
}

static void shell_help_topic(const char *topic) {
    if (shell_streq(topic, "echo")) {
        shell_puts("echo [-n] <text>: print text (+ newline unless -n)\n");
    } else if (shell_streq(topic, "exec")) {
        shell_puts("exec <path> [args...]: replace shell with program from initrd\n");
    } else if (shell_streq(topic, "echo")) {
        shell_puts("echo [-n] <text>: print text (+ newline unless -n)\n");
    } else if (shell_streq(topic, "hex")) {
        shell_puts("hex <text>: hexdump the argument bytes\n");
    } else if (shell_streq(topic, "sleep")) {
        shell_puts("sleep <ticks>: wait N timer ticks, yielding\n");
    } else if (shell_streq(topic, "history")) {
        shell_puts("history: list recent commands; !! repeats last, !n repeats #n\n");
    } else if (shell_streq(topic, "kbd")) {
        shell_puts("kbd: keyboard driver status (virtio-input + UART ring)\n");
    } else if (shell_streq(topic, "hd")) {
        shell_puts("hd: alias for hex\n");
    } else if (shell_streq(topic, "ver") || shell_streq(topic, "version") ||
               shell_streq(topic, "uname")) {
        shell_puts("ver: MoonlightOS version and platform\n");
    } else if (shell_streq(topic, "poweroff") || shell_streq(topic, "reboot")) {
        shell_puts("poweroff/reboot: halt or reset via SiFive test-finisher\n");
    } else if (shell_streq(topic, "clear") || shell_streq(topic, "cls")) {
        shell_puts("clear: clear screen (cls works too)\n");
    } else if (shell_streq(topic, "console")) {
        shell_puts("console: show serial/VGA routing (split vs mirror)\n");
    } else if (shell_streq(topic, "yield")) {
        shell_puts("yield: yield the CPU (ecall test)\n");
    } else if (shell_streq(topic, "uptime") || shell_streq(topic, "ticks")) {
        shell_puts("uptime: timer ticks since boot (ticks is an alias)\n");
    } else if (shell_streq(topic, "ps")) {
        shell_puts("ps: threads, states, budgets + dispatcher's next pick\n");
    } else if (shell_streq(topic, "kill")) {
        shell_puts("kill [-STOP|-CONT] <tid>: destroy (default), suspend, resume\n");
    } else if (shell_streq(topic, "ls")) {
        shell_puts("ls: list files (name size/used)\n");
    } else if (shell_streq(topic, "cat")) {
        shell_puts("cat <file>: print file contents\n");
    } else if (shell_streq(topic, "write")) {
        shell_puts("write <file> <text...>: create (first use) + overwrite from offset 0\n");
    } else if (shell_streq(topic, "rm")) {
        shell_puts("rm <file>: delete your own file (must be closed)\n");
    } else if (shell_streq(topic, "nice")) {
        shell_puts("nice <tid> <prio>: retarget priority 0-255 (0 highest)\n");
    } else if (shell_streq(topic, "mem")) {
        shell_puts("mem: frame pool usage, per-color counts, PT pages\n");
    } else {
        shell_puts("moonsh: no help for '");
        shell_puts(topic);
        shell_puts("'\n");
    }
}

/* Testable core: parse + dispatch one line. Pushes history (no static input
 * state besides history/stats, so unit tests drive it directly). */
void shell_exec_line(const char *line) {
    const char *cmd = line;
    while (*cmd == ' ') cmd++;
    if (*cmd == '\0') return;

    /* History expansion (not re-pushed literally; the expansion is). */
    if (cmd[0] == '!') {
        const char *exp = NULL;
        if (cmd[1] == '!') {
            int entries = shell_hist_count < SHELL_HIST_MAX ? shell_hist_count : SHELL_HIST_MAX;
            if (entries == 0) {
                shell_puts("moonsh: no history yet\n");
                return;
            }
            exp = shell_history_get(entries);
            if (cmd[2] != '\0' && cmd[2] != ' ') {
                shell_puts("moonsh: use `!!` alone or `!n`\n");
                return;
            }
        } else {
            unsigned long n = 0;
            if (!shell_atoul(cmd + 1, &n) || n == 0) {
                shell_puts("moonsh: use `!!` or `!n` (n >= 1)\n");
                return;
            }
            exp = shell_history_get((int)n);
            if (!exp) {
                shell_puts("moonsh: no such history entry\n");
                return;
            }
        }
        shell_puts(exp);
        moonlight_putc('\n');
        shell_history_add(exp);
        shell_exec_line(exp);
        return;
    }
    shell_history_add(cmd);

    if (shell_strncmp(cmd, "help", 4) == 0 && (cmd[4] == '\0' || cmd[4] == ' ')) {
        const char *t = cmd + 4;
        while (*t == ' ') t++;
        if (*t) {
            shell_help_topic(t);
            return;
        }
        shell_puts("moonsh builtins:\n");
        shell_puts("  help [cmd]      this list (or one command)\n");
        shell_puts("  echo [-n] <tx>  print text\n");
        shell_puts("  hex <text>      hexdump argument bytes (hd works too)\n");
        shell_puts("  clear           clear screen (cls works too)\n");
        shell_puts("  console         show serial/VGA routing\n");
        shell_puts("  history         list recent commands (!! / !n repeat)\n");
        shell_puts("  yield           yield the CPU (ecall test)\n");
        shell_puts("  sleep <ticks>   wait N timer ticks\n");
        shell_puts("  uptime          timer ticks since boot (ticks too)\n");
        shell_puts("  ver             OS version (version/uname too)\n");
        shell_puts("  kbd             keyboard driver status\n");
        shell_puts("  ps              threads + next pick (cooperative dispatch)\n");
        shell_puts("  mem             allocator + page-table usage\n");
        shell_puts("  kill [-STOP|-CONT] <tid>  destroy | suspend | resume\n");
        shell_puts("  nice <tid> <p>  retarget priority 0-255 (0 highest)\n");
        shell_puts("  ls              list files (VFS, per-client fds)\n");
        shell_puts("  cat <file>      print file contents\n");
        shell_puts("  write <f> <tx>  create + overwrite file with text\n");
        shell_puts("  rm <file>       delete own closed file\n");
        shell_puts("  poweroff        halt (reboot resets)\n");
    } else if (shell_strncmp(cmd, "echo", 4) == 0 && (cmd[4] == '\0' || cmd[4] == ' ')) {
        const char *t = cmd + 4;
        int nl = 1;
        while (*t == ' ') t++;
        if (shell_strncmp(t, "-n", 2) == 0 && (t[2] == '\0' || t[2] == ' ')) {
            nl = 0;
            t += 2;
            while (*t == ' ') t++;
        }
        shell_puts(t);
        if (nl) moonlight_putc('\n');
    } else if (shell_streq(cmd, "clear") || shell_streq(cmd, "cls")) {
        /* Kernel hook clears the real framebuffer (no ANSI parser there);
         * userspace build falls back to ANSI for its serial terminal. */
        if (moonsh_console_clear) moonsh_console_clear();
        else shell_puts("\x1b[2J\x1b[H");
    } else if (shell_streq(cmd, "console")) {
        if (moonsh_console_mode)
            shell_puts(moonsh_console_mode() ?
                "console: split - shell on VGA + virtio-kbd (serial keeps boot log)\n" :
                "console: mirror - shell on serial + VGA\n");
        else
            shell_puts("console: kernel status unavailable in this build\n");
    } else if (shell_streq(cmd, "yield")) {
        moonlight_yield();
        shell_puts("yielded OK\n");
    } else if (shell_strncmp(cmd, "sleep", 5) == 0 && (cmd[5] == '\0' || cmd[5] == ' ')) {
        const char *t = cmd + 5;
        unsigned long n = 0;
        while (*t == ' ') t++;
        if (!shell_atoul(t, &n)) {
            shell_puts("usage: sleep <ticks>\n");
        } else {
            unsigned long start = shell_rdtime();
            while (shell_rdtime() - start < n) moonlight_yield();
            shell_puts("slept ");
            shell_print_ulong(n);
            shell_puts(" ticks\n");
        }
    } else if (shell_streq(cmd, "uptime") || shell_streq(cmd, "ticks")) {
        shell_puts("ticks: ");
        shell_print_ulong(shell_rdtime());
        moonlight_putc('\n');
    } else if (shell_streq(cmd, "ver") || shell_streq(cmd, "version") ||
               shell_streq(cmd, "uname")) {
        shell_puts("moonsh 0.2 on MoonlightOS (rv64 Sv39, M-mode cooperative)\n");
        shell_puts("input: virtio-keyboard + UART merged (see `kbd`)\n");
    } else if (shell_streq(cmd, "kbd")) {
        char kb[160];
        int i;
        for (i = 0; i < 160; i++) kb[i] = '\0';
        if (moonsh_kbd_status) {
            int n = moonsh_kbd_status(kb, sizeof(kb));
            if (n > 0) {
                shell_puts("kbd: ");
                shell_puts(kb);
                moonlight_putc('\n');
            } else {
                shell_puts("kbd: driver present, status unavailable\n");
            }
        } else {
            shell_puts("kbd: merged virtio-input + UART ring (kernel status needs INFO path)\n");
        }
        shell_puts("shell input: lines=");
        shell_print_ulong(shell_stat_lines);
        shell_puts(" chars=");
        shell_print_ulong(shell_stat_chars);
        moonlight_putc('\n');
    } else if (shell_streq(cmd, "history")) {
        shell_history_show();
    } else if ((shell_strncmp(cmd, "hex", 3) == 0 && (cmd[3] == '\0' || cmd[3] == ' ')) ||
               (shell_strncmp(cmd, "hd", 2) == 0 && (cmd[2] == '\0' || cmd[2] == ' '))) {
        const char *t = cmd[1] == 'd' ? cmd + 2 : cmd + 3;
        while (*t == ' ') t++;
        if (*t == '\0') {
            shell_puts("usage: hex <text>\n");
        } else {
            /* Join remaining args with single spaces for the dump. */
            char joined[SHELL_LINE_MAX];
            int j = 0, k = 0;
            while (t[k] && j < SHELL_LINE_MAX - 1) {
                if (t[k] == ' ' && (k == 0 || t[k - 1] == ' ')) { k++; continue; }
                joined[j++] = t[k++];
            }
            while (j > 0 && joined[j - 1] == ' ') j--;
            joined[j] = '\0';
            shell_hexdump(joined, j);
        }
    } else if (shell_streq(cmd, "hd")) {
        shell_puts("usage: hd <text> (alias for hex)\n");
    } else if (shell_streq(cmd, "ps")) {
        char pb[256];
        unsigned cur = 0;
        if (moonsh_ps_line) {
            shell_puts("TID NAME         STATE        PC       PART PRIO BUDGET/LEFT\n");
            while (moonsh_ps_line(pb, sizeof(pb), &cur)) shell_puts(pb);
            shell_puts("shell: hart0 M-mode idle (outside TCB table)\n");
        } else {
            shell_puts("STATE         THREAD\n");
            shell_puts("RUNNING       this shell (hart0, cooperative)\n");
            shell_puts("note: TCB table needs scheduler dispatch (TODO)\n");
        }
    } else if (shell_streq(cmd, "mem")) {
        char mb[256];
        if (moonsh_mem_status && moonsh_mem_status(mb, sizeof(mb)) > 0)
            shell_puts(mb);
        else
            shell_puts("needs INFO syscall for allocator state (TODO)\n");
    } else if (shell_strncmp(cmd, "kill", 4) == 0 && (cmd[4] == '\0' || cmd[4] == ' ')) {
        const char *t = cmd + 4;
        int op = 0;
        unsigned long n = 0;
        while (*t == ' ') t++;
        if (shell_strncmp(t, "-STOP", 5) == 0 && (t[5] == '\0' || t[5] == ' ')) {
            op = 1;
            t += 5;
            while (*t == ' ') t++;
        } else if (shell_strncmp(t, "-CONT", 5) == 0 && (t[5] == '\0' || t[5] == ' ')) {
            op = 2;
            t += 5;
            while (*t == ' ') t++;
        }
        if (!shell_atoul(t, &n) || n > 1000000ul) {
            shell_puts("usage: kill [-STOP|-CONT] <tid>\n");
        } else if (!moonsh_kill_tid) {
            shell_puts("kill needs the process table (TODO in this build)\n");
        } else {
            int r = moonsh_kill_tid((long)n, op);
            if (r == 0) {
                shell_puts(op == 0 ? "killed tid " : op == 1 ? "stopped tid " : "resumed tid ");
                shell_print_ulong(n);
                moonlight_putc('\n');
            } else if (r == -2) {
                shell_puts("kill: bad operation\n");
            } else {
                shell_puts("kill: no such thread: ");
                shell_print_ulong(n);
                moonlight_putc('\n');
            }
        }
    } else if (shell_strncmp(cmd, "nice", 4) == 0 && (cmd[4] == '\0' || cmd[4] == ' ')) {
        const char *t = cmd + 4, *e;
        unsigned long tid = 0, prio = 0;
        if (!shell_atoul_end(t, &tid, &e) || tid > 1000000ul) {
            shell_puts("usage: nice <tid> <prio 0-255>\n");
        } else {
            t = e;
            if (!shell_atoul_end(t, &prio, &e) || prio > 255) {
                shell_puts("usage: nice <tid> <prio 0-255>\n");
            } else {
                t = e;
                while (*t == ' ') t++;
                if (*t != '\0') {
                    shell_puts("usage: nice <tid> <prio 0-255>\n");
                } else if (!moonsh_nice_tid) {
                    shell_puts("nice needs the scheduler (TODO in this build)\n");
                } else {
                    int r = moonsh_nice_tid((long)tid, (int)prio);
                    if (r == 0) {
                        shell_puts("tid ");
                        shell_print_ulong(tid);
                        shell_puts(" now prio ");
                        shell_print_ulong(prio);
                        moonlight_putc('\n');
                    } else if (r == -2) {
                        shell_puts("nice: priority must be 0-255\n");
                    } else {
                        shell_puts("nice: no such thread: ");
                        shell_print_ulong(tid);
                        moonlight_putc('\n');
                    }
                }
            }
        }
    } else if (shell_streq(cmd, "ls")) {
        if (!vfs_list) {
            shell_puts("ls needs the VFS (TODO in this build)\n");
        } else {
            int cur = 0, n = 0;
            char nm[32];
            unsigned sz = 0, used = 0;
            while (vfs_list(&cur, nm, &sz, &used) == 0) {
                shell_puts(nm);
                shell_puts(" ");
                shell_print_ulong(sz);
                moonlight_putc('/');
                shell_print_ulong(used);
                moonlight_putc('\n');
                n++;
            }
            if (n == 0) shell_puts("(empty)\n");
        }
    } else if (shell_strncmp(cmd, "cat", 3) == 0 && (cmd[3] == '\0' || cmd[3] == ' ')) {
        const char *t = cmd + 3;
        while (*t == ' ') t++;
        if (*t == '\0') {
            shell_puts("usage: cat <file>\n");
        } else if (!vfs_open) {
            shell_puts("cat needs the VFS (TODO in this build)\n");
        } else {
            char name[32];
            int i = 0, fd;
            while (*t && *t != ' ' && i < 31) name[i++] = *t++;
            name[i] = '\0';
            fd = vfs_open(VFS_SHELL_CLIENT, name, VFS_R);
            if (fd < 0) {
                shell_puts("cat: no such file or denied: ");
                shell_puts(name);
                moonlight_putc('\n');
            } else {
                char chunk[64];
                int r;
                do {
                    int k;
                    r = vfs_read(VFS_SHELL_CLIENT, fd, chunk, sizeof(chunk));
                    for (k = 0; k < r; k++) moonlight_putc(chunk[k]);
                } while (r > 0);
                moonlight_putc('\n');
                vfs_close(VFS_SHELL_CLIENT, fd);
            }
        }
    } else if (shell_strncmp(cmd, "write", 5) == 0 && (cmd[5] == '\0' || cmd[5] == ' ')) {
        const char *t = cmd + 5;
        while (*t == ' ') t++;
        if (*t == '\0') {
            shell_puts("usage: write <file> <text...>\n");
        } else if (!vfs_open || !vfs_create || !vfs_write) {
            shell_puts("write needs the VFS (TODO in this build)\n");
        } else {
            char name[32];
            int i = 0, fd, w = 0;
            unsigned long tlen = 0;
            while (*t && *t != ' ' && i < 31) name[i++] = *t++;
            name[i] = '\0';
            while (*t == ' ') t++;
            while (t[tlen]) tlen++;
            fd = vfs_open(VFS_SHELL_CLIENT, name, VFS_R | VFS_W);
            if (fd < 0) {
                /* First use: mint from the demo frame pool (production:
                 * Untyped retype via invoke hands the server a Frame cap). */
                if (vfs_shell_nframes >= 2) {
                    shell_puts("write: demo frame pool exhausted\n");
                } else {
                    unsigned cap = (unsigned)(unsigned long)&vfs_shell_frames[vfs_shell_nframes];
                    if (vfs_create(VFS_SHELL_CLIENT, name, cap, 4096, 0, VFS_R) == 0) {
                        vfs_shell_nframes++;
                        fd = vfs_open(VFS_SHELL_CLIENT, name, VFS_R | VFS_W);
                    } else {
                        shell_puts("write: create denied\n");
                    }
                }
            }
            if (fd >= 0) {
                if (tlen > 0) w = vfs_write(VFS_SHELL_CLIENT, fd, t, tlen);
                vfs_close(VFS_SHELL_CLIENT, fd);
                shell_puts("wrote ");
                shell_print_ulong((unsigned long)(w < 0 ? 0 : w));
                shell_puts(" bytes to ");
                shell_puts(name);
                moonlight_putc('\n');
            } else {
                shell_puts("write: cannot open ");
                shell_puts(name);
                moonlight_putc('\n');
            }
        }
    } else if (shell_strncmp(cmd, "rm", 2) == 0 && (cmd[2] == '\0' || cmd[2] == ' ')) {
        const char *t = cmd + 2;
        while (*t == ' ') t++;
        if (*t == '\0') {
            shell_puts("usage: rm <file>\n");
        } else if (!vfs_unlink) {
            shell_puts("rm needs the VFS (TODO in this build)\n");
        } else {
            char name[32];
            int i = 0;
            while (*t && *t != ' ' && i < 31) name[i++] = *t++;
            name[i] = '\0';
            if (vfs_unlink(VFS_SHELL_CLIENT, name) == 0) {
                shell_puts("removed ");
                shell_puts(name);
                moonlight_putc('\n');
            } else {
                shell_puts("rm: denied (owner-only, must be closed): ");
                shell_puts(name);
                moonlight_putc('\n');
            }
        }
    } else if (shell_strncmp(cmd, "exec", 4) == 0 && (cmd[4] == '\0' || cmd[4] == ' ')) {
        const char *t = cmd + 4;
        while (*t == ' ') t++;
        if (*t == '\0') {
            shell_puts("usage: exec <path> [args...]\n");
        } else {
            /* Parse path and args */
            char path[64];
            int i = 0;
            while (*t && *t != ' ' && i < 63) {
                path[i++] = *t++;
            }
            path[i] = '\0';
            while (*t == ' ') t++;
            (void)t; /* suppress unused warning */
            
            shell_puts("exec: loading ");
            shell_puts(path);
            shell_puts("...\n");
            
            /* Open file via VFS */
            if (!vfs_open) {
                shell_puts("exec: VFS not available\n");
            } else {
                int fd = vfs_open(VFS_SHELL_CLIENT, path, VFS_R);
                if (fd < 0) {
                    shell_puts("exec: cannot open ");
                    shell_puts(path);
                    shell_puts("\n");
                } else {
                    /* Get file size */
                    unsigned size = 0;
                    vfs_stat(VFS_SHELL_CLIENT, path, &size, NULL);
                    
                    /* Request ELF frame from mem_server (label 4) */
                    struct { uint32_t label, length, caps; uint64_t words[30]; uint32_t cap_ptrs[3]; } msg;
                    msg.label = 4;
                    msg.words[0] = 0; /* first ELF in initrd */
                    msg.length = 1;
                    int rc = moonlight_call(1, &msg); /* endpoint 1 = mem_server */
                    
                    if (rc == 0 && (int64_t)msg.words[0] >= 0) {
                        /* Read program headers from file */
                        /* For simplicity, assume ELF is at offset 0 with standard layout */
                        /* Read ELF header to get phoff, phnum */
                        char elf_buf[64];
                        int r = vfs_read(VFS_SHELL_CLIENT, fd, elf_buf, 64);
                        if (r >= 64) {
                            uint64_t *eh = (uint64_t*)elf_buf;
                            if (eh[0] == 0x464C457F) { /* ELF magic */
                                
                                /* For simplicity, just use frame 0 (first ELF in initrd) */
                                /* Call V2_INV_EXEC */
                                struct { uint32_t label, length, caps; uint64_t words[30]; uint32_t cap_ptrs[3]; } exec_msg;
                                exec_msg.label = 7;
                                exec_msg.length = 3;
                                exec_msg.caps = 0;
                                exec_msg.words[0] = 11;
                                exec_msg.words[1] = 0;
                                exec_msg.words[2] = 0;
                                rc = moonlight_call(7, &exec_msg);
                                
                                if (rc == 0) {
                                    shell_puts("exec: image replaced\n");
                                    return; /* Should not return */
                                } else {
                                    shell_puts("exec: V2_INV_EXEC failed\n");
                                }
                            } else {
                                shell_puts("exec: invalid ELF\n");
                            }
                        }
                    }
                    vfs_close(VFS_SHELL_CLIENT, fd);
                }
            }
        }
    } else if (shell_streq(cmd, "poweroff") || shell_streq(cmd, "reboot")) {
        if (moonsh_system_reset) {
            shell_puts(cmd[0] == 'p' ? "powering off...\n" : "rebooting...\n");
            moonsh_system_reset(cmd[0] == 'r' ? 1 : 0);
            shell_puts("moonsh: reset request returned (finisher absent?)\n");
        } else {
            shell_puts("needs test-finisher mapping (TODO in this build)\n");
        }
    } else {
        shell_puts("moonsh: unknown command: ");
        shell_puts(cmd);
        shell_puts("\ntype 'help'\n");
    }
}

/* ---- interactive line reader (history + VGA-safe editing) ---- */
#define PROMPT "moonsh> "

static char rd_buf[SHELL_LINE_MAX];
static int rd_len, rd_pos, rd_shown;
static int rd_nav; /* -1 = live line, else history index 0-based into shell_hist */

static void rd_redraw(void) {
    int i, back;
    moonlight_putc('\r');
    shell_puts(PROMPT);
    for (i = 0; i < rd_len; i++) moonlight_putc(rd_buf[i]);
    for (i = rd_len; i < rd_shown; i++) moonlight_putc(' ');
    for (i = rd_len; i < rd_shown; i++) moonlight_putc('\b');
    if (rd_len > rd_shown) rd_shown = rd_len;
    back = rd_len - rd_pos;
    for (i = 0; i < back; i++) moonlight_putc('\b');
}

static void rd_load_history(int idx) {
    int i = 0;
    const char *s = shell_hist[idx];
    while (s[i] && i < SHELL_LINE_MAX - 1) {
        rd_buf[i] = s[i];
        i++;
    }
    rd_len = i;
    rd_pos = i;
    rd_buf[rd_len] = '\0';
    rd_redraw();
}

static void rd_insert(char c) {
    int i;
    if (rd_len >= SHELL_LINE_MAX - 1) return;
    if (rd_pos == rd_len) { /* append: single echo, no full redraw */
        rd_buf[rd_pos] = c;
        rd_pos++;
        rd_len++;
        rd_buf[rd_len] = '\0';
        if (rd_len > rd_shown) rd_shown = rd_len;
        rd_nav = -1;
        moonlight_putc(c);
        return;
    }
    for (i = rd_len; i > rd_pos; i--) rd_buf[i] = rd_buf[i - 1];
    rd_buf[rd_pos] = c;
    rd_pos++;
    rd_len++;
    rd_buf[rd_len] = '\0';
    rd_nav = -1;
    rd_redraw();
}

static void rd_backspace(void) {
    int i;
    if (rd_pos == 0) return;
    if (rd_pos == rd_len) { /* erase at end: VGA-safe "\b \b", no redraw */
        rd_pos--;
        rd_len--;
        rd_buf[rd_len] = '\0';
        rd_nav = -1;
        shell_puts("\b \b");
        return;
    }
    for (i = rd_pos - 1; i < rd_len - 1; i++) rd_buf[i] = rd_buf[i + 1];
    rd_pos--;
    rd_len--;
    rd_buf[rd_len] = '\0';
    rd_nav = -1;
    rd_redraw();
}

static void rd_delete_at(void) {
    int i;
    if (rd_pos >= rd_len) return;
    for (i = rd_pos; i < rd_len - 1; i++) rd_buf[i] = rd_buf[i + 1];
    rd_len--;
    rd_buf[rd_len] = '\0';
    rd_nav = -1;
    rd_redraw();
}

void shell_main(void) {
    /* Weak: only present in the in-kernel build (vfs_server linked).
     * The bare moonsh.elf has no VFS server; an unguarded call would
     * jump to address 0. */
    if (vfs_server_init)
        vfs_server_init();
    shell_puts("\nmoonsh 0.2 on MoonlightOS (type 'help')\n");
    for (;;) {
        int esc = 0; /* 0 normal, 1 got ESC, 2 got ESC [, 3 got ESC [ <digits> */
        char csip[8];
        int csip_len = 0;
        shell_puts(PROMPT);
        rd_len = 0;
        rd_pos = 0;
        rd_shown = 0;
        rd_nav = -1;
        rd_buf[0] = '\0';
        for (;;) {
            int c = moonlight_getc();
            int k;
            if (c < 0) { moonlight_yield(); continue; }
            shell_stat_chars++;
            if (esc == 1) {
                if (c == '[') { esc = 2; csip_len = 0; continue; }
                esc = 0; /* lone ESC / Alt combo: ignore */
                continue;
            }
            if (esc == 2 || esc == 3) {
                if (c >= '0' && c <= '9') {
                    if (csip_len < 7) csip[csip_len++] = (char)c;
                    esc = 3;
                    continue;
                }
                esc = 0;
                if (c == 'A') { /* Up: older */
                    int entries = shell_hist_count < SHELL_HIST_MAX ?
                                      shell_hist_count : SHELL_HIST_MAX;
                    if (entries > 0) {
                        if (rd_nav < 0) rd_nav = entries - 1;
                        else if (rd_nav > 0) rd_nav--;
                        rd_load_history(rd_nav);
                    }
                } else if (c == 'B') { /* Down: newer */
                    int entries = shell_hist_count < SHELL_HIST_MAX ?
                                      shell_hist_count : SHELL_HIST_MAX;
                    if (rd_nav >= 0) {
                        rd_nav++;
                        if (rd_nav >= entries) {
                            rd_nav = -1;
                            rd_len = 0;
                            rd_pos = 0;
                            rd_buf[0] = '\0';
                            rd_redraw();
                        } else {
                            rd_load_history(rd_nav);
                        }
                    }
                } else if (c == 'C') { /* Right */
                    if (rd_pos < rd_len) {
                        moonlight_putc(rd_buf[rd_pos]);
                        rd_pos++;
                    }
                } else if (c == 'D') { /* Left */
                    if (rd_pos > 0) {
                        moonlight_putc('\b');
                        rd_pos--;
                    }
                } else if (c == 'H') { /* Home */
                    while (rd_pos > 0) {
                        moonlight_putc('\b');
                        rd_pos--;
                    }
                } else if (c == 'F') { /* End */
                    while (rd_pos < rd_len) {
                        moonlight_putc(rd_buf[rd_pos]);
                        rd_pos++;
                    }
                } else if (c == '~') {
                    int n = 0;
                    for (k = 0; k < csip_len; k++) n = n * 10 + (csip[k] - '0');
                    if (n == 3) rd_delete_at();
                    else if (n == 1 || n == 7) {
                        while (rd_pos > 0) {
                            moonlight_putc('\b');
                            rd_pos--;
                        }
                    } else if (n == 4 || n == 8) {
                        while (rd_pos < rd_len) {
                            moonlight_putc(rd_buf[rd_pos]);
                            rd_pos++;
                        }
                    }
                }
                continue;
            }
            if (c == 0x1b) { esc = 1; continue; }
            if (c == '\r') c = '\n';
            if (c == '\n') {
                moonlight_putc('\n');
                break;
            }
            if (c == 0x03) { /* Ctrl-C: cancel line */
                shell_puts("^C\n");
                rd_len = 0;
                rd_pos = 0;
                rd_shown = 0;
                rd_nav = -1;
                rd_buf[0] = '\0';
                shell_puts(PROMPT);
                continue;
            }
            if (c == 0x15) { /* Ctrl-U: kill line */
                rd_len = 0;
                rd_pos = 0;
                rd_nav = -1;
                rd_buf[0] = '\0';
                rd_redraw();
                continue;
            }
            if (c == 0x04) { /* Ctrl-D on empty line: hint */
                if (rd_len == 0) shell_puts("(use poweroff to halt)\n" PROMPT);
                continue;
            }
            if (c == 0x7f || c == 0x08) { /* backspace/DEL */
                rd_backspace();
                continue;
            }
            if (c < 0x20 || c > 0x7e) continue; /* ignore other controls */
            rd_insert((char)c);
        }
        rd_buf[rd_len] = '\0';
        shell_stat_lines++;
        shell_exec_line(rd_buf);
    }
}
