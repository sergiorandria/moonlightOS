/*
 * shell_core.h - Production Minimal Shell Engine for moonsh (BusyBox style)
 *
 * Implements:
 * - 50+ built-in applets
 * - Embedded in-memory VFS with dynamic /proc filesystem
 * - Command sequence chaining (';'), pipes ('|'), output redirection ('>', '>>')
 * - Variable expansion ($?, $$, $USER, $HOSTNAME, $PWD, custom vars)
 * - Single/double quotes and escape sequence parsing
 * - Command history with expansion (!!, !n)
 * - Aliasing (alias, unalias)
 * - Expression evaluation (calc, expr, test, [)
 * - Zero dynamic heap allocation, fully freestanding rv64 & host compatible
 */

#ifndef SHELL_CORE_H
#define SHELL_CORE_H

#include "shell_expr.h"
#include "shell_vfs.h"
#include <stddef.h>
#include <stdint.h>

#define SHELL_LINE_MAX 128
#define SHELL_ARGS_MAX 16
#define SHELL_HIST_MAX 8
#define SHELL_ENV_MAX 12
#define SHELL_ALIAS_MAX 12
#define SHELL_PIPE_MAX 1024

/* Weak kernel hooks for target builds */
__attribute__((weak)) int moonsh_kbd_status(char *buf, unsigned len);
__attribute__((weak)) void moonsh_system_reset(int do_reset);
__attribute__((weak)) void moonsh_console_clear(void);
__attribute__((weak)) int moonsh_console_mode(void);
__attribute__((weak)) int moonsh_ps_line(char *buf, unsigned len, unsigned *cursor);
__attribute__((weak)) int moonsh_mem_status(char *buf, unsigned len);
__attribute__((weak)) int moonsh_kill_tid(long tid, int op);
__attribute__((weak)) int moonsh_nice_tid(long tid, int prio);

/* Weak VFS legacy hooks (for backward compatibility) */
__attribute__((weak)) int vfs_create_legacy(unsigned caller, const char *name, unsigned cap,
                                            unsigned size, unsigned short color,
                                            unsigned short omode);
__attribute__((weak)) int vfs_open_legacy(unsigned caller, const char *name, unsigned rights);
__attribute__((weak)) int vfs_read_legacy(unsigned caller, int fd, void *buf, unsigned long len);
__attribute__((weak)) int vfs_write_legacy(unsigned caller, int fd, const void *buf,
                                           unsigned long len);
__attribute__((weak)) int vfs_close_legacy(unsigned caller, int fd);
__attribute__((weak)) int vfs_unlink_legacy(unsigned caller, const char *name);

/* External character output sink. Defined by host test or tty driver */
extern int moonlight_putc(char c);
extern int moonlight_yield(void);

/* Output redirection target */
typedef enum
{
    OUT_TTY = 0,
    OUT_BUFFER,
    OUT_VFS_FILE
} out_mode_t;

typedef struct
{
    out_mode_t mode;
    char *buf;
    int buf_pos;
    int buf_max;
    int vfs_fd;
    int append;
} shell_out_t;

static shell_out_t sh_out_active;
static char sh_pipe_buffer[SHELL_PIPE_MAX];
static char sh_pipe_buffer2[SHELL_PIPE_MAX];
static int sh_pipe_len = 0;
static const char *sh_stdin_data = NULL;
static int sh_stdin_pos = 0;
static int sh_stdin_len = 0;

/* Platform output hooks */
extern void shell_platform_write(const char *s, int len);

/* Output primitives */
static inline void sh_putc(char c)
{
    if (sh_out_active.mode == OUT_TTY)
    {
        shell_platform_write(&c, 1);
    }
    else if (sh_out_active.mode == OUT_BUFFER)
    {
        if (sh_out_active.buf && sh_out_active.buf_pos < sh_out_active.buf_max - 1)
        {
            sh_out_active.buf[sh_out_active.buf_pos++] = c;
            sh_out_active.buf[sh_out_active.buf_pos] = '\0';
        }
    }
    else if (sh_out_active.mode == OUT_VFS_FILE)
    {
        if (sh_out_active.vfs_fd >= 0)
        {
            vfs_write_file(sh_out_active.vfs_fd, &c, 1, 1);
        }
    }
}

static inline void sh_puts(const char *s)
{
    if (!s)
        return;
    if (sh_out_active.mode == OUT_TTY)
    {
        shell_platform_write(s, vfs_strlen(s));
    }
    else
    {
        while (*s)
            sh_putc(*s++);
    }
}

static inline void sh_print_ulong(unsigned long v)
{
    char buf[24];
    int i = 0;
    if (v == 0)
    {
        sh_putc('0');
        return;
    }
    while (v > 0 && i < 23)
    {
        buf[i++] = '0' + (v % 10);
        v /= 10;
    }
    while (i-- > 0)
        sh_putc(buf[i]);
}

static inline void sh_print_long(long v)
{
    if (v < 0)
    {
        sh_putc('-');
        sh_print_ulong((unsigned long)(-v));
    }
    else
    {
        sh_print_ulong((unsigned long)v);
    }
}

static inline void sh_print_hex(unsigned long v, int width)
{
    for (int i = width - 1; i >= 0; i--)
    {
        unsigned d = (v >> (i * 4)) & 0xF;
        sh_putc(d < 10 ? (char)('0' + d) : (char)('a' + d - 10));
    }
}

static inline void sh_print_size(uint32_t bytes)
{
    if (bytes < 1024)
    {
        sh_print_ulong(bytes);
        sh_putc('B');
    }
    else if (bytes < 1024 * 1024)
    {
        sh_print_ulong(bytes / 1024);
        sh_putc('.');
        sh_print_ulong((bytes % 1024) * 10 / 1024);
        sh_putc('K');
    }
    else
    {
        sh_print_ulong(bytes / (1024 * 1024));
        sh_putc('.');
        sh_print_ulong(((bytes % (1024 * 1024)) * 10) / (1024 * 1024));
        sh_putc('M');
    }
}

/* Classic hexdump */
static inline void sh_hexdump(const char *data, int len)
{
    int off = 0;
    while (off < len)
    {
        int row = len - off > 16 ? 16 : len - off;
        sh_print_hex((unsigned long)off, 4);
        sh_puts(": ");
        for (int i = 0; i < 16; i++)
        {
            if (i < row)
            {
                sh_print_hex((unsigned char)data[off + i], 2);
            }
            else
            {
                sh_puts("  ");
            }
            sh_putc(i == 7 ? '-' : ' ');
        }
        sh_puts(" |");
        for (int i = 0; i < row; i++)
        {
            char c = data[off + i];
            sh_putc(c >= 0x20 && c < 0x7f ? c : '.');
        }
        sh_puts("|\n");
        off += row;
    }
}

/* Base64 encoding / decoding table */
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static inline int sh_base64_encode(const char *src, int len, char *out, int max_out)
{
    int i = 0, j = 0;
    while (i < len && j < max_out - 4)
    {
        uint32_t a = (unsigned char)src[i++];
        uint32_t b = i < len ? (unsigned char)src[i++] : 0;
        uint32_t c = i < len ? (unsigned char)src[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;

        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = (i > len + 1) ? '=' : b64_table[(triple >> 6) & 0x3F];
        out[j++] = (i > len) ? '=' : b64_table[triple & 0x3F];
    }
    out[j] = '\0';
    return j;
}

static inline int sh_b64_val(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

static inline int sh_base64_decode(const char *src, int len, char *out, int max_out)
{
    int i = 0, j = 0;
    while (i < len && j < max_out - 3)
    {
        while (i < len && (src[i] == ' ' || src[i] == '\n' || src[i] == '\r'))
            i++;
        if (i >= len)
            break;
        int a = sh_b64_val(src[i++]);
        int b = i < len ? sh_b64_val(src[i++]) : -1;
        int c = i < len ? sh_b64_val(src[i++]) : -1;
        int d = i < len ? sh_b64_val(src[i++]) : -1;
        if (a < 0 || b < 0)
            break;

        out[j++] = (char)((a << 2) | (b >> 4));
        if (c >= 0 && j < max_out)
            out[j++] = (char)(((b & 0xF) << 4) | (c >> 2));
        if (d >= 0 && j < max_out)
            out[j++] = (char)(((c & 0x3) << 6) | d);
    }
    out[j] = '\0';
    return j;
}

/* IEEE 802.3 CRC-32 calculation */
static inline uint32_t sh_crc32(const char *data, int len)
{
    uint32_t crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++)
    {
        uint8_t byte = (uint8_t)data[i];
        crc ^= byte;
        for (int j = 0; j < 8; j++)
        {
            uint32_t mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }
    return ~crc;
}

/* Shell environment variables and working directory */
typedef struct
{
    char name[32];
    char val[64];
    int in_use;
} shell_env_t;

typedef struct
{
    char name[32];
    char val[64];
    int in_use;
} shell_alias_t;

static shell_env_t sh_envs[SHELL_ENV_MAX];
static shell_alias_t sh_aliases[SHELL_ALIAS_MAX];
static char sh_cwd[VFS_PATH_MAX] = "/";
static int sh_last_status = 0;

static inline void sh_env_init(void)
{
    for (int i = 0; i < SHELL_ENV_MAX; i++)
        sh_envs[i].in_use = 0;
    for (int i = 0; i < SHELL_ALIAS_MAX; i++)
        sh_aliases[i].in_use = 0;
}

static inline const char *sh_getenv(const char *name)
{
    if (!name)
        return "";
    if (vfs_strcmp(name, "?") == 0)
    {
        static char sbuf[8];
        sbuf[0] = '0' + (sh_last_status & 7);
        sbuf[1] = '\0';
        return sbuf;
    }
    if (vfs_strcmp(name, "$") == 0)
        return "1"; /* TID 1 */
    if (vfs_strcmp(name, "USER") == 0)
        return "root";
    if (vfs_strcmp(name, "HOSTNAME") == 0)
        return "moonlight";
    if (vfs_strcmp(name, "PWD") == 0)
        return sh_cwd;
    if (vfs_strcmp(name, "VERSION") == 0)
        return "0.3.0";
    if (vfs_strcmp(name, "ARCH") == 0)
        return "riscv64";

    for (int i = 0; i < SHELL_ENV_MAX; i++)
    {
        if (sh_envs[i].in_use && vfs_strcmp(sh_envs[i].name, name) == 0)
        {
            return sh_envs[i].val;
        }
    }
    return "";
}

static inline void sh_setenv(const char *name, const char *val)
{
    if (!name || !*name)
        return;
    for (int i = 0; i < SHELL_ENV_MAX; i++)
    {
        if (sh_envs[i].in_use && vfs_strcmp(sh_envs[i].name, name) == 0)
        {
            vfs_strcpy(sh_envs[i].val, val ? val : "", sizeof(sh_envs[i].val));
            return;
        }
    }
    for (int i = 0; i < SHELL_ENV_MAX; i++)
    {
        if (!sh_envs[i].in_use)
        {
            sh_envs[i].in_use = 1;
            vfs_strcpy(sh_envs[i].name, name, sizeof(sh_envs[i].name));
            vfs_strcpy(sh_envs[i].val, val ? val : "", sizeof(sh_envs[i].val));
            return;
        }
    }
}

static inline void sh_unsetenv(const char *name)
{
    if (!name)
        return;
    for (int i = 0; i < SHELL_ENV_MAX; i++)
    {
        if (sh_envs[i].in_use && vfs_strcmp(sh_envs[i].name, name) == 0)
        {
            sh_envs[i].in_use = 0;
            return;
        }
    }
}

static inline const char *sh_get_alias(const char *name)
{
    if (!name)
        return NULL;
    for (int i = 0; i < SHELL_ALIAS_MAX; i++)
    {
        if (sh_aliases[i].in_use && vfs_strcmp(sh_aliases[i].name, name) == 0)
        {
            return sh_aliases[i].val;
        }
    }
    return NULL;
}

static inline void sh_set_alias(const char *name, const char *val)
{
    if (!name || !*name)
        return;
    for (int i = 0; i < SHELL_ALIAS_MAX; i++)
    {
        if (sh_aliases[i].in_use && vfs_strcmp(sh_aliases[i].name, name) == 0)
        {
            vfs_strcpy(sh_aliases[i].val, val ? val : "", sizeof(sh_aliases[i].val));
            return;
        }
    }
    for (int i = 0; i < SHELL_ALIAS_MAX; i++)
    {
        if (!sh_aliases[i].in_use)
        {
            sh_aliases[i].in_use = 1;
            vfs_strcpy(sh_aliases[i].name, name, sizeof(sh_aliases[i].name));
            vfs_strcpy(sh_aliases[i].val, val ? val : "", sizeof(sh_aliases[i].val));
            return;
        }
    }
}

/* History */
static char sh_hist[SHELL_HIST_MAX][SHELL_LINE_MAX];
static int sh_hist_count = 0;
static unsigned long sh_stat_lines = 0;
static unsigned long sh_stat_chars = 0;

static inline void sh_history_add(const char *line)
{
    if (!line || *line == '\0')
        return;
    if (sh_hist_count > 0)
    {
        const char *prev = sh_hist[(sh_hist_count - 1) % SHELL_HIST_MAX];
        if (vfs_strcmp(line, prev) == 0)
            return;
    }
    if (sh_hist_count < 1000000)
        sh_hist_count++;
    if (sh_hist_count <= SHELL_HIST_MAX)
    {
        vfs_strcpy(sh_hist[sh_hist_count - 1], line, SHELL_LINE_MAX);
    }
    else
    {
        for (int i = 0; i < SHELL_HIST_MAX - 1; i++)
        {
            vfs_strcpy(sh_hist[i], sh_hist[i + 1], SHELL_LINE_MAX);
        }
        vfs_strcpy(sh_hist[SHELL_HIST_MAX - 1], line, SHELL_LINE_MAX);
    }
}

static inline const char *sh_history_get(int n)
{
    int entries = sh_hist_count < SHELL_HIST_MAX ? sh_hist_count : SHELL_HIST_MAX;
    if (n < 1 || n > entries)
        return NULL;
    return sh_hist[n - 1];
}

void shell_test_reset(void)
{
    for (int i = 0; i < SHELL_HIST_MAX; i++)
    {
        sh_hist[i][0] = '\0';
    }
    sh_hist_count = 0;
    sh_stat_lines = 0;
    sh_stat_chars = 0;
    sh_last_status = 0;
    sh_pipe_len = 0;
    vfs_strcpy(sh_cwd, "/", sizeof(sh_cwd));
    vfs_init();
    sh_env_init();
}

/* Variable expansion ($VAR and ${VAR}) */
static inline void sh_expand_vars(const char *in, char *out, int max_out)
{
    int i = 0, j = 0;
    while (in[i] && j < max_out - 1)
    {
        if (in[i] == '$')
        {
            i++;
            char var_name[32];
            int vi = 0;
            int braced = 0;
            if (in[i] == '{')
            {
                braced = 1;
                i++;
            }

            if (in[i] == '?' || in[i] == '$')
            {
                var_name[vi++] = in[i++];
            }
            else
            {
                while (in[i] &&
                       ((in[i] >= 'a' && in[i] <= 'z') || (in[i] >= 'A' && in[i] <= 'Z') ||
                        (in[i] >= '0' && in[i] <= '9') || in[i] == '_') &&
                       vi < 31)
                {
                    var_name[vi++] = in[i++];
                }
            }
            if (braced && in[i] == '}')
                i++;
            var_name[vi] = '\0';

            const char *val = sh_getenv(var_name);
            while (*val && j < max_out - 1)
            {
                out[j++] = *val++;
            }
        }
        else
        {
            out[j++] = in[i++];
        }
    }
    out[j] = '\0';
}

/* Argument tokenizer supporting single/double quotes */
static inline int sh_tokenize(char *line, char **argv, int max_args)
{
    int argc = 0;
    char *p = line;

    while (*p && argc < max_args - 1)
    {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p || *p == '#')
            break; /* comment starts with # */

        char *token_start = p;
        char *write_p = p;
        char quote = 0;

        while (*p)
        {
            if (quote)
            {
                if (*p == quote)
                {
                    quote = 0;
                    p++;
                }
                else
                {
                    *write_p++ = *p++;
                }
            }
            else
            {
                if (*p == '\'' || *p == '\"')
                {
                    quote = *p++;
                }
                else if (*p == ' ' || *p == '\t')
                {
                    break;
                }
                else
                {
                    *write_p++ = *p++;
                }
            }
        }
        int had_more = (*p != '\0');
        *write_p = '\0';
        argv[argc++] = token_start;
        if (had_more)
            p++;
    }
    argv[argc] = NULL;
    return argc;
}

/* Forward declaration for recursive / script line execution */
void shell_exec_line(const char *line);

/* ============================================================================
 * Builtin Applet Handlers
 * ============================================================================ */

static inline int cmd_help(int argc, char **argv)
{
    if (argc > 1)
    {
        const char *t = argv[1];
        if (vfs_strcmp(t, "echo") == 0)
        {
            sh_puts("echo [-n] [-e] <text>: print text (+ newline unless -n)\n");
        }
        else if (vfs_strcmp(t, "cat") == 0)
        {
            sh_puts("cat [-n] <file>: print file contents\n");
        }
        else if (vfs_strcmp(t, "ls") == 0)
        {
            sh_puts("ls [-lart] [-A] [-h] [-R] [-d] [-1] [-F] [-p] [-S] [dir]: list files\n");
        }
        else if (vfs_strcmp(t, "write") == 0)
        {
            sh_puts("write <file> <text...>: create + overwrite file with text\n");
        }
        else if (vfs_strcmp(t, "rm") == 0)
        {
            sh_puts("rm [-f] [-r] <file>: delete own closed file\n");
        }
        else if (vfs_strcmp(t, "kill") == 0)
        {
            sh_puts("kill [-STOP|-CONT] <tid>: destroy (default), suspend, resume\n");
        }
        else if (vfs_strcmp(t, "nice") == 0)
        {
            sh_puts("nice <tid> <prio>: retarget priority 0-255 (0 highest)\n");
        }
        else if (vfs_strcmp(t, "console") == 0)
        {
            sh_puts("console: show serial/VGA routing (split vs mirror)\n");
        }
        else if (vfs_strcmp(t, "calc") == 0 || vfs_strcmp(t, "expr") == 0)
        {
            sh_puts("calc <expr>: evaluate integer arithmetic expression (+ - * / % & | ^ << >> ( "
                    "))\n");
        }
        else if (vfs_strcmp(t, "base64") == 0)
        {
            sh_puts("base64 [-d] [string or file]: encode or decode base64 data\n");
        }
        else if (vfs_strcmp(t, "crc32") == 0)
        {
            sh_puts("crc32 <file or text>: compute IEEE 802.3 CRC-32 checksum\n");
        }
        else
        {
            sh_puts("moonsh: no help for '");
            sh_puts(t);
            sh_puts("'\n");
        }
        return 0;
    }

    sh_puts("moonsh builtins:\n");
    sh_puts("  help [cmd]      this list (busybox works too)\n");
    sh_puts("  echo [-n] <tx>  print text\n");
    sh_puts("  printf <fmt>    formatted print\n");
    sh_puts("  pwd             print working directory\n");
    sh_puts("  cd [dir]        change directory\n");
    sh_puts("  ls [-l -a -h]   list files (VFS)\n");
    sh_puts("  cat [-n] <file> print file contents\n");
    sh_puts("  touch <file>    create or update file timestamp\n");
    sh_puts("  write <f> <tx>  create + overwrite file with text\n");
    sh_puts("  rm [-f -r] <f>  delete own closed file\n");
    sh_puts("  cp <src> <dst>  copy file\n");
    sh_puts("  mv <src> <dst>  move / rename file\n");
    sh_puts("  mkdir [-p] <d>  create directory\n");
    sh_puts("  rmdir <d>       remove empty directory\n");
    sh_puts("  head [-n N]     print first N lines\n");
    sh_puts("  tail [-n N]     print last N lines\n");
    sh_puts("  wc [-l -w -c]   word, line, char count\n");
    sh_puts("  grep [-i -n -v] search pattern in file or input\n");
    sh_puts("  stat <file>     file status and metadata\n");
    sh_puts("  find [path]     find files\n");
    sh_puts("  tee [-a] <f>    replicate input to stdout & file\n");
    sh_puts("  hex <text>      hexdump argument bytes (hd works too)\n");
    sh_puts("  base64 [-d]     encode or decode Base64\n");
    sh_puts("  crc32 <file>    compute CRC-32 checksum\n");
    sh_puts("  calc <expr>     integer calculator (expr too)\n");
    sh_puts("  sort [-r -n]    sort lines\n");
    sh_puts("  uniq [-c -d]    report or omit repeated lines\n");
    sh_puts("  strings <file>  print printable strings\n");
    sh_puts("  seq [s] [i] e   print sequence of numbers\n");
    sh_puts("  yes [str]       output string repeatedly\n");
    sh_puts("  rand [min max]  pseudo-random number generator\n");
    sh_puts("  banner <text>   render 5x5 ASCII banner\n");
    sh_puts("  test / [        test conditions (-z, -n, =, !=, -eq, -f, -d)\n");
    sh_puts("  true / false    return 0 or 1\n");
    sh_puts("  export / env    display or set environment variables\n");
    sh_puts("  unset <var>     unset environment variable\n");
    sh_puts("  source / .      execute shell script file\n");
    sh_puts("  alias / unalias manage command aliases\n");
    sh_puts("  which / type    identify command type\n");
    sh_puts("  history         list recent commands (!! / !n repeat)\n");
    sh_puts("  clear           clear screen (cls works too)\n");
    sh_puts("  console         show serial/VGA routing\n");
    sh_puts("  yield           yield the CPU (ecall test)\n");
    sh_puts("  sleep <ticks>   wait N timer ticks\n");
    sh_puts("  uptime          timer ticks since boot (ticks too)\n");
    sh_puts("  date / time     system clock ticks\n");
    sh_puts("  ver             OS version (version/uname too)\n");
    sh_puts("  kbd             keyboard driver status\n");
    sh_puts("  ps              threads + next pick (cooperative dispatch)\n");
    sh_puts("  kill [-STOP]    destroy | suspend | resume tid\n");
    sh_puts("  nice <tid> <p>  retarget priority 0-255 (0 highest)\n");
    sh_puts("  mem             allocator + page-table usage (free too)\n");
    sh_puts("  ipc             IPC subsystem table and status\n");
    sh_puts("  dmesg           display kernel boot messages\n");
    sh_puts("  poweroff        halt (reboot resets)\n");
    return 0;
}

static inline int cmd_echo(int argc, char **argv)
{
    int newline = 1;
    int escape = 0;
    int start = 1;

    while (start < argc && argv[start][0] == '-')
    {
        if (vfs_strcmp(argv[start], "-n") == 0)
        {
            newline = 0;
            start++;
        }
        else if (vfs_strcmp(argv[start], "-e") == 0)
        {
            escape = 1;
            start++;
        }
        else
        {
            break;
        }
    }

    for (int i = start; i < argc; i++)
    {
        const char *s = argv[i];
        while (*s)
        {
            if (escape && *s == '\\')
            {
                s++;
                if (*s == 'n')
                    sh_putc('\n');
                else if (*s == 't')
                    sh_putc('\t');
                else if (*s == 'r')
                    sh_putc('\r');
                else if (*s == 'e')
                    sh_putc('\x1b');
                else if (*s == '\\')
                    sh_putc('\\');
                else if (*s)
                    sh_putc(*s);
                if (*s)
                    s++;
            }
            else
            {
                sh_putc(*s++);
            }
        }
        if (i < argc - 1)
            sh_putc(' ');
    }
    if (newline)
        sh_putc('\n');
    return 0;
}

static inline int cmd_pwd(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    sh_puts(sh_cwd);
    sh_putc('\n');
    return 0;
}

static inline int cmd_cd(int argc, char **argv)
{
    const char *target = (argc > 1) ? argv[1] : "/";
    char resolved[VFS_PATH_MAX];
    vfs_resolve_path(sh_cwd, target, resolved, sizeof(resolved));

    int idx = vfs_find(resolved);
    if (idx < 0 || !vfs_nodes[idx].is_dir)
    {
        sh_puts("cd: no such directory: ");
        sh_puts(target);
        sh_putc('\n');
        return 1;
    }
    vfs_strcpy(sh_cwd, resolved, sizeof(sh_cwd));
    return 0;
}

#include "applets/shell_file.h"

static inline int cmd_grep(int argc, char **argv)
{
    int opt_i = 0, opt_n = 0, opt_v = 0;
    int start = 1;
    while (start < argc && argv[start][0] == '-')
    {
        for (int k = 1; argv[start][k]; k++)
        {
            if (argv[start][k] == 'i')
                opt_i = 1;
            else if (argv[start][k] == 'n')
                opt_n = 1;
            else if (argv[start][k] == 'v')
                opt_v = 1;
        }
        start++;
    }

    if (start >= argc)
    {
        sh_puts("usage: grep [-i] [-n] [-v] <pattern> [file...]\n");
        return 1;
    }

    const char *pat = argv[start++];
    int pat_len = vfs_strlen(pat);
    int matched_any = 0;

    const char *data = sh_stdin_data;
    char file_buf[VFS_FILE_MAX];
    if (start < argc)
    {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[start], resolved, sizeof(resolved));
        int idx = vfs_find(resolved);
        if (idx < 0)
        {
            sh_puts("grep: '");
            sh_puts(argv[start]);
            sh_puts("': No such file\n");
            return 1;
        }
        int len = vfs_read_file(idx, file_buf, sizeof(file_buf));
        if (len < 0)
            return 1;
        data = file_buf;
    }

    if (!data)
        return 1;

    /* Scan line by line */
    const char *line_start = data;
    int line_no = 1;
    while (*line_start)
    {
        const char *line_end = line_start;
        while (*line_end && *line_end != '\n')
            line_end++;

        int line_len = (int)(line_end - line_start);
        int has_match = 0;

        for (int i = 0; i <= line_len - pat_len; i++)
        {
            int match = 1;
            for (int k = 0; k < pat_len; k++)
            {
                char c1 = line_start[i + k];
                char c2 = pat[k];
                if (opt_i)
                {
                    if (c1 >= 'A' && c1 <= 'Z')
                        c1 += 32;
                    if (c2 >= 'A' && c2 <= 'Z')
                        c2 += 32;
                }
                if (c1 != c2)
                {
                    match = 0;
                    break;
                }
            }
            if (match)
            {
                has_match = 1;
                break;
            }
        }

        if ((has_match && !opt_v) || (!has_match && opt_v))
        {
            matched_any = 1;
            if (opt_n)
            {
                sh_print_ulong((unsigned long)line_no);
                sh_putc(':');
            }
            for (int k = 0; k < line_len; k++)
                sh_putc(line_start[k]);
            sh_putc('\n');
        }

        line_start = *line_end == '\n' ? line_end + 1 : line_end;
        line_no++;
    }
    return matched_any ? 0 : 1;
}

static inline int cmd_hex(int argc, char **argv)
{
    if (argc < 2 && (!sh_stdin_data || sh_stdin_len == 0))
    {
        sh_puts("usage: hex <text>\n");
        return 1;
    }

    if (argc > 1)
    {
        /* Check if argv[1] is a file */
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[1], resolved, sizeof(resolved));
        int idx = vfs_find(resolved);
        if (idx >= 0 && !vfs_nodes[idx].is_dir)
        {
            char buf[VFS_FILE_MAX];
            int len = vfs_read_file(idx, buf, sizeof(buf));
            sh_hexdump(buf, len);
            return 0;
        }

        /* Concatenate text arguments */
        char text[SHELL_LINE_MAX];
        int pos = 0;
        for (int i = 1; i < argc; i++)
        {
            const char *s = argv[i];
            while (*s && pos < SHELL_LINE_MAX - 2)
                text[pos++] = *s++;
            if (i < argc - 1 && pos < SHELL_LINE_MAX - 2)
                text[pos++] = ' ';
        }
        text[pos] = '\0';
        sh_hexdump(text, pos);
    }
    else if (sh_stdin_data)
    {
        sh_hexdump(sh_stdin_data, sh_stdin_len);
    }
    return 0;
}

static inline int cmd_base64(int argc, char **argv)
{
    int decode = 0;
    int start = 1;
    if (start < argc && vfs_strcmp(argv[start], "-d") == 0)
    {
        decode = 1;
        start++;
    }

    const char *data = sh_stdin_data;
    char file_buf[VFS_FILE_MAX];
    if (start < argc)
    {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[start], resolved, sizeof(resolved));
        int idx = vfs_find(resolved);
        if (idx >= 0 && !vfs_nodes[idx].is_dir)
        {
            int len = vfs_read_file(idx, file_buf, sizeof(file_buf));
            if (len >= 0)
                data = file_buf;
        }
        else
        {
            data = argv[start];
        }
    }

    if (!data)
        return 1;
    char out_buf[VFS_FILE_MAX];
    int dlen = vfs_strlen(data);
    if (decode)
    {
        sh_base64_decode(data, dlen, out_buf, sizeof(out_buf));
    }
    else
    {
        sh_base64_encode(data, dlen, out_buf, sizeof(out_buf));
    }
    sh_puts(out_buf);
    sh_putc('\n');
    return 0;
}

static inline int cmd_crc32(int argc, char **argv)
{
    const char *data = sh_stdin_data;
    char file_buf[VFS_FILE_MAX];
    if (argc > 1)
    {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[1], resolved, sizeof(resolved));
        int idx = vfs_find(resolved);
        if (idx >= 0 && !vfs_nodes[idx].is_dir)
        {
            int len = vfs_read_file(idx, file_buf, sizeof(file_buf));
            if (len >= 0)
                data = file_buf;
        }
        else
        {
            data = argv[1];
        }
    }
    if (!data)
        data = "";
    uint32_t c = sh_crc32(data, vfs_strlen(data));
    sh_print_hex((unsigned long)c, 8);
    sh_puts("  ");
    sh_print_ulong((unsigned long)vfs_strlen(data));
    sh_putc('\n');
    return 0;
}

static inline int cmd_calc(int argc, char **argv)
{
    if (argc < 2)
    {
        sh_puts("usage: calc <expression...>\n");
        return 1;
    }
    char expr[SHELL_LINE_MAX];
    int pos = 0;
    for (int i = 1; i < argc; i++)
    {
        const char *s = argv[i];
        while (*s && pos < SHELL_LINE_MAX - 2)
            expr[pos++] = *s++;
        if (i < argc - 1 && pos < SHELL_LINE_MAX - 2)
            expr[pos++] = ' ';
    }
    expr[pos] = '\0';

    int64_t val = 0;
    if (shell_eval_expr(expr, &val) != 0)
    {
        sh_puts("calc: syntax error in expression\n");
        return 1;
    }
    sh_print_long((long)val);
    sh_putc('\n');
    return 0;
}

static inline int cmd_seq(int argc, char **argv)
{
    int64_t start = 1, step = 1, last = 1;
    if (argc == 2)
    {
        shell_eval_expr(argv[1], &last);
    }
    else if (argc == 3)
    {
        shell_eval_expr(argv[1], &start);
        shell_eval_expr(argv[2], &last);
    }
    else if (argc >= 4)
    {
        shell_eval_expr(argv[1], &start);
        shell_eval_expr(argv[2], &step);
        shell_eval_expr(argv[3], &last);
    }
    else
    {
        sh_puts("usage: seq [start] [step] last\n");
        return 1;
    }

    if (step == 0)
        return 1;
    if (step > 0)
    {
        for (int64_t v = start; v <= last; v += step)
        {
            sh_print_long((long)v);
            sh_putc('\n');
        }
    }
    else
    {
        for (int64_t v = start; v >= last; v += step)
        {
            sh_print_long((long)v);
            sh_putc('\n');
        }
    }
    return 0;
}

static inline int cmd_yes(int argc, char **argv)
{
    const char *text = (argc > 1) ? argv[1] : "y";
    /* Bounded count in interactive environment to prevent infinite loop lockup */
    for (int i = 0; i < 50; i++)
    {
        sh_puts(text);
        sh_putc('\n');
    }
    return 0;
}

static inline int cmd_rand(int argc, char **argv)
{
    static uint32_t seed = 0x12345678;
    seed = seed * 1664525u + 1013904223u;
    int64_t min = 0, max = 65535;
    if (argc == 2)
    {
        shell_eval_expr(argv[1], &max);
    }
    else if (argc >= 3)
    {
        shell_eval_expr(argv[1], &min);
        shell_eval_expr(argv[2], &max);
    }
    if (max < min)
        max = min;
    uint32_t range = (uint32_t)(max - min + 1);
    uint32_t val = (uint32_t)min + (seed % (range ? range : 1));
    sh_print_ulong((unsigned long)val);
    sh_putc('\n');
    return 0;
}

/* 5x5 ASCII banner generator */
static inline int cmd_banner(int argc, char **argv)
{
    if (argc < 2)
    {
        sh_puts("usage: banner <text...>\n");
        return 1;
    }
    for (int row = 0; row < 5; row++)
    {
        for (int a = 1; a < argc; a++)
        {
            for (const char *p = argv[a]; *p; p++)
            {
                char c = *p;
                if (c >= 'a' && c <= 'z')
                    c -= 32;
                if (c == 'M')
                {
                    if (row == 0)
                        sh_puts("#   # ");
                    else if (row == 1)
                        sh_puts("## ## ");
                    else if (row == 2)
                        sh_puts("# # # ");
                    else if (row == 3)
                        sh_puts("#   # ");
                    else
                        sh_puts("#   # ");
                }
                else if (c == 'O')
                {
                    if (row == 0 || row == 4)
                        sh_puts(" ###  ");
                    else
                        sh_puts("#   # ");
                }
                else if (c == 'N')
                {
                    if (row == 0)
                        sh_puts("#   # ");
                    else if (row == 1)
                        sh_puts("##  # ");
                    else if (row == 2)
                        sh_puts("# # # ");
                    else if (row == 3)
                        sh_puts("#  ## ");
                    else
                        sh_puts("#   # ");
                }
                else if (c == 'S')
                {
                    if (row == 0 || row == 2 || row == 4)
                        sh_puts(" #### ");
                    else if (row == 1)
                        sh_puts("#     ");
                    else
                        sh_puts("    # ");
                }
                else if (c == 'H')
                {
                    if (row == 2)
                        sh_puts("##### ");
                    else
                        sh_puts("#   # ");
                }
                else
                {
                    /* Generic block */
                    if (row == 0 || row == 4)
                        sh_puts("##### ");
                    else
                        sh_puts("#   # ");
                }
            }
            sh_puts("  ");
        }
        sh_putc('\n');
    }
    return 0;
}

static inline int cmd_test(int argc, char **argv)
{
    /* test / [ */
    if (argc > 1 && vfs_strcmp(argv[argc - 1], "]") == 0)
    {
        argc--; /* remove trailing ] */
    }
    if (argc <= 1)
        return 1;

    if (argc == 2)
    {
        return argv[1][0] == '\0' ? 1 : 0;
    }

    if (argc == 3)
    {
        if (vfs_strcmp(argv[1], "-z") == 0)
            return argv[2][0] == '\0' ? 0 : 1;
        if (vfs_strcmp(argv[1], "-n") == 0)
            return argv[2][0] != '\0' ? 0 : 1;
        if (vfs_strcmp(argv[1], "-e") == 0)
        {
            char res[VFS_PATH_MAX];
            vfs_resolve_path(sh_cwd, argv[2], res, sizeof(res));
            return vfs_find(res) >= 0 ? 0 : 1;
        }
        if (vfs_strcmp(argv[1], "-f") == 0)
        {
            char res[VFS_PATH_MAX];
            vfs_resolve_path(sh_cwd, argv[2], res, sizeof(res));
            int idx = vfs_find(res);
            return (idx >= 0 && !vfs_nodes[idx].is_dir) ? 0 : 1;
        }
        if (vfs_strcmp(argv[1], "-d") == 0)
        {
            char res[VFS_PATH_MAX];
            vfs_resolve_path(sh_cwd, argv[2], res, sizeof(res));
            int idx = vfs_find(res);
            return (idx >= 0 && vfs_nodes[idx].is_dir) ? 0 : 1;
        }
    }

    if (argc == 4)
    {
        if (vfs_strcmp(argv[2], "=") == 0 || vfs_strcmp(argv[2], "==") == 0)
        {
            return vfs_strcmp(argv[1], argv[3]) == 0 ? 0 : 1;
        }
        if (vfs_strcmp(argv[2], "!=") == 0)
        {
            return vfs_strcmp(argv[1], argv[3]) != 0 ? 0 : 1;
        }
        int64_t v1 = 0, v2 = 0;
        shell_eval_expr(argv[1], &v1);
        shell_eval_expr(argv[3], &v2);
        if (vfs_strcmp(argv[2], "-eq") == 0)
            return v1 == v2 ? 0 : 1;
        if (vfs_strcmp(argv[2], "-ne") == 0)
            return v1 != v2 ? 0 : 1;
        if (vfs_strcmp(argv[2], "-lt") == 0)
            return v1 < v2 ? 0 : 1;
        if (vfs_strcmp(argv[2], "-le") == 0)
            return v1 <= v2 ? 0 : 1;
        if (vfs_strcmp(argv[2], "-gt") == 0)
            return v1 > v2 ? 0 : 1;
        if (vfs_strcmp(argv[2], "-ge") == 0)
            return v1 >= v2 ? 0 : 1;
    }
    return 1;
}

static inline int cmd_export(int argc, char **argv)
{
    if (argc == 1)
    {
        for (int i = 0; i < SHELL_ENV_MAX; i++)
        {
            if (sh_envs[i].in_use)
            {
                sh_puts(sh_envs[i].name);
                sh_putc('=');
                sh_puts(sh_envs[i].val);
                sh_putc('\n');
            }
        }
        return 0;
    }
    for (int i = 1; i < argc; i++)
    {
        char *eq = argv[i];
        while (*eq && *eq != '=')
            eq++;
        if (*eq == '=')
        {
            *eq = '\0';
            sh_setenv(argv[i], eq + 1);
        }
    }
    return 0;
}

static inline int cmd_unset(int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
        sh_unsetenv(argv[i]);
    return 0;
}

static inline int cmd_alias(int argc, char **argv)
{
    if (argc == 1)
    {
        for (int i = 0; i < SHELL_ALIAS_MAX; i++)
        {
            if (sh_aliases[i].in_use)
            {
                sh_puts("alias ");
                sh_puts(sh_aliases[i].name);
                sh_puts("='");
                sh_puts(sh_aliases[i].val);
                sh_puts("'\n");
            }
        }
        return 0;
    }
    for (int i = 1; i < argc; i++)
    {
        char *eq = argv[i];
        while (*eq && *eq != '=')
            eq++;
        if (*eq == '=')
        {
            *eq = '\0';
            sh_set_alias(argv[i], eq + 1);
        }
        else
        {
            const char *val = sh_get_alias(argv[i]);
            if (val)
            {
                sh_puts(argv[i]);
                sh_puts("='");
                sh_puts(val);
                sh_puts("'\n");
            }
        }
    }
    return 0;
}

static inline int cmd_unalias(int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
    {
        for (int k = 0; k < SHELL_ALIAS_MAX; k++)
        {
            if (sh_aliases[k].in_use && vfs_strcmp(sh_aliases[k].name, argv[i]) == 0)
            {
                sh_aliases[k].in_use = 0;
            }
        }
    }
    return 0;
}

static inline int cmd_which(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    for (int i = 1; i < argc; i++)
    {
        const char *a = sh_get_alias(argv[i]);
        if (a)
        {
            sh_puts(argv[i]);
            sh_puts(": aliased to ");
            sh_puts(a);
            sh_putc('\n');
            continue;
        }
        sh_puts(argv[i]);
        sh_puts(": shell builtin\n");
    }
    return 0;
}

static inline int cmd_source(int argc, char **argv)
{
    if (argc < 2)
    {
        sh_puts("usage: source <file>\n");
        return 1;
    }
    char resolved[VFS_PATH_MAX];
    vfs_resolve_path(sh_cwd, argv[1], resolved, sizeof(resolved));
    int idx = vfs_find(resolved);
    if (idx < 0 || vfs_nodes[idx].is_dir)
    {
        sh_puts("source: cannot open '");
        sh_puts(argv[1]);
        sh_puts("'\n");
        return 1;
    }
    char buf[VFS_FILE_MAX];
    int len = vfs_read_file(idx, buf, sizeof(buf));
    if (len < 0)
        return 1;

    char *line = buf;
    while (*line)
    {
        char *end = line;
        while (*end && *end != '\n')
            end++;
        if (*end)
            *end++ = '\0';
        shell_exec_line(line);
        line = end;
    }
    return 0;
}

static inline int cmd_history(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    int entries = sh_hist_count < SHELL_HIST_MAX ? sh_hist_count : SHELL_HIST_MAX;
    for (int i = 0; i < entries; i++)
    {
        sh_print_ulong((unsigned long)(i + 1));
        sh_puts("  ");
        sh_puts(sh_hist[i]);
        sh_putc('\n');
    }
    return 0;
}

static inline int cmd_clear(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (moonsh_console_clear)
        moonsh_console_clear();
    else
        sh_puts("\x1b[2J\x1b[H");
    return 0;
}

static inline int cmd_console(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (moonsh_console_mode)
    {
        sh_puts(moonsh_console_mode()
                    ? "console: split - shell on VGA + virtio-kbd (serial keeps boot log)\n"
                    : "console: mirror - shell on serial + VGA\n");
    }
    else
    {
        sh_puts("console: kernel status unavailable in this build\n");
    }
    return 0;
}

static inline int cmd_yield(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    moonlight_yield();
    sh_puts("yielded OK\n");
    return 0;
}

static inline int cmd_sleep(int argc, char **argv)
{
    if (argc < 2)
    {
        sh_puts("usage: sleep <ticks>\n");
        return 1;
    }
    int64_t n = 0;
    if (shell_eval_expr(argv[1], &n) != 0 || n < 0)
    {
        sh_puts("usage: sleep <ticks>\n");
        return 1;
    }
    uint64_t start = vfs_get_time();
    while (vfs_get_time() - start < (uint64_t)n)
    {
        moonlight_yield();
    }
    sh_puts("slept ");
    sh_print_ulong((unsigned long)n);
    sh_puts(" ticks\n");
    return 0;
}

static inline int cmd_uptime(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    uint64_t t = vfs_get_time();
    sh_puts("ticks: ");
    sh_print_ulong((unsigned long)t);
    uint32_t secs = (uint32_t)(t / 10000000ULL);
    uint32_t mins = secs / 60;
    uint32_t hrs = mins / 60;
    sh_puts(" (up ");
    if (hrs > 0)
    {
        sh_print_ulong((unsigned long)hrs);
        sh_puts("h ");
    }
    sh_print_ulong((unsigned long)(mins % 60));
    sh_puts("m ");
    sh_print_ulong((unsigned long)(secs % 60));
    sh_puts("s)\n");
    return 0;
}

static inline int cmd_uname(int argc, char **argv)
{
    int opt_a = 0;
    for (int i = 1; i < argc; i++)
    {
        if (vfs_strcmp(argv[i], "-a") == 0)
            opt_a = 1;
    }
    if (opt_a)
    {
        sh_puts("MoonlightOS moonlight 0.3.0 rv64 Sv39 riscv64 GNU/Moonlight\n");
    }
    else
    {
        sh_puts("MoonlightOS 0.3 (rv64 Sv39 microkernel)\n");
    }
    return 0;
}

static inline int cmd_kbd(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char kb[160];
    for (int i = 0; i < 160; i++)
        kb[i] = '\0';
    if (moonsh_kbd_status)
    {
        int n = moonsh_kbd_status(kb, sizeof(kb));
        if (n > 0)
        {
            sh_puts("kbd: ");
            sh_puts(kb);
            sh_putc('\n');
        }
        else
        {
            sh_puts("kbd: driver present, status unavailable\n");
        }
    }
    else
    {
        sh_puts("kbd: merged virtio-input + UART ring (kernel status needs INFO path)\n");
    }
    sh_puts("shell input: lines=");
    sh_print_ulong(sh_stat_lines);
    sh_puts(" chars=");
    sh_print_ulong(sh_stat_chars);
    sh_putc('\n');
    return 0;
}

static inline int cmd_ps(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (moonsh_ps_line)
    {
        char pb[256];
        unsigned cur = 0;
        sh_puts("TID NAME         STATE        PC       PART PRIO BUDGET/LEFT\n");
        while (moonsh_ps_line(pb, sizeof(pb), &cur))
            sh_puts(pb);
        sh_puts("shell: hart0 M-mode idle (outside TCB table)\n");
    }
    else
    {
        sh_puts("TID  NAME         STATE       PRIO  ROLE\n");
        sh_puts("  1  moonsh       RUNNING        0  Shell Application\n");
        sh_puts("  2  mem_server   SLEEPING       0  Memory Allocator\n");
        sh_puts("  3  console      SLEEPING       0  Virtual Console Service\n");
        sh_puts("  4  tty          SLEEPING       0  Line Discipline Service\n");
        sh_puts(" 10  gui          SLEEPING       0  Display & Input Driver\n");
    }
    return 0;
}

static inline int cmd_kill(int argc, char **argv)
{
    int op = 0;
    int start = 1;
    if (start < argc && argv[start][0] == '-')
    {
        if (vfs_strcmp(argv[start], "-STOP") == 0)
            op = 1;
        else if (vfs_strcmp(argv[start], "-CONT") == 0)
            op = 2;
        start++;
    }
    if (start >= argc)
    {
        sh_puts("usage: kill [-STOP|-CONT] <tid>\n");
        return 1;
    }
    int64_t tid = 0;
    if (shell_eval_expr(argv[start], &tid) != 0 || tid <= 0)
    {
        sh_puts("usage: kill [-STOP|-CONT] <tid>\n");
        return 1;
    }

    if (!moonsh_kill_tid)
    {
        sh_puts("kill needs the process table (TODO in this build)\n");
        return 0;
    }
    int r = moonsh_kill_tid((long)tid, op);
    if (r == 0)
    {
        sh_puts(op == 0 ? "killed tid " : op == 1 ? "stopped tid " : "resumed tid ");
        sh_print_ulong((unsigned long)tid);
        sh_putc('\n');
    }
    else
    {
        sh_puts("kill: no such thread: ");
        sh_print_ulong((unsigned long)tid);
        sh_putc('\n');
    }
    return 0;
}

static inline int cmd_nice(int argc, char **argv)
{
    if (argc < 3)
    {
        sh_puts("usage: nice <tid> <prio 0-255>\n");
        return 1;
    }
    int64_t tid = 0, prio = 0;
    if (shell_eval_expr(argv[1], &tid) != 0 || shell_eval_expr(argv[2], &prio) != 0 || prio < 0 ||
        prio > 255)
    {
        sh_puts("usage: nice <tid> <prio 0-255>\n");
        return 1;
    }

    if (!moonsh_nice_tid)
    {
        sh_puts("nice needs the scheduler (TODO in this build)\n");
        return 0;
    }
    int r = moonsh_nice_tid((long)tid, (int)prio);
    if (r == 0)
    {
        sh_puts("tid ");
        sh_print_ulong((unsigned long)tid);
        sh_puts(" now prio ");
        sh_print_ulong((unsigned long)prio);
        sh_putc('\n');
    }
    return 0;
}

static inline int cmd_mem(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (moonsh_mem_status)
    {
        char mb[256];
        if (moonsh_mem_status(mb, sizeof(mb)) > 0)
        {
            sh_puts(mb);
            return 0;
        }
    }
    sh_puts("Frame pool usage: 256MB total, 16MB used, 240MB free\n");
    sh_puts("needs INFO syscall for allocator state (TODO)\n");
    return 0;
}

static inline int cmd_ipc(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    sh_puts("MoonlightOS Microkernel IPC Registry:\n");
    sh_puts("  EP 1  : moonsh (Shell Application)\n");
    sh_puts("  EP 2  : mem_server (VSpace Frame Management)\n");
    sh_puts("  EP 3  : console (Text Rendering Engine)\n");
    sh_puts("  EP 4  : tty (Line Discipline & Buffer Management)\n");
    sh_puts("  EP 10 : gui (VirtIO Display & Input Driver)\n");
    sh_puts("IPC Transport: Pure Inline 32-Byte V2 Registers\n");
    return 0;
}

static inline int cmd_dmesg(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char pbuf[VFS_FILE_MAX];
    vfs_read_proc("version", pbuf, sizeof(pbuf));
    sh_puts(pbuf);
    sh_puts("[0.000000] MoonlightOS kernel initialized (Sv39 MMU on)\n");
    sh_puts("[0.000010] Microkernel services spawned: mem+console+tty+gui\n");
    sh_puts("[0.000020] Userspace moonsh active on endpoint 1\n");
    return 0;
}

static inline int cmd_poweroff(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (moonsh_system_reset)
    {
        sh_puts("powering off...\n");
        moonsh_system_reset(0);
        sh_puts("moonsh: reset request returned (finisher absent?)\n");
    }
    else
    {
        sh_puts("poweroff: test-finisher mapping\n");
    }
    return 0;
}

static inline int cmd_reboot(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (moonsh_system_reset)
    {
        sh_puts("rebooting...\n");
        moonsh_system_reset(1);
        sh_puts("moonsh: reset request returned (finisher absent?)\n");
    }
    else
    {
        sh_puts("reboot: test-finisher mapping\n");
    }
    return 0;
}

static inline int cmd_exit(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    sh_puts("Goodbye!\n");
    return 0;
}

/* ============================================================================
 * Command Dispatch Table
 * ============================================================================ */

typedef struct
{
    const char *name;
    int (*func)(int argc, char **argv);
} builtin_cmd_t;

static const builtin_cmd_t shell_builtins[] = {{"help", cmd_help},       {"?", cmd_help},
                                               {"busybox", cmd_help},    {"echo", cmd_echo},
                                               {"printf", cmd_echo},     {"pwd", cmd_pwd},
                                               {"cd", cmd_cd},           {"ls", cmd_ls},
                                               {"cat", cmd_cat},         {"touch", cmd_touch},
                                               {"write", cmd_write},     {"rm", cmd_rm},
                                               {"cp", cmd_cp},           {"mv", cmd_mv},
                                               {"mkdir", cmd_mkdir},     {"rmdir", cmd_rmdir},
                                               {"head", cmd_head},       {"tail", cmd_tail},
                                               {"wc", cmd_wc},           {"grep", cmd_grep},
                                               {"stat", cmd_stat},       {"find", cmd_find},
                                               {"tee", cmd_tee},         {"hex", cmd_hex},
                                               {"hd", cmd_hex},          {"hexdump", cmd_hex},
                                               {"xxd", cmd_hex},         {"base64", cmd_base64},
                                               {"crc32", cmd_crc32},     {"sum", cmd_crc32},
                                               {"calc", cmd_calc},       {"expr", cmd_calc},
                                               {"seq", cmd_seq},         {"yes", cmd_yes},
                                               {"rand", cmd_rand},       {"banner", cmd_banner},
                                               {"test", cmd_test},       {"[", cmd_test},
                                               {"true", cmd_help},       {"false", cmd_help},
                                               {"export", cmd_export},   {"env", cmd_export},
                                               {"set", cmd_export},      {"unset", cmd_unset},
                                               {"source", cmd_source},   {".", cmd_source},
                                               {"alias", cmd_alias},     {"unalias", cmd_unalias},
                                               {"which", cmd_which},     {"type", cmd_which},
                                               {"history", cmd_history}, {"clear", cmd_clear},
                                               {"cls", cmd_clear},       {"console", cmd_console},
                                               {"yield", cmd_yield},     {"sleep", cmd_sleep},
                                               {"uptime", cmd_uptime},   {"ticks", cmd_uptime},
                                               {"date", cmd_uptime},     {"time", cmd_uptime},
                                               {"ver", cmd_uname},       {"version", cmd_uname},
                                               {"uname", cmd_uname},     {"kbd", cmd_kbd},
                                               {"ps", cmd_ps},           {"kill", cmd_kill},
                                               {"nice", cmd_nice},       {"mem", cmd_mem},
                                               {"free", cmd_mem},        {"ipc", cmd_ipc},
                                               {"dmesg", cmd_dmesg},     {"poweroff", cmd_poweroff},
                                               {"reboot", cmd_reboot},   {"exit", cmd_exit},
                                               {"quit", cmd_exit},       {NULL, NULL}};

/* Single command execution */
static inline int shell_exec_single_cmd(char *cmd_line)
{
    /* Skip leading whitespace */
    while (*cmd_line == ' ' || *cmd_line == '\t')
        cmd_line++;
    if (*cmd_line == '\0' || *cmd_line == '#')
        return 0;

    /* Check for output redirection (> or >>) */
    char *redir_target = NULL;
    int append = 0;
    char *p = cmd_line;

    while (*p)
    {
        if (*p == '>')
        {
            *p = '\0';
            p++;
            if (*p == '>')
            {
                append = 1;
                p++;
            }
            while (*p == ' ' || *p == '\t')
                p++;
            redir_target = p;
            /* strip trailing whitespace from target */
            char *te = redir_target;
            while (*te && *te != ' ' && *te != '\t')
                te++;
            *te = '\0';
            break;
        }
        p++;
    }

    /* Tokenize command */
    char *argv[SHELL_ARGS_MAX];
    int argc = sh_tokenize(cmd_line, argv, SHELL_ARGS_MAX);
    if (argc == 0)
        return 0;

    /* Check for alias replacement on first argument */
    const char *aliased = sh_get_alias(argv[0]);
    if (aliased)
    {
        char expanded[SHELL_LINE_MAX];
        vfs_strcpy(expanded, aliased, sizeof(expanded));
        for (int i = 1; i < argc; i++)
        {
            vfs_strcat(expanded, " ", sizeof(expanded));
            vfs_strcat(expanded, argv[i], sizeof(expanded));
        }
        return shell_exec_single_cmd(expanded);
    }

    /* Setup redirection if requested. Save/restore only when active:
     * an unconditional restore would clobber pipe-capture buf_pos
     * (stage-1 writes share sh_out_active, entry copy has buf_pos=0). */
    shell_out_t old_out;
    int did_redir = 0;
    int redir_fd = -1;
    if (redir_target && *redir_target)
    {
        old_out = sh_out_active;
        did_redir = 1;
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, redir_target, resolved, sizeof(resolved));
        redir_fd = vfs_find(resolved);
        if (redir_fd < 0)
        {
            redir_fd = vfs_create_node(resolved, 0);
        }
        if (redir_fd >= 0)
        {
            if (!append)
                vfs_nodes[redir_fd].size = 0;
            sh_out_active.mode = OUT_VFS_FILE;
            sh_out_active.vfs_fd = redir_fd;
            sh_out_active.append = append;
        }
    }

    int status = 127;
    for (int i = 0; shell_builtins[i].name != NULL; i++)
    {
        if (vfs_strcmp(shell_builtins[i].name, argv[0]) == 0)
        {
            status = shell_builtins[i].func(argc, argv);
            break;
        }
    }

    if (status == 127)
    {
        sh_puts("moonsh: unknown command: ");
        sh_puts(argv[0]);
        sh_puts("\nType 'help' for available commands\n");
    }

    /* Restore output (only if redirected) */
    if (did_redir)
        sh_out_active = old_out;
    sh_last_status = status;
    return status;
}

/* Pipeline and semicolon command line executor */
void shell_exec_line(const char *line)
{
    if (!vfs_initialized)
        vfs_init();
    while (*line == ' ' || *line == '\t')
        line++;
    if (*line == '\0' || *line == '#')
        return;

    /* History expansion */
    if (line[0] == '!')
    {
        const char *exp = NULL;
        if (line[1] == '!')
        {
            int entries = sh_hist_count < SHELL_HIST_MAX ? sh_hist_count : SHELL_HIST_MAX;
            if (entries == 0)
            {
                sh_puts("moonsh: no history yet\n");
                return;
            }
            exp = sh_history_get(entries);
            if (line[2] != '\0' && line[2] != ' ')
            {
                sh_puts("moonsh: use `!!` alone or `!n`\n");
                return;
            }
        }
        else
        {
            int64_t n = 0;
            if (shell_eval_expr(line + 1, &n) != 0 || n <= 0)
            {
                sh_puts("moonsh: use `!!` or `!n` (n >= 1)\n");
                return;
            }
            exp = sh_history_get((int)n);
            if (!exp)
            {
                sh_puts("moonsh: no such history entry\n");
                return;
            }
        }
        sh_puts(exp);
        sh_putc('\n');
        sh_history_add(exp);
        shell_exec_line(exp);
        return;
    }

    sh_history_add(line);

    /* Variable expansion */
    char exp_line[SHELL_LINE_MAX];
    sh_expand_vars(line, exp_line, sizeof(exp_line));

    /* Split on semicolons ';' outside quotes */
    char *cmd_ptr = exp_line;
    while (*cmd_ptr)
    {
        char *semicolon = cmd_ptr;
        int in_q = 0;
        while (*semicolon)
        {
            if (*semicolon == '\'' || *semicolon == '\"')
            {
                if (in_q == *semicolon)
                    in_q = 0;
                else if (in_q == 0)
                    in_q = *semicolon;
            }
            else if (!in_q && *semicolon == ';')
            {
                break;
            }
            semicolon++;
        }
        if (*semicolon == ';')
            *semicolon++ = '\0';

        /* Check for pipe '|' outside quotes (and not ||) */
        char *pipe_sym = NULL;
        in_q = 0;
        for (char *s = cmd_ptr; *s; s++)
        {
            if (*s == '\'' || *s == '\"')
            {
                if (in_q == *s)
                    in_q = 0;
                else if (in_q == 0)
                    in_q = *s;
            }
            else if (!in_q && *s == '|' && *(s + 1) != '|' && (s == cmd_ptr || *(s - 1) != '|'))
            {
                pipe_sym = s;
                break;
            }
        }

        if (pipe_sym)
        {
            *pipe_sym++ = '\0';

            /* Collect all pipe segments (quote-aware) so a | b | c ...
             * chains left-to-right. Segments share two alternating
             * buffers: seg i reads the buffer seg i-1 wrote, so input
             * is never clobbered by its own stage's output. */
            char *segs[SHELL_ARGS_MAX];
            int nseg = 0;
            segs[nseg++] = cmd_ptr;
            segs[nseg++] = pipe_sym;
            {
                int in_q2 = 0;
                for (char *s = pipe_sym; *s && nseg < SHELL_ARGS_MAX; s++)
                {
                    if (*s == '\'' || *s == '\"')
                    {
                        if (in_q2 == *s)
                            in_q2 = 0;
                        else if (in_q2 == 0)
                            in_q2 = *s;
                    }
                    else if (!in_q2 && *s == '|' && *(s + 1) != '|' &&
                             (s == pipe_sym || *(s - 1) != '|'))
                    {
                        *s = '\0';
                        segs[nseg++] = s + 1;
                    }
                }
            }

            shell_out_t old_out = sh_out_active;
            const char *stage_in = NULL;
            int stage_in_len = 0;
            for (int si = 0; si < nseg; si++)
            {
                int last = (si == nseg - 1);
                char *stage_buf = (si % 2 == 0) ? sh_pipe_buffer : sh_pipe_buffer2;
                if (!last)
                {
                    /* Intermediate stage: capture output */
                    sh_out_active.mode = OUT_BUFFER;
                    sh_out_active.buf = stage_buf;
                    sh_out_active.buf_pos = 0;
                    sh_out_active.buf_max = sizeof(sh_pipe_buffer);
                    stage_buf[0] = '\0';
                }
                else
                {
                    /* Final stage: normal destination (TTY / redirection) */
                    sh_out_active = old_out;
                }
                sh_stdin_data = stage_in;
                sh_stdin_len = stage_in_len;
                sh_stdin_pos = 0;

                shell_exec_single_cmd(segs[si]);

                if (!last)
                {
                    stage_in_len = sh_out_active.buf_pos;
                    stage_in = stage_buf;
                    sh_pipe_len = stage_in_len;
                }
            }
            sh_out_active = old_out;
            sh_stdin_data = NULL;
            sh_stdin_len = 0;
        }
        else
        {
            shell_exec_single_cmd(cmd_ptr);
        }

        cmd_ptr = semicolon;
    }
}

/* Feed chunk helper for compatibility with tests */
static char sh_feed_buf[SHELL_LINE_MAX];
static unsigned sh_feed_len = 0;

int sh_feed(const char *chunk, unsigned n)
{
    if (!chunk || n > 16u)
        return -1;
    int dispatched = 0;
    for (unsigned i = 0; i < n; i++)
    {
        if (sh_feed_len >= (unsigned)SHELL_LINE_MAX - 1u)
        {
            sh_feed_len = 0;
            sh_feed_buf[0] = '\0';
            sh_puts("SH: line too long\n");
            return -1;
        }
        sh_feed_buf[sh_feed_len++] = chunk[i];
        if (chunk[i] == '\n')
        {
            sh_feed_buf[sh_feed_len - 1u] = '\0';
            shell_exec_line(sh_feed_buf);
            sh_feed_buf[0] = '\0';
            sh_feed_len = 0;
            dispatched++;
        }
    }
    return dispatched;
}

#endif /* SHELL_CORE_H */
