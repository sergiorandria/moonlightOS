/* test_shell - host-sim for moonsh: scripted input, captured output. */
#include <stdio.h>
#include <string.h>
#include <assert.h>

static char out_buf[4096];
static int out_len;

int moonlight_putc(char c) {
    if (out_len < (int)sizeof(out_buf) - 1) out_buf[out_len++] = c;
    return c;
}
int moonlight_getc(void) { return -1; }
int moonlight_yield(void) { return 0; }

void shell_exec_line(const char *line);

static void reset_out(void) { out_len = 0; out_buf[0] = '\0'; }
static void check(const char *cmd, const char *expect) {
    reset_out();
    shell_exec_line(cmd);
    out_buf[out_len] = '\0';
    if (!strstr(out_buf, expect)) {
        printf("FAIL: cmd='%s' expected '%s' got '%s'\n", cmd, expect, out_buf);
        assert(0);
    }
    printf("PASS: shell '%s' -> '%s'\n", cmd, expect);
}

int main(void) {
    check("help", "moonsh builtins");
    check("help", "yield");
    check("echo hello moon", "hello moon");
    check("echo", "\n");
    check("clear", "\x1b[2J");
    check("yield", "yielded OK");
    check("uptime", "ticks:");
    check("ps", "RUNNING");
    check("mem", "TODO");
    check("frobnicate", "unknown command");
    check("", "");
    check("   ", "");
    printf("ALL SHELL TESTS PASS\n");
    return 0;
}
