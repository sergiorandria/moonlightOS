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
void shell_test_reset(void);

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

static void check_exact(const char *cmd, const char *expect) {
    reset_out();
    shell_exec_line(cmd);
    out_buf[out_len] = '\0';
    if (strcmp(out_buf, expect) != 0) {
        printf("FAIL: cmd='%s' expected exact '%s' got '%s'\n", cmd, expect, out_buf);
        assert(0);
    }
    printf("PASS: shell '%s' exact\n", cmd);
}

int main(void) {
    shell_test_reset();
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

    /* Extended builtins. */
    check("ver", "MoonlightOS");
    check("version", "MoonlightOS");
    check("uname", "MoonlightOS");
    check("ticks", "ticks:");
    check("cls", "\x1b[2J");
    check("kbd", "kbd:");
    check("sleep 0", "slept 0 ticks");
    check("sleep xyz", "usage: sleep");
    check("hex hi", "68");
    check("hex hi", "hi");
    check("hd hi", "68");
    check("hd", "usage:");
    check("hex", "usage: hex");
    check_exact("echo -n hi", "hi");
    check("echo -n hi", "hi");
    check("help echo", "echo [-n]");
    check("help frobnicate", "no help");
    check("poweroff", "test-finisher");
    check("reboot", "test-finisher");
    check("kill 3", "TODO in this build");
    check("kill -STOP 3", "TODO in this build");
    check("kill -CONT 3", "TODO in this build");
    check("kill", "usage: kill");
    check("kill xyz", "usage: kill");
    check("nice 3 2", "TODO in this build");
    check("nice", "usage: nice");
    check("nice 3", "usage: nice");
    check("nice 3 300", "usage: nice");
    check("help kill", "destroy");
    /* VFS: userspace ELF has no server linked (weak refs NULL). */
    check("ls", "TODO in this build");
    check("cat notes.txt", "TODO in this build");
    check("cat", "usage: cat");
    check("write notes.txt hi", "TODO in this build");
    check("write", "usage: write");
    check("rm notes.txt", "TODO in this build");
    check("rm", "usage: rm");
    check("help ls", "list files");
    check("help cat", "print file");
    check("help write", "overwrite");
    check("help rm", "delete");
    check("help nice", "priority");
    check("console", "console:");
    check("help console", "serial/VGA");

    /* History: reset, record two commands, expand. */
    shell_test_reset();
    reset_out();
    shell_exec_line("!!");
    out_buf[out_len] = '\0';
    assert(strstr(out_buf, "no history") && "!! empty -> no history");
    printf("PASS: shell '!!' empty\n");

    check("echo first", "first");
    check("echo second", "second");
    check("history", "echo first");
    check("history", "echo second");
    check("!!", "second");       /* repeats `history` output tail; contains second */
    check("!1", "first");        /* repeats entry #1 */
    reset_out();
    shell_exec_line("!99");
    out_buf[out_len] = '\0';
    assert(strstr(out_buf, "no such history") && "!99 -> no such");
    printf("PASS: shell '!99'\n");
    reset_out();
    shell_exec_line("!x");
    out_buf[out_len] = '\0';
    assert(strstr(out_buf, "use `!!`") && "!x -> usage");
    printf("PASS: shell '!x'\n");

    printf("ALL SHELL TESTS PASS\n");
    return 0;
}
