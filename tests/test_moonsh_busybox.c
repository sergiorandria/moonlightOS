/*
 * test_moonsh_busybox.c - Comprehensive test suite for moonsh BusyBox applets
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static char test_out[8192];
static int test_out_len = 0;

void shell_platform_write(const char *s, int len)
{
    for (int i = 0; i < len; i++)
    {
        if (test_out_len < (int)sizeof(test_out) - 1)
        {
            test_out[test_out_len++] = s[i];
        }
    }
    test_out[test_out_len] = '\0';
}

int moonlight_putc(char c)
{
    shell_platform_write(&c, 1);
    return (int)(unsigned char)c;
}

int moonlight_yield(void)
{
    return 0;
}

#include "../userspace/sh/shell_core.h"

static void reset_buf(void)
{
    test_out_len = 0;
    test_out[0] = '\0';
}

static void run_check(const char *cmd, const char *expected)
{
    reset_buf();
    shell_exec_line(cmd);
    if (!strstr(test_out, expected))
    {
        printf("FAIL: cmd='%s' expected '%s' got '%s'\n", cmd, expected, test_out);
        fflush(stdout);
        assert(0);
    }
    printf("PASS: '%s' -> contains '%s'\n", cmd, expected);
    fflush(stdout);
}

static void run_exact(const char *cmd, const char *expected)
{
    reset_buf();
    shell_exec_line(cmd);
    if (strcmp(test_out, expected) != 0)
    {
        printf("FAIL: cmd='%s' expected exact '%s' got '%s'\n", cmd, expected, test_out);
        fflush(stdout);
        assert(0);
    }
    printf("PASS: '%s' -> exact '%s'\n", cmd, expected);
    fflush(stdout);
}

int main(void)
{
    setbuf(stdout, NULL);
    printf("=== Testing moonsh BusyBox Suite ===\n");
    shell_test_reset();

    /* 1. Core Builtins */
    run_check("help", "moonsh builtins:");
    run_check("help", "busybox");
    run_check("help echo", "echo [-n]");
    run_check("help calc", "integer arithmetic");
    run_check("busybox", "moonsh builtins:");
    run_exact("echo hello world", "hello world\n");
    run_exact("echo -n hello", "hello");
    run_exact("echo -e hello\\tworld\\n", "hello\tworld\n\n");
    run_check("pwd", "/");
    run_check("clear", "\x1b[2J");
    run_check("yield", "yielded OK");
    run_check("true", "");
    run_check("which echo", "shell builtin");

    /* 2. Math & Expressions */
    run_exact("calc 2 + 2", "4\n");
    run_exact("calc 10 + 20 * 3", "70\n");
    run_exact("calc (10 + 20) * 3", "90\n");
    run_exact("calc 100 / 4 - 5", "20\n");
    run_exact("calc 1 << 8", "256\n");
    run_exact("calc 0xFF & 0x0F", "15\n");
    run_exact("calc \"0x10 | 0x01\"", "17\n");
    run_exact("calc 10 % 3", "1\n");
    run_exact("calc 5 == 5", "1\n");
    run_exact("calc 5 != 5", "0\n");
    run_exact("seq 1 4", "1\n2\n3\n4\n");
    run_exact("seq 2 2 8", "2\n4\n6\n8\n");

    /* 3. Base64 & CRC32 */
    run_exact("echo hello | base64", "aGVsbG8K\n");
    run_exact("echo aGVsbG8K | base64 -d", "hello\n\n");
    run_check("echo 123456789 | crc32", "  10\n");

    /* 4. VFS & File Operations */
    run_check("ls", "etc/");
    run_check("ls", "proc/");
    run_check("ls -l /etc", "os-release");
    run_check("cat /etc/version", "0.3.0");
    run_check("cat -n /etc/hostname", "     1\tmoonlight");
    run_check("cat /readme.txt", "MoonlightOS Production Shell");
    run_check("stat /etc/os-release", "Regular File");

    /* File creation, write, read */
    shell_exec_line("touch /test.txt");
    run_check("ls /", "test.txt");
    shell_exec_line("write /test.txt my test file content");
    run_check("cat /test.txt", "my test file content");
    shell_exec_line("cp /test.txt /copy.txt");
    run_check("cat /copy.txt", "my test file content");
    shell_exec_line("mv /copy.txt /moved.txt");
    run_check("cat /moved.txt", "my test file content");
    shell_exec_line("rm /moved.txt");
    run_check("cat /moved.txt", "No such file or directory");

    /* Directories */
    shell_exec_line("mkdir /my_dir");
    run_check("ls /", "my_dir/");
    shell_exec_line("cd /my_dir");
    run_check("pwd", "/my_dir");
    shell_exec_line("touch file_in_dir.txt");
    run_check("ls", "file_in_dir.txt");
    shell_exec_line("cd ..");
    run_check("pwd", "/");

    /* Task 2: uniform BusyBox error text + exit codes */
    run_check("ls /nope", "ls: cannot access '/nope'");
    shell_exec_line("ls /nope");
    run_check("echo $?", "1");
    run_check("cat /nope", "cat: /nope: No such file or directory");
    run_check("ls -z /", "invalid option");
    shell_exec_line("ls -z /");
    run_check("echo $?", "2");

    /* Task 3: ls busybox compat (coreutils/ls.c) */
    run_check("ls -A /", "etc/");
    run_exact("ls -d /etc", "/etc\n");
    run_check("ls -1 /etc", "os-release");
    run_check("ls /etc /nope", "os-release");
    shell_exec_line("ls /etc /nope");
    run_check("echo $?", "1");
    run_check("ls -R /", "etc/");
    run_check("ls -R /", "/etc:");
    run_exact("ls -dR /etc", "/etc\n");

    /* ls sorting (coreutils/ls.c sortcmp: name default, -r/-S/-t) */
    shell_exec_line("mkdir /sortt");
    shell_exec_line("touch /sortt/zebra.txt");
    shell_exec_line("touch /sortt/apple.txt");
    shell_exec_line("touch /sortt/mango.txt");
    run_exact("ls /sortt", "apple.txt\nmango.txt\nzebra.txt\n");
    run_exact("ls -r /sortt", "zebra.txt\nmango.txt\napple.txt\n");
    shell_exec_line("write /sortt/zebra.txt 1234567890");
    shell_exec_line("write /sortt/apple.txt 12");
    run_exact("ls -S /sortt", "zebra.txt\napple.txt\nmango.txt\n");
    shell_exec_line("rm -r /sortt");

    /* Task 4: cat busybox compat (coreutils/cat.c: catv/numbering/open_or_warn_stdin) */
    run_exact("echo -e \"a\\n\\nb\" | cat -b", "     1\ta\n\n     2\tb\n");
    run_exact("echo -e \"a\\n\\nb\" | cat -n", "     1\ta\n     2\t\n     3\tb\n");
    run_exact("echo -e \"a\\n\\n\\nb\" | cat -s", "a\n\nb\n");
    run_exact("echo -e \"a\\nb\" | cat -E", "a$\nb$\n");
    run_exact("echo -e \"a\\n\\nb\" | cat -bn", "     1\ta\n\n     2\tb\n");
    run_exact("echo -e \"a\\n\\n\\nb\" | cat -sn", "     1\ta\n     2\t\n     3\tb\n");
    run_exact("echo -e \"hi\" | cat", "hi\n");
    run_exact("echo -e \"hi\" | cat -", "hi\n");
    run_check("cat /etc/version /nope", "0.3.0");
    shell_exec_line("cat /etc/version /nope");
    run_check("echo $?", "1");

    /* Head & Tail & WC */
    run_check("head -n 2 /etc/os-release", "NAME=\"MoonlightOS\"");
    run_check("tail -n 2 /etc/os-release", "ARCH=\"riscv64\"");
    run_check("wc -l /etc/os-release", "6");

    /* Task 5: head/tail/wc busybox compat (head.c/tail.c/wc.c: -n/-c, +n, total) */
    run_exact("seq 1 5 | head -c 3", "1\n2");
    run_exact("seq 1 5 | head -n 2", "1\n2\n");
    run_exact("seq 1 5 | tail -n 2", "4\n5\n");
    run_exact("seq 1 5 | tail -c 4", "4\n5\n");
    run_exact("seq 1 5 | tail -n +3", "3\n4\n5\n");
    run_exact("seq 1 10 | tail -n +8", "8\n9\n10\n");
    run_exact("seq 1 5 | tail +2", "2\n3\n4\n5\n");
    run_exact("echo -e \"hi\" | head -", "hi\n");
    run_exact("echo -e \"hi\" | tail -", "hi\n");
    run_exact("echo hi | wc -c", "3\n");
    run_exact("echo abcdef | wc -L", "6\n");
    run_exact("wc /etc/version /etc/hostname",
              "1 1 6 /etc/version\n1 1 10 /etc/hostname\n2 2 16 total\n");
    run_check("wc /etc/version /etc/hostname", "total");
    run_check("wc /nope /etc/version", "1 1 6 /etc/version");
    shell_exec_line("wc /etc/version /nope");
    run_check("echo $?", "1");
    run_check("head -z", "invalid option");
    shell_exec_line("head -z");
    run_check("echo $?", "2");
    run_exact("head -n 1 /etc/version /etc/hostname",
              "==> /etc/version <==\n0.3.0\n\n==> /etc/hostname <==\nmoonlight\n");

    /* Task 6: touch/cp/mv/rm/mkdir/rmdir/stat/find/tee (BusyBox 1_36_stable
       cp.c/mv.c/rm.c/mkdir.c/touch.c/stat.c/findutils/find.c/tee.c) */
    shell_exec_line("mkdir -p /a/b/c");
    run_check("ls /a/b", "c/");
    shell_exec_line("touch -c /nope");
    run_check("echo $?", "0");
    run_check("cat /nope", "No such file or directory");
    shell_exec_line("touch /t6.txt");
    run_check("ls /", "t6.txt");
    run_exact("stat -c %n /t6.txt", "/t6.txt");
    run_exact("stat -c %s /etc/version", "6");
    run_exact("stat -c %n:%s /t6.txt", "/t6.txt:0");
    run_exact("stat -c %F /etc", "directory");
    run_exact("stat -c %F /etc/version", "regular file");
    shell_exec_line("stat /nope");
    run_check("echo $?", "1");
    shell_exec_line("write /t6src.txt hello6");
    shell_exec_line("cp /t6src.txt /t6dst.txt");
    run_check("cat /t6dst.txt", "hello6");
    shell_exec_line("rm /t6dst.txt");
    shell_exec_line("cp -r /a /a2");
    run_check("ls /a2/b", "c/");
    shell_exec_line("rm -r /a2");
    shell_exec_line("rm -r /a");
    shell_exec_line("write /t6a.txt AAA");
    shell_exec_line("write /t6b.txt BBB");
    shell_exec_line("cp -i /t6a.txt /t6b.txt");
    run_check("cat /t6b.txt", "BBB");
    shell_exec_line("cp -f /t6a.txt /t6b.txt");
    run_check("cat /t6b.txt", "AAA");
    shell_exec_line("rm /t6a.txt /t6b.txt");
    shell_exec_line("write /t6m1.txt M1");
    shell_exec_line("write /t6m2.txt M2");
    shell_exec_line("mv -i /t6m1.txt /t6m2.txt");
    run_check("cat /t6m2.txt", "M2");
    run_check("cat /t6m1.txt", "M1");
    shell_exec_line("mv -f /t6m1.txt /t6m2.txt");
    run_check("cat /t6m2.txt", "M1");
    run_check("cat /t6m1.txt", "No such file or directory");
    shell_exec_line("rm /t6m2.txt");
    shell_exec_line("mkdir /t6d");
    shell_exec_line("touch /t6d/f");
    shell_exec_line("rm /t6d");
    run_check("echo $?", "1");
    shell_exec_line("rm -r /t6d");
    run_check("ls /t6d", "cannot access");
    shell_exec_line("touch /t6i.txt");
    shell_exec_line("rm -i /t6i.txt");
    run_check("ls /", "t6i.txt");
    shell_exec_line("rm -f /t6i.txt");
    run_check("cat /t6i.txt", "No such file or directory");
    shell_exec_line("rm -f /nope2");
    run_check("echo $?", "0");
    shell_exec_line("cp /nope /x");
    run_check("echo $?", "1");
    run_check("cp /nope /x", "cp: cannot stat '/nope'");
    shell_exec_line("mkdir -p /t6p/x/y");
    run_check("ls /t6p/x", "y/");
    shell_exec_line("rmdir -p /t6p/x/y");
    run_check("ls /t6p", "cannot access");
    shell_exec_line("mkdir -p /etc");
    run_check("echo $?", "0");
    run_exact("mkdir /t_fix", "");
    run_check("echo $?", "0");
    shell_exec_line("rmdir /t_fix");
    run_check("find /etc -name os*", "os-release");
    run_check("find /etc -type f -name hostname", "hostname");
    run_check("find / -maxdepth 1 -name etc", "/etc");
    shell_exec_line("echo one | tee /t6t.txt");
    run_check("cat /t6t.txt", "one");
    shell_exec_line("echo two | tee -a /t6t.txt");
    run_check("cat /t6t.txt", "one");
    run_check("cat /t6t.txt", "two");
    run_check("cp -z a b", "invalid option");
    shell_exec_line("cp -z a b");
    run_check("echo $?", "2");
    shell_exec_line("rm /t6.txt /t6src.txt /t6t.txt");

    /* 5. Dynamic Procfs */
    run_check("cat /proc/version", "MoonlightOS version 0.3.0");
    run_check("cat /proc/meminfo", "MemTotal:");
    run_check("cat /proc/cpuinfo", "processor");
    run_check("cat /proc/threads", "moonsh");
    run_check("cat /proc/mounts", "rootfs / ramfs");

    /* 6. Redirection & Pipes */
    shell_exec_line("echo \"redirected string\" > /output.txt");
    run_check("cat /output.txt", "redirected string");
    shell_exec_line("echo \"second line\" >> /output.txt");
    run_check("cat /output.txt", "second line");
    run_check("wc -l /output.txt", "2");

    /* Pipes */
    run_exact("cat /etc/version | grep 0.3.0", "0.3.0\n");
    run_check("cat /etc/os-release | grep ID=", "ID=\"moonlight\"");
    run_exact("echo \"foo bar baz\" | wc -w", "3\n");
    run_exact("seq 1 10 | head -n 3", "1\n2\n3\n");

    /* Chained pipes (a | b | c ...): N-segment left-to-right threading */
    run_exact("echo hello | cat | wc -c", "6\n");
    run_exact("seq 1 10 | head -n 3 | wc -l", "3\n");
    run_exact("seq 1 10 | head -n 5 | tail -n 2 | wc -l", "2\n");

    /* 7. Variables & Expansion */
    shell_exec_line("export MY_VAR=MoonlightRock");
    run_check("echo $MY_VAR", "MoonlightRock");
    run_check("echo $USER", "root");
    run_check("echo $HOSTNAME", "moonlight");
    run_check("echo $ARCH", "riscv64");
    shell_exec_line("unset MY_VAR");
    run_exact("echo $MY_VAR", "\n");

    /* 8. Conditions (test / [) */
    shell_exec_line("test 10 -lt 20");
    run_check("echo $?", "0");
    shell_exec_line("test 10 -gt 20");
    run_check("echo $?", "1");
    shell_exec_line("[ -f /etc/os-release ]");
    run_check("echo $?", "0");
    shell_exec_line("[ -d /etc ]");
    run_check("echo $?", "0");
    shell_exec_line("[ \"apple\" = \"apple\" ]");
    run_check("echo $?", "0");
    shell_exec_line("[ \"apple\" != \"banana\" ]");
    run_check("echo $?", "0");

    /* 9. Aliases */
    shell_exec_line("alias myver=\"cat /etc/version\"");
    run_check("which myver", "aliased to");
    run_check("myver", "0.3.0");
    shell_exec_line("unalias myver");

    /* 10. System Diagnostics */
    run_check("uname", "MoonlightOS");
    run_check("uname -a", "riscv64");
    run_check("uptime", "ticks:");
    run_check("ps", "moonsh");
    run_check("ipc", "Microkernel IPC Registry");
    run_check("dmesg", "MoonlightOS");
    run_check("banner MOON", "#");

    /* 11. Script Execution */
    run_check("source /bin/demo.sh", "System architecture");
    run_check("source /bin/demo.sh", "Finished demo");

    /* 12. Command Chaining with Semicolons */
    run_exact("echo A; echo B; echo C", "A\nB\nC\n");

    /* 13. VFS node budget discipline (VFS_MAX_NODES=32): the suite must
     * clean up its scratch dirs (rm -r /sortt etc.) so later tests keep
     * headroom. Baseline image + legitimate leftovers sit near ~23. */
    {
        int vfs_used = 0;
        for (int i = 0; i < VFS_MAX_NODES; i++)
            if (vfs_nodes[i].in_use)
                vfs_used++;
        if (vfs_used > 28)
        {
            printf("FAIL: VFS budget exceeded: %d/32 nodes in use (leaked scratch?)\n", vfs_used);
            assert(0);
        }
        printf("PASS: VFS budget %d/32 nodes\n", vfs_used);
    }

    printf("\n>>> ALL MOONSH BUSYBOX TESTS PASSED SUCCESSFULLY! <<<\n");
    return 0;
}
