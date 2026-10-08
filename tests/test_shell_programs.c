/* tests/test_shell_programs.c — pins userspace/shell_programs.h to the
 * tools/mkinitrd.sh ELFS order (single source of truth, production
 * microkernel layout):
 *   0 mem_server, 1 moonsh, 2 UNUSED, 3 console, 4 tty, 5-9 UNUSED, 10 gui.
 * A stale table executes the WRONG image (isolation violation), so any
 * mkinitrd.sh reorder must update shell_programs.h + this test together.
 *
 * Run: gcc -o /tmp/test_shell_programs tests/test_shell_programs.c && /tmp/test_shell_programs
 */
#include <stdio.h>

#include "../userspace/shell_programs.h"

#define CHECK(c)                                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(c))                                                                                                      \
        {                                                                                                              \
            printf("FAIL line %d: %s\n", __LINE__, #c);                                                                \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

int main(void)
{
    /* Packed images resolve to their real initrd slots. */
    CHECK(shell_lookup_program("mem_server") == 0);
    CHECK(shell_lookup_program("moonsh") == 1);
    CHECK(shell_lookup_program("console") == 3);
    CHECK(shell_lookup_program("tty") == 4);
    CHECK(shell_lookup_program("gui") == 10);
    /* Unpacked names + UNUSED holes must not resolve (no wrong-image). */
    CHECK(shell_lookup_program("qrexec") == -1);
    CHECK(shell_lookup_program("adminvm") == -1);
    CHECK(shell_lookup_program("firewall") == -1);
    CHECK(shell_lookup_program("net") == -1);
    CHECK(shell_lookup_program("vault") == -1);
    CHECK(shell_lookup_program("cryptblk") == -1);
    CHECK(shell_lookup_program("ls") == -1);
    CHECK(shell_lookup_program("cat") == -1);
    CHECK(shell_lookup_program("echo") == -1);
    CHECK(shell_lookup_program("hello") == -1);
    CHECK(shell_lookup_program("") == -1);
    CHECK(shell_lookup_program("nope") == -1);
    printf("shell_programs ok\n");
    return 0;
}
