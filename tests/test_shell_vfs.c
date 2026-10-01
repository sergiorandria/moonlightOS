/* tests/test_shell_vfs.c - KATs for sh_feed + VA-backed VFS pairing. */
#include <stdio.h>
#include <string.h>
#include "../userspace/sh/shell.c"
#include "../userspace/lib/moonlight.c"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

int main(void) {
    /* feed: VFS-free lines dispatch, chunk splits reassemble. */
    CHECK(sh_feed("help\n", 5) == 1);
    CHECK(sh_feed("ec", 2) == 0);
    CHECK(sh_feed("ho hi\n", 6) == 1);   /* "echo hi" across a split */
    CHECK(sh_feed("", 0) == 0);          /* empty chunk */
    CHECK(sh_feed("0123456789ABCDEFx", 17) == -1); /* n > 16 reject */
    printf("PASS: test_shell_vfs\n");
    return 0;
}
