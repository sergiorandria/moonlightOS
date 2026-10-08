/* tests/test_shell_vfs.c - KATs for sh_feed + VA-backed VFS pairing. */
#include <stdio.h>
#include <stdlib.h>
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
    CHECK(sh_feed((const char *)0, 1) == -1); /* NULL chunk */
    { /* Task-1 deferred: >127B without newline drops + resets, fail-closed. */
        int k, r = 0;
        for (k = 0; k < 7; k++) /* bound: 7 */
            r = sh_feed("0123456789ABCDEF", 16);
        CHECK(r == 0);
        CHECK(sh_feed("0123456789ABCDEF", 16) == -1); /* 128th byte trips */
        CHECK(sh_feed("ok\n", 3) == 1); /* reset worked, dispatch ok */
    }
    /* VA round-trip over a malloc'd shadow (stands in for a mapped frame). */
    {
        char *shadow;
        int fd;
        char back[8];
        int r;
        shadow = (char *)malloc(4096);
        CHECK(shadow != (char *)0);
        memset(shadow, 0, 4096);
        CHECK(vfs_create(128u, "f", (unsigned)(uintptr_t)shadow, 4096, 0, 1u) == 0);
        CHECK(vfs_open(128u, "f", 1u) >= 0);
        fd = vfs_open(128u, "f", 3u);
        CHECK(fd >= 0);
        CHECK(vfs_write(128u, fd, "hi", 2) == 2);
        vfs_close(128u, fd);
        fd = vfs_open(128u, "f", 1u);
        CHECK(fd >= 0);
        r = vfs_read(128u, fd, back, 2);
        CHECK(r == 2 && back[0] == 'h' && back[1] == 'i');
        vfs_close(128u, fd);
        /* fail-closed without invoke (host vfs_invoke returns -1): */
        CHECK(sh_feed("write g hi\n", 11) == 1);
        CHECK(vfs_open(128u, "g", 1u) < 0); /* no frames on host: nothing registered */
    }
    printf("PASS: test_shell_vfs\n");
    return 0;
}
