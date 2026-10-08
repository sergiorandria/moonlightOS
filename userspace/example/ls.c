#include "../lib/moonlight.h"

#define VFS_SHELL_CLIENT 128u
#define VFS_R 1u
#define VFS_W 2u

__attribute__((weak)) int vfs_open(unsigned caller, const char *name, unsigned rights);
__attribute__((weak)) int vfs_read(unsigned caller, int fd, void *buf, unsigned long len);
__attribute__((weak)) int vfs_close(unsigned caller, int fd);
__attribute__((weak)) int vfs_list(int *cursor, char *name_out, unsigned *size_out, unsigned *used_out);

static size_t ls_strlen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static void shell_puts(const char *s) {
    while (*s) moonlight_putc(*s++);
}

static void shell_put_hex(unsigned v, int width) {
    int i;
    for (i = width - 1; i >= 0; i--) {
        unsigned d = (v >> (i * 4)) & 0xF;
        moonlight_putc(d < 10 ? (char)('0' + d) : (char)('a' + d - 10));
    }
}

void ls_main(void) {
    int cursor = 0;
    char name[32];
    unsigned sz = 0, used = 0;
    int n = 0;

    shell_puts("NAME       SIZE  USED\n");
    while (vfs_list(&cursor, name, &sz, &used) == 0) {
        shell_puts(name);
        int i;
        for (i = 0; i < 12 - (int)ls_strlen(name); i++) shell_puts(" ");
        shell_put_hex(sz, 6);
        shell_puts("  ");
        shell_put_hex(used, 6);
        shell_puts("\n");
        n++;
    }
    if (n == 0) shell_puts("(empty)\n");
}