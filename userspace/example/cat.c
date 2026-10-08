#include "../lib/moonlight.h"

#define VFS_SHELL_CLIENT 128u
#define VFS_R 1u
#define VFS_W 2u

__attribute__((weak)) int vfs_open(unsigned caller, const char *name, unsigned rights);
__attribute__((weak)) int vfs_read(unsigned caller, int fd, void *buf, unsigned long len);
__attribute__((weak)) int vfs_close(unsigned caller, int fd);
__attribute__((weak)) int vfs_stat(unsigned caller, const char *name, unsigned *size_out, unsigned *used_out);

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

static size_t ls_strlen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

void cat_main(void) {
    const char *path = "sh"; /* default to shell binary for demo */
    int fd = vfs_open(VFS_SHELL_CLIENT, "sh", 1); /* VFS_R = 1 */
    if (fd < 0) {
        shell_puts("cat: cannot open file\n");
        return;
    }

    char buf[64];
    int n;
    while ((n = vfs_read(VFS_SHELL_CLIENT, fd, buf, sizeof(buf))) > 0) {
        int i;
        for (int j = 0; j < n; j++) {
            moonlight_putc(buf[j]);
        }
    }
    vfs_close(VFS_SHELL_CLIENT, fd);
}