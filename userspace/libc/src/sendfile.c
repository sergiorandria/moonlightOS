/* libc sendfile: file-to-file transfer over pread/write.
 * Honors an in/out offset pointer (like Linux); returns bytes moved. */
#include <sys/sendfile.h>
#include <unistd.h>
#include <errno.h>

ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
    char buf[4096];
    size_t total = 0;
    off_t cur = 0;
    if (out_fd < 0 || in_fd < 0) {
        errno = EBADF;
        return -1;
    }
    if (offset) cur = *offset;
    while (total < count) {
        size_t want = count - total;
        ssize_t r, w = 0;
        if (want > sizeof(buf)) want = sizeof(buf);
        r = pread(in_fd, buf, want, cur);
        if (r < 0) return total ? (ssize_t)total : -1;
        if (r == 0) break;
        while (w < r) {
            ssize_t k = write(out_fd, buf + w, (size_t)(r - w));
            if (k < 0) return total ? (ssize_t)total : -1;
            if (k == 0) break;
            w += k;
        }
        if (w < r) break;
        cur += r;
        total += (size_t)r;
    }
    if (offset) *offset = cur;
    return (ssize_t)total;
}
