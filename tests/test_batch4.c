/* test_batch4 - host unit tests for batch 4 (unistd extensions, statx
 * validation, wait-family options, fcntl validation, wide memstreams).
 *
 * Links the REAL libc sources; the raw-syscall layer is the host stub
 * (-ENOSYS), so kernel-dependent success paths are asserted as clean
 * failures while every validation/pure path is asserted exactly.
 * Diagnostics use a raw host write (tests/host_console_shim style):
 * our own dprintf routes into the kernel console path and stays
 * silent on host-sim.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <wchar.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>

/* Heap backing for stdlib.c (brk/sbrk are ours to provide on host). */
static char heap_arena[1 << 20];
static size_t heap_top = 0;

void *sbrk(intptr_t inc) {
    size_t old = heap_top;
    if (inc < 0 || heap_top + (size_t)inc > sizeof(heap_arena))
        return (void *)-1;
    heap_top += (size_t)inc;
    return heap_arena + old;
}

int brk(void *addr) {
    uintptr_t a = (uintptr_t)addr, base = (uintptr_t)heap_arena;
    if (a < base || a > base + sizeof(heap_arena)) return -1;
    if (a > base + heap_top) heap_top = a - base;
    return 0;
}

extern int dprintf(int fd, const char *fmt, ...);

/* Diagnostics must bypass the libc under test: raw host write. */
static void t4_puts(const char *s) {
    unsigned long n = 0;
    while (s[n]) n++;
#ifdef __x86_64__
    {
        long r;
        __asm__ volatile("syscall"
                         : "=a"(r)
                         : "a"(1L), "D"(2L), "S"(s), "d"(n)
                         : "rcx", "r11", "memory");
        (void)r;
    }
#else
    dprintf(2, "%s", s);
#endif
}

static void t4_fail(const char *why, int line) {
    char b[256];
    int i = 0, j;
    unsigned u;
    while (why[i] && i < 200) {
        b[i] = why[i];
        i++;
    }
    b[i++] = ' ';
    b[i++] = '(';
    u = (unsigned)line;
    {
        char d[16];
        int nd = 0;
        do {
            d[nd++] = (char)('0' + u % 10);
            u /= 10;
        } while (u && nd < 15);
        for (j = nd - 1; j >= 0; j--) b[i++] = d[j];
    }
    b[i++] = ')';
    b[i++] = '\n';
    b[i] = '\0';
    t4_puts("FAIL: ");
    t4_puts(b);
}

static int failures = 0;
#define CHECK(cond, why) do { \
    if (!(cond)) { t4_fail(why, __LINE__); failures++; } \
} while (0)

int main(void) {
    t4_puts("=== test_batch4 ===\n");

    /* ---- confstr ---- */
    {
        char b[64];
        long n = confstr(_CS_PATH, b, sizeof(b));
        CHECK(n == 14 && strcmp(b, "/bin:/usr/bin") == 0, "confstr path");
        n = confstr(_CS_PATH, b, 5);
        CHECK(n == 14 && strcmp(b, "/bin") == 0, "confstr trunc");
        CHECK(confstr(_CS_PATH, 0, 0) == 14, "confstr size query");
        errno = 0;
        CHECK(confstr(9999, b, sizeof(b)) == 0 && errno == EINVAL,
              "confstr EINVAL");
        CHECK(confstr(_CS_POSIX_V7_LP64_OFF64_CFLAGS, b, sizeof(b)) > 0,
              "confstr cflags");
    }

    /* ---- ctermid / ttyname ---- */
    {
        char b[32];
        CHECK(strcmp(ctermid(0), "/dev/console") == 0, "ctermid null");
        CHECK(ctermid(b) == b && strcmp(b, "/dev/console") == 0,
              "ctermid buf");
        CHECK(strcmp(ttyname(0), "/dev/console") == 0, "tty0");
        CHECK(strcmp(ttyname(2), "/dev/console") == 0, "tty2");
        CHECK(ttyname(5) == 0 && errno == ENOTTY, "tty bad ENOTTY");
        CHECK(ttyname_r(1, b, sizeof(b)) == 0 &&
                  strcmp(b, "/dev/console") == 0,
              "ttyname_r");
        CHECK(ttyname_r(1, b, 4) == ERANGE, "ttyname_r range");
        CHECK(ttyname_r(9, b, sizeof(b)) == ENOTTY, "ttyname_r notty");
    }

    /* ---- login / groups / ids ---- */
    {
        gid_t g[4];
        char b[16];
        CHECK(strcmp(getlogin(), "root") == 0, "login");
        CHECK(getlogin_r(b, sizeof(b)) == 0 && strcmp(b, "root") == 0,
              "login_r");
        CHECK(getlogin_r(b, 2) == ERANGE, "login_r range");
        CHECK(getgroups(0, 0) == 1, "groups count");
        CHECK(getgroups(4, g) == 1 && g[0] == 0, "groups one");
        CHECK(getgroups(-1, g) == -1 && errno == EINVAL, "groups EINVAL");
        CHECK(setgroups(0, 0) == 0, "setgroups empty");
        {
            gid_t one[1] = {0};
            CHECK(setgroups(1, one) == 0, "setgroups zero");
            one[0] = 1;
            CHECK(setgroups(1, one) == -1 && errno == EPERM,
                  "setgroups EPERM");
        }
        CHECK(setgroups(17, 0) == -1, "setgroups size");
        CHECK(setuid(0) == 0 && setgid(0) == 0, "set 0");
        CHECK(seteuid((uid_t)-1) == 0 && setegid((gid_t)-1) == 0,
              "set -1");
        CHECK(setuid(1000) == -1 && errno == EPERM, "setuid EPERM");
        CHECK(setgid(1000) == -1 && errno == EPERM, "setgid EPERM");
        CHECK(nice(5) == 0, "nice");
    }

    /* ---- hostname (process-local override) ---- */
    {
        char b[65];
        CHECK(sethostname("web1", 4) == 0, "sethostname");
        CHECK(gethostname(b, sizeof(b)) == 0 && strcmp(b, "web1") == 0,
              "gethostname override");
        CHECK(sethostname("x", 0) == -1 && errno == EINVAL,
              "sethostname empty");
        CHECK(sethostname("bad name", 8) == -1, "sethostname chars");
        {
            char big[65];
            memset(big, 'a', sizeof(big));
            CHECK(sethostname(big, sizeof(big)) == -1, "sethostname len");
        }
        CHECK(gethostname(0, 0) == -1, "gethostname null");
    }

    /* ---- alarm (host: no tick clock, so it disarms to 0) ---- */
    {
        CHECK(alarm(0) == 0, "alarm disarm");
        CHECK(setitimer(99, 0, 0) == -1 && errno == EINVAL,
              "setitimer which");
    }

    /* ---- shells database (no /etc/shells on host: builtins) ---- */
    {
        char *s1, *s2, *s3;
        setusershell();
        s1 = getusershell();
        s2 = getusershell();
        s3 = getusershell();
        CHECK(s1 && strcmp(s1, "/bin/sh") == 0, "shell 1");
        CHECK(s2 && strcmp(s2, "/bin/moonsh") == 0, "shell 2");
        CHECK(s3 == 0, "shell end");
        endusershell();
    }

    /* ---- swab ---- */
    {
        char out[6];
        swab("abcdef", out, 6);
        CHECK(memcmp(out, "badcfe", 6) == 0, "swab");
    }

    /* ---- fchdir (host: syscall ENOSYS, still -1, no crash) ---- */
    CHECK(fchdir(-1) == -1, "fchdir bad");

    /* ---- statx validation (kernel-independent) ---- */
    {
        struct statx x;
        errno = 0;
        CHECK(statx(AT_FDCWD, "f", 0, 0xFFFFu, &x) == -1 &&
                  errno == EINVAL,
              "statx bad mask");
        CHECK(statx(AT_FDCWD, "f", 0x8000, STATX_BASIC_STATS, &x) == -1 &&
                  errno == EINVAL,
              "statx bad flags");
        CHECK(statx(AT_FDCWD, "f", 0, STATX_BASIC_STATS, 0) == -1 &&
                  errno == EFAULT,
              "statx null buf");
        CHECK(statx(AT_FDCWD, "f", 0, STATX_BASIC_STATS, 0) == -1,
              "statx null again");
        CHECK(statx(AT_FDCWD, 0, 0, STATX_BASIC_STATS, &x) == -1 &&
                  errno == EFAULT,
              "statx null path");
        /* AT_EMPTY_PATH on FDCWD is ENOENT without a syscall. */
        CHECK(statx(AT_FDCWD, "", AT_EMPTY_PATH, STATX_BASIC_STATS,
                    &x) == -1 &&
                  errno == ENOENT,
              "statx empty FDCWD");
        /* Anything else needs the kernel (host-sim ENOSYS here). */
        CHECK(statx(AT_FDCWD, "f", 0, STATX_BASIC_STATS, &x) == -1 &&
                  errno == ENOSYS,
              "statx host ENOSYS");
        /* Mask narrowing is honored even through the fstat path:
         * bad fd -> error, but a good one would mask stx_mask. */
        CHECK(statx(AT_FDCWD, "", AT_EMPTY_PATH, STATX_SIZE, &x) == -1,
              "statx empty masked err");
    }

    /* ---- wait-family validation (no syscalls on these paths) ---- */
    {
        struct rusage ru;
        siginfo_t si;
        CHECK(waitpid(-1, 0, WNOWAIT) == -1 && errno == EINVAL,
              "waitpid WNOWAIT");
        CHECK(waitpid(-1, 0, WEXITED) == -1 && errno == EINVAL,
              "waitpid WEXITED");
        CHECK(waitpid(-1, 0, 0x40000000) == -1 && errno == EINVAL,
              "waitpid junk");
        /* WSTOPPED == WUNTRACED (both 2, Linux values): accepted as
         * WUNTRACED and reaches the kernel (host-sim ENOSYS here). */
        CHECK(wait4(-1, 0, WSTOPPED, 0) == -1 && errno == ENOSYS,
              "wait4 WSTOPPED");
        CHECK(wait3(0, WNOWAIT, 0) == -1 && errno == EINVAL,
              "wait3 WNOWAIT");
        CHECK(waitid(99, 0, &si, WEXITED) == -1 && errno == EINVAL,
              "waitid idtype");
        CHECK(waitid(P_PIDFD, 0, &si, WEXITED) == -1 && errno == EINVAL,
              "waitid pidfd");
        CHECK(waitid(P_ALL, 0, &si, WNOHANG) == -1 && errno == EINVAL,
              "waitid no selector");
        CHECK(waitid(P_ALL, 0, &si, WEXITED | 0x2000000) == -1 &&
                  errno == EINVAL,
              "waitid junk opt");
        CHECK(waitid(P_ALL, 7, &si, WEXITED) == -1 && errno == EINVAL,
              "waitid P_ALL id");
        CHECK(waitid(P_PID, 0, &si, WEXITED) == -1 && errno == EINVAL,
              "waitid P_PID 0");
        CHECK(waitid(P_PGID, (id_t)-1, &si, WEXITED) == -1 &&
                  errno == EINVAL,
              "waitid P_PGID neg");
        /* WSTOPPED-only can never match (no job control): reports no
         * change with a zeroed siginfo instead of hanging. */
        memset(&si, 0xAA, sizeof(si));
        CHECK(waitid(P_ALL, 0, &si, WSTOPPED | WCONTINUED) == 0,
              "waitid stop-only");
        CHECK(si.si_signo == 0, "waitid stop-only zeroed");
        /* WEXITED needs the kernel (host-sim ENOSYS here). */
        CHECK(waitid(P_ALL, 0, &si, WEXITED | WNOHANG) == -1 &&
                  errno == ENOSYS,
              "waitid host ENOSYS");
        (void)ru;
    }

    /* ---- fcntl validation (no syscalls on these paths) ---- */
    {
        CHECK(fcntl(-1, F_DUPFD, 0) == -1 && errno == EINVAL,
              "fcntl dupfd fd");
        CHECK(fcntl(3, F_DUPFD, -5) == -1 && errno == EINVAL,
              "fcntl dupfd arg");
        CHECK(fcntl(3, F_DUPFD_CLOEXEC, -1) == -1 && errno == EINVAL,
              "fcntl dupfd_ce arg");
        CHECK(fcntl(3, F_SETFD, 4) == -1 && errno == EINVAL,
              "fcntl setfd bits");
        CHECK(fcntl(3, F_SETFL, 0xFFFF) == -1 && errno == EINVAL,
              "fcntl setfl bits");
        /* Valid forms reach the kernel (host-sim ENOSYS here). */
        CHECK(fcntl(3, F_GETFD) == -1 && errno == ENOSYS,
              "fcntl host ENOSYS");
    }

    /* ---- open_wmemstream (fully real on host: no syscalls) ---- */
    {
        wchar_t *wp = 0;
        size_t wl = 99;
        FILE *m = open_wmemstream(&wp, &wl);
        CHECK(m != 0, "wmem open");
        if (m) {
            CHECK(wl == 0 && wp != 0 && wp[0] == 0, "wmem init");
            CHECK(fputwc(0x20AC, m) == 0x20AC, "wmem euro");
            CHECK(fputws(L"ab", m) == 0, "wmem abs");
            CHECK(wl == 3, "wmem len");
            CHECK(wp[0] == 0x20AC && wp[1] == 'a' && wp[2] == 'b' &&
                      wp[3] == 0,
                  "wmem content");
            CHECK(fflush(m) == 0 && wl == 3, "wmem fflush");
            /* Byte view is the UTF-8 encoding (5 bytes). */
            {
                char bb[16];
                size_t n;
                rewind(m);
                n = fread(bb, 1, sizeof(bb), m);
                CHECK(n == 5 &&
                          memcmp(bb, "\xE2\x82\xAC"
                                         "ab",
                                     5) == 0,
                      "wmem bytes");
            }
            /* Seek back + overwrite preserves the tail. */
            CHECK(fseek(m, 0, SEEK_SET) == 0, "wmem rewind");
            CHECK(fputwc('Z', m) == 'Z', "wmem overwrite");
            CHECK(fclose(m) == 0, "wmem close");
            CHECK(wl == 3 && wp[0] == 'Z' && wp[1] == 'a' &&
                      wp[2] == 'b' && wp[3] == 0,
                  "wmem spliced");
            free(wp);
        }
        CHECK(open_wmemstream(0, &wl) == 0, "wmem null");
        {
            /* Growth past the initial 32-wide cap. */
            wchar_t *gp = 0;
            size_t gl = 0, i;
            int ok = 1;
            m = open_wmemstream(&gp, &gl);
            CHECK(m != 0, "wmem grow open");
            if (m) {
                for (i = 0; i < 100; i++)
                    if (fputwc((wchar_t)(0x100 + i), m) ==
                        (wint_t)WEOF) {
                        ok = 0;
                        break;
                    }
                CHECK(ok && gl == 100, "wmem grown");
                if (ok) {
                    for (i = 0; i < 100; i++)
                        if (gp[i] != (wchar_t)(0x100 + i)) {
                            ok = 0;
                            break;
                        }
                    CHECK(ok, "wmem grown content");
                }
                CHECK(fputwc(0xD800, m) == (wint_t)WEOF,
                      "wmem surrogate");
                CHECK(fclose(m) == 0, "wmem grow close");
                free(gp);
            }
        }
        /* Narrow writes widen 1:1 into the wide view. */
        {
            wchar_t *np = 0;
            size_t nl = 0;
            m = open_wmemstream(&np, &nl);
            if (m) {
                CHECK(fputc('Q', m) == 'Q', "wmem narrow");
                CHECK(fclose(m) == 0, "wmem narrow close");
                CHECK(nl == 1 && np[0] == 'Q', "wmem widened");
                free(np);
            } else {
                CHECK(0, "wmem narrow open");
            }
        }
    }

    if (failures == 0) t4_puts("ALL BATCH4 TESTS PASS\n");
    else t4_puts("FAIL: batch4 (see count above)\n");
    return failures ? 1 : 0;
}
