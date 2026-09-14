/* test_linux - host unit tests for the Linux personality layer.
 *
 * Links the REAL kernel/src/linux.c + VFS server on the build machine.
 * File backing needs a sub-4GB pool address (VFS cap is u32): build with
 * -no-pie on Linux (static pool lands low, like test_vfs MAP_32BIT); the
 * test SKIP-exits when the pool is out of range instead of faulting.
 */
#include "../kernel/include/linux_abi.h"
#include "../kernel/include/linux.h"
#include "../kernel/include/tcb.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* Kernel objects live in stub_globals (weak); the VFS tables are static
 * in server.c. moonlight IPC stubs satisfy the server's externs. */
int moonlight_call(uint32_t ep, void *msg) { (void)ep; (void)msg; return 0; }
int moonlight_recv(uint32_t ep, void *msg) { (void)ep; (void)msg; return 0; }

/* Scripted stdin for fd-0 tests (replaces kbd.c, which is not linked). */
static const char *stdin_script = NULL;
static size_t stdin_pos = 0;
int kbd_getc(void) {
    if (!stdin_script || stdin_script[stdin_pos] == '\0') return -1;
    return (unsigned char)stdin_script[stdin_pos++];
}

extern tcb_table_t g_tcbs;
extern uintptr_t linux_file_pool_base(void);

#define C5 5u /* demo client */
#define C6 6u /* second client (isolation) */

static int failures = 0;
#define CHECK(cond, why) do { \
    if (!(cond)) { printf("FAIL: %s (line %d)\n", why, __LINE__); failures++; } \
} while (0)

static long LX(long nr, uintptr_t a0, uintptr_t a1, uintptr_t a2,
               uintptr_t a3, uint32_t c) {
    return linux_syscall_nr(nr, a0, a1, a2, a3, 0, 0, c);
}
static long LX6(long nr, uintptr_t a0, uintptr_t a1, uintptr_t a2,
                uintptr_t a3, uintptr_t a4, uintptr_t a5, uint32_t c) {
    return linux_syscall_nr(nr, a0, a1, a2, a3, a4, a5, c);
}

int main(void) {
    printf("=== test_linux (personality) ===\n");
    if (linux_file_pool_base() > 0xFFFFFFFFull) {
        printf("SKIP: file pool above 4GB (rebuild -no-pie)\n");
        return 0;
    }

    /* 1. numbers sanity: rv64 table (musl asm-generic). */
    CHECK(LX_SYS_read == 63 && LX_SYS_write == 64, "rw numbers");
    CHECK(LX_SYS_openat == 56 && LX_SYS_close == 57, "open numbers");
    CHECK(LX_SYS_exit == 93 && LX_SYS_brk == 214 && LX_SYS_mmap == 222,
          "exit/brk/mmap numbers");
    CHECK(LX_SYS_newfstatat == 79 && LX_SYS_fstat == 80, "stat numbers");

    /* 2. unknown numbers -> ENOSYS (incl. Linux 0..7, shadowed by native). */
    CHECK(LX(999, 0, 0, 0, 0, C5) == -LX_ENOSYS, "unknown ENOSYS");
    CHECK(LX(4, 0, 0, 0, 0, C5) == -LX_ENOSYS, "io_getevents ENOSYS");
    CHECK(LX(221, 0, 0, 0, 0, C5) == -LX_ENOSYS, "execve ENOSYS");
    /* kill is implemented (lx_do_kill): bad-signal and bad-pid fail
     * deterministically regardless of TCB liveness. */
    CHECK(LX(129, 99, 99, 0, 0, C5) == -LX_EINVAL, "kill bad sig");
    CHECK(LX(129, 0, 1, 0, 0, C5) == -LX_ESRCH, "kill pid 0 ESRCH");
    CHECK(LX(129, 99, 0, 0, 0, C5) == -LX_ESRCH, "kill dead ESRCH");

    /* 3. fd validation + console semantics. */
    CHECK(LX(LX_SYS_read, 99, 0, 10, 0, C5) == -LX_EBADF, "read bad fd");
    CHECK(LX(LX_SYS_write, 99, 0, 10, 0, C5) == -LX_EBADF, "write bad fd");
    CHECK(LX(LX_SYS_read, 1, 0, 10, 0, C5) == -LX_EBADF, "read stdout");
    CHECK(LX(LX_SYS_write, 0, 0, 10, 0, C5) == -LX_EBADF, "write stdin");
    CHECK(LX(LX_SYS_close, 0, 0, 0, 0, C5) == -LX_EBADF, "close stdin");
    stdin_script = NULL;
    {
        char b[8];
        CHECK(LX(LX_SYS_read, 0, (uintptr_t)b, 8, 0, C5) == -LX_EAGAIN,
              "stdin empty EAGAIN");
    }
    stdin_script = "Z\n";
    stdin_pos = 0;
    {
        char b[8];
        long n = LX(LX_SYS_read, 0, (uintptr_t)b, 8, 0, C5);
        CHECK(n == 2 && b[0] == 'Z' && b[1] == '\n', "stdin line");
    }

    /* 4. missing file, no CREAT. */
    CHECK(LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t)"nope.txt", 0, 0, C5) ==
              -LX_ENOENT,
          "open missing");
    CHECK(LX(LX_SYS_openat, 3, (uintptr_t)"x.txt", 0, 0, C5) == -LX_EBADF,
          "bad dirfd");
    CHECK(LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t)"/", 0, 0, C5) ==
              -LX_ENOENT,
          "open root");

    /* 5. full file roundtrip. */
    {
        long fd = LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t)"lx_t1",
                     LX_O_CREAT | LX_O_RDWR, 0644, C5);
        char rbuf[16];
        lx_stat_t st;
        CHECK(fd == 3, "first file fd 3");
        CHECK(LX(LX_SYS_write, fd, (uintptr_t) "hello", 5, 0, C5) == 5,
              "write 5");
        CHECK(LX(LX_SYS_lseek, fd, 0, LX_SEEK_SET, 0, C5) == 0, "seek 0");
        memset(rbuf, 0, sizeof(rbuf));
        CHECK(LX(LX_SYS_read, fd, (uintptr_t)rbuf, 5, 0, C5) == 5, "read 5");
        CHECK(memcmp(rbuf, "hello", 5) == 0, "bytes match");
        CHECK(LX(LX_SYS_read, fd, (uintptr_t)rbuf, 5, 0, C5) == 0, "EOF 0");
        CHECK(LX(LX_SYS_lseek, fd, 0, LX_SEEK_END, 0, C5) == 5, "seek END");
        CHECK(LX(LX_SYS_fstat, fd, (uintptr_t)&st, 0, 0, C5) == 0,
              "fstat ok");
        CHECK(st.st_size == 5 && (st.st_mode & 0777) == 0644, "fstat values");
        CHECK(st.st_blksize == 4096, "fstat blksize");
        CHECK(LX(LX_SYS_close, fd, 0, 0, 0, C5) == 0, "close ok");
        CHECK(LX(LX_SYS_close, fd, 0, 0, 0, C5) == -LX_EBADF,
              "double close");
        CHECK(LX(LX_SYS_newfstatat, LX_AT_FDCWD, (uintptr_t)"lx_t1",
                 (uintptr_t)&st, 0, C5) == 0,
              "fstatat ok");
        CHECK(st.st_size == 5, "fstatat size");
        CHECK(LX(LX_SYS_unlinkat, LX_AT_FDCWD, (uintptr_t)"lx_t1", 0, 0,
                 C5) == 0,
              "unlink ok");
        CHECK(LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t)"lx_t1",
                 LX_O_RDONLY, 0, C5) == -LX_ENOENT,
              "gone after unlink");
    }

    /* 6. O_EXCL / O_TRUNC / O_APPEND. */
    {
        long fd;
        char rbuf[16];
        CHECK(LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t)"lx_t2",
                 LX_O_CREAT | LX_O_WRONLY, 0644, C5) >= 3,
              "create t2");
        fd = LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t)"lx_t2",
                LX_O_CREAT | LX_O_EXCL | LX_O_RDWR, 0644, C5);
        CHECK(fd == -LX_EEXIST, "O_EXCL denies");
        CHECK(LX(LX_SYS_write, 3, (uintptr_t) "abcdef", 6, 0, C5) == 6,
              "t2 write");
        CHECK(LX(LX_SYS_close, 3, 0, 0, 0, C5) == 0, "t2 close");
        fd = LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t)"lx_t2",
                LX_O_WRONLY | LX_O_TRUNC, 0, C5);
        CHECK(fd >= 3, "reopen trunc");
        {
            lx_stat_t st;
            CHECK(LX(LX_SYS_fstat, fd, (uintptr_t)&st, 0, 0, C5) == 0,
                  "fstat trunc");
            CHECK(st.st_size == 0, "truncated to 0");
        }
        CHECK(LX(LX_SYS_write, fd, (uintptr_t) "xy", 2, 0, C5) == 2,
              "write after trunc");
        CHECK(LX(LX_SYS_close, fd, 0, 0, 0, C5) == 0, "close");
        fd = LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t)"lx_t2",
                LX_O_WRONLY | LX_O_APPEND, 0, C5);
        CHECK(LX(LX_SYS_write, fd, (uintptr_t) "z", 1, 0, C5) == 1,
              "append write");
        CHECK(LX(LX_SYS_lseek, fd, 0, LX_SEEK_SET, 0, C5) == 0, "rewind");
        memset(rbuf, 0, sizeof(rbuf));
        CHECK(LX(LX_SYS_read, fd, (uintptr_t)rbuf, 3, 0, C5) == -LX_EBADF,
              "WRONLY read denied");
        CHECK(LX(LX_SYS_close, fd, 0, 0, 0, C5) == 0, "close");
        fd = LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t)"lx_t2", LX_O_RDONLY,
                0, C5);
        memset(rbuf, 0, sizeof(rbuf));
        CHECK(LX(LX_SYS_read, fd, (uintptr_t)rbuf, 9, 0, C5) == 3,
              "read xyz");
        CHECK(memcmp(rbuf, "xyz", 3) == 0, "append bytes");
        CHECK(LX(LX_SYS_unlinkat, LX_AT_FDCWD, (uintptr_t)"lx_t2", 0, 0,
                 C5) == -LX_ENOENT,
              "unlink while open denied");
        CHECK(LX(LX_SYS_close, fd, 0, 0, 0, C5) == 0, "close");
        CHECK(LX(LX_SYS_unlinkat, LX_AT_FDCWD, (uintptr_t)"lx_t2", 0, 0,
                 C5) == 0,
              "unlink ok");
    }

    /* 7. sparse: seek past EOF, write, gap reads zero. */
    {
        long fd = LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t)"lx_t3",
                     LX_O_CREAT | LX_O_RDWR, 0644, C5);
        char rbuf[12];
        CHECK(LX(LX_SYS_write, fd, (uintptr_t) "AB", 2, 0, C5) == 2,
              "sparse base");
        CHECK(LX(LX_SYS_lseek, fd, 10, LX_SEEK_SET, 0, C5) == 10,
              "seek past EOF");
        CHECK(LX(LX_SYS_write, fd, (uintptr_t) "C", 1, 0, C5) == 1,
              "sparse write");
        CHECK(LX(LX_SYS_lseek, fd, 0, LX_SEEK_SET, 0, C5) == 0, "rewind");
        memset(rbuf, 0xAA, sizeof(rbuf));
        CHECK(LX(LX_SYS_read, fd, (uintptr_t)rbuf, 11, 0, C5) == 11,
              "read 11");
        CHECK(rbuf[0] == 'A' && rbuf[1] == 'B' && rbuf[10] == 'C',
              "sparse edges");
        {
            int i, holes = 1;
            for (i = 2; i < 10; i++)
                if (rbuf[i] != 0) holes = 0;
            CHECK(holes, "gap is zero");
        }
        CHECK(LX(LX_SYS_lseek, fd, -1, LX_SEEK_SET, 0, C5) == -LX_EINVAL,
              "neg seek");
        CHECK(LX(LX_SYS_lseek, fd, 0, 9, 0, C5) == -LX_EINVAL, "bad whence");
        CHECK(LX(LX_SYS_close, fd, 0, 0, 0, C5) == 0, "close");
        CHECK(LX(LX_SYS_unlinkat, LX_AT_FDCWD, (uintptr_t)"lx_t3", 0, 0,
                 C5) == 0,
              "unlink");
    }

    /* 8. pread/pwrite preserve the cursor. */
    {
        long fd = LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t)"lx_t4",
                     LX_O_CREAT | LX_O_RDWR, 0644, C5);
        char rbuf[8];
        CHECK(LX(LX_SYS_write, fd, (uintptr_t) "01234567", 8, 0, C5) == 8,
              "pw base");
        CHECK(LX(LX_SYS_pwrite64, fd, (uintptr_t) "AB", 2, 2, C5) == 2,
              "pwrite");
        memset(rbuf, 0, sizeof(rbuf));
        CHECK(LX(LX_SYS_pread64, fd, (uintptr_t)rbuf, 4, 0, C5) == 4,
              "pread");
        CHECK(memcmp(rbuf, "01AB", 4) == 0, "pread bytes");
        CHECK(LX(LX_SYS_lseek, fd, 0, LX_SEEK_CUR, 0, C5) == 8,
              "cursor kept");
        CHECK(LX(LX_SYS_close, fd, 0, 0, 0, C5) == 0, "close");
        CHECK(LX(LX_SYS_unlinkat, LX_AT_FDCWD, (uintptr_t)"lx_t4", 0, 0,
                 C5) == 0,
              "unlink");
    }

    /* 9. writev/readv. */
    {
        long fd = LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t)"lx_t5",
                     LX_O_CREAT | LX_O_RDWR, 0644, C5);
        lx_iovec_t wv[2] = {
            {(void *)"foo", 3},
            {(void *)"bar", 3},
        };
        lx_iovec_t rv[2];
        char b1[4], b2[4];
        memset(b1, 0, sizeof(b1));
        memset(b2, 0, sizeof(b2));
        rv[0].iov_base = b1;
        rv[0].iov_len = 3;
        rv[1].iov_base = b2;
        rv[1].iov_len = 3;
        CHECK(LX(LX_SYS_writev, fd, (uintptr_t)wv, 2, 0, C5) == 6,
              "writev 6");
        CHECK(LX(LX_SYS_lseek, fd, 0, LX_SEEK_SET, 0, C5) == 0, "rewind");
        CHECK(LX(LX_SYS_readv, fd, (uintptr_t)rv, 2, 0, C5) == 6,
              "readv 6");
        CHECK(memcmp(b1, "foo", 3) == 0 && memcmp(b2, "bar", 3) == 0,
              "vec bytes");
        CHECK(LX(LX_SYS_writev, fd, (uintptr_t)wv, 99, 0, C5) == -LX_EINVAL,
              "vec count cap");
        CHECK(LX(LX_SYS_close, fd, 0, 0, 0, C5) == 0, "close");
        CHECK(LX(LX_SYS_unlinkat, LX_AT_FDCWD, (uintptr_t)"lx_t5", 0, 0,
                 C5) == 0,
              "unlink");
    }

    /* 10. brk + mmap. */
    {
        long b0 = LX(LX_SYS_brk, 0, 0, 0, 0, C5);
        long b1;
        CHECK(b0 != 0, "brk base nonzero");
        b1 = LX(LX_SYS_brk, (uintptr_t)(b0 + 8192), 0, 0, 0, C5);
        CHECK(b1 == b0 + 8192, "brk extend");
        memset((void *)b1, 0x5A, 16);
        CHECK(((unsigned char *)b0)[8192] == 0x5A, "brk memory usable");
        CHECK(LX(LX_SYS_brk, 0, 0, 0, 0, C5) == b1, "brk query");
        CHECK(LX(LX_SYS_brk, (uintptr_t)0x7fffffffffffll, 0, 0, 0, C5) == b1,
              "brk OOB keeps old");
        {
            long m = LX6(LX_SYS_mmap, 0, 8192, LX_PROT_READ | LX_PROT_WRITE,
                         LX_MAP_PRIVATE | LX_MAP_ANONYMOUS, (uintptr_t)-1, 0,
                         C5);
            CHECK(m > b1, "mmap above brk");
            memset((void *)m, 0xA5, 8192);
            CHECK(LX(LX_SYS_munmap, m, 8192, 0, 0, C5) == 0, "munmap ok");
            CHECK(LX(LX_SYS_mprotect, m, 8192, 0, 0, C5) == 0,
                  "mprotect ok");
            CHECK(LX6(LX_SYS_mmap, 0, 0, 0,
                      LX_MAP_PRIVATE | LX_MAP_ANONYMOUS, 0, 0, C5) ==
                      -LX_EINVAL,
                  "mmap 0 denied");
            CHECK(LX6(LX_SYS_mmap, 0, 8192, 0,
                      LX_MAP_PRIVATE /* no ANON */, 0, 0, C5) == -LX_ENOSYS,
                  "file mmap ENOSYS");
        }
    }

    /* 11. identity + time + cwd + access. */
    {
        lx_utsname_t u;
        lx_timespec_t ts;
        lx_timeval_t tv;
        char cwd[4];
        CHECK(LX(LX_SYS_getpid, 0, 0, 0, 0, C5) == C5, "getpid");
        CHECK(LX(LX_SYS_gettid, 0, 0, 0, 0, C5) == C5, "gettid");
        CHECK(LX(LX_SYS_getppid, 0, 0, 0, 0, C5) == 0, "getppid 0");
        CHECK(LX(LX_SYS_getuid, 0, 0, 0, 0, C5) == 0, "getuid 0");
        CHECK(LX(LX_SYS_uname, (uintptr_t)&u, 0, 0, 0, C5) == 0, "uname");
        CHECK(strcmp(u.machine, "riscv64") == 0, "machine rv64");
        CHECK(strcmp(u.sysname, "MoonlightOS") == 0, "sysname");
        CHECK(LX(LX_SYS_clock_gettime, LX_CLOCK_MONOTONIC, (uintptr_t)&ts, 0,
                 0, C5) == 0,
              "clock_gettime");
        CHECK(ts.tv_nsec >= 0 && ts.tv_nsec < 1000000000ll, "nsec range");
        CHECK(LX(LX_SYS_clock_gettime, 99, (uintptr_t)&ts, 0, 0, C5) ==
                  -LX_EINVAL,
              "bad clock");
        CHECK(LX(LX_SYS_clock_getres, LX_CLOCK_REALTIME, (uintptr_t)&ts, 0,
                 0, C5) == 0,
              "clock_getres");
        CHECK(LX(LX_SYS_gettimeofday, (uintptr_t)&tv, 0, 0, 0, C5) == 0,
              "gettimeofday");
        CHECK(LX(LX_SYS_getcwd, (uintptr_t)cwd, 4, 0, 0, C5) == 1 &&
                  strcmp(cwd, "/") == 0,
              "getcwd root");
        CHECK(LX(LX_SYS_getcwd, (uintptr_t)cwd, 1, 0, 0, C5) == -LX_ERANGE,
              "getcwd small");
        CHECK(LX(LX_SYS_chdir, (uintptr_t) "/", 0, 0, 0, C5) == 0,
              "chdir root");
        CHECK(LX(LX_SYS_chdir, (uintptr_t) "/nope", 0, 0, 0, C5) ==
                  -LX_ENOENT,
              "chdir missing");
    }

    /* 12. sharing + owner-only unlink: C6 can read C5's world-open
     * file (v1 omode=RW, like a shared /tmp) but cannot unlink it. */
    {
        long fd = LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t)"lx_t6",
                     LX_O_CREAT | LX_O_RDWR, 0644, C5);
        long fd6;
        char rbuf[4];
        lx_stat_t st;
        CHECK(fd >= 3, "C5 create t6");
        CHECK(LX(LX_SYS_write, fd, (uintptr_t) "x", 1, 0, C5) == 1,
              "C5 write");
        fd6 = LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t)"lx_t6",
                 LX_O_RDONLY, 0, C6);
        CHECK(fd6 >= 3, "C6 open shared");
        memset(rbuf, 0, sizeof(rbuf));
        CHECK(LX(LX_SYS_read, fd6, (uintptr_t)rbuf, 1, 0, C6) == 1 &&
                  rbuf[0] == 'x',
              "C6 reads C5 bytes");
        CHECK(LX(LX_SYS_close, fd6, 0, 0, 0, C6) == 0, "C6 close");
        CHECK(LX(LX_SYS_newfstatat, LX_AT_FDCWD, (uintptr_t)"lx_t6",
                 (uintptr_t)&st, 0, C6) == 0,
              "C6 stat allowed");
        CHECK(LX(LX_SYS_unlinkat, LX_AT_FDCWD, (uintptr_t)"lx_t6", 0, 0,
                 C6) == -LX_ENOENT,
              "C6 unlink denied");
        CHECK(LX(LX_SYS_close, fd, 0, 0, 0, C5) == 0, "close");
        CHECK(LX(LX_SYS_unlinkat, LX_AT_FDCWD, (uintptr_t)"lx_t6", 0, 0,
                 C5) == 0,
              "C5 unlink");
    }

    /* 13. faccessat + ftruncate. */
    {
        long fd = LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t)"lx_t7",
                     LX_O_CREAT | LX_O_RDWR, 0644, C5);
        lx_stat_t st;
        CHECK(LX(LX_SYS_write, fd, (uintptr_t) "12345678", 8, 0, C5) == 8,
              "t7 write");
        CHECK(LX(LX_SYS_faccessat, LX_AT_FDCWD, (uintptr_t)"lx_t7", LX_F_OK,
                 0, C5) == 0,
              "access F_OK");
        CHECK(LX(LX_SYS_faccessat, LX_AT_FDCWD, (uintptr_t)"lx_t7", LX_X_OK,
                 0, C5) == -LX_EACCES,
              "access X denied");
        CHECK(LX(LX_SYS_faccessat, LX_AT_FDCWD, (uintptr_t)"lx_gone",
                 LX_F_OK, 0, C5) == -LX_ENOENT,
              "access missing");
        CHECK(LX(LX_SYS_ftruncate, fd, 3, 0, 0, C5) == 0, "ftruncate 3");
        CHECK(LX(LX_SYS_fstat, fd, (uintptr_t)&st, 0, 0, C5) == 0,
              "fstat after trunc");
        CHECK(st.st_size == 3, "truncated size");
        CHECK(LX(LX_SYS_ftruncate, fd, 99, 0, 0, C5) == -LX_EINVAL,
              "grow refused");
        CHECK(LX(LX_SYS_close, fd, 0, 0, 0, C5) == 0, "close");
        CHECK(LX(LX_SYS_unlinkat, LX_AT_FDCWD, (uintptr_t)"lx_t7", 0, 0,
                 C5) == 0,
              "unlink");
    }

    /* 14. exit parks the TCB and records the code (host: no dispatch). */
    {
        long rc = LX(LX_SYS_exit, 42, 0, 0, 0, 7u);
        CHECK(rc == 42, "exit returns code");
        CHECK(g_tcbs.threads[7].state == TCB_INACTIVE, "exited INACTIVE");
        CHECK(linux_last_exit_code == 42 && linux_exit_count == 1,
              "exit recorded");
        CHECK(LX(LX_SYS_set_tid_address, (uintptr_t)&rc, 0, 0, 0, C5) == C5,
              "set_tid_address");
        CHECK(LX(LX_SYS_sched_yield, 0, 0, 0, 0, C5) == 0, "yield 0");
    }

    /* 15. fault handling: NULL user pointers. */
    CHECK(LX(LX_SYS_read, 0, 0, 5, 0, C5) == -LX_EFAULT, "NULL read");
    CHECK(LX(LX_SYS_write, 1, 0, 5, 0, C5) == -LX_EFAULT, "NULL write");
    CHECK(LX(LX_SYS_openat, LX_AT_FDCWD, 0, LX_O_RDONLY, 0, C5) == -LX_EFAULT,
          "NULL path");

    /* 16. pool slots recycle after unlink (8-file cap). */
    {
        int i;
        char nm[16];
        for (i = 0; i < 8; i++) {
            long fd;
            snprintf(nm, sizeof(nm), "lx_p%d", i);
            fd = LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t)nm,
                    LX_O_CREAT | LX_O_RDWR, 0644, C5);
            CHECK(fd >= 3, "pool fill");
            CHECK(LX(LX_SYS_close, fd, 0, 0, 0, C5) == 0, "pool close");
        }
        CHECK(LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t) "lx_pfull",
                 LX_O_CREAT | LX_O_RDWR, 0644, C5) == -LX_ENOSPC,
              "pool full");
        CHECK(LX(LX_SYS_unlinkat, LX_AT_FDCWD, (uintptr_t) "lx_p0", 0, 0,
                 C5) == 0,
              "free one");
        {
            long fdf = LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t) "lx_pfull",
                          LX_O_CREAT | LX_O_RDWR, 0644, C5);
            CHECK(fdf >= 3, "slot recycled");
            CHECK(LX(LX_SYS_close, fdf, 0, 0, 0, C5) == 0, "close full");
        }
        for (i = 0; i < 8; i++) {
            snprintf(nm, sizeof(nm), "lx_p%d", i);
            if (i != 0)
                CHECK(LX(LX_SYS_unlinkat, LX_AT_FDCWD, (uintptr_t)nm, 0, 0,
                         C5) == 0,
                      "pool cleanup");
        }
        CHECK(LX(LX_SYS_unlinkat, LX_AT_FDCWD, (uintptr_t) "lx_pfull", 0, 0,
                 C5) == 0,
              "pool cleanup full");
    }

    /* 17. batch 4: statx mask/flags, wait4 validation/groups, console
     * dup aliases + F_DUPFD_CLOEXEC. */
    {
        long fd = LX(LX_SYS_openat, LX_AT_FDCWD, (uintptr_t)"lx_sx",
                     LX_O_CREAT | LX_O_RDWR, 0644, C5);
        lx_statx_t x;
        lx_stat_t st;
        CHECK(fd >= 3, "sx create");
        CHECK(LX(LX_SYS_write, fd, (uintptr_t)"data", 4, 0, C5) == 4,
              "sx write");
        memset(&x, 0xAA, sizeof(x));
        CHECK(LX6(LX_SYS_statx, LX_AT_FDCWD, (uintptr_t)"lx_sx", 0,
                  LX_STATX_BASIC_STATS, (uintptr_t)&x, 0, C5) == 0,
              "statx ok");
        CHECK(x.stx_mask == LX_STATX_BASIC_STATS, "statx mask full");
        CHECK(x.stx_size == 4, "statx size");
        CHECK(LX6(LX_SYS_statx, LX_AT_FDCWD, (uintptr_t)"lx_sx", 0,
                  0x200u /* STATX_SIZE */, (uintptr_t)&x, 0, C5) == 0,
              "statx partial");
        CHECK(x.stx_mask == 0x200u, "statx mask partial");
        CHECK(x.stx_size == 4, "statx size still filled");
        CHECK(LX6(LX_SYS_statx, LX_AT_FDCWD, (uintptr_t)"lx_sx", 0,
                  0x1000u, (uintptr_t)&x, 0, C5) == -LX_EINVAL,
              "statx bad mask");
        CHECK(LX6(LX_SYS_statx, LX_AT_FDCWD, (uintptr_t)"lx_sx", 0x8000u,
                  LX_STATX_BASIC_STATS, (uintptr_t)&x, 0, C5) == -LX_EINVAL,
              "statx bad flags");
        CHECK(LX6(LX_SYS_statx, LX_AT_FDCWD, (uintptr_t)"lx_sx",
                  LX_AT_NO_AUTOMOUNT | LX_AT_STATX_SYNC_TYPE,
                  LX_STATX_BASIC_STATS, (uintptr_t)&x, 0, C5) == 0,
              "statx sync bits ok");
        CHECK(LX6(LX_SYS_statx, (uintptr_t)fd, 0, LX_AT_EMPTY_PATH,
                  LX_STATX_BASIC_STATS, (uintptr_t)&x, 0, C5) == 0,
              "statx empty path");
        CHECK(x.stx_size == 4, "statx empty-path size");
        CHECK(LX(LX_SYS_fstat, fd, (uintptr_t)&st, 0, 0, C5) == 0,
              "fstat sx");
        CHECK(x.stx_ino == st.st_ino, "statx/fstat ino agree");
        CHECK(LX(LX_SYS_close, fd, 0, 0, 0, C5) == 0, "sx close");
        CHECK(LX(LX_SYS_unlinkat, LX_AT_FDCWD, (uintptr_t)"lx_sx", 0, 0,
                 C5) == 0,
              "sx unlink");
    }

    /* 18. wait4: no children here, so every pid form is ECHILD (group
     * forms are accepted, they just match nothing); garbage options
     * are EINVAL. */
    {
        int st;
        CHECK(LX(LX_SYS_wait4, -1, (uintptr_t)&st, 0, 0, C5) == -LX_ECHILD,
              "wait4 ECHILD");
        CHECK(LX(LX_SYS_wait4, 0, (uintptr_t)&st, 0, 0, C5) == -LX_ECHILD,
              "wait4 group ECHILD");
        CHECK(LX(LX_SYS_wait4, -5, (uintptr_t)&st, 0, 0, C5) == -LX_ECHILD,
              "wait4 pgid-self ECHILD");
        CHECK(LX(LX_SYS_wait4, -6, (uintptr_t)&st, 0, 0, C5) == -LX_ECHILD,
              "wait4 pgid-other ECHILD");
        CHECK(LX(LX_SYS_wait4, -1, (uintptr_t)&st, LX_WNOHANG, 0, C5) ==
                  -LX_ECHILD,
              "wait4 nohang ECHILD");
        CHECK(LX(LX_SYS_wait4, -1, (uintptr_t)&st, 0xFFFF, 0, C5) ==
                  -LX_EINVAL,
              "wait4 bad options");
        CHECK(LX(LX_SYS_wait4, -1, 0, 0, 0, C5) == -LX_ECHILD,
              "wait4 null status ECHILD");
    }

    /* 19. console dup aliases (dup/dup3/fcntl all share them). */
    {
        lx_stat_t st;
        long a1, a2;
        CHECK(LX(LX_SYS_dup, 99, 0, 0, 0, C5) == -LX_EBADF, "dup bad");
        CHECK(LX(LX_SYS_fcntl, 99, LX_F_DUPFD, 3, 0, C5) == -LX_EBADF,
              "fcntl dupfd bad");
        a1 = LX(LX_SYS_dup, 1, 0, 0, 0, C5);
        CHECK(a1 >= 3, "dup stdout");
        CHECK(LX(LX_SYS_fstat, a1, (uintptr_t)&st, 0, 0, C5) == 0,
              "fstat alias");
        CHECK((st.st_mode & (uint32_t)LX_S_IFMT) ==
                  (uint32_t)LX_S_IFCHR,
              "alias is char dev");
        CHECK(LX(LX_SYS_fcntl, a1, LX_F_GETFD, 0, 0, C5) == 0,
              "alias no cloexec");
        a2 = LX(LX_SYS_fcntl, 1, LX_F_DUPFD_CLOEXEC, 3, 0, C5);
        CHECK(a2 >= 3 && a2 != a1, "dupfd_cloexec");
        CHECK(LX(LX_SYS_fcntl, a2, LX_F_GETFD, 0, 0, C5) == LX_FD_CLOEXEC,
              "cloexec set");
        CHECK(LX(LX_SYS_fcntl, a2, LX_F_GETFL, 0, 0, C5) == LX_O_WRONLY,
              "alias getfl wronly");
        CHECK(LX(LX_SYS_close, a1, 0, 0, 0, C5) == 0, "close a1");
        CHECK(LX(LX_SYS_close, a2, 0, 0, 0, C5) == 0, "close a2");
        CHECK(LX(LX_SYS_fstat, a1, (uintptr_t)&st, 0, 0, C5) == -LX_EBADF,
              "alias gone");
        CHECK(LX(LX_SYS_fcntl, 99, LX_F_DUPFD_CLOEXEC, 3, 0, C5) ==
                  -LX_EBADF,
              "dupfd_cloexec bad");
    }

    if (failures == 0) printf("ALL LINUX TESTS PASS\n");
    else printf("FAIL: linux (%d)\n", failures);
    return failures ? 1 : 0;
}
