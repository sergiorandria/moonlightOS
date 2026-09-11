#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#ifdef __linux__
#include <sys/mman.h>
#endif

/* New caller-keyed API (server.c). */
extern int vfs_create(uint32_t caller, const char *name, uint32_t cap,
                      uint32_t size, uint16_t color, uint16_t omode);
extern int vfs_open(uint32_t caller, const char *name, uint32_t rights);
extern int vfs_read(uint32_t caller, int fd, void *buf, size_t len);
extern int vfs_write(uint32_t caller, int fd, const void *buf, size_t len);
extern int vfs_close(uint32_t caller, int fd);
extern int vfs_unlink(uint32_t caller, const char *name);
extern int vfs_stat(uint32_t caller, const char *name, uint32_t *size_out,
                    uint32_t *used_out);
extern int vfs_list(int *cursor, char *name_out, uint32_t *size_out,
                    uint32_t *used_out);

int moonlight_call(uint32_t ep, void *msg) { (void)ep; (void)msg; return 0; }
int moonlight_recv(uint32_t ep, void *msg) { (void)ep; (void)msg; return 0; }

#define A 1u
#define B 2u
#define UNK 0xFFFFFFFFu
#define R 1u
#define W 2u
#define VFS_FDS 16

/* Backing frames need a sub-4GB address (cap is u32). MAP_32BIT on Linux. */
static uint8_t *low_frame(void) {
#ifdef __linux__
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (p == MAP_FAILED) return NULL;
    return p;
#else
    return NULL;
#endif
}

static int failures = 0;
#define CHECK(cond, why) do { \
    if (!(cond)) { printf("FAIL: %s (line %d)\n", why, __LINE__); failures++; } \
} while (0)

int main(void) {
    printf("=== test_vfs (hardened) ===\n");
    uint8_t *bk1 = low_frame();
    uint8_t *bk2 = low_frame();
    printf("backing %s\n", (bk1 && bk2) ? "low-mapped" : "UNAVAILABLE");
    uint32_t cap1 = bk1 ? (uint32_t)(uintptr_t)bk1 : 0x10000000u;
    uint32_t cap2 = bk2 ? (uint32_t)(uintptr_t)bk2 : 0x10001000u;

    /* 1. create happy path (owner A, world-readable). */
    CHECK(vfs_create(A, "test.txt", cap1, 4096, 0, R) == 0, "create");
    CHECK(vfs_create(A, "test.txt", cap1, 4096, 0, R) == -1, "dup denied");
    /* 2. bad inputs fail closed. */
    CHECK(vfs_create(UNK, "x.txt", cap1, 4096, 0, R) == -1, "unknown caller");
    CHECK(vfs_create(A, "", cap1, 4096, 0, R) == -1, "empty name");
    CHECK(vfs_create(A, "/etc/passwd", cap1, 4096, 0, R) == -1, "slash");
    CHECK(vfs_create(A, "-flag", cap1, 4096, 0, R) == -1, "leading dash");
    CHECK(vfs_create(A, "bad name", cap1, 4096, 0, R) == -1, "space");
    CHECK(vfs_create(A, "12345678901234567890123456789012", cap1, 4096, 0, R) == -1, "32char");
    CHECK(vfs_create(A, "s0.txt", cap1, 0, 0, R) == -1, "size 0");
    CHECK(vfs_create(A, "s1.txt", cap1, 0x100001, 0, R) == -1, "size huge");
    CHECK(vfs_create(A, "c0.txt", cap1, 4096, 16, R) == -1, "color 16");
    CHECK(vfs_create(A, "m0.txt", cap1, 4096, 0, 4) == -1, "bad omode");
    CHECK(vfs_create(A, "n0.txt", 0, 4096, 0, R) == -1, "null cap");

    /* 3. open with rights: owner gets RW, B gets omode (R). */
    int fa_rw = vfs_open(A, "test.txt", R | W);
    CHECK(fa_rw >= 0, "owner open RW");
    CHECK(vfs_open(A, "test.txt", 0) == -1, "empty rights");
    CHECK(vfs_open(A, "test.txt", 4) == -1, "bad rights bit");
    CHECK(vfs_open(A, "nope.txt", R) == -1, "missing file");
    int fb_r = vfs_open(B, "test.txt", R);
    CHECK(fb_r >= 0, "B open R (omode)");
    CHECK(vfs_open(B, "test.txt", W) == -1, "B open W denied");
    CHECK(vfs_open(B, "test.txt", R | W) == -1, "B open RW denied");

    /* 4. unknown caller + wild fds denied everywhere. */
    {
        char tmp[16];
        CHECK(vfs_read(UNK, 0, tmp, sizeof(tmp)) == -1, "unknown read");
        CHECK(vfs_write(UNK, 0, tmp, 1) == -1, "unknown write");
        CHECK(vfs_close(UNK, 0) == -1, "unknown close");
        CHECK(vfs_read(A, 99, tmp, sizeof(tmp)) == -1, "fd 99");
        CHECK(vfs_read(A, -1, tmp, sizeof(tmp)) == -1, "fd -1");
        CHECK(vfs_close(A, VFS_FDS) == -1, "fd 16 edge");
    }

    /* 5. data plane (needs real backing). */
    if (bk1 && bk2) {
        const char *msg = "hello-vfs";
        int n = vfs_write(A, fa_rw, msg, strlen(msg));
        CHECK(n == (int)strlen(msg), "write bytes");
        CHECK(memcmp(bk1, msg, strlen(msg)) == 0, "bytes land in frame");
        /* B (R-only) reads them. */
        char rbuf[32];
        memset(rbuf, 0, sizeof(rbuf));
        int m = vfs_read(B, fb_r, rbuf, sizeof(rbuf));
        CHECK(m == (int)strlen(msg), "B reads used bytes");
        CHECK(memcmp(rbuf, msg, strlen(msg)) == 0, "B sees A's bytes");
        /* B cannot write; A cannot exceed rights it didn't take. */
        CHECK(vfs_write(B, fb_r, "x", 1) == -1, "B write denied (rights)");
        /* Cursor independence: same fd number, separate offsets. */
        {
            char p[8];
            /* Reset: reopen both (fresh offset 0), then interleave. */
            CHECK(vfs_close(A, fa_rw) == 0, "reopen A");
            CHECK(vfs_close(B, fb_r) == 0, "reopen B");
            fa_rw = vfs_open(A, "test.txt", R | W);
            fb_r = vfs_open(B, "test.txt", R);
            CHECK(fa_rw >= 0 && fb_r >= 0, "reopened");
            CHECK(vfs_read(A, fa_rw, p, 4) == 4, "A reads hell");
            CHECK(memcmp(p, "hell", 4) == 0, "A bytes");
            CHECK(vfs_read(B, fb_r, p, 9) == 9, "B reads all (own cursor)");
            CHECK(vfs_read(A, fa_rw, p, 5) == 5, "A resumes at 4 (undisturbed)");
            CHECK(memcmp(p, "o-vfs", 5) == 0, "A tail bytes");
            CHECK(vfs_close(B, fb_r) == 0, "B close no touch A");
            memset(p, 0, sizeof(p));
            fb_r = vfs_open(B, "test.txt", R);
            CHECK(vfs_read(B, fb_r, p, 9) == 9, "B reopen resets cursor");
        }
        /* EOF + truncation, wrap-safe huge lens. */
        CHECK(vfs_read(B, fb_r, rbuf, sizeof(rbuf)) == 0, "EOF zeros");
        CHECK(vfs_write(A, fa_rw, rbuf, (size_t)-1) == (int)(4096 - strlen(msg)),
              "huge write truncates to size");
        CHECK(vfs_read(A, fa_rw, rbuf, 0) == 0, "zero-len read ok");
        CHECK(vfs_write(A, fa_rw, NULL, 5) == -1, "NULL buf denied");
        CHECK(vfs_read(A, fa_rw, NULL, 5) == -1, "NULL read denied");
        /* Offset past end is clamped: seek-less model keeps offset<=used;
         * drain the file then read EOF. */
    } else {
        printf("SKIP data plane (no low frames)\n");
    }

    /* 6. lifecycle: unlink blocked while open, owner-only, close reuses. */
    CHECK(vfs_unlink(B, "test.txt") == -1, "B unlink denied (owner)");
    CHECK(vfs_unlink(A, "test.txt") == -1, "unlink while open denied");
    CHECK(vfs_close(A, fa_rw) == 0, "close A");
    CHECK(vfs_close(A, fa_rw) == -1, "double close denied");
    CHECK(vfs_close(B, fb_r) == 0, "close B");
    CHECK(vfs_unlink(A, "test.txt") == 0, "unlink after close ok");
    CHECK(vfs_open(A, "test.txt", R) == -1, "gone after unlink");
    {
        uint32_t sz = 0, used = 0;
        CHECK(vfs_stat(A, "test.txt", &sz, &used) == -1, "stat gone");
    }

    /* 7. stat + list. */
    CHECK(vfs_create(A, "a.txt", cap2, 512, 2, R) == 0, "create a");
    {
        uint32_t sz = 0, used = 0;
        CHECK(vfs_stat(B, "a.txt", &sz, &used) == 0, "B stat ok");
        CHECK(sz == 512 && used == 0, "stat values");
    }
    {
        int cur = 0;
        char nm[32];
        uint32_t sz = 0, used = 0;
        int found = 0;
        while (vfs_list(&cur, nm, &sz, &used) == 0) {
            if (strcmp(nm, "a.txt") == 0) found = 1;
        }
        CHECK(found, "list finds a.txt");
    }

    /* 8. table exhaustion fails closed (63 more + a.txt = 64). */
    {
        int i, rc = 0;
        char nm[16];
        for (i = 0; i < 63; i++) {
            snprintf(nm, sizeof(nm), "f%02d.txt", i);
            rc = vfs_create(A, nm, cap2, 64, 0, 0);
            if (rc != 0) break;
        }
        CHECK(i == 63 && rc == 0, "fill to 64 files");
        CHECK(vfs_create(A, "overflow.txt", cap2, 64, 0, 0) == -1,
              "65th denied");
    }

    if (failures == 0) printf("PASS: vfs (hardened)\n");
    else printf("FAIL: vfs (%d)\n", failures);
    return failures ? 1 : 0;
}
