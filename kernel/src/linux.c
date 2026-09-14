/* Linux personality: rv64 Linux syscalls on Moonlight primitives.
 *
 * Each thread is a "process" (getpid = TCB id). fds 0/1/2 are the console;
 * fds >= 3 are that caller's VFS fds (linux_fd - 3). Heap, mmap and file
 * data live in static arenas (always mapped, no boot ordering, no device
 * mapping, no reclaim). See docs/LINUX.md for the contract and limits.
 */
#include "../include/linux.h"
#include "../include/cap.h"
#include "../include/tcb.h"
#include "../include/sched.h"
#include "../include/vspace.h"
#include "../include/console.h"
#include "../include/kbd.h"
#include "../include/process.h"
#include "../include/alloc.h"
#include "../include/elf.h"
#include <string.h>
#include <stdbool.h>

extern tcb_table_t g_tcbs;
extern vspace_t g_kernel_vspace;
extern frame_alloc_t g_alloc;
extern mdb_tree_t g_mdb;
extern sched_state_t g_sched;

/* ---- VFS server edge (userspace/vfs_server/server.c, linked in-image).
 * Limits mirrored from server.c (single source would be nicer; the values
 * are asserted where cheap). */
#define LX_VFS_MAX_CLIENTS 129u
#define LX_VFS_FDS_PER_CLIENT 16
#define LX_VFS_SHELL_CLIENT 128u
#define LX_VFS_UNKNOWN_CLIENT 0xFFFFFFFFu
#define LX_VFS_NAME_LEN 31u
#define LX_VFS_MAX_FILE_SIZE 0x100000u

int vfs_create(uint32_t caller, const char *name, uint32_t cap, uint32_t size,
               uint16_t color, uint16_t omode);
int vfs_open(uint32_t caller, const char *name, uint32_t rights);
int vfs_read(uint32_t caller, int fd, void *buf, size_t len);
int vfs_write(uint32_t caller, int fd, const void *buf, size_t len);
int vfs_close(uint32_t caller, int fd);
int vfs_unlink(uint32_t caller, const char *name);
int vfs_unlink_at(uint32_t caller, const char *name, bool dir);
int vfs_stat(uint32_t caller, const char *name, uint32_t *size_out,
             uint32_t *used_out);
int vfs_stat_full(uint32_t caller, const char *name, uint32_t *size_out,
                  uint32_t *used_out, uint8_t *kind_out, uint32_t *nlink_out,
                  uint64_t *mtime_out);
int vfs_seek(uint32_t caller, int fd, int64_t off, int whence,
             uint32_t *new_off);
int vfs_truncate_fd(uint32_t caller, int fd, uint32_t len);
int vfs_set_append(uint32_t caller, int fd, bool on);
int vfs_mkdir(uint32_t caller, const char *name);
int vfs_mkfifo(uint32_t caller, const char *name);
int vfs_symlink(uint32_t caller, const char *target, const char *name);
int vfs_link(uint32_t caller, const char *oldp, const char *newp);
int vfs_readlink(uint32_t caller, const char *name, char *out, size_t cap);
int vfs_kind(uint32_t caller, const char *name);
int vfs_list_full(int *cursor, char *name_out, uint32_t *size_out,
                  uint32_t *used_out, uint8_t *kind_out, uint64_t *mtime_out);
int vfs_set_mtime(uint32_t caller, const char *name, uint64_t ticks);

int linux_last_exit_code = 0;
int linux_exit_count = 0;

/* ---- static arenas ---- */

/* Heap+mmap arena (brk grows up from base, mmap takes pages from the same
 * bump; munmap never reclaims - documented in LINUX.md). */
#define LX_HEAP_SIZE (192u * 1024u)
/* 16-byte aligned: sbrk hands this out as malloc blocks (header + payload
 * math assumes MLS-style unit alignment; an unaligned base would poison
 * every free-list pointer on strict targets). */
static uint8_t lx_heap[LX_HEAP_SIZE] __attribute__((aligned(16)));
static uintptr_t lx_heap_top; /* bump: heap_base < top <= heap_base+SIZE */

/* File-data pool: one static frame per Linux-created file (shell pattern:
 * the frame address names the data, like vfs_shell_frames). */
#define LX_MAX_FILES 8
#define LX_FILE_SIZE (32u * 1024u)
static uint8_t lx_file_pool[LX_MAX_FILES][LX_FILE_SIZE];
static char lx_file_names[LX_MAX_FILES][LX_VFS_NAME_LEN + 1];
static bool lx_file_taken[LX_MAX_FILES];

static uintptr_t lx_heap_base(void) { return (uintptr_t)lx_heap; }
static uintptr_t lx_heap_end(void) { return (uintptr_t)(lx_heap + LX_HEAP_SIZE); }

/* Inspection hook (mem reporting, host-test range guard): base of the
 * file-data pool. The VFS cap is u32, so this must sit below 4GB. */
uintptr_t linux_file_pool_base(void) { return (uintptr_t)&lx_file_pool[0][0]; }

static uint32_t lx_caller(uint32_t cur) {
    return (cur == TCB_NONE) ? LX_VFS_SHELL_CLIENT : cur;
}

/* ---- user memory ----
 * M-mode today: the kernel vspace identity-maps everything, but user
 * pointers are still validated page-by-page (lengths capped) so a bad
 * app gets -EFAULT, not a kernel fault. Host-sim skips the resolve
 * (same pattern as copy_msg_from_user). */
#define LX_USER_MAX (16u * 1024u * 1024u)

static bool lx_range_ok(uintptr_t uaddr, size_t len) {
    uintptr_t base, end, p;
    if (len == 0) return true;
    if (uaddr == 0) return false;
    if (len > LX_USER_MAX) return false;
    if (uaddr + len < uaddr) return false; /* wrap */
#ifdef __riscv
    base = uaddr & ~(uintptr_t)(PAGE_SIZE - 1);
    end = (uaddr + len - 1) & ~(uintptr_t)(PAGE_SIZE - 1);
    for (p = base;; p += PAGE_SIZE) {
        uintptr_t pa = 0;
        if (!vspace_resolve(&g_kernel_vspace, p, &pa)) return false;
        if (p == end) break;
        if (p + PAGE_SIZE < p) return false; /* wrap */
    }
#endif
    return true;
}

/* Bounded NUL-string copy from user. 0 ok, -LX_EFAULT / -LX_ENAMETOOLONG.
 * Always NUL-terminates out (cap includes the NUL). */
static long lx_copy_path(uintptr_t uaddr, char *out, size_t cap) {
    size_t n = 0;
    const char *u;
    if (cap == 0) return -LX_EINVAL;
    if (!lx_range_ok(uaddr, 1)) return -LX_EFAULT;
    u = (const char *)uaddr;
    /* Probe one byte at a time so a missing NUL can't run past the cap
     * or into an unmapped page: re-validate per page crossed. */
    while (n + 1 < cap) {
        uintptr_t here = uaddr + n;
        char c;
        if ((here & (PAGE_SIZE - 1)) == 0 && !lx_range_ok(here, 1))
            return -LX_EFAULT;
        c = u[n];
        out[n] = c;
        n++;
        if (c == '\0') return 0;
        if (!lx_range_ok(uaddr + n, 1)) return -LX_EFAULT;
    }
    out[cap - 1] = '\0';
    return -LX_ENAMETOOLONG;
}

/* Basename: strip trailing slashes, take the final component ("a/b/c" ->
 * "c", "/" -> ""). Mirrors the flat VFS namespace (docs/LINUX.md). */
static void lx_basename(char *path) {
    size_t n, end, start, i;
    n = strlen(path);
    while (n > 0 && path[n - 1] == '/') n--;
    path[n] = '\0';
    if (n == 0) return; /* was all slashes: empty */
    end = n;
    start = 0;
    for (i = 0; i < end; i++)
        if (path[i] == '/') start = i + 1;
    if (start > 0) {
        memmove(path, path + start, end - start + 1);
    }
}

static bool lx_name_ok(const char *name) {
    size_t n = 0;
    if (!name || name[0] == '\0' || name[0] == '-') return false;
    while (name[n] != '\0') {
        char c = name[n];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok) return false;
        n++;
        if (n > LX_VFS_NAME_LEN) return false;
    }
    return n >= 1;
}

/* ---- time (CLINT MTIME, 10MHz on QEMU virt -> 100ns/tick) ---- */
static uint64_t lx_ticks(void) {
#ifdef __riscv
    uint64_t t = *(volatile uint64_t *)0x200BFF8u;
    __asm__ volatile("fence iorw,iorw" ::: "memory");
    return t;
#else
    return 0;
#endif
}

static int64_t lx_now_ns(void) {
    return (int64_t)(lx_ticks() * 100u);
}

/* ---- console fds ---- */

static long lx_console_write(const char *buf, size_t len) {
    size_t i;
    if (!lx_range_ok((uintptr_t)buf, len)) return -LX_EFAULT;
    if (len > LX_USER_MAX) return -LX_EFAULT;
    for (i = 0; i < len; i++) console_putc(buf[i]);
    return (long)len;
}

/* Nonblocking: bytes available now, or -EAGAIN when the ring is empty
 * (v1 stdin is poll-based; libc retries with yield). */
static long lx_console_read(char *buf, size_t len) {
    size_t n = 0;
    int c;
    if (!lx_range_ok((uintptr_t)buf, len)) return -LX_EFAULT;
    if (len == 0) return 0;
    if (len > LX_USER_MAX) return -LX_EFAULT;
    while (n < len) {
        c = kbd_getc();
        if (c < 0) break;
        buf[n++] = (char)c;
        if (c == '\n') break; /* line discipline: return early */
    }
    if (n == 0) return -LX_EAGAIN;
    return (long)n;
}

/* ---- file pool slots ---- */

/* Forward declarations (helpers call across sections). */
static long lx_do_open(uint32_t caller, uintptr_t upath, unsigned flags);
static long lx_do_close(uint32_t caller, long fd);
static long lx_do_read(uint32_t caller, long fd, uintptr_t ubuf, size_t len);
static long lx_do_write(uint32_t caller, long fd, uintptr_t ubuf,
                        size_t len);
static long lx_do_fstat(uint32_t caller, long fd, uintptr_t ust);

static int lx_slot_for_name(const char *name) {
    int i;
    for (i = 0; i < LX_MAX_FILES; i++)
        if (lx_file_taken[i] && strcmp(lx_file_names[i], name) == 0) return i;
    return -1;
}

static int lx_slot_alloc(const char *name) {
    int i;
    for (i = 0; i < LX_MAX_FILES; i++) {
        if (lx_file_taken[i]) continue;
        strncpy(lx_file_names[i], name, LX_VFS_NAME_LEN);
        lx_file_names[i][LX_VFS_NAME_LEN] = '\0';
        lx_file_taken[i] = true;
        return i;
    }
    return -1;
}

/* ---- per-caller fd table: dup shares the VFS slot (offset shared),
 * pipes/sockets live here too. lfd = index + 3, so numbering matches
 * the old vfd+3 scheme when no aliasing is used. ---- */
#define LX_NFDS 32
#define LX_FD_VFS 0
#define LX_FD_PIPE 1
#define LX_FD_SOCK 2
#define LX_FD_CONS 3 /* dup alias of console fd 0..2 (vfd = cons number) */
typedef struct {
    bool valid;
    uint8_t kind;
    uint8_t cloexec;
    uint8_t nonblock;
    int vfd; /* VFS fd, or pipe/sock index */
    int end; /* pipe/sock endpoint: 0 read, 1 write */
} lx_fd_t;
static lx_fd_t lx_fds[LX_VFS_MAX_CLIENTS][LX_NFDS];
static int lx_fd_refs[LX_VFS_MAX_CLIENTS][LX_VFS_FDS_PER_CLIENT];

static lx_fd_t *lx_fd_lookup(uint32_t caller, long fd) {
    long idx = fd - 3;
    if (caller >= LX_VFS_MAX_CLIENTS) return NULL;
    if (idx < 0 || idx >= LX_NFDS) return NULL;
    if (!lx_fds[caller][idx].valid) return NULL;
    return &lx_fds[caller][idx];
}

static long lx_fd_alloc(uint32_t caller, uint8_t kind, int vfd, int end,
                        unsigned flags) {
    int i;
    if (caller >= LX_VFS_MAX_CLIENTS) return -LX_EINVAL;
    for (i = 0; i < LX_NFDS; i++) {
        if (lx_fds[caller][i].valid) continue;
        lx_fds[caller][i].valid = true;
        lx_fds[caller][i].kind = kind;
        lx_fds[caller][i].vfd = vfd;
        lx_fds[caller][i].end = end;
        lx_fds[caller][i].cloexec = (flags & LX_O_CLOEXEC) ? 1 : 0;
        lx_fds[caller][i].nonblock = (flags & LX_O_NONBLOCK) ? 1 : 0;
        if (kind == LX_FD_VFS && vfd >= 0 &&
            vfd < LX_VFS_FDS_PER_CLIENT)
            lx_fd_refs[caller][vfd]++;
        return (long)(i + 3);
    }
    return -LX_EMFILE;
}

/* ---- pipes: 8 static 4KB rings (in-kernel local IPC) ---- */
#define LX_NPIPES 8
#define LX_PIPE_SIZE 4096
static uint8_t lx_pipes[LX_NPIPES][LX_PIPE_SIZE];
static uint32_t lx_pipe_rd[LX_NPIPES], lx_pipe_wr[LX_NPIPES];
static uint32_t lx_pipe_bnwr[LX_NPIPES], lx_pipe_bnrd[LX_NPIPES];
static uint32_t lx_pipe_rdref[LX_NPIPES], lx_pipe_wrref[LX_NPIPES];
static bool lx_pipe_used[LX_NPIPES];

static int lx_pipe_alloc(void) {
    int i;
    for (i = 0; i < LX_NPIPES; i++) {
        if (lx_pipe_used[i]) continue;
        lx_pipe_used[i] = true;
        lx_pipe_rd[i] = lx_pipe_wr[i] = 0;
        lx_pipe_bnwr[i] = lx_pipe_bnrd[i] = 0;
        lx_pipe_rdref[i] = lx_pipe_wrref[i] = 0;
        return i;
    }
    return -1;
}

static bool lx_pipe_has_reader(int p) { return lx_pipe_rdref[p] > 0; }
static bool lx_pipe_has_writer(int p) { return lx_pipe_wrref[p] > 0; }

static size_t lx_pipe_used_n(int p) {
    return (size_t)(lx_pipe_bnwr[p] - lx_pipe_bnrd[p]);
}

static long lx_pipe_read(int p, char *dst, size_t len) {
    size_t n = lx_pipe_used_n(p), i;
    uint32_t r;
    if (len > n) len = n;
    r = lx_pipe_rd[p];
    for (i = 0; i < len; i++) {
        dst[i] = (char)lx_pipes[p][r];
        r = (r + 1) & (LX_PIPE_SIZE - 1);
    }
    lx_pipe_rd[p] = r;
    lx_pipe_bnrd[p] += (uint32_t)len;
    return (long)len;
}

static long lx_pipe_write(int p, const char *src, size_t len) {
    size_t free = LX_PIPE_SIZE - lx_pipe_used_n(p), i;
    uint32_t w;
    if (len > free) len = free;
    w = lx_pipe_wr[p];
    for (i = 0; i < len; i++) {
        lx_pipes[p][w] = (uint8_t)src[i];
        w = (w + 1) & (LX_PIPE_SIZE - 1);
    }
    lx_pipe_wr[p] = w;
    lx_pipe_bnwr[p] += (uint32_t)len;
    return (long)len;
}

/* ---- sockets: 16 AF_UNIX/loopback-INET endpoints over the same rings.
 * STREAM pairs are full-duplex; DGRAM preserves boundaries with a 2-byte
 * length prefix per datagram (max 2048 payload). ---- */
#define LX_NSOCK 16
#define LX_SOCK_RX 8192
typedef struct {
    bool valid;
    int type; /* SOCK_STREAM/DGRAM */
    int state; /* 0 fresh, 1 bound, 2 listening, 3 connected */
    uint32_t owner;
    int peer; /* connected peer index, -1 none */
    uint8_t rx[LX_SOCK_RX];
    uint32_t rx_rd, rx_wr, rx_nrd, rx_nwr;
    uint32_t nrd_ref, nwr_ref; /* endpoint refcounts */
    char addr[32]; /* bound unix path basename or "ip:port" */
    int backlog;
    int pending[8]; /* listener queue of connecting sock idx */
    int npending;
    uint32_t snd_timeo_ms, rcv_timeo_ms;
    int sndbuf, rcvbuf;
} lx_sock_t;
static lx_sock_t lx_socks[LX_NSOCK];

static int lx_sock_alloc(void) {
    int i;
    for (i = 0; i < LX_NSOCK; i++) {
        if (lx_socks[i].valid) continue;
        memset(&lx_socks[i], 0, sizeof(lx_socks[i]));
        lx_socks[i].valid = true;
        lx_socks[i].peer = -1;
        lx_socks[i].sndbuf = lx_socks[i].rcvbuf = LX_SOCK_RX;
        return i;
    }
    return -1;
}

static size_t lx_sock_used(lx_sock_t *s) {
    return (size_t)(s->rx_nwr - s->rx_nrd);
}

static long lx_sock_push(lx_sock_t *s, const char *src, size_t len) {
    size_t free = LX_SOCK_RX - lx_sock_used(s), i;
    if (len > free) len = free;
    for (i = 0; i < len; i++) {
        s->rx[s->rx_wr] = (uint8_t)src[i];
        s->rx_wr = (s->rx_wr + 1) & (LX_SOCK_RX - 1);
    }
    s->rx_nwr += (uint32_t)len;
    return (long)len;
}

static long lx_sock_pop(lx_sock_t *s, char *dst, size_t len, bool peek) {
    size_t n = lx_sock_used(s), i;
    uint32_t r;
    if (len > n) len = n;
    r = s->rx_rd;
    for (i = 0; i < len; i++) {
        dst[i] = (char)s->rx[r];
        r = (r + 1) & (LX_SOCK_RX - 1);
    }
    if (!peek) {
        s->rx_rd = r;
        s->rx_nrd += (uint32_t)len;
    }
    return (long)len;
}

/* ---- children / exit statuses for wait4 ---- */
#define LX_NCHILD 16
typedef struct {
    bool used, exited;
    uint32_t parent, child;
    int status;
} lx_child_t;
static lx_child_t lx_children[LX_NCHILD];
static uint32_t lx_parent_of[128];

static void lx_child_add(uint32_t parent, uint32_t child) {
    int i;
    if (child < 128) lx_parent_of[child] = parent;
    for (i = 0; i < LX_NCHILD; i++) {
        if (lx_children[i].used) continue;
        lx_children[i].used = true;
        lx_children[i].exited = false;
        lx_children[i].parent = parent;
        lx_children[i].child = child;
        lx_children[i].status = 0;
        return;
    }
}

static void lx_child_exit(uint32_t child, int status) {
    int i;
    for (i = 0; i < LX_NCHILD; i++) {
        if (!lx_children[i].used || lx_children[i].child != child) continue;
        lx_children[i].exited = true;
        lx_children[i].status = status;
    }
}

/* ---- cross-thread signal pending (kill/tgkill set, sigpending reads) ---- */
static uint32_t lx_sigpend[128];

/* ---- advisory file locks (flock): one owner per file id ---- */
#define LX_NFLOCK 16
typedef struct {
    bool used;
    uint32_t caller;
    char name[32];
    int mode; /* LOCK_SH/LOCK_EX */
} lx_flock_t;
static lx_flock_t lx_flocks[LX_NFLOCK];

/* ---- console termios state per caller (TCGETS/TCSETS honor it) ---- */
typedef struct {
    uint32_t iflag, oflag, cflag, lflag;
    uint8_t cc[8];
} lx_termios_t;
static lx_termios_t lx_terms[LX_VFS_MAX_CLIENTS];
static bool lx_terms_init[LX_VFS_MAX_CLIENTS];

static lx_termios_t *lx_term(uint32_t caller) {
    if (caller >= LX_VFS_MAX_CLIENTS) return NULL;
    if (!lx_terms_init[caller]) {
        lx_terms[caller].iflag = 0x500; /* ICRNL|IXON-ish */
        lx_terms[caller].oflag = 0x5; /* OPOST|ONLCR */
        lx_terms[caller].cflag = 0x1CB2; /* CREAD|HUPCL-ish */
        lx_terms[caller].lflag = 0x8CB; /* ISIG|ICANON|ECHO-ish */
        lx_terms_init[caller] = true;
    }
    return &lx_terms[caller];
}

/* ---- PRNG for getrandom (xorshift, seeded from ticks+heap addr) ---- */
static uint64_t lx_rng = 0x9E3779B97F4A7C15ull;
static uint64_t lx_rand64(void) {
    uint64_t x = lx_rng ? lx_rng : 0x9E3779B97F4A7C15ull;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    lx_rng = x;
    return x * 0x2545F4914F6CDD1Dull;
}

/* ---- per-call implementations (all take the VFS caller id) ---- */

static long lx_do_open(uint32_t caller, uintptr_t upath, unsigned flags) {
    char path[256];
    uint32_t rights;
    int vfd, kind;
    bool existed;
    long rc, lfd;
    rc = lx_copy_path(upath, path, sizeof(path));
    if (rc != 0) return rc;
    lx_basename(path);
    if (path[0] == '\0') return -LX_ENOENT;
    if (!lx_name_ok(path)) return -LX_ENOENT;
    if ((flags & LX_O_ACCMODE) == LX_O_RDONLY) rights = CAP_RIGHTS_READ;
    else if ((flags & LX_O_ACCMODE) == LX_O_WRONLY) rights = CAP_RIGHTS_WRITE;
    else if ((flags & LX_O_ACCMODE) == LX_O_RDWR)
        rights = CAP_RIGHTS_READ | CAP_RIGHTS_WRITE;
    else return -LX_EINVAL;
    kind = vfs_kind(caller, path);
    existed = kind >= 0;
    /* O_DIRECTORY: must exist and be a dir; plain open of a dir without
     * it still succeeds (read/getdents decide), like Linux. */
    if (flags & LX_O_DIRECTORY) {
        if (!existed) return -LX_ENOENT;
        if (kind != 1) return -LX_ENOTDIR;
        if ((flags & LX_O_ACCMODE) != LX_O_RDONLY) return -LX_EISDIR;
    }
    if (!existed && !(flags & LX_O_CREAT)) return -LX_ENOENT;
    if (existed && (flags & (LX_O_CREAT | LX_O_EXCL)) == (LX_O_CREAT | LX_O_EXCL))
        return -LX_EEXIST;
    if (existed && kind == 1 &&
        ((flags & LX_O_CREAT) || (flags & LX_O_TRUNC))) {
        if ((flags & LX_O_ACCMODE) != LX_O_RDONLY) return -LX_EISDIR;
    }
    if (existed && kind == 2 && !(flags & LX_O_NOFOLLOW)) {
        /* Symlink: vfs_open resolves; nothing extra here. */
    }
    if (!existed) {
        /* Create: back the file with a static pool frame (the shell's
         * vfs_shell_frames pattern). Purecap needs a real Frame cap for
         * this; without one the create is refused, not faked. */
        int slot = lx_slot_alloc(path);
        uint32_t cap;
        if (slot < 0) return -LX_ENOSPC;
#ifdef __CHERI_PURE_CAPABILITY__
        (void)cap;
        lx_file_taken[slot] = false;
        lx_file_names[slot][0] = '\0';
        return -LX_EIO; /* need Untyped-retype backing (future) */
#else
        cap = (uint32_t)(uintptr_t)&lx_file_pool[slot][0];
        if (vfs_create(caller, path, cap, LX_FILE_SIZE, 0,
                       CAP_RIGHTS_READ | CAP_RIGHTS_WRITE) != 0) {
            lx_file_taken[slot] = false;
            lx_file_names[slot][0] = '\0';
            return -LX_EIO;
        }
#endif
    }
    vfd = vfs_open(caller, path, rights);
    if (vfd < 0) return -LX_EACCES; /* exists but rights/table deny */
    if (vfd >= LX_VFS_FDS_PER_CLIENT) {
        vfs_close(caller, vfd);
        return -LX_EMFILE;
    }
    if ((flags & LX_O_TRUNC) && rights != CAP_RIGHTS_READ) {
        if (vfs_truncate_fd(caller, vfd, 0) != 0) {
            vfs_close(caller, vfd);
            return -LX_EIO;
        }
    }
    if (flags & LX_O_APPEND) vfs_set_append(caller, vfd, true);
    lfd = lx_fd_alloc(caller, LX_FD_VFS, vfd, 0, flags);
    if (lfd < 0) {
        vfs_close(caller, vfd); /* fresh vfd: no aliases yet */
        return lfd;
    }
    return lfd;
}

static int lx_to_vfd(uint32_t caller, long fd) {
    lx_fd_t *e = lx_fd_lookup(caller, fd);
    if (!e || e->kind != LX_FD_VFS) return -1;
    return e->vfd;
}

static long lx_do_read(uint32_t caller, long fd, uintptr_t ubuf, size_t len) {
    lx_fd_t *e;
    int vfd;
    char *kbuf;
    /* Stage through a bounded kernel buffer (user pages are validated,
     * but the VFS copy must not run on user memory directly). */
    static uint8_t io[4096];
    size_t total = 0;
    if (len > (size_t)0x40000000) return -LX_EINVAL;
    /* fd before pointer (Linux validates the fd first). */
    if (fd == 0) return lx_console_read((char *)ubuf, len);
    if (fd == 1 || fd == 2) return -LX_EBADF;
    e = lx_fd_lookup(caller, fd);
    if (!e) return -LX_EBADF;
    if (e->kind == LX_FD_CONS)
        return e->vfd == 0 ? lx_console_read((char *)ubuf, len)
                           : -LX_EBADF;
    if (e->kind == LX_FD_PIPE || e->kind == LX_FD_SOCK) {
        long r;
        if (!lx_range_ok(ubuf, len)) return -LX_EFAULT;
        if (len == 0) return 0;
        if (e->kind == LX_FD_PIPE) {
            int p = e->vfd;
            if (p < 0 || p >= LX_NPIPES || !lx_pipe_used[p]) return -LX_EBADF;
            if (lx_pipe_used_n(p) == 0)
                return lx_pipe_has_writer(p) ? -LX_EAGAIN : 0;
            r = lx_pipe_read(p, (char *)ubuf, len);
            return r;
        } else {
            lx_sock_t *s = &lx_socks[e->vfd];
            if (e->vfd < 0 || e->vfd >= LX_NSOCK || !s->valid)
                return -LX_EBADF;
            if (lx_sock_used(s) == 0) {
                if (s->peer < 0 || !lx_socks[s->peer].valid) return 0;
                return -LX_EAGAIN;
            }
            return lx_sock_pop(s, (char *)ubuf, len, false);
        }
    }
    vfd = e->vfd;
    if (!lx_range_ok(ubuf, len)) return -LX_EFAULT;
    kbuf = (char *)ubuf;
    while (total < len) {
        size_t chunk = len - total;
        int rc;
        if (chunk > sizeof(io)) chunk = sizeof(io);
        rc = vfs_read(caller, vfd, io, chunk);
        if (rc < 0) return total > 0 ? (long)total : -LX_EBADF;
        if (rc == 0) break; /* EOF */
        memcpy(kbuf + total, io, (size_t)rc);
        total += (size_t)rc;
    }
    return (long)total;
}

static long lx_do_write(uint32_t caller, long fd, uintptr_t ubuf, size_t len) {
    lx_fd_t *e;
    int vfd;
    const char *kbuf;
    static uint8_t io[4096];
    size_t total = 0;
    if (len > (size_t)0x40000000) return -LX_EINVAL;
    if (fd == 1 || fd == 2) return lx_console_write((const char *)ubuf, len);
    if (fd == 0) return -LX_EBADF;
    e = lx_fd_lookup(caller, fd);
    if (!e) return -LX_EBADF;
    if (e->kind == LX_FD_CONS)
        return (e->vfd == 1 || e->vfd == 2)
                   ? lx_console_write((const char *)ubuf, len)
                   : -LX_EBADF;
    if (e->kind == LX_FD_PIPE || e->kind == LX_FD_SOCK) {
        if (!lx_range_ok(ubuf, len)) return -LX_EFAULT;
        if (len == 0) return 0;
        if (e->kind == LX_FD_PIPE) {
            int p = e->vfd;
            long r;
            if (p < 0 || p >= LX_NPIPES || !lx_pipe_used[p]) return -LX_EBADF;
            if (!lx_pipe_has_reader(p)) return -LX_EPIPE;
            if (LX_PIPE_SIZE - lx_pipe_used_n(p) == 0) return -LX_EAGAIN;
            r = lx_pipe_write(p, (const char *)ubuf, len);
            return r == 0 ? -LX_EAGAIN : r;
        } else {
            lx_sock_t *s = &lx_socks[e->vfd];
            lx_sock_t *peer;
            long r;
            if (e->vfd < 0 || e->vfd >= LX_NSOCK || !s->valid)
                return -LX_EBADF;
            if (s->peer < 0 || !lx_socks[s->peer].valid) return -LX_EPIPE;
            peer = &lx_socks[s->peer];
            if (LX_SOCK_RX - lx_sock_used(peer) == 0) return -LX_EAGAIN;
            r = lx_sock_push(peer, (const char *)ubuf, len);
            return r == 0 ? -LX_EAGAIN : r;
        }
    }
    vfd = e->vfd;
    if (!lx_range_ok(ubuf, len)) return -LX_EFAULT;
    kbuf = (const char *)ubuf;
    while (total < len) {
        size_t chunk = len - total;
        int rc;
        if (chunk > sizeof(io)) chunk = sizeof(io);
        memcpy(io, kbuf + total, chunk);
        rc = vfs_write(caller, vfd, io, chunk);
        if (rc < 0) return total > 0 ? (long)total : -LX_EBADF;
        if (rc == 0) break; /* full */
        total += (size_t)rc;
    }
    return (long)total;
}

static long lx_do_vec(uint32_t caller, long fd, uintptr_t uvec,
                      unsigned count, bool is_write) {
    /* iovec count capped (Linux allows 1024; 16 covers real apps here and
     * bounds kernel staging). Total per call capped at 64KB. */
    static lx_iovec_t kv[16];
    size_t total = 0, budget = 64u * 1024u;
    unsigned i;
    if (count > 16) return -LX_EINVAL;
    if (count == 0) return 0;
    if (!lx_range_ok(uvec, (size_t)count * sizeof(lx_iovec_t)))
        return -LX_EFAULT;
    memcpy(kv, (const void *)uvec, (size_t)count * sizeof(lx_iovec_t));
    for (i = 0; i < count && budget > 0; i++) {
        size_t want = kv[i].iov_len;
        long rc;
        if (want > budget) want = budget;
        if (want == 0) continue;
        rc = is_write ? lx_do_write(caller, fd, (uintptr_t)kv[i].iov_base, want)
                      : lx_do_read(caller, fd, (uintptr_t)kv[i].iov_base, want);
        if (rc < 0) return total > 0 ? (long)total : rc;
        total += (size_t)rc;
        budget -= (size_t)rc;
        if ((size_t)rc < want) break; /* EOF/full */
    }
    return (long)total;
}

static long lx_do_lseek(uint32_t caller, long fd, int64_t off, int whence) {
    lx_fd_t *e;
    int vfd;
    uint32_t n = 0;
    int vse;
    if (fd >= 0 && fd < 3) return -LX_EINVAL; /* console: no seek (ESPIPE-ish) */
    e = lx_fd_lookup(caller, fd);
    if (!e) return -LX_EBADF;
    if (e->kind != LX_FD_VFS) return -LX_ESPIPE; /* pipes/sockets: no seek */
    vfd = e->vfd;
    if (whence < LX_SEEK_SET || whence > LX_SEEK_END) return -LX_EINVAL;
    vse = (whence == LX_SEEK_SET) ? 0 : (whence == LX_SEEK_CUR) ? 1 : 2;
    if (vfs_seek(caller, vfd, off, vse, &n) != 0) return -LX_EINVAL;
    return (long)n;
}

static long lx_do_preadwrite(uint32_t caller, long fd, uintptr_t ubuf,
                             size_t len, int64_t off, bool is_write) {
    /* Single-hart: seek + IO + restore (not atomic; documented). */
    lx_fd_t *e;
    int vfd;
    uint32_t cur = 0, ign = 0;
    long rc;
    if (fd >= 0 && fd < 3) return -LX_EINVAL;
    e = lx_fd_lookup(caller, fd);
    if (!e) return -LX_EBADF;
    if (e->kind != LX_FD_VFS) return -LX_ESPIPE;
    vfd = e->vfd;
    if (off < 0) return -LX_EINVAL;
    if (vfs_seek(caller, vfd, 0, 1 /*CUR*/, &cur) != 0) return -LX_EBADF;
    if (vfs_seek(caller, vfd, off, 0 /*SET*/, &ign) != 0) return -LX_EINVAL;
    rc = is_write ? lx_do_write(caller, fd, ubuf, len)
                  : lx_do_read(caller, fd, ubuf, len);
    vfs_seek(caller, vfd, (int64_t)cur, 0 /*SET*/, &ign); /* best effort */
    return rc;
}

static void lx_fill_stat(uint32_t file_id, uint32_t used, lx_stat_t *st) {
    memset(st, 0, sizeof(*st));
    st->st_dev = 1;
    st->st_ino = (uint64_t)file_id + 2;
    st->st_mode = (uint32_t)LX_S_IFREG | 0644u;
    st->st_nlink = 1;
    st->st_size = (int64_t)used;
    st->st_blksize = 4096;
    st->st_blocks = (int64_t)((used + 511u) / 512u);
}

/* Mode bits for a VFS kind. */
static uint32_t lx_kind_mode(uint8_t kind, uint32_t perm) {
    uint32_t base = LX_S_IFREG;
    if (kind == 1) base = LX_S_IFDIR;
    else if (kind == 2) base = LX_S_IFLNK;
    else if (kind == 3) base = LX_S_IFIFO;
    return base | (perm & 0777u);
}

static long lx_do_fstatat(uint32_t caller, long dirfd, uintptr_t upath,
                          uintptr_t ust, int flags) {
    /* newfstatat. AT_SYMLINK_NOFOLLOW stats the link itself;
     * AT_EMPTY_PATH stats the fd itself. */
    char path[256];
    uint32_t size = 0, used = 0, nlink = 1;
    uint8_t kind = 0;
    uint64_t mtime = 0;
    lx_stat_t st;
    long rc;
    if (flags & ~(LX_AT_SYMLINK_NOFOLLOW | LX_AT_EMPTY_PATH)) return -LX_EINVAL;
    if (!lx_range_ok(ust, sizeof(st))) return -LX_EFAULT;
    if ((flags & LX_AT_EMPTY_PATH) && (upath == 0 || *(const char *)upath == '\0')) {
        return lx_do_fstat(caller, dirfd, ust);
    }
    if (dirfd != LX_AT_FDCWD) return -LX_EBADF;
    rc = lx_copy_path(upath, path, sizeof(path));
    if (rc != 0) return rc;
    lx_basename(path);
    if (path[0] == '\0' || !lx_name_ok(path)) return -LX_ENOENT;
    if (vfs_stat_full(caller, path, &size, &used, &kind, &nlink, &mtime) != 0)
        return -LX_ENOENT;
    {
        /* Stable ino: pool slot when ours, else an FNV hash of the name. */
        uint64_t ino = 0xcbf29ce484222325ull;
        size_t i;
        int slot = lx_slot_for_name(path);
        if (slot >= 0) ino = 1000ull + (uint64_t)slot;
        else {
            for (i = 0; path[i]; i++) {
                ino ^= (uint64_t)(unsigned char)path[i];
                ino *= 0x100000001b3ull;
            }
        }
        memset(&st, 0, sizeof(st));
        st.st_dev = 1;
        st.st_ino = ino;
        st.st_mode = lx_kind_mode(kind, kind == 1 ? 0755u : 0644u);
        st.st_nlink = nlink;
        st.st_size = (int64_t)used;
        st.st_blksize = 4096;
        st.st_blocks = (int64_t)((used + 511u) / 512u);
        st.st_mtime_sec = (int64_t)(mtime / 10000000u);
        st.st_mtime_nsec = (int64_t)((mtime % 10000000u) * 100u);
        st.st_atime_sec = st.st_mtime_sec;
        st.st_atime_nsec = st.st_mtime_nsec;
        st.st_ctime_sec = st.st_mtime_sec;
        st.st_ctime_nsec = st.st_mtime_nsec;
        (void)size;
    }
    memcpy((void *)ust, &st, sizeof(st));
    return 0;
}

/* fstat(fd): size/used via a stat-by-fd helper. The VFS has no
 * stat-by-fd, so regular files resolve through the caller's open table
 * indirectly (seek-to-END, non-destructive, + restore). Pipes report a
 * fifo with the queued byte count; sockets a socket. */
static long lx_do_fstat(uint32_t caller, long fd, uintptr_t ust) {
    lx_fd_t *e;
    int vfd;
    uint32_t cur = 0, end = 0, ign = 0;
    lx_stat_t st;
    if (fd >= 0 && fd < 3) {
        /* Console: character device, size 0. */
        if (!lx_range_ok(ust, sizeof(st))) return -LX_EFAULT;
        memset(&st, 0, sizeof(st));
        st.st_dev = 2;
        st.st_ino = (uint64_t)fd;
        st.st_mode = 0020000u | 0600u; /* S_IFCHR */
        st.st_nlink = 1;
        st.st_blksize = 1024;
        memcpy((void *)ust, &st, sizeof(st));
        return 0;
    }
    e = lx_fd_lookup(caller, fd);
    if (!e) return -LX_EBADF;
    if (!lx_range_ok(ust, sizeof(st))) return -LX_EFAULT;
    if (e->kind == LX_FD_CONS) {
        memset(&st, 0, sizeof(st));
        st.st_dev = 2;
        st.st_ino = (uint64_t)e->vfd;
        st.st_mode = 0020000u | 0600u; /* S_IFCHR */
        st.st_nlink = 1;
        st.st_blksize = 1024;
        memcpy((void *)ust, &st, sizeof(st));
        return 0;
    }
    if (e->kind == LX_FD_PIPE) {
        int p = e->vfd;
        if (p < 0 || p >= LX_NPIPES || !lx_pipe_used[p]) return -LX_EBADF;
        memset(&st, 0, sizeof(st));
        st.st_dev = 3;
        st.st_ino = 2000ull + (uint64_t)p;
        st.st_mode = (uint32_t)LX_S_IFIFO | 0600u;
        st.st_nlink = 1;
        st.st_size = (int64_t)lx_pipe_used_n(p);
        st.st_blksize = 4096;
        memcpy((void *)ust, &st, sizeof(st));
        return 0;
    }
    if (e->kind == LX_FD_SOCK) {
        int s = e->vfd;
        if (s < 0 || s >= LX_NSOCK || !lx_socks[s].valid) return -LX_EBADF;
        memset(&st, 0, sizeof(st));
        st.st_dev = 4;
        st.st_ino = 3000ull + (uint64_t)s;
        st.st_mode = (uint32_t)LX_S_IFSOCK | 0600u;
        st.st_nlink = 1;
        memcpy((void *)ust, &st, sizeof(st));
        return 0;
    }
    vfd = e->vfd;
    if (vfs_seek(caller, vfd, 0, 1, &cur) != 0) return -LX_EBADF;
    if (vfs_seek(caller, vfd, 0, 2, &end) != 0) return -LX_EBADF;
    vfs_seek(caller, vfd, (int64_t)cur, 0, &ign);
    lx_fill_stat((uint32_t)vfd, end, &st);
    memcpy((void *)ust, &st, sizeof(st));
    return 0;
}

static long lx_do_brk(uintptr_t addr) {
    uintptr_t base = lx_heap_base(), end = lx_heap_end();
    /* No bulk clear here: the arena is BSS (zeroed by start.S at boot),
     * and only the incremental extension below is memset - a full
     * 192KB clear inside the syscall blows the 5us WCET budget and the
     * caller would see EAGAIN (see syscall.c). */
    if (lx_heap_top == 0) lx_heap_top = base;
    if (addr == 0) return (long)lx_heap_top;
    /* Linux returns the CURRENT break on failure (not an error). */
    if (addr < base || addr > end) return (long)lx_heap_top;
    if (addr > lx_heap_top) memset((void *)lx_heap_top, 0, addr - lx_heap_top);
    lx_heap_top = addr;
    return (long)addr;
}

static long lx_do_mmap(uintptr_t addr, size_t len, unsigned prot,
                       unsigned flags) {
    uintptr_t base = lx_heap_base(), end = lx_heap_end();
    uintptr_t top, out;
    (void)prot; /* M-mode: no per-page XN yet (documented); RW heap */
    if (len == 0) return -LX_EINVAL;
    if (len > LX_HEAP_SIZE) return -LX_ENOMEM;
    if (!(flags & LX_MAP_ANONYMOUS)) return -LX_ENOSYS; /* no file mmap v1 */
    if (lx_heap_top == 0) lx_heap_top = base;
    top = (lx_heap_top + 4095u) & ~(uintptr_t)4095u;
    len = (len + 4095u) & ~(size_t)4095u;
    if (flags & LX_MAP_FIXED) {
        uintptr_t a = addr & ~(uintptr_t)4095u;
        if (addr == 0) return -LX_EINVAL;
        if (a < base || a + len < a || a + len > end) return -LX_ENOMEM;
        if (a < top) return -LX_ENOMEM; /* occupied (bump-only) */
        memset((void *)a, 0, len);
        if (a + len > lx_heap_top) lx_heap_top = a + len;
        return (long)a;
    }
    if (top + len < top || top + len > end) return -LX_ENOMEM;
    out = top;
    memset((void *)out, 0, len);
    lx_heap_top = out + len;
    return (long)out;
}

static long lx_do_mprotect(uintptr_t addr, size_t len) {
    uintptr_t base = lx_heap_base();
    if (len == 0) return -LX_EINVAL;
    if (addr < base || addr + len < addr || addr + len > lx_heap_end())
        return -LX_ENOMEM;
    return 0; /* accepted, single RW domain (documented) */
}

static long lx_path_arg(uintptr_t uaddr, char *out) {
    long rc = lx_copy_path(uaddr, out, 256);
    size_t i, start = 0, n;
    char tmp[256];
    if (rc != 0) return rc;
    n = strlen(out);
    while (n > 0 && out[n - 1] == '/') n--;
    out[n] = '\0';
    if (n == 0) {
        out[0] = '\0';
        return 0;
    }
    for (i = 0; i < n; i++)
        if (out[i] == '/') start = i + 1;
    if (start > 0) {
        memmove(tmp, out + start, n - start + 1);
        memcpy(out, tmp, n - start + 1);
    }
    return 0;
}

static long lx_do_mkdirat(uint32_t caller, long dirfd, uintptr_t upath,
                          unsigned mode) {
    char path[256];
    long rc;
    (void)mode;
    if (dirfd != LX_AT_FDCWD) return -LX_EBADF;
    rc = lx_path_arg(upath, path);
    if (rc != 0) return rc;
    if (path[0] == '\0' || !lx_name_ok(path)) return -LX_ENOENT;
    return vfs_mkdir(caller, path) == 0 ? 0 : -LX_EEXIST;
}

static long lx_do_mknodat(uint32_t caller, long dirfd, uintptr_t upath,
                          unsigned mode, unsigned dev) {
    char path[256];
    long rc;
    (void)dev;
    if (dirfd != LX_AT_FDCWD) return -LX_EBADF;
    rc = lx_path_arg(upath, path);
    if (rc != 0) return rc;
    if (path[0] == '\0' || !lx_name_ok(path)) return -LX_ENOENT;
    if ((mode & LX_S_IFMT) == 0 || (mode & LX_S_IFMT) == LX_S_IFREG)
        return lx_do_open(caller, upath,
                          LX_O_CREAT | LX_O_WRONLY | LX_O_EXCL);
    if ((mode & LX_S_IFMT) == LX_S_IFIFO)
        return vfs_mkfifo(caller, path) == 0 ? 0 : -LX_EEXIST;
    return -LX_EINVAL;
}

static long lx_do_symlinkat(uint32_t caller, uintptr_t utarget, long dirfd,
                            uintptr_t upath) {
    char target[256], path[256];
    long rc;
    if (dirfd != LX_AT_FDCWD) return -LX_EBADF;
    rc = lx_copy_path(utarget, target, sizeof(target));
    if (rc != 0) return rc;
    rc = lx_path_arg(upath, path);
    if (rc != 0) return rc;
    if (path[0] == '\0' || !lx_name_ok(path)) return -LX_ENOENT;
    if (target[0] == '\0') return -LX_ENOENT;
    return vfs_symlink(caller, target, path) == 0 ? 0 : -LX_EEXIST;
}

static long lx_do_linkat(uint32_t caller, long olddir, uintptr_t uold,
                         long newdir, uintptr_t unew, unsigned flags) {
    char oldp[256], newp[256];
    long rc;
    if (flags & ~(LX_AT_SYMLINK_NOFOLLOW | LX_AT_EMPTY_PATH)) return -LX_EINVAL;
    if (olddir != LX_AT_FDCWD || newdir != LX_AT_FDCWD) return -LX_EBADF;
    rc = lx_path_arg(uold, oldp);
    if (rc != 0) return rc;
    rc = lx_path_arg(unew, newp);
    if (rc != 0) return rc;
    if (oldp[0] == '\0' || newp[0] == '\0') return -LX_ENOENT;
    if (!lx_name_ok(oldp) || !lx_name_ok(newp)) return -LX_ENOENT;
    rc = vfs_link(caller, oldp, newp);
    if (rc == 0) return 0;
    return vfs_stat(caller, oldp, NULL, NULL) == 0 ? -LX_EEXIST : -LX_ENOENT;
}

static long lx_do_readlinkat(uint32_t caller, long dirfd, uintptr_t upath,
                             uintptr_t ubuf, size_t len) {
    char path[256], tmp[64];
    long rc;
    int n;
    if (dirfd != LX_AT_FDCWD) return -LX_EBADF;
    rc = lx_path_arg(upath, path);
    if (rc != 0) return rc;
    if (path[0] == '\0' || !lx_name_ok(path)) return -LX_ENOENT;
    if (!lx_range_ok(ubuf, len)) return -LX_EFAULT;
    if (len == 0) return -LX_EINVAL;
    n = vfs_readlink(caller, path, tmp, sizeof(tmp));
    if (n < 0) {
        int k = vfs_kind(caller, path);
        return k < 0 ? -LX_ENOENT : -LX_EINVAL;
    }
    if ((size_t)n > len) n = (int)len;
    memcpy((void *)ubuf, tmp, (size_t)n);
    return n;
}

static long lx_do_getdents(uint32_t caller, long fd, uintptr_t udirent,
                           size_t len) {
    lx_fd_t *e = lx_fd_lookup(caller, fd);
    int cursor = 0, n = 0;
    char *out;
    uint32_t off = 0, ign = 0;
    if (!e || e->kind != LX_FD_VFS) return -LX_ENOTDIR;
    if (vfs_seek(caller, e->vfd, 0, 1, &off) != 0) return -LX_EBADF;
    cursor = (int)off;
    if (!lx_range_ok(udirent, len)) return -LX_EFAULT;
    if (len < sizeof(lx_dirent64_t)) return -LX_EINVAL;
    out = (char *)udirent;
    for (;;) {
        char nm[32];
        uint8_t kind = 0;
        uint64_t mt = 0;
        lx_dirent64_t *d;
        size_t nl;
        if (vfs_list_full(&cursor, nm, NULL, NULL, &kind, &mt) != 0) break;
        nl = strlen(nm) + 1;
        if ((size_t)n + sizeof(lx_dirent64_t) > len) break;
        d = (lx_dirent64_t *)(out + n);
        d->d_ino = 1000ull + (uint64_t)n;
        d->d_off = cursor;
        d->d_reclen = (unsigned short)sizeof(lx_dirent64_t);
        d->d_type = kind == 1 ? LX_DT_DIR
                    : kind == 2 ? LX_DT_LNK
                    : kind == 3 ? LX_DT_FIFO
                                : LX_DT_REG;
        memcpy(d->d_name, nm, nl > 32 ? 32 : nl);
        if (nl < 32) memset(d->d_name + nl, 0, 32 - nl);
        n += sizeof(lx_dirent64_t);
    }
    vfs_seek(caller, e->vfd, (int64_t)cursor, 0, &ign);
    return n;
}

static long lx_do_truncate_path(uint32_t caller, uintptr_t upath,
                                int64_t len) {
    char path[256];
    long rc, fd;
    int vfd;
    uint32_t cur = 0, ign = 0, end = 0;
    if (len < 0) return -LX_EINVAL;
    if ((uint64_t)len > LX_VFS_MAX_FILE_SIZE) return -LX_EINVAL;
    rc = lx_path_arg(upath, path);
    if (rc != 0) return rc;
    if (path[0] == '\0' || !lx_name_ok(path)) return -LX_ENOENT;
    fd = lx_do_open(caller, upath, LX_O_WRONLY);
    if (fd < 0) {
        fd = lx_do_open(caller, upath, LX_O_RDWR);
        if (fd < 0) return fd;
    }
    vfd = lx_to_vfd(caller, fd);
    if (vfd < 0) {
        lx_do_close(caller, fd);
        return -LX_EBADF;
    }
    if (vfs_seek(caller, vfd, 0, 2, &end) != 0) {
        lx_do_close(caller, fd);
        return -LX_EBADF;
    }
    if (vfs_seek(caller, vfd, 0, 1, &cur) != 0) {
        lx_do_close(caller, fd);
        return -LX_EBADF;
    }
    if ((uint64_t)len > end) {
        lx_do_close(caller, fd);
        return -LX_EINVAL;
    }
    rc = vfs_truncate_fd(caller, vfd, (uint32_t)len) == 0 ? 0 : -LX_EIO;
    vfs_seek(caller, vfd, (int64_t)cur, 0, &ign);
    lx_do_close(caller, fd);
    return rc;
}

static long lx_do_fchmodat(uint32_t caller, long dirfd, uintptr_t upath,
                           unsigned mode) {
    char path[256];
    long rc;
    (void)mode;
    if (dirfd != LX_AT_FDCWD) return -LX_EBADF;
    rc = lx_path_arg(upath, path);
    if (rc != 0) return rc;
    if (path[0] == '\0' || !lx_name_ok(path)) return -LX_ENOENT;
    return vfs_stat(caller, path, NULL, NULL) == 0 ? 0 : -LX_ENOENT;
}

static long lx_do_fchownat(uint32_t caller, long dirfd, uintptr_t upath,
                           unsigned uid, unsigned gid, unsigned flags) {
    char path[256];
    long rc;
    (void)flags;
    if (dirfd != LX_AT_FDCWD) return -LX_EBADF;
    if (!((uid == 0 || uid == 0xFFFFFFFFu) &&
          (gid == 0 || gid == 0xFFFFFFFFu)))
        return -LX_EPERM;
    rc = lx_path_arg(upath, path);
    if (rc != 0) return rc;
    if (path[0] == '\0' || !lx_name_ok(path)) return -LX_ENOENT;
    return vfs_stat(caller, path, NULL, NULL) == 0 ? 0 : -LX_ENOENT;
}

static short lx_poll_one(uint32_t caller, int fd, short events) {
    short re = 0;
    lx_fd_t *e;
    if (fd >= 0 && fd < 3) {
        if (fd == 0 && (events & LX_POLLIN)) re |= LX_POLLIN;
        if ((fd == 1 || fd == 2) && (events & LX_POLLOUT))
            re |= LX_POLLOUT;
        return re;
    }
    e = lx_fd_lookup(caller, fd);
    if (!e) return LX_POLLNVAL;
    if (e->kind == LX_FD_CONS) {
        if (e->vfd == 0 && (events & LX_POLLIN)) re |= LX_POLLIN;
        if ((e->vfd == 1 || e->vfd == 2) && (events & LX_POLLOUT))
            re |= LX_POLLOUT;
        return re;
    }
    if (e->kind == LX_FD_VFS) {
        if (events & (LX_POLLIN | LX_POLLOUT))
            re |= events & (LX_POLLIN | LX_POLLOUT);
        return re;
    }
    if (e->kind == LX_FD_PIPE) {
        int p = e->vfd;
        if (p < 0 || p >= LX_NPIPES || !lx_pipe_used[p])
            return LX_POLLNVAL;
        if (e->end == 0) {
            if ((events & LX_POLLIN) && lx_pipe_used_n(p) > 0)
                re |= LX_POLLIN;
            if (!lx_pipe_has_writer(p)) re |= LX_POLLHUP;
        } else {
            if ((events & LX_POLLOUT) &&
                LX_PIPE_SIZE - lx_pipe_used_n(p) > 0)
                re |= LX_POLLOUT;
            if (!lx_pipe_has_reader(p)) re |= LX_POLLERR;
        }
        return re;
    }
    {
        lx_sock_t *s = &lx_socks[e->vfd];
        if (e->vfd < 0 || e->vfd >= LX_NSOCK || !s->valid)
            return LX_POLLNVAL;
        if (s->state == 2 && (events & LX_POLLIN) && s->npending > 0)
            re |= LX_POLLIN;
        if (s->state == 3) {
            if ((events & LX_POLLIN) && lx_sock_used(s) > 0) re |= LX_POLLIN;
            if ((events & LX_POLLOUT) && s->peer >= 0 &&
                lx_socks[s->peer].valid &&
                LX_SOCK_RX - lx_sock_used(&lx_socks[s->peer]) > 0)
                re |= LX_POLLOUT;
            if (s->peer < 0 || !lx_socks[s->peer].valid) re |= LX_POLLHUP;
        }
        return re;
    }
}

static long lx_do_ppoll(uint32_t caller, uintptr_t ufds, unsigned nfds,
                        int64_t timeout_ns) {
    static lx_pollfd_t kf[32];
    unsigned i;
    int nready = 0;
    int64_t deadline;
    if (nfds > 32) return -LX_EINVAL;
    if (nfds > 0 && !lx_range_ok(ufds, nfds * sizeof(lx_pollfd_t)))
        return -LX_EFAULT;
    if (nfds > 0)
        memcpy(kf, (const void *)ufds, nfds * sizeof(lx_pollfd_t));
    deadline = timeout_ns < 0 ? -1 : lx_now_ns() + timeout_ns;
    for (;;) {
        nready = 0;
        for (i = 0; i < nfds; i++) {
            kf[i].revents = lx_poll_one(caller, kf[i].fd, kf[i].events);
            if (kf[i].revents) nready++;
        }
        if (nready > 0 || timeout_ns == 0) break;
        if (deadline >= 0 && lx_now_ns() >= deadline) break;
#ifndef __riscv
        break;
#endif
        break;
    }
    if (nfds > 0)
        memcpy((void *)ufds, kf, nfds * sizeof(lx_pollfd_t));
    return nready;
}

static long lx_do_nanosleep(int64_t sec, int64_t nsec) {
    int64_t total, deadline, now;
    if (sec < 0 || nsec < 0 || nsec >= 1000000000ll) return -LX_EINVAL;
    total = sec * 1000000000ll + nsec;
    if (total <= 0) return 0;
#ifdef __riscv
    deadline = lx_now_ns() + total;
    do {
        now = lx_now_ns();
        __asm__ volatile("" ::: "memory");
    } while (now < deadline);
#else
    {
        volatile int i;
        for (i = 0; i < 1000; i++) {
        }
    }
#endif
    return 0;
}

static bool lx_tcb_live(uint32_t id) {
    tcb_t *t;
    if (id >= MAX_TCBS) return false;
    t = &g_tcbs.threads[id];
    return !(t->pc == 0 && t->sp == 0 && t->cspace == NULL);
}

static long lx_do_kill(uint32_t caller_raw, long pid, unsigned sig) {
    uint32_t target;
    (void)caller_raw;
    if (sig >= 32) return -LX_EINVAL;
    if (pid <= 0 || pid >= 128) return -LX_ESRCH;
    target = (uint32_t)pid;
    if (!lx_tcb_live(target)) return -LX_ESRCH;
    if (sig == 0) return 0;
    lx_sigpend[target] |= 1u << sig;
    return 0;
}

/* pid match: -1 any; 0 caller's group (single group per thread, so
 * any child); <-1 pgid -pid (single group: match iff -pid == caller,
 * else no child can match -> ECHILD). WUNTRACED/WCONTINUED accepted
 * (no job control: never match, never error). WNOWAIT peeks. */
static bool lx_wait_match(uint32_t caller, long pid, uint32_t child) {
    (void)child;
    if (pid == -1) return true;
    if (pid == 0) return true;
    if (pid < -1) return (long)caller == -pid;
    return child == (uint32_t)pid;
}

static long lx_do_wait4(uint32_t caller, long pid, uintptr_t ustatus,
                        unsigned options) {
    int i;
    bool hang, nowait;
    if (options & ~(LX_WNOHANG | LX_WUNTRACED | LX_WCONTINUED |
                    LX_WNOWAIT))
        return -LX_EINVAL;
    hang = !(options & LX_WNOHANG);
    nowait = (options & LX_WNOWAIT) != 0;
    if (pid < -1 && (long)caller != -pid) return -LX_ECHILD;
    for (;;) {
        for (i = 0; i < LX_NCHILD; i++) {
            if (!lx_children[i].used || lx_children[i].parent != caller)
                continue;
            if (!lx_wait_match(caller, pid, lx_children[i].child))
                continue;
            if (!lx_children[i].exited) continue;
            {
                int st = lx_children[i].status;
                uint32_t ch = lx_children[i].child;
                if (!nowait) lx_children[i].used = false;
                if (ustatus != 0) {
                    if (!lx_range_ok(ustatus, sizeof(int)))
                        return -LX_EFAULT;
                    *(int *)ustatus = (st & 0xFF) << 8;
                }
                return (long)ch;
            }
        }
        {
            bool any = false;
            for (i = 0; i < LX_NCHILD; i++)
                if (lx_children[i].used &&
                    lx_children[i].parent == caller &&
                    lx_wait_match(caller, pid, lx_children[i].child)) {
                    any = true;
                    break;
                }
            if (!any) return -LX_ECHILD;
        }
        if (!hang) return -LX_EAGAIN;
#ifndef __riscv
        return -LX_EAGAIN;
#endif
        break;
    }
}

static long lx_do_getrandom(uintptr_t ubuf, size_t len, unsigned flags) {
    size_t i;
    if (flags & ~(LX_GRND_NONBLOCK | LX_GRND_RANDOM)) return -LX_EINVAL;
    if (!lx_range_ok(ubuf, len)) return -LX_EFAULT;
    if (len > 256) len = 256;
    lx_rng ^= (uint64_t)lx_ticks() + 0x9E3779B97F4A7C15ull;
    if (lx_rng == 0) lx_rng = 0x9E3779B97F4A7C15ull;
    for (i = 0; i < len; i++) {
        if ((i & 7) == 0) lx_rand64();
        ((char *)ubuf)[i] = (char)(lx_rng >> ((i & 7) * 8));
    }
    lx_rand64();
    return (long)len;
}

/* utimensat 280: (dirfd, path, times[2]{sec,nsec}, flags). Times are
 * {actime, modtime}; UTIME_NOW means now, UTIME_OMIT skips. Only the
 * mtime is stored (no atime field); atime values are validated. */
static long lx_do_utimensat(uint32_t caller, long dirfd, uintptr_t upath,
                            uintptr_t utimes, unsigned flags) {
    char path[256];
    long rc;
    int64_t sec;
    int64_t nsec;
    if (dirfd != LX_AT_FDCWD) return -LX_EBADF;
    if (flags & ~LX_AT_SYMLINK_NOFOLLOW) return -LX_EINVAL;
    rc = lx_path_arg(upath, path);
    if (rc != 0) return rc;
    if (path[0] == '\0' || !lx_name_ok(path)) return -LX_ENOENT;
    if (vfs_stat(caller, path, NULL, NULL) != 0) return -LX_ENOENT;
    if (utimes == 0) {
        vfs_set_mtime(caller, path, lx_ticks());
        return 0;
    }
    if (!lx_range_ok(utimes, 32)) return -LX_EFAULT;
    /* Entry 1 is the mtime. */
    sec = ((int64_t *)utimes)[2];
    nsec = ((int64_t *)utimes)[3];
    if (nsec != 0x3fffffff && nsec != 0x3ffffffe &&
        (nsec < 0 || nsec >= 1000000000ll))
        return -LX_EINVAL;
    if (sec < 0) return -LX_EINVAL;
    if (nsec == 0x3ffffffe) return 0; /* OMIT */
    if (nsec == 0x3fffffff) {
        vfs_set_mtime(caller, path, lx_ticks());
        return 0;
    }
    vfs_set_mtime(caller, path,
                  (uint64_t)sec * 10000000u + (uint64_t)nsec / 100u);
    return 0;
}

static long lx_do_statx(uint32_t caller, long dirfd, uintptr_t upath,
                        unsigned flags, unsigned mask,
                        uintptr_t ustx) {
    lx_stat_t st;
    lx_statx_t x;
    long rc;
    if (flags & ~(LX_AT_SYMLINK_NOFOLLOW | LX_AT_EMPTY_PATH |
                  LX_AT_NO_AUTOMOUNT | LX_AT_STATX_SYNC_TYPE))
        return -LX_EINVAL;
    if (mask & ~0xFFFu) return -LX_EINVAL;
    if (!lx_range_ok(ustx, sizeof(x))) return -LX_EFAULT;
    if ((flags & LX_AT_EMPTY_PATH) && (upath == 0 || *(const char *)upath == '\0')) {
        if (dirfd == LX_AT_FDCWD) return -LX_ENOENT;
        rc = lx_do_fstat(caller, dirfd, (uintptr_t)&st);
        if (rc != 0) return rc;
    } else {
        if (dirfd != LX_AT_FDCWD) return -LX_EBADF;
        rc = lx_do_fstatat(caller, dirfd, upath, (uintptr_t)&st, 0);
        if (rc != 0) return rc;
    }
    memset(&x, 0, sizeof(x));
    x.stx_mask = mask & LX_STATX_BASIC_STATS;
    x.stx_blksize = (uint32_t)st.st_blksize;
    x.stx_nlink = st.st_nlink;
    x.stx_mode = (uint16_t)st.st_mode;
    x.stx_ino = st.st_ino;
    x.stx_size = (uint64_t)st.st_size;
    x.stx_blocks = (uint64_t)(st.st_blocks >= 0 ? st.st_blocks : 0);
    x.stx_atime_sec = st.st_atime_sec;
    x.stx_atime_nsec = (uint32_t)st.st_atime_nsec;
    x.stx_mtime_sec = st.st_mtime_sec;
    x.stx_mtime_nsec = (uint32_t)st.st_mtime_nsec;
    x.stx_ctime_sec = st.st_ctime_sec;
    x.stx_ctime_nsec = (uint32_t)st.st_ctime_nsec;
    x.stx_dev_major = 1;
    memcpy((void *)ustx, &x, sizeof(x));
    return 0;
}

static long lx_do_futex(uintptr_t uaddr, int op, int val) {
    uint32_t *p;
    op &= ~LX_FUTEX_PRIVATE_FLAG;
    if (!lx_range_ok(uaddr, sizeof(uint32_t))) return -LX_EFAULT;
    p = (uint32_t *)uaddr;
    if (op == LX_FUTEX_WAKE) {
        (void)val;
        return 0;
    }
    if (op == LX_FUTEX_WAIT) {
        if (*p != (uint32_t)val) return -LX_EAGAIN;
        return 0;
    }
    return -LX_ENOSYS;
}

static long lx_do_socket(uint32_t caller, int domain, int type, int proto) {
    int s, lfd;
    (void)proto;
    {
        unsigned nb = (unsigned)type & LX_SOCK_NONBLOCK;
        unsigned ce = (unsigned)type & LX_SOCK_CLOEXEC;
        type &= ~(LX_SOCK_NONBLOCK | LX_SOCK_CLOEXEC);
        if (domain != LX_AF_UNIX && domain != LX_AF_INET)
            return -LX_EAFNOSUPPORT;
        if (type != LX_SOCK_STREAM && type != LX_SOCK_DGRAM)
            return -LX_ESOCKTNOSUPPORT;
        s = lx_sock_alloc();
        if (s < 0) return -LX_ENOMEM;
        lx_socks[s].type = type;
        lx_socks[s].owner = caller;
        lx_socks[s].nrd_ref = lx_socks[s].nwr_ref = 1;
        lfd = (int)lx_fd_alloc(caller, LX_FD_SOCK, s, 0,
                               nb | ce);
        if (lfd < 0) {
            lx_socks[s].valid = false;
            return lfd;
        }
        return lfd;
    }
}

static long lx_sock_addr(uintptr_t uaddr, size_t addrlen, char *out,
                         size_t outcap) {
    uint16_t fam;
    size_t i;
    if (addrlen < 2 || outcap == 0) return -LX_EINVAL;
    if (!lx_range_ok(uaddr, addrlen > 64 ? 64 : addrlen)) return -LX_EFAULT;
    fam = *(uint16_t *)uaddr;
    if (fam == LX_AF_UNIX) {
        const char *p = (const char *)uaddr + 2;
        size_t n = addrlen > 2 ? addrlen - 2 : 0;
        size_t start = 0;
        if (n >= outcap) n = outcap - 1;
        for (i = 0; i < n; i++)
            if (p[i] == '/') start = i + 1;
        if (n > start) {
            size_t m = n - start;
            if (m >= outcap) m = outcap - 1;
            memcpy(out, p + start, m);
            out[m] = '\0';
        } else {
            out[0] = '\0';
        }
        return 0;
    }
    if (fam == LX_AF_INET) {
        uint32_t ip;
        uint16_t port;
        char *q = out;
        unsigned vals[5];
        int k;
        if (addrlen < 8) return -LX_EINVAL;
        port = (uint16_t)(((uint8_t *)uaddr)[2] << 8 | ((uint8_t *)uaddr)[3]);
        memcpy(&ip, (char *)uaddr + 4, 4);
        if (ip != 0x0100007Fu && ip != 0) return -LX_EADDRNOTAVAIL;
        vals[0] = 127;
        vals[1] = 0;
        vals[2] = 0;
        vals[3] = 1;
        vals[4] = port;
        for (k = 0; k < 5; k++) {
            char tmp[8];
            int n2 = 0, j;
            unsigned v = vals[k];
            if (v == 0) tmp[n2++] = '0';
            else {
                while (v > 0 && n2 < 8) {
                    tmp[n2++] = (char)('0' + v % 10);
                    v /= 10;
                }
            }
            if (k == 4) *q++ = ':';
            else if (k > 0) *q++ = '.';
            for (j = n2 - 1; j >= 0 && (size_t)(q - out) < outcap - 1;
                 j--)
                *q++ = tmp[j];
        }
        *q = '\0';
        return 0;
    }
    return -LX_EAFNOSUPPORT;
}

static long lx_do_bind(uint32_t caller, long fd, uintptr_t uaddr,
                       size_t addrlen) {
    lx_fd_t *e = lx_fd_lookup(caller, fd);
    lx_sock_t *s;
    char name[32];
    int i;
    if (!e || e->kind != LX_FD_SOCK) return -LX_ENOTSOCK;
    s = &lx_socks[e->vfd];
    if (s->state != 0) return -LX_EINVAL;
    if (lx_sock_addr(uaddr, addrlen, name, sizeof(name)) != 0)
        return -LX_EAFNOSUPPORT;
    for (i = 0; i < LX_NSOCK; i++)
        if (lx_socks[i].valid && i != e->vfd && lx_socks[i].state >= 1 &&
            strcmp(lx_socks[i].addr, name) == 0)
            return -LX_EADDRINUSE;
    strncpy(s->addr, name, sizeof(s->addr) - 1);
    s->addr[sizeof(s->addr) - 1] = '\0';
    s->state = 1;
    return 0;
}

static long lx_do_listen(uint32_t caller, long fd, int backlog) {
    lx_fd_t *e = lx_fd_lookup(caller, fd);
    lx_sock_t *s;
    if (!e || e->kind != LX_FD_SOCK) return -LX_ENOTSOCK;
    s = &lx_socks[e->vfd];
    if (s->type != LX_SOCK_STREAM) return -LX_EOPNOTSUPP;
    if (s->state != 1) return -LX_EINVAL;
    if (backlog < 0) backlog = 0;
    if (backlog > 8) backlog = 8;
    s->backlog = backlog;
    s->state = 2;
    return 0;
}

static long lx_do_accept(uint32_t caller, long fd, uintptr_t uaddr,
                         uintptr_t uaddrlen) {
    lx_fd_t *e = lx_fd_lookup(caller, fd);
    lx_sock_t *ls, *cs;
    int ci, si, lfd, k;
    if (!e || e->kind != LX_FD_SOCK) return -LX_ENOTSOCK;
    ls = &lx_socks[e->vfd];
    if (ls->state != 2) return -LX_EINVAL;
    if (ls->npending == 0) return -LX_EAGAIN;
    ci = ls->pending[0];
    for (k = 1; k < ls->npending; k++) ls->pending[k - 1] = ls->pending[k];
    ls->npending--;
    if (ci < 0 || ci >= LX_NSOCK || !lx_socks[ci].valid)
        return -LX_ECONNABORTED;
    cs = &lx_socks[ci];
    si = lx_sock_alloc();
    if (si < 0) return -LX_ENOMEM;
    lx_socks[si].type = ls->type;
    lx_socks[si].owner = caller;
    lx_socks[si].state = 3;
    lx_socks[si].peer = ci;
    lx_socks[si].nrd_ref = lx_socks[si].nwr_ref = 1;
    strncpy(lx_socks[si].addr, ls->addr, sizeof(lx_socks[si].addr) - 1);
    cs->peer = si;
    cs->state = 3;
    lfd = (int)lx_fd_alloc(caller, LX_FD_SOCK, si, 0, 0);
    if (lfd < 0) {
        lx_socks[si].valid = false;
        cs->peer = -1;
        return lfd;
    }
    if (uaddr != 0 && uaddrlen != 0 && lx_range_ok(uaddrlen, sizeof(uint32_t)) &&
        lx_range_ok(uaddr, 2)) {
        *(uint16_t *)uaddr = LX_AF_UNIX;
        if (*(uint32_t *)uaddrlen >= 2) *(uint32_t *)uaddrlen = 2;
    }
    return lfd;
}

static long lx_do_connect(uint32_t caller, long fd, uintptr_t uaddr,
                          size_t addrlen) {
    lx_fd_t *e = lx_fd_lookup(caller, fd);
    lx_sock_t *s;
    char name[32];
    int i;
    if (!e || e->kind != LX_FD_SOCK) return -LX_ENOTSOCK;
    s = &lx_socks[e->vfd];
    if (s->state == 3) return -LX_EISCONN;
    if (s->state != 0 && s->state != 1) return -LX_EINVAL;
    if (lx_sock_addr(uaddr, addrlen, name, sizeof(name)) != 0)
        return -LX_EAFNOSUPPORT;
    for (i = 0; i < LX_NSOCK; i++) {
        if (!lx_socks[i].valid || lx_socks[i].state != 2) continue;
        if (strcmp(lx_socks[i].addr, name) != 0) continue;
        if (lx_socks[i].npending >= 8) return -LX_ECONNREFUSED;
        if (lx_socks[i].type != s->type) return -LX_EPROTOTYPE;
        lx_socks[i].pending[lx_socks[i].npending++] = e->vfd;
        return 0;
    }
    if (s->type == LX_SOCK_DGRAM) {
        strncpy(s->addr, name, sizeof(s->addr) - 1);
        s->state = 3;
        s->peer = -1;
        return 0;
    }
    return -LX_ECONNREFUSED;
}

static long lx_do_sendto(uint32_t caller, long fd, uintptr_t ubuf, size_t len,
                         unsigned flags, uintptr_t uaddr, size_t addrlen) {
    lx_fd_t *e = lx_fd_lookup(caller, fd);
    lx_sock_t *s, *peer;
    char hdr[2];
    (void)flags;
    if (!e) return -LX_EBADF;
    if (e->kind == LX_FD_PIPE)
        return lx_do_write(caller, fd, ubuf, len);
    if (e->kind != LX_FD_SOCK) return -LX_ENOTSOCK;
    s = &lx_socks[e->vfd];
    if (uaddr != 0) {
        if (s->state != 3) {
            long rc = lx_do_connect(caller, fd, uaddr, addrlen);
            if (rc != 0) return rc;
        }
    }
    if (s->peer < 0 || !lx_socks[s->peer].valid) {
        if (s->type == LX_SOCK_DGRAM) peer = s;
        else return -LX_ENOTCONN;
    } else {
        peer = &lx_socks[s->peer];
    }
    if (!lx_range_ok(ubuf, len)) return -LX_EFAULT;
    if (len > 2048 && s->type == LX_SOCK_DGRAM) return -LX_EMSGSIZE;
    if (LX_SOCK_RX - lx_sock_used(peer) <
        len + (s->type == LX_SOCK_DGRAM ? 2u : 0u))
        return -LX_EAGAIN;
    if (s->type == LX_SOCK_DGRAM) {
        hdr[0] = (char)(len & 0xFF);
        hdr[1] = (char)((len >> 8) & 0xFF);
        lx_sock_push(peer, hdr, 2);
    }
    return lx_sock_push(peer, (const char *)ubuf, len);
}

static long lx_do_recvfrom(uint32_t caller, long fd, uintptr_t ubuf,
                           size_t len, unsigned flags, uintptr_t uaddr,
                           uintptr_t uaddrlen) {
    lx_fd_t *e = lx_fd_lookup(caller, fd);
    lx_sock_t *s;
    bool peek = (flags & LX_MSG_PEEK) != 0;
    if (!e) return -LX_EBADF;
    if (e->kind == LX_FD_PIPE)
        return lx_do_read(caller, fd, ubuf, len);
    if (e->kind != LX_FD_SOCK) return -LX_ENOTSOCK;
    s = &lx_socks[e->vfd];
    if (!lx_range_ok(ubuf, len)) return -LX_EFAULT;
    if (s->type == LX_SOCK_DGRAM) {
        unsigned dlen;
        char hdr[2];
        if (lx_sock_used(s) < 2) return -LX_EAGAIN;
        lx_sock_pop(s, hdr, 2, true);
        dlen = (unsigned)(uint8_t)hdr[0] | ((unsigned)(uint8_t)hdr[1] << 8);
        if (lx_sock_used(s) - 2 < dlen) return -LX_EAGAIN;
        lx_sock_pop(s, hdr, 2, false);
        if (len > dlen) len = dlen;
        {
            long r = lx_sock_pop(s, (char *)ubuf, len, peek);
            if (!peek && len < dlen) {
                char tmp[64];
                size_t left = dlen - len;
                while (left > 0) {
                    size_t c = left > sizeof(tmp) ? sizeof(tmp) : left;
                    lx_sock_pop(s, tmp, c, false);
                    left -= c;
                }
            }
            if (uaddr != 0 && uaddrlen != 0 &&
                lx_range_ok(uaddrlen, sizeof(uint32_t)) &&
                lx_range_ok(uaddr, 2)) {
                *(uint16_t *)uaddr = LX_AF_UNIX;
                if (*(uint32_t *)uaddrlen >= 2)
                    *(uint32_t *)uaddrlen = 2;
            }
            return r;
        }
    }
    if (lx_sock_used(s) == 0) {
        if (s->peer < 0 || !lx_socks[s->peer].valid) return 0;
        return -LX_EAGAIN;
    }
    if (uaddr != 0 && uaddrlen != 0 &&
        lx_range_ok(uaddrlen, sizeof(uint32_t)) &&
        lx_range_ok(uaddr, 2)) {
        *(uint16_t *)uaddr = LX_AF_UNIX;
        if (*(uint32_t *)uaddrlen >= 2) *(uint32_t *)uaddrlen = 2;
    }
    return lx_sock_pop(s, (char *)ubuf, len, peek);
}

static long lx_do_sockname(uint32_t caller, long fd, uintptr_t uaddr,
                           uintptr_t uaddrlen, bool peer) {
    lx_fd_t *e = lx_fd_lookup(caller, fd);
    lx_sock_t *s;
    size_t n, cap;
    if (!e || e->kind != LX_FD_SOCK) return -LX_ENOTSOCK;
    s = &lx_socks[e->vfd];
    if (peer) {
        if (s->peer < 0 || !lx_socks[s->peer].valid) return -LX_ENOTCONN;
        s = &lx_socks[s->peer];
    }
    if (!lx_range_ok(uaddrlen, sizeof(uint32_t))) return -LX_EFAULT;
    cap = *(uint32_t *)uaddrlen;
    n = strlen(s->addr) + 3;
    if (cap < 2) return -LX_EINVAL;
    if (!lx_range_ok(uaddr, cap < n ? cap : n)) return -LX_EFAULT;
    *(uint16_t *)uaddr = LX_AF_UNIX;
    {
        size_t m = strlen(s->addr);
        if (m > cap - 2) m = cap - 2;
        memcpy((char *)uaddr + 2, s->addr, m);
    }
    *(uint32_t *)uaddrlen = (uint32_t)n;
    return 0;
}

static long lx_do_setsockopt(uint32_t caller, long fd, int level, int name,
                             uintptr_t uval, size_t vlen) {
    lx_fd_t *e = lx_fd_lookup(caller, fd);
    lx_sock_t *s;
    (void)caller;
    if (!e || e->kind != LX_FD_SOCK) return -LX_ENOTSOCK;
    s = &lx_socks[e->vfd];
    if (level != LX_SOL_SOCKET) return -LX_ENOPROTOOPT;
    if (name == LX_SO_SNDBUF || name == LX_SO_RCVBUF) {
        int v;
        if (vlen != sizeof(int) || !lx_range_ok(uval, sizeof(int)))
            return -LX_EFAULT;
        v = *(int *)uval;
        if (v <= 0) return -LX_EINVAL;
        if (name == LX_SO_SNDBUF) s->sndbuf = v;
        else s->rcvbuf = v;
        return 0;
    }
    if (name == LX_SO_REUSEADDR || name == LX_SO_KEEPALIVE) return 0;
    if (name == LX_SO_RCVTIMEO_OLD || name == LX_SO_SNDTIMEO_OLD) {
        long sec, usec;
        if (vlen != 16 || !lx_range_ok(uval, 16)) return -LX_EFAULT;
        sec = ((long *)uval)[0];
        usec = ((long *)uval)[1];
        if (sec < 0 || usec < 0 || usec >= 1000000) return -LX_EINVAL;
        if (name == LX_SO_RCVTIMEO_OLD)
            s->rcv_timeo_ms = (uint32_t)(sec * 1000 + usec / 1000);
        else s->snd_timeo_ms = (uint32_t)(sec * 1000 + usec / 1000);
        return 0;
    }
    return -LX_ENOPROTOOPT;
}

static long lx_do_getsockopt(uint32_t caller, long fd, int level, int name,
                             uintptr_t uval, uintptr_t uvlen) {
    lx_fd_t *e = lx_fd_lookup(caller, fd);
    lx_sock_t *s;
    (void)caller;
    if (!e || e->kind != LX_FD_SOCK) return -LX_ENOTSOCK;
    s = &lx_socks[e->vfd];
    if (!lx_range_ok(uvlen, sizeof(uint32_t))) return -LX_EFAULT;
    if (level != LX_SOL_SOCKET) return -LX_ENOPROTOOPT;
    if (name == LX_SO_TYPE || name == LX_SO_ERROR ||
        name == LX_SO_SNDBUF || name == LX_SO_RCVBUF) {
        if (*(uint32_t *)uvlen < sizeof(int)) return -LX_EINVAL;
        if (!lx_range_ok(uval, sizeof(int))) return -LX_EFAULT;
        if (name == LX_SO_TYPE) *(int *)uval = s->type;
        else if (name == LX_SO_ERROR) *(int *)uval = 0;
        else *(int *)uval = name == LX_SO_SNDBUF ? s->sndbuf : s->rcvbuf;
        *(uint32_t *)uvlen = sizeof(int);
        return 0;
    }
    return -LX_ENOPROTOOPT;
}

/* ---- main dispatch (frame-free; host-testable) ---- */

static long lx_do_close(uint32_t caller, long fd) {
    lx_fd_t *e;
    if (fd >= 0 && fd < 3) return -LX_EBADF;
    e = lx_fd_lookup(caller, fd);
    if (!e) return -LX_EBADF;
    if (e->kind == LX_FD_VFS) {
        int v = e->vfd;
        e->valid = false;
        if (v >= 0 && v < LX_VFS_FDS_PER_CLIENT) {
            if (--lx_fd_refs[caller][v] <= 0) {
                lx_fd_refs[caller][v] = 0;
                if (vfs_close(caller, v) != 0) return -LX_EBADF;
            }
        }
        return 0;
    }
    if (e->kind == LX_FD_CONS) {
        e->valid = false; /* console itself is never closed */
        return 0;
    }
    if (e->kind == LX_FD_PIPE) {
        int p = e->vfd;
        e->valid = false;
        if (p >= 0 && p < LX_NPIPES && lx_pipe_used[p]) {
            if (e->end == 0 && lx_pipe_rdref[p] > 0) lx_pipe_rdref[p]--;
            if (e->end == 1 && lx_pipe_wrref[p] > 0) lx_pipe_wrref[p]--;
            if (lx_pipe_rdref[p] == 0 && lx_pipe_wrref[p] == 0)
                lx_pipe_used[p] = false;
        }
        return 0;
    }
    /* socket */
    {
        int s = e->vfd;
        e->valid = false;
        if (s >= 0 && s < LX_NSOCK && lx_socks[s].valid) {
            if (e->end == 0 && lx_socks[s].nrd_ref > 0) lx_socks[s].nrd_ref--;
            if (e->end == 1 && lx_socks[s].nwr_ref > 0) lx_socks[s].nwr_ref--;
            if (lx_socks[s].nrd_ref == 0 && lx_socks[s].nwr_ref == 0) {
                int peer = lx_socks[s].peer;
                lx_socks[s].valid = false;
                if (peer >= 0 && peer < LX_NSOCK && lx_socks[peer].valid)
                    lx_socks[peer].peer = -1;
            }
        }
        return 0;
    }
}

static void lx_close_all(uint32_t caller) {
    int i;
    if (caller >= LX_VFS_MAX_CLIENTS) return;
    for (i = 0; i < LX_NFDS; i++) {
        if (!lx_fds[caller][i].valid) continue;
        lx_do_close(caller, (long)(i + 3));
    }
}

static void lx_close_cloexec(uint32_t caller) {
    int i;
    if (caller >= LX_VFS_MAX_CLIENTS) return;
    for (i = 0; i < LX_NFDS; i++) {
        if (!lx_fds[caller][i].valid || !lx_fds[caller][i].cloexec) continue;
        lx_do_close(caller, (long)(i + 3));
    }
}

static long lx_do_dup(uint32_t caller, long oldfd, long newfd, bool exact) {
    lx_fd_t *e;
    long lfd;
    int i;
    if (oldfd >= 0 && oldfd < 3) {
        /* Console fd: allocate a CONS alias (reads/writes dispatch
         * on the stored console number). */
        if (!exact) {
            lfd = lx_fd_alloc(caller, LX_FD_CONS, (int)oldfd, 0, 0);
            return lfd;
        }
        if (newfd < 0 || newfd >= 3 + LX_NFDS) return -LX_EBADF;
        if (newfd < 3) return -LX_EBADF;
        if (newfd == oldfd) return newfd;
        for (i = 0; i < LX_NFDS; i++)
            if (lx_fds[caller][i].valid && i + 3 == newfd) {
                lx_do_close(caller, newfd);
                break;
            }
        lx_fds[caller][newfd - 3].valid = true;
        lx_fds[caller][newfd - 3].kind = LX_FD_CONS;
        lx_fds[caller][newfd - 3].vfd = (int)oldfd;
        lx_fds[caller][newfd - 3].end = 0;
        lx_fds[caller][newfd - 3].cloexec = 0;
        lx_fds[caller][newfd - 3].nonblock = 0;
        return newfd;
    }
    e = lx_fd_lookup(caller, oldfd);
    if (!e) return -LX_EBADF;
    if (!exact) {
        lfd = lx_fd_alloc(caller, e->kind, e->vfd, e->end, 0);
        if (lfd < 0) return lfd;
        if (e->kind == LX_FD_PIPE) {
            if (e->end == 0) lx_pipe_rdref[e->vfd]++;
            else lx_pipe_wrref[e->vfd]++;
        } else if (e->kind == LX_FD_SOCK) {
            if (e->end == 0) lx_socks[e->vfd].nrd_ref++;
            else lx_socks[e->vfd].nwr_ref++;
        }
        lx_fds[caller][lfd - 3].cloexec = 0;
        lx_fds[caller][lfd - 3].nonblock = e->nonblock;
        return lfd;
    }
    if (newfd < 0 || newfd >= 3 + LX_NFDS) return -LX_EBADF;
    if (newfd < 3) return -LX_EBADF;
    if (newfd == oldfd) return newfd;
    for (i = 0; i < LX_NFDS; i++)
        if (lx_fds[caller][i].valid && i + 3 == newfd) {
            lx_do_close(caller, newfd);
            break;
        }
    lx_fds[caller][newfd - 3].valid = true;
    lx_fds[caller][newfd - 3].kind = e->kind;
    lx_fds[caller][newfd - 3].vfd = e->vfd;
    lx_fds[caller][newfd - 3].end = e->end;
    lx_fds[caller][newfd - 3].cloexec = 0;
    lx_fds[caller][newfd - 3].nonblock = e->nonblock;
    if (e->kind == LX_FD_VFS && e->vfd >= 0 &&
        e->vfd < LX_VFS_FDS_PER_CLIENT)
        lx_fd_refs[caller][e->vfd]++;
    else if (e->kind == LX_FD_PIPE) {
        if (e->end == 0) lx_pipe_rdref[e->vfd]++;
        else lx_pipe_wrref[e->vfd]++;
    } else {
        if (e->end == 0) lx_socks[e->vfd].nrd_ref++;
        else lx_socks[e->vfd].nwr_ref++;
    }
    return newfd;
}

static long lx_do_pipe2(uint32_t caller, uintptr_t ufd, unsigned flags) {
    int p;
    long rfd, wfd;
    if (flags & ~(LX_O_NONBLOCK | LX_O_CLOEXEC)) return -LX_EINVAL;
    if (!lx_range_ok(ufd, 2 * sizeof(int))) return -LX_EFAULT;
    p = lx_pipe_alloc();
    if (p < 0) return -LX_ENOMEM;
    lx_pipe_rdref[p] = lx_pipe_wrref[p] = 1;
    rfd = lx_fd_alloc(caller, LX_FD_PIPE, p, 0, flags);
    if (rfd < 0) {
        lx_pipe_used[p] = false;
        return rfd;
    }
    wfd = lx_fd_alloc(caller, LX_FD_PIPE, p, 1, flags);
    if (wfd < 0) {
        lx_do_close(caller, rfd);
        return wfd;
    }
    ((int *)ufd)[0] = (int)rfd;
    ((int *)ufd)[1] = (int)wfd;
    return 0;
}

static long lx_do_fcntl(uint32_t caller, long fd, unsigned cmd, long arg) {
    lx_fd_t *e = lx_fd_lookup(caller, fd);
    if (!e && cmd != LX_F_DUPFD && cmd != LX_F_DUPFD_CLOEXEC) {
        if (fd >= 0 && fd < 3) {
            /* Console fds: GETFD/GETFL succeed. */
            if (cmd == LX_F_GETFD) return 0;
            if (cmd == LX_F_GETFL)
                return LX_O_RDONLY | LX_O_ACCMODE;
            return -LX_EINVAL;
        }
        return -LX_EBADF;
    }
    switch (cmd) {
    case LX_F_DUPFD:
    case LX_F_DUPFD_CLOEXEC: {
        long min = arg < 0 ? 0 : arg, i, out;
        bool cloexec = (cmd == LX_F_DUPFD_CLOEXEC);
        if (min < 3) min = 3;
        if (min >= 3 + LX_NFDS) return -LX_EINVAL;
        if (!e) {
            /* Console fd: allocate a CONS alias. Anything else is
             * not an open fd (EBADF, not an alias). */
            if (fd < 0 || fd >= 3) return -LX_EBADF;
            for (i = min - 3; i < LX_NFDS; i++)
                if (!lx_fds[caller][i].valid) {
                    lx_fds[caller][i].valid = true;
                    lx_fds[caller][i].kind = LX_FD_CONS;
                    lx_fds[caller][i].vfd = (int)fd;
                    lx_fds[caller][i].end = 0;
                    lx_fds[caller][i].cloexec = cloexec ? 1 : 0;
                    lx_fds[caller][i].nonblock = 0;
                    return i + 3;
                }
            return -LX_EMFILE;
        }
        for (i = min - 3; i < LX_NFDS; i++) {
            if (lx_fds[caller][i].valid) continue;
            out = lx_do_dup(caller, fd, i + 3, true);
            if (out >= 0 && cloexec)
                lx_fds[caller][out - 3].cloexec = 1;
            return out;
        }
        return -LX_EMFILE;
    }
    case LX_F_GETFD:
        return e->cloexec ? LX_FD_CLOEXEC : 0;
    case LX_F_SETFD:
        e->cloexec = (arg & LX_FD_CLOEXEC) ? 1 : 0;
        return 0;
    case LX_F_GETFL: {
        int fl = e->nonblock ? LX_O_NONBLOCK : 0;
        if (e->kind == LX_FD_VFS) {
            /* Recover access mode: assume RDWR (stored rights unknown
             * here); report RDWR always — honest for our open paths. */
            fl |= LX_O_RDWR;
        } else if (e->kind == LX_FD_CONS) {
            fl |= (e->vfd == 0) ? LX_O_RDONLY : LX_O_WRONLY;
        }
        return fl;
    }
    case LX_F_SETFL:
        if (arg & ~(LX_O_NONBLOCK | LX_O_APPEND)) return -LX_EINVAL;
        e->nonblock = (arg & LX_O_NONBLOCK) ? 1 : 0;
        if (e->kind == LX_FD_VFS && (arg & LX_O_APPEND))
            vfs_set_append(caller, e->vfd, true);
        return 0;
    default:
        return -LX_EINVAL;
    }
}

static long lx_do_ioctl(uint32_t caller, long fd, unsigned req, uintptr_t arg) {
    lx_fd_t *e;
    if (fd >= 0 && fd < 3) e = NULL;
    else {
        e = lx_fd_lookup(caller, fd);
        if (!e) return -LX_EBADF;
    }
    switch (req) {
    case LX_FIONREAD: {
        long n = 0;
        if (!lx_range_ok(arg, sizeof(int))) return -LX_EFAULT;
        if (fd == 0) {
            /* Console: bytes available without blocking is unknown;
             * report 0/1 via a non-destructive probe is impossible on
             * the kbd ring, so report 0 (real: no buffered lookahead). */
            n = 0;
        } else if (e && e->kind == LX_FD_PIPE) {
            n = (long)lx_pipe_used_n(e->vfd);
        } else if (e && e->kind == LX_FD_SOCK) {
            n = (long)lx_sock_used(&lx_socks[e->vfd]);
        } else if (e) {
            uint32_t cur = 0, end = 0, ign = 0;
            if (vfs_seek(caller, e->vfd, 0, 1, &cur) != 0) return -LX_EBADF;
            if (vfs_seek(caller, e->vfd, 0, 2, &end) != 0) return -LX_EBADF;
            vfs_seek(caller, e->vfd, (int64_t)cur, 0, &ign);
            n = end >= cur ? (long)(end - cur) : 0;
        }
        *(int *)arg = (int)n;
        return 0;
    }
    case LX_TIOCGWINSZ: {
        /* 4x unsigned short: rows, cols, xpixel, ypixel. */
        if (!lx_range_ok(arg, 8)) return -LX_EFAULT;
        ((unsigned short *)arg)[0] = 24;
        ((unsigned short *)arg)[1] = 80;
        ((unsigned short *)arg)[2] = 0;
        ((unsigned short *)arg)[3] = 0;
        return 0;
    }
    case LX_TIOCSWINSZ:
        if (!lx_range_ok(arg, 8)) return -LX_EFAULT;
        return 0; /* accepted: no framebuffer resize on virt */
    case LX_TCGETS: {
        lx_termios_t *t = lx_term(caller);
        if (!t || !lx_range_ok(arg, 12 + 8)) return -LX_EFAULT;
        ((uint32_t *)arg)[0] = t->iflag;
        ((uint32_t *)arg)[1] = t->oflag;
        ((uint32_t *)arg)[2] = t->cflag;
        ((uint32_t *)arg)[3] = t->lflag;
        memcpy((char *)arg + 16, t->cc, 8);
        return 0;
    }
    case LX_TCSETS: {
        lx_termios_t *t = lx_term(caller);
        if (!t || !lx_range_ok(arg, 12 + 8)) return -LX_EFAULT;
        t->iflag = ((uint32_t *)arg)[0];
        t->oflag = ((uint32_t *)arg)[1];
        t->cflag = ((uint32_t *)arg)[2];
        t->lflag = ((uint32_t *)arg)[3];
        memcpy(t->cc, (char *)arg + 16, 8);
        return 0;
    }
    default:
        return -LX_ENOSYS;
    }
}

static long lx_do_flock(uint32_t caller, long fd, int op) {
    lx_fd_t *e = lx_fd_lookup(caller, fd);
    char name[32];
    int i, mode;
    bool nb;
    if (!e || e->kind != LX_FD_VFS) return -LX_EBADF;
    /* Identify the file by the (caller, vfd) pair — sufficient for
     * advisory locks here. */
    {
        char *p = name;
        uint32_t v;
        *p++ = 'c';
        v = caller;
        if (v == 0) *p++ = '0';
        else {
            char tmp[12];
            int n = 0;
            while (v > 0 && n < 12) {
                tmp[n++] = (char)('0' + v % 10);
                v /= 10;
            }
            while (n > 0) *p++ = tmp[--n];
        }
        *p++ = '/';
        v = (uint32_t)e->vfd;
        if (v == 0) *p++ = '0';
        else {
            char tmp[12];
            int n = 0;
            while (v > 0 && n < 12) {
                tmp[n++] = (char)('0' + v % 10);
                v /= 10;
            }
            while (n > 0) *p++ = tmp[--n];
        }
        *p = '\0';
    }
    nb = (op & LX_LOCK_NB) != 0;
    mode = op & ~LX_LOCK_NB;
    if (mode != LX_LOCK_SH && mode != LX_LOCK_EX && mode != LX_LOCK_UN)
        return -LX_EINVAL;
    if (mode == LX_LOCK_UN) {
        for (i = 0; i < LX_NFLOCK; i++)
            if (lx_flocks[i].used && lx_flocks[i].caller == caller &&
                strcmp(lx_flocks[i].name, name) == 0) {
                lx_flocks[i].used = false;
                return 0;
            }
        return 0; /* unlocking an unlocked file is ok */
    }
    for (i = 0; i < LX_NFLOCK; i++) {
        if (!lx_flocks[i].used || strcmp(lx_flocks[i].name, name) != 0)
            continue;
        if (lx_flocks[i].caller == caller) {
            /* Upgrade SH->EX needs exclusivity; downgrade always ok. */
            if (mode == LX_LOCK_EX && lx_flocks[i].mode == LX_LOCK_SH) {
                lx_flocks[i].mode = LX_LOCK_EX;
                return 0;
            }
            return 0;
        }
        /* Another client holds it. */
        if (mode == LX_LOCK_SH && lx_flocks[i].mode == LX_LOCK_SH)
            break; /* shared compatible: fall through to add */
        return nb ? -LX_EAGAIN : -LX_EAGAIN; /* single-hart: no blocking */
    }
    for (i = 0; i < LX_NFLOCK; i++) {
        if (lx_flocks[i].used) continue;
        lx_flocks[i].used = true;
        lx_flocks[i].caller = caller;
        strncpy(lx_flocks[i].name, name, sizeof(lx_flocks[i].name) - 1);
        lx_flocks[i].name[sizeof(lx_flocks[i].name) - 1] = '\0';
        lx_flocks[i].mode = mode;
        return 0;
    }
    return -LX_ENOMEM;
}

long linux_syscall_nr(long nr, uintptr_t a0, uintptr_t a1, uintptr_t a2,
                      uintptr_t a3, uintptr_t a4, uintptr_t a5,
                      uint32_t caller_raw) {
    uint32_t caller = lx_caller(caller_raw);
    if (caller >= LX_VFS_MAX_CLIENTS || caller == LX_VFS_UNKNOWN_CLIENT)
        return -LX_EINVAL;
    switch (nr) {
    case LX_SYS_read:
        return lx_do_read(caller, (long)a0, a1, (size_t)a2);
    case LX_SYS_write:
        return lx_do_write(caller, (long)a0, a1, (size_t)a2);
    case LX_SYS_readv:
        return lx_do_vec(caller, (long)a0, a1, (unsigned)a2, false);
    case LX_SYS_writev:
        return lx_do_vec(caller, (long)a0, a1, (unsigned)a2, true);
    case LX_SYS_pread64:
        return lx_do_preadwrite(caller, (long)a0, a1, (size_t)a2,
                                (int64_t)a3, false);
    case LX_SYS_pwrite64:
        return lx_do_preadwrite(caller, (long)a0, a1, (size_t)a2,
                                (int64_t)a3, true);
    case LX_SYS_openat: {
        long dirfd = (long)a0;
        if (dirfd != LX_AT_FDCWD) return -LX_EBADF;
        return lx_do_open(caller, a1, (unsigned)a2);
    }
    case LX_SYS_close:
        return lx_do_close(caller, (long)a0);
    case LX_SYS_dup:
        return lx_do_dup(caller, (long)a0, -1, false);
    case LX_SYS_dup3:
        if (a2 & ~LX_O_CLOEXEC) return -LX_EINVAL;
        if ((long)a0 == (long)a1) return -LX_EINVAL;
        return lx_do_dup(caller, (long)a0, (long)a1, true);
    case LX_SYS_fcntl:
        return lx_do_fcntl(caller, (long)a0, (unsigned)a1, (long)a2);
    case LX_SYS_ioctl:
        return lx_do_ioctl(caller, (long)a0, (unsigned)a1, a2);
    case LX_SYS_flock:
        return lx_do_flock(caller, (long)a0, (int)a1);
    case LX_SYS_pipe2:
        return lx_do_pipe2(caller, a0, (unsigned)a1);
    case LX_SYS_mknodat:
        return lx_do_mknodat(caller, (long)a0, a1, (unsigned)a2,
                             (unsigned)a3);
    case LX_SYS_mkdirat:
        return lx_do_mkdirat(caller, (long)a0, a1, (unsigned)a2);
    case LX_SYS_symlinkat:
        return lx_do_symlinkat(caller, a0, (long)a1, a2);
    case LX_SYS_linkat:
        return lx_do_linkat(caller, (long)a0, a1, (long)a2, a3,
                            (unsigned)a4);
    case LX_SYS_readlinkat:
        return lx_do_readlinkat(caller, (long)a0, a1, a2, (size_t)a3);
    case LX_SYS_getdents64:
        return lx_do_getdents(caller, (long)a0, a1, (size_t)a2);
    case LX_SYS_truncate:
        return lx_do_truncate_path(caller, a0, (int64_t)a1);
    case LX_SYS_fchmodat:
        return lx_do_fchmodat(caller, (long)a0, a1, (unsigned)a2);
    case LX_SYS_fchownat:
        return lx_do_fchownat(caller, (long)a0, a1, (unsigned)a2,
                              (unsigned)a3, (unsigned)a4);
    case LX_SYS_pselect6:
    case LX_SYS_ppoll: {
        /* pselect6 (nfds, readfds, writefds, exceptfds, timeout, sigmask)
         * and ppoll (fds, nfds, timeout, sigmask) share the poll core.
         * pselect fd_sets are converted to a poll list (up to 32 fds). */
        if (nr == LX_SYS_ppoll) {
            int64_t to = -1;
            if (a2 != 0) {
                /* struct timespec { long sec, nsec } */
                long sec, nsec;
                if (!lx_range_ok(a2, 16)) return -LX_EFAULT;
                sec = ((long *)a2)[0];
                nsec = ((long *)a2)[1];
                if (sec < 0 || nsec < 0 || nsec >= 1000000000ll)
                    return -LX_EINVAL;
                to = sec * 1000000000ll + nsec;
            }
            return lx_do_ppoll(caller, a0, (unsigned)a1, to);
        } else {
            /* pselect6: scan fds 0..nfds-1 for set bits (bounded 32). */
            static lx_pollfd_t kf[32];
            unsigned nf = (unsigned)a0, i, n = 0;
            long rbits = 0, wbits = 0;
            int64_t to = -1;
            if (nf > 32) return -LX_EINVAL;
            if (nf == 0) {
                if (a4 != 0) {
                    long sec, nsec;
                    if (!lx_range_ok(a4, 16)) return -LX_EFAULT;
                    sec = ((long *)a4)[0];
                    nsec = ((long *)a4)[1];
                    if (sec < 0 || nsec < 0 || nsec >= 1000000000ll)
                        return -LX_EINVAL;
                    lx_do_nanosleep(sec, nsec);
                }
                return 0;
            }
            if (a1 != 0) {
                if (!lx_range_ok(a1, sizeof(long))) return -LX_EFAULT;
                rbits = *(long *)a1;
            }
            if (a2 != 0) {
                if (!lx_range_ok(a2, sizeof(long))) return -LX_EFAULT;
                wbits = *(long *)a2;
            }
            for (i = 0; i < nf && n < 32; i++) {
                short ev = 0;
                if (rbits & (1L << i)) ev |= LX_POLLIN;
                if (wbits & (1L << i)) ev |= LX_POLLOUT;
                if (!ev) continue;
                kf[n].fd = (int)i;
                kf[n].events = ev;
                kf[n].revents = 0;
                n++;
            }
            if (a4 != 0) {
                long sec, nsec;
                if (!lx_range_ok(a4, 16)) return -LX_EFAULT;
                sec = ((long *)a4)[0];
                nsec = ((long *)a4)[1];
                if (sec < 0 || nsec < 0 || nsec >= 1000000000ll)
                    return -LX_EINVAL;
                to = sec * 1000000000ll + nsec;
            }
            {
                long ready = 0;
                unsigned k;
                for (k = 0; k < n; k++) {
                    kf[k].revents =
                        lx_poll_one(caller, kf[k].fd, kf[k].events);
                    if (kf[k].revents) ready++;
                }
                if (ready == 0 && to != 0) {
                    if (to > 0) lx_do_nanosleep(0, to > 1000000 ? 1000000 : to);
                    for (k = 0; k < n; k++) {
                        kf[k].revents =
                            lx_poll_one(caller, kf[k].fd, kf[k].events);
                        if (kf[k].revents) ready++;
                    }
                }
                /* Write back ready fd_sets (bits for ready fds only). */
                if (a1 != 0) {
                    long m = 0;
                    for (k = 0; k < n; k++)
                        if (kf[k].revents & LX_POLLIN)
                            m |= 1L << kf[k].fd;
                    *(long *)a1 = m;
                }
                if (a2 != 0) {
                    long m = 0;
                    for (k = 0; k < n; k++)
                        if (kf[k].revents & LX_POLLOUT)
                            m |= 1L << kf[k].fd;
                    *(long *)a2 = m;
                }
                return ready;
            }
        }
    }
    case LX_SYS_nanosleep: {
        long sec, nsec;
        if (!lx_range_ok(a0, 16)) return -LX_EFAULT;
        sec = ((long *)a0)[0];
        nsec = ((long *)a0)[1];
        return lx_do_nanosleep(sec, nsec);
    }
    case LX_SYS_clock_nanosleep: {
        long sec, nsec;
        if (a0 != LX_CLOCK_REALTIME && a0 != LX_CLOCK_MONOTONIC)
            return -LX_EINVAL;
        if (a1 & ~1u) return -LX_EINVAL; /* only TIMER_ABSTIME bit */
        if (!lx_range_ok(a2, 16)) return -LX_EFAULT;
        sec = ((long *)a2)[0];
        nsec = ((long *)a2)[1];
        if (sec < 0 || nsec < 0 || nsec >= 1000000000ll) return -LX_EINVAL;
        if (a1 & 1u) {
            /* Absolute: sleep until req (relative = req - now). */
            int64_t target = sec * 1000000000ll + nsec;
            int64_t rel = target - lx_now_ns();
            if (rel <= 0) return 0;
            return lx_do_nanosleep(rel / 1000000000ll,
                                   rel % 1000000000ll);
        }
        return lx_do_nanosleep(sec, nsec);
    }
    case LX_SYS_futex:
        return lx_do_futex(a0, (int)a1, (int)a2);
    case LX_SYS_kill:
        return lx_do_kill(caller_raw, (long)a0, (unsigned)a1);
    case LX_SYS_tgkill:
        return lx_do_kill(caller_raw, (long)a2, (unsigned)a1);
    case LX_SYS_rt_sigpending: {
        uint32_t id = caller_raw == TCB_NONE ? LX_VFS_SHELL_CLIENT
                                             : caller_raw;
        if (a0 == 0) return 0;
        if (!lx_range_ok(a0, sizeof(unsigned long))) return -LX_EFAULT;
        *(unsigned long *)a0 =
            id < 128 ? lx_sigpend[id] : 0;
        return 0;
    }
    case LX_SYS_rt_sigtimedwait: {
        /* Take one pending signal for this thread: a0 = &sigset mask
         * (0 = any), returns the signal number and clears it. */
        uint32_t id = caller_raw == TCB_NONE ? LX_VFS_SHELL_CLIENT
                                             : caller_raw;
        unsigned long mask = ~0ul;
        int sig;
        if (id >= 128) return -LX_EINVAL;
        if (a0 != 0) {
            if (!lx_range_ok(a0, sizeof(unsigned long)))
                return -LX_EFAULT;
            mask = *(unsigned long *)a0;
        }
        for (sig = 1; sig < 32; sig++) {
            if ((mask & (1ul << (sig - 1))) &&
                (lx_sigpend[id] & (1u << sig))) {
                lx_sigpend[id] &= ~(1u << sig);
                return sig;
            }
        }
        return -LX_EAGAIN;
    }
    case LX_SYS_socket:
        return lx_do_socket(caller, (int)a0, (int)a1, (int)a2);
    case LX_SYS_socketpair: {
        /* (domain, type, proto, sv[2]): connected pair via two fds. */
        int s0, s1, f0, f1;
        int type = (int)a1;
        unsigned nbce = (unsigned)type & (LX_SOCK_NONBLOCK | LX_SOCK_CLOEXEC);
        if (!lx_range_ok(a3, 2 * sizeof(int))) return -LX_EFAULT;
        type &= ~(LX_SOCK_NONBLOCK | LX_SOCK_CLOEXEC);
        if ((int)a0 != LX_AF_UNIX && (int)a0 != LX_AF_INET)
            return -LX_EAFNOSUPPORT;
        if (type != LX_SOCK_STREAM && type != LX_SOCK_DGRAM)
            return -LX_ESOCKTNOSUPPORT;
        s0 = lx_sock_alloc();
        s1 = lx_sock_alloc();
        if (s0 < 0 || s1 < 0) {
            if (s0 >= 0) lx_socks[s0].valid = false;
            if (s1 >= 0) lx_socks[s1].valid = false;
            return -LX_ENOMEM;
        }
        lx_socks[s0].type = lx_socks[s1].type = type;
        lx_socks[s0].owner = lx_socks[s1].owner = caller;
        lx_socks[s0].state = lx_socks[s1].state = 3;
        lx_socks[s0].peer = s1;
        lx_socks[s1].peer = s0;
        lx_socks[s0].nrd_ref = lx_socks[s0].nwr_ref = 1;
        lx_socks[s1].nrd_ref = lx_socks[s1].nwr_ref = 1;
        f0 = (int)lx_fd_alloc(caller, LX_FD_SOCK, s0, 0, nbce);
        if (f0 < 0) {
            lx_socks[s0].valid = lx_socks[s1].valid = false;
            return f0;
        }
        f1 = (int)lx_fd_alloc(caller, LX_FD_SOCK, s1, 0, nbce);
        if (f1 < 0) {
            lx_do_close(caller, f0);
            lx_socks[s1].valid = false;
            return f1;
        }
        ((int *)a3)[0] = f0;
        ((int *)a3)[1] = f1;
        return 0;
    }
    case LX_SYS_bind:
        return lx_do_bind(caller, (long)a0, a1, (size_t)a2);
    case LX_SYS_listen:
        return lx_do_listen(caller, (long)a0, (int)a1);
    case LX_SYS_accept:
    case LX_SYS_accept4:
        return lx_do_accept(caller, (long)a0, a1, a2);
    case LX_SYS_connect:
        return lx_do_connect(caller, (long)a0, a1, (size_t)a2);
    case LX_SYS_getsockname:
        return lx_do_sockname(caller, (long)a0, a1, a2, false);
    case LX_SYS_getpeername:
        return lx_do_sockname(caller, (long)a0, a1, a2, true);
    case LX_SYS_sendto:
        return lx_do_sendto(caller, (long)a0, a1, (size_t)a2,
                            (unsigned)a3, a4, (size_t)a5);
    case LX_SYS_recvfrom:
        return lx_do_recvfrom(caller, (long)a0, a1, (size_t)a2,
                              (unsigned)a3, a4, a5);
    case LX_SYS_setsockopt:
        return lx_do_setsockopt(caller, (long)a0, (int)a1, (int)a2, a3,
                                (size_t)a4);
    case LX_SYS_getsockopt:
        return lx_do_getsockopt(caller, (long)a0, (int)a1, (int)a2, a3,
                                a4);
    case LX_SYS_shutdown: {
        lx_fd_t *e = lx_fd_lookup(caller, (long)a0);
        if (!e || e->kind != LX_FD_SOCK) return -LX_ENOTSOCK;
        if ((int)a1 < 0 || (int)a1 > 2) return -LX_EINVAL;
        /* Single-hart: shutdown severs the peer link (reads see EOF). */
        {
            lx_sock_t *s = &lx_socks[e->vfd];
            if (s->peer >= 0 && lx_socks[s->peer].valid &&
                ((int)a1 == LX_SHUT_WR || (int)a1 == LX_SHUT_RDWR))
                lx_socks[s->peer].peer = -1;
            if ((int)a1 == LX_SHUT_RD || (int)a1 == LX_SHUT_RDWR)
                s->rx_nrd = s->rx_nwr;
            return 0;
        }
    }
    case LX_SYS_wait4:
        return lx_do_wait4(caller, (long)a0, a1, (unsigned)a2);
    case LX_SYS_getrandom:
        return lx_do_getrandom(a0, (size_t)a1, (unsigned)a2);
    case LX_SYS_utimensat:
        return lx_do_utimensat(caller, (long)a0, a1, a2,
                               (unsigned)a3);
    case LX_SYS_statx:
        return lx_do_statx(caller, (long)a0, a1, (unsigned)a2,
                           (unsigned)a3, a4);
    case LX_SYS_lseek:
        return lx_do_lseek(caller, (long)a0, (int64_t)a1, (int)a2);
    case LX_SYS_fstat:
        return lx_do_fstat(caller, (long)a0, a1);
    case LX_SYS_newfstatat:
        return lx_do_fstatat(caller, (long)a0, a1, a2, (int)a3);
    case LX_SYS_unlinkat: {
        /* (dirfd, path, flags). Only AT_FDCWD. */
        char path[256];
        long rc;
        int slot;
        bool rmdir;
        if ((long)a0 != LX_AT_FDCWD) return -LX_EBADF;
        if ((a2 & ~LX_AT_REMOVEDIR) != 0) return -LX_EINVAL;
        rmdir = (a2 & LX_AT_REMOVEDIR) != 0;
        rc = lx_copy_path(a1, path, sizeof(path));
        if (rc != 0) return rc;
        lx_basename(path);
        if (path[0] == '\0' || !lx_name_ok(path)) return -LX_ENOENT;
        rc = vfs_unlink_at(caller, path, rmdir);
        if (rc == -2) return -LX_ENOTDIR;
        if (rc == -3) return -LX_EISDIR;
        if (rc != 0) return -LX_ENOENT;
        slot = lx_slot_for_name(path);
        if (slot >= 0) {
            lx_file_taken[slot] = false;
            lx_file_names[slot][0] = '\0';
        }
        return 0;
    }
    case LX_SYS_faccessat: {
        /* (dirfd, path, mode, flags). Existence + RW granted to all
         * files here (owner model); X denied (no exec-permission bit). */
        char path[256];
        long rc;
        uint32_t size = 0, used = 0;
        (void)a3;
        if ((long)a0 != LX_AT_FDCWD) return -LX_EBADF;
        if ((a2 & ~(LX_R_OK | LX_W_OK | LX_X_OK)) != 0) return -LX_EINVAL;
        rc = lx_copy_path(a1, path, sizeof(path));
        if (rc != 0) return rc;
        lx_basename(path);
        if (path[0] == '\0' || !lx_name_ok(path)) return -LX_ENOENT;
        if (vfs_stat(caller, path, &size, &used) != 0) return -LX_ENOENT;
        if (a2 & LX_X_OK) return -LX_EACCES;
        return 0;
    }
    case LX_SYS_getcwd: {
        /* Flat single root. */
        if (!lx_range_ok(a0, (size_t)a1)) return -LX_EFAULT;
        if (a1 < 2) return -LX_ERANGE;
        ((char *)a0)[0] = '/';
        ((char *)a0)[1] = '\0';
        return 1;
    }
    case LX_SYS_chdir: {
        char path[256];
        long rc = lx_copy_path(a0, path, sizeof(path));
        uint8_t kind = 0;
        if (rc != 0) return rc;
        lx_basename(path);
        if ((path[0] == '/' && path[1] == '\0') ||
            (path[0] == '.' && path[1] == '\0') ||
            (path[0] == '\0'))
            return 0;
        if (!lx_name_ok(path)) return -LX_ENOENT;
        if (vfs_stat_full(caller, path, NULL, NULL, &kind, NULL, NULL) != 0)
            return -LX_ENOENT;
        return kind == 1 ? 0 : -LX_ENOTDIR;
    }
    case LX_SYS_fchdir: {
        lx_fd_t *e = lx_fd_lookup(caller, (long)a0);
        if (!e || e->kind != LX_FD_VFS) return -LX_EBADF;
        return 0; /* flat single root: any open fd keeps us at / */
    }
    case LX_SYS_ftruncate: {
        lx_fd_t *e = lx_fd_lookup(caller, (long)a0);
        int vfd;
        int64_t len = (int64_t)a1;
        if ((long)a0 >= 0 && (long)a0 < 3) return -LX_EINVAL;
        if (!e || e->kind != LX_FD_VFS) return -LX_EBADF;
        vfd = e->vfd;
        if (len < 0) return -LX_EINVAL;
        if ((uint64_t)len > LX_VFS_MAX_FILE_SIZE) return -LX_EINVAL;
        /* Grow-by-truncate is refused (no zero-fill obligation without a
         * write); shrink only. Linux apps in v1 extend via writes. */
        {
            uint32_t cur = 0, ign = 0, end = 0;
            if (vfs_seek(caller, vfd, 0, 2, &end) != 0) return -LX_EBADF;
            if (vfs_seek(caller, vfd, 0, 1, &cur) != 0) return -LX_EBADF;
            if ((uint64_t)len > end) return -LX_EINVAL;
            if (vfs_truncate_fd(caller, vfd, (uint32_t)len) != 0)
                return -LX_EIO;
            vfs_seek(caller, vfd, (int64_t)cur, 0, &ign);
            return 0;
        }
    }
    case LX_SYS_brk:
        return lx_do_brk(a0);
    case LX_SYS_mmap:
        /* (addr, len, prot, flags, fd, off). fd/off ignored for anon. */
        return lx_do_mmap(a0, (size_t)a1, (unsigned)a2, (unsigned)a3);
    case LX_SYS_munmap:
        /* No reclaim (bump arena); validate + accept. */
        if (a1 == 0) return -LX_EINVAL;
        if (a0 < lx_heap_base() || a0 + a1 < a0 ||
            a0 + a1 > lx_heap_end())
            return -LX_EINVAL;
        return 0;
    case LX_SYS_mprotect:
        return lx_do_mprotect(a0, (size_t)a1);
    case LX_SYS_madvise:
        if (a0 < lx_heap_base() || a0 + a1 < a0 ||
            a0 + a1 > lx_heap_end())
            return -LX_EINVAL;
        return 0;
    case LX_SYS_exit:
    case LX_SYS_exit_group:
        /* Parking needs the trap frame (target) - handled by the frame
         * wrapper. Host-sim: suspend the TCB directly. */
        if (caller_raw != TCB_NONE && caller_raw < MAX_TCBS) {
            g_tcbs.threads[caller_raw].state = TCB_INACTIVE;
            linux_last_exit_code = (int)(a0 & 0xff);
            linux_exit_count++;
            lx_child_exit(caller_raw, (int)(a0 & 0xff));
            lx_close_all(caller);
            if (caller_raw < 128) lx_sigpend[caller_raw] = 0;
        }
        return (long)(a0 & 0xff);
    case LX_SYS_set_tid_address:
        if (!lx_range_ok(a0, sizeof(long))) return -LX_EFAULT;
        return (long)(caller_raw == TCB_NONE ? 0 : caller_raw);
    case LX_SYS_getpid:
    case LX_SYS_gettid:
        return (long)(caller_raw == TCB_NONE ? 0 : caller_raw);
    case LX_SYS_getppid:
        if (caller_raw != TCB_NONE && caller_raw < 128)
            return (long)lx_parent_of[caller_raw];
        return 0;
    case LX_SYS_getuid:
    case LX_SYS_geteuid:
    case LX_SYS_getgid:
    case LX_SYS_getegid:
        return 0; /* single-user microkernel */
    case LX_SYS_uname: {
        lx_utsname_t u;
        if (!lx_range_ok(a0, sizeof(u))) return -LX_EFAULT;
        memset(&u, 0, sizeof(u));
        strncpy(u.sysname, "MoonlightOS", sizeof(u.sysname) - 1);
        strncpy(u.nodename, "moonlight", sizeof(u.nodename) - 1);
        strncpy(u.release, "0.1-linux-compat", sizeof(u.release) - 1);
        strncpy(u.version, "#moonlight", sizeof(u.version) - 1);
        strncpy(u.machine, "riscv64", sizeof(u.machine) - 1);
        memcpy((void *)a0, &u, sizeof(u));
        return 0;
    }
    case LX_SYS_clock_gettime: {
        lx_timespec_t ts;
        int64_t ns = lx_now_ns();
        if (a0 != LX_CLOCK_REALTIME && a0 != LX_CLOCK_MONOTONIC &&
            a0 != LX_CLOCK_PROCESS_CPUTIME_ID)
            return -LX_EINVAL;
        if (!lx_range_ok(a1, sizeof(ts))) return -LX_EFAULT;
        ts.tv_sec = ns / 1000000000ll;
        ts.tv_nsec = ns % 1000000000ll;
        memcpy((void *)a1, &ts, sizeof(ts));
        return 0;
    }
    case LX_SYS_clock_getres: {
        lx_timespec_t ts;
        if (a0 != LX_CLOCK_REALTIME && a0 != LX_CLOCK_MONOTONIC &&
            a0 != LX_CLOCK_PROCESS_CPUTIME_ID)
            return -LX_EINVAL;
        if (a1 == 0) return 0;
        if (!lx_range_ok(a1, sizeof(ts))) return -LX_EFAULT;
        ts.tv_sec = 0;
        ts.tv_nsec = 100; /* 10MHz tick */
        memcpy((void *)a1, &ts, sizeof(ts));
        return 0;
    }
    case LX_SYS_gettimeofday: {
        lx_timeval_t tv;
        int64_t ns = lx_now_ns();
        if (a0 == 0) return 0;
        if (a1 != 0) return -LX_EINVAL; /* obsolete tz arg must be NULL */
        if (!lx_range_ok(a0, sizeof(tv))) return -LX_EFAULT;
        tv.tv_sec = ns / 1000000000ll;
        tv.tv_usec = (ns % 1000000000ll) / 1000ll;
        memcpy((void *)a0, &tv, sizeof(tv));
        return 0;
    }
    case LX_SYS_sched_yield:
        return 0; /* frame wrapper parks + reschedules on target */
    default:
        (void)a4;
        (void)a5;
        return -LX_ENOSYS;
    }
}

/* Trap-frame wrapper: exit/yield/fork/clone/exec recycle the frame. */
static uintptr_t lx_clear_tid[128];
static int lx_exit_sig[128];
static uint32_t lx_vfork_parent[128];
static bool lx_vfork_init = false;

static void lx_fork_fds(uint32_t parent, uint32_t child) {
    int i;
    if (parent >= LX_VFS_MAX_CLIENTS || child >= LX_VFS_MAX_CLIENTS)
        return;
    for (i = 0; i < LX_NFDS; i++) {
        lx_fd_t *s = &lx_fds[parent][i];
        lx_fd_t *d = &lx_fds[child][i];
        if (!s->valid) continue;
        *d = *s;
        if (s->kind == LX_FD_VFS && s->vfd >= 0 &&
            s->vfd < LX_VFS_FDS_PER_CLIENT)
            lx_fd_refs[child][s->vfd]++;
        else if (s->kind == LX_FD_PIPE) {
            if (s->end == 0) lx_pipe_rdref[s->vfd]++;
            else lx_pipe_wrref[s->vfd]++;
        } else if (s->kind == LX_FD_SOCK) {
            if (s->end == 0) lx_socks[s->vfd].nrd_ref++;
            else lx_socks[s->vfd].nwr_ref++;
        }
    }
}

/* Spawn a child that resumes past the trapping ecall with a0=0 (the
 * parent returns the child id through the live frame). stack==0 means
 * fork-style: copy a 16KB stack window and relocate sp/fp (nommu
 * semantics, documented in LINUX.md); nonzero stack is clone-style
 * (pthread_create provides its own stack, no copy). */
#define LX_FORK_STACK_WIN 16384u
static long lx_spawn(trap_frame_t *frame, uint32_t cur, unsigned long flags,
                     uintptr_t stack, uintptr_t ptid, uintptr_t tls,
                     uintptr_t ctid) {
    tcb_t *parent, *child;
    sched_context_t *psc;
    process_create_args_t args;
    uint32_t id;
    kerror_t e;
    uintptr_t psp, child_top, delta;
    if (cur == TCB_NONE || cur >= MAX_TCBS) return -LX_EINVAL;
    if (!lx_vfork_init) {
        int k;
        for (k = 0; k < 128; k++) lx_vfork_parent[k] = 0xFFFFFFFFu;
        lx_vfork_init = true;
    }
    parent = &g_tcbs.threads[cur];
    if (parent->sched_context >= MAX_SCHED_CONTEXTS) return -LX_EINVAL;
    psc = &g_sched.contexts[parent->sched_context];
    memset(&args, 0, sizeof(args));
    args.partition_id = parent->time_partition;
    args.budget_us = psc->budget_us;
    args.period_us = psc->period_us ? psc->period_us : psc->budget_us;
    if (args.budget_us == 0) {
        args.budget_us = 1000;
        args.period_us = 5000;
    }
    args.priority = parent->priority;
    args.pc = frame->pc;
    args.stack_size = LX_FORK_STACK_WIN;
    args.name = "lx-fork";
    e = process_create(&g_tcbs, &g_alloc, &g_sched, &g_mdb, &args, &id);
    if (e != ERR_OK) return -LX_EAGAIN;
    if (id >= 128) return -LX_EAGAIN;
    child = &g_tcbs.threads[id];
    child_top = child->sp;
    psp = frame->sp;
    if (stack != 0) {
        if (!lx_range_ok(stack, 16)) {
            process_destroy(&g_tcbs, &g_sched, &g_mdb, id);
            return -LX_EFAULT;
        }
        child->sp = stack;
        child->saved = *frame;
    } else {
        if (!lx_range_ok(psp, 1) ||
            child_top < LX_FORK_STACK_WIN + 4096) {
            process_destroy(&g_tcbs, &g_sched, &g_mdb, id);
            return -LX_EFAULT;
        }
        memcpy((void *)(child_top - LX_FORK_STACK_WIN), (const void *)psp,
               LX_FORK_STACK_WIN);
        child->sp = child_top - LX_FORK_STACK_WIN;
        child->saved = *frame;
        delta = child->sp - psp;
        child->saved.sp += delta;
        if (child->saved.s0 >= psp &&
            child->saved.s0 < psp + LX_FORK_STACK_WIN)
            child->saved.s0 += delta;
    }
    child->saved.a0 = 0;
    if (tls != 0) child->saved.tp = tls;
    child->has_frame = 1;
    if (ctid != 0 && (flags & LX_CLONE_CHILD_SETTID)) {
        if (!lx_range_ok(ctid, sizeof(uint32_t))) {
            process_destroy(&g_tcbs, &g_sched, &g_mdb, id);
            return -LX_EFAULT;
        }
        *(uint32_t *)ctid = id;
    }
    if (ptid != 0 && (flags & LX_CLONE_PARENT_SETTID)) {
        if (!lx_range_ok(ptid, sizeof(uint32_t))) {
            process_destroy(&g_tcbs, &g_sched, &g_mdb, id);
            return -LX_EFAULT;
        }
        *(uint32_t *)ptid = id;
    }
    lx_clear_tid[id] = (flags & LX_CLONE_CHILD_CLEARTID) ? ctid : 0;
    lx_exit_sig[id] = (int)(flags & LX_CSIGNAL);
    lx_parent_of[id] = cur;
    lx_child_add(cur, id);
    lx_fork_fds(lx_caller(cur), id);
    if (flags & LX_CLONE_VFORK) {
        tcb_suspend(parent);
        lx_vfork_parent[id] = cur;
    } else {
        lx_vfork_parent[id] = 0xFFFFFFFFu;
    }
    tcb_resume(child);
    return (long)id;
}

/* execve: load a user ELF (0x81000000 region) from the VFS into the
 * CALLER thread (fresh heap, cloexec fds closed). Never returns on
 * success (the live frame is rewritten to the entry point). */
#define LX_EXEC_MAX (64u * 1024u)
static uint8_t lx_exec_img[LX_EXEC_MAX];
static long lx_exec(trap_frame_t *frame, uint32_t cur, uintptr_t upath) {
    char path[256];
    long rc, fd;
    uint32_t caller = lx_caller(cur);
    int vfd;
    size_t total = 0;
    const elf64_hdr_t *h;
    const elf64_phdr_t *ph;
    int i;
    if (cur == TCB_NONE || cur >= MAX_TCBS) return -LX_ENOSYS;
    if (!lx_vfork_init) {
        int k;
        for (k = 0; k < 128; k++) lx_vfork_parent[k] = 0xFFFFFFFFu;
        lx_vfork_init = true;
    }
    rc = lx_path_arg(upath, path);
    if (rc != 0) return rc;
    if (path[0] == '\0' || !lx_name_ok(path)) return -LX_ENOENT;
    fd = lx_do_open(caller, upath, LX_O_RDONLY);
    if (fd < 0) return fd;
    vfd = lx_to_vfd(caller, fd);
    if (vfd < 0) {
        lx_do_close(caller, fd);
        return -LX_EBADF;
    }
    for (;;) {
        int r;
        size_t want = LX_EXEC_MAX - total;
        uint8_t io[1024];
        size_t chunk = want > sizeof(io) ? sizeof(io) : want;
        if (chunk == 0) break;
        r = vfs_read(caller, vfd, io, chunk);
        if (r <= 0) break;
        memcpy(lx_exec_img + total, io, (size_t)r);
        total += (size_t)r;
    }
    lx_do_close(caller, fd);
    if (total < sizeof(elf64_hdr_t)) return -LX_ENOEXEC;
    h = (const elf64_hdr_t *)lx_exec_img;
    if (h->magic != ELF_MAGIC || h->cls != ELFCLASS64 ||
        h->type != ET_EXEC || h->machine != 243)
        return -LX_ENOEXEC;
    if (h->phoff + h->phnum * sizeof(elf64_phdr_t) > total)
        return -LX_ENOEXEC;
    ph = (const elf64_phdr_t *)(lx_exec_img + h->phoff);
    for (i = 0; i < h->phnum; i++) {
        uintptr_t dst;
        if (ph[i].type != PT_LOAD) continue;
        dst = (uintptr_t)ph[i].paddr;
        if (dst < 0x81000000u || ph[i].memsz > 16u * 1024u * 1024u ||
            dst + ph[i].memsz < dst ||
            dst + ph[i].memsz > 0x83000000u)
            return -LX_ENOEXEC;
        if (ph[i].offset + ph[i].filesz > total) return -LX_ENOEXEC;
        memmove((void *)dst, lx_exec_img + ph[i].offset, ph[i].filesz);
        if (ph[i].memsz > ph[i].filesz)
            memset((void *)(dst + ph[i].filesz), 0,
                   ph[i].memsz - ph[i].filesz);
    }
    lx_heap_top = lx_heap_base();
    lx_close_cloexec(caller);
    if (cur < 128) lx_sigpend[cur] = 0;
    {
        tcb_t *t = &g_tcbs.threads[cur];
        size_t n = strlen(path);
        if (n > 15) n = 15;
        memcpy(t->name, path, n);
        t->name[n] = '\0';
    }
    if (cur < 128 && lx_vfork_parent[cur] != 0xFFFFFFFFu) {
        uint32_t p = lx_vfork_parent[cur];
        lx_vfork_parent[cur] = 0xFFFFFFFFu;
        if (p < MAX_TCBS) tcb_resume(&g_tcbs.threads[p]);
    }
    frame->pc = (uintptr_t)h->entry;
    frame->a0 = 0;
    frame->a1 = 0;
    frame->a2 = 0;
    return 0;
}

int linux_syscall_frame(trap_frame_t *frame, uint32_t cur, long *result_out) {
    long nr = (long)frame->a7;
    long rc;
    if ((nr == LX_SYS_exit || nr == LX_SYS_exit_group) && cur != TCB_NONE &&
        cur < MAX_TCBS) {
        uint32_t caller = lx_caller(cur);
        int status = (int)(frame->a0 & 0xff);
        g_tcbs.threads[cur].state = TCB_INACTIVE;
        linux_last_exit_code = status;
        linux_exit_count++;
        lx_child_exit(cur, status);
        lx_close_all(caller);
        if (cur < 128) {
            /* Clear the CLONE_CHILD_CLEARTID word + release a vfork
             * parent; queue the exit signal to the parent. */
            if (lx_clear_tid[cur] != 0 &&
                lx_range_ok(lx_clear_tid[cur], sizeof(uint32_t)))
                *(uint32_t *)lx_clear_tid[cur] = 0;
            lx_clear_tid[cur] = 0;
            if (lx_vfork_parent[cur] != 0xFFFFFFFFu) {
                uint32_t p = lx_vfork_parent[cur];
                lx_vfork_parent[cur] = 0xFFFFFFFFu;
                if (p < MAX_TCBS) tcb_resume(&g_tcbs.threads[p]);
            }
            if (lx_exit_sig[cur] > 0 && lx_exit_sig[cur] < 32 &&
                lx_parent_of[cur] < 128)
                lx_sigpend[lx_parent_of[cur]] |=
                    1u << (unsigned)lx_exit_sig[cur];
            lx_sigpend[cur] = 0;
        }
        sched_coop_switch(frame, cur);
        *result_out = (long)(frame->a0 & 0xff);
        return 0; /* frame recycled: caller must not touch it */
    }
    if (nr == LX_SYS_sched_yield && cur != TCB_NONE && cur < MAX_TCBS) {
        sched_coop_switch(frame, cur);
        *result_out = 0;
        return 0;
    }
    if (nr == LX_SYS_clone && cur != TCB_NONE && cur < MAX_TCBS) {
        /* clone(flags, stack, parent_tid, tls, child_tid) */
        rc = lx_spawn(frame, cur, (unsigned long)frame->a0, frame->a1,
                      frame->a2, frame->a3, frame->a4);
        *result_out = rc;
        return 1;
    }
    if (nr == LX_SYS_execve && cur != TCB_NONE && cur < MAX_TCBS) {
        rc = lx_exec(frame, cur, frame->a0);
        *result_out = rc;
        return 1;
    }
    rc = linux_syscall_nr(nr, frame->a0, frame->a1, frame->a2, frame->a3,
                          frame->a4, frame->a5, cur);
    *result_out = rc;
    return 1;
}
