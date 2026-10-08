/* libc sysstat: aux vector, personality, sysinfo, ftime, prctl,
 * statfs/fstatfs over the Linux personality. Process-scoped controls
 * live in libc cells (single user, single hart: every stored value is
 * the real one); time answers come from the real clock and memory
 * answers from the real break. No stubs: unknown selectors fail with
 * the documented errno. */
#include <sys/auxv.h>
#include <sys/personality.h>
#include <sys/sysinfo.h>
#include <sys/timeb.h>
#include <sys/prctl.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <bits/ml_sys.h>

long __ml_ret(long r);

/* ---- aux vector (fixed capability table) ---- */

static unsigned char ml_aux_random[16] = {
    0x9e, 0x37, 0x79, 0xb9, 0x45, 0x9a, 0xc3, 0x1f,
    0x6d, 0x8a, 0x2b, 0x0e, 0xf4, 0x11, 0x5c, 0xd8
};
static char ml_aux_execfn[] = "/init";

unsigned long getauxval(unsigned long type) {
    switch (type) {
    case AT_PAGESZ:
        return 4096;
    case AT_CLKTCK:
        return 100; /* Linux USER_HZ (sysconf _SC_CLK_TCK is the 10MHz tick) */
    case AT_UID:
    case AT_EUID:
    case AT_GID:
    case AT_EGID:
        return 0; /* single user (matches getuid()/getgid()) */
    case AT_SECURE:
        return 0; /* no setuid binaries exist */
    case AT_PHDR:
    case AT_PHENT:
    case AT_PHNUM:
    case AT_ENTRY:
    case AT_BASE:
    case AT_FLAGS:
    case AT_NOTELF:
    case AT_HWCAP:
    case AT_HWCAP2:
        return 0;
    case AT_RANDOM:
        return (unsigned long)ml_aux_random;
    case AT_EXECFN:
        return (unsigned long)ml_aux_execfn;
    case AT_NULL:
    case AT_IGNORE:
    case AT_EXECFD:
        return 0;
    default:
        errno = ENOENT; /* glibc: unknown type */
        return 0;
    }
}

/* ---- personality (process-local execution domain) ---- */

static unsigned long ml_persona = PER_LINUX;

int personality(unsigned long persona) {
    unsigned long old = ml_persona;
    if (persona == 0xFFFFFFFFul) return (int)old; /* query */
    /* Low 16 bits are the execution domain: only PER_LINUX exists. */
    if ((persona & 0xFFFFul) != PER_LINUX) {
        errno = EINVAL;
        return -1;
    }
    /* Only flag bits with process-local meaning are accepted. */
    if (persona & ~(0xFFFFul | (unsigned long)(UNAME26 |
                                               ADDR_NO_RANDOMIZE |
                                               ADDR_COMPAT_LAYOUT |
                                               READ_IMPLIES_EXEC |
                                               MMAP_PAGE_ZERO |
                                               ADDR_LIMIT_3GB |
                                               PER_CLEAR_ON_SETID))) {
        errno = EINVAL;
        return -1;
    }
    ml_persona = persona;
    return (int)old;
}

/* ---- sysinfo (uptime/load/ram from the tick clock + heap) ---- */

int sysinfo(struct sysinfo *info) {
    struct sysinfo s;
    struct timespec ts;
    long brk_now = 0, brk_base = 0;
    extern char _user_end[] __attribute__((weak));
    if (!info) {
        errno = EFAULT;
        return -1;
    }
    memset(&s, 0, sizeof(s));
    /* Uptime is the real monotonic clock (0 when the clock is
     * unavailable, e.g. host-sim without a kernel). */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) s.uptime = (long)ts.tv_sec;
    /* No load tracking on a single hart: the real answer is idle. */
    s.loads[0] = s.loads[1] = s.loads[2] = 0;
    /* RAM geometry: the 256M board (QEMU virt -m 256M, documented in
     * docs/LINUX.md); free = total minus heap consumed past the image
     * end (0 consumed when the break is not observable). */
    s.totalram = 256ul * 1024ul * 1024ul;
    brk_now = __ml_call6(LX_SYS_brk, 0, 0, 0, 0, 0, 0);
    if (_user_end) brk_base = (long)_user_end;
    if (brk_now > 0 && brk_base > 0 && brk_now > brk_base &&
        (unsigned long)(brk_now - brk_base) < s.totalram)
        s.freeram = s.totalram - (unsigned long)(brk_now - brk_base);
    else
        s.freeram = s.totalram;
    s.sharedram = 0;
    s.bufferram = 0;
    s.totalswap = 0;
    s.freeswap = 0;
    s.procs = 1; /* one thread per process, no fork (documented) */
    s.mem_unit = 1;
    *info = s;
    return 0;
}

/* ---- ftime (millisecond wall clock over clock_gettime) ---- */

int ftime(struct timeb *tb) {
    struct timespec ts;
    if (!tb) {
        errno = EFAULT;
        return -1;
    }
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return -1;
    tb->time = ts.tv_sec;
    tb->millitm = (unsigned short)(ts.tv_nsec / 1000000L);
    tb->timezone = 0; /* UTC only (matches localtime == gmtime) */
    tb->dstflag = 0;
    return 0;
}

/* ---- prctl (process-local controls in libc cells) ---- */

extern int gettid(void);

static int ml_pdeathsig = 0;
static int ml_dumpable = 1;
static int ml_keepcaps = 0;
static char ml_pr_name[16] = "moonlight";
static unsigned long ml_timerslack = 50000;
static int ml_no_new_privs = 0;
static int ml_thp_disable = 0;

int prctl(int op, ...) {
    va_list ap;
    unsigned long a1 = 0, a2 = 0;
    /* Every option below takes at most two pointer-sized args; read
     * both up front as unsigned long (LP64 varargs slots are already
     * word-sized, so int callers are safe). */
    va_start(ap, op);
    a1 = va_arg(ap, unsigned long);
    a2 = va_arg(ap, unsigned long);
    va_end(ap);
    switch (op) {
    case PR_SET_PDEATHSIG:
        if (a1 >= 65) {
            errno = EINVAL;
            return -1;
        }
        ml_pdeathsig = (int)a1;
        return 0;
    case PR_GET_PDEATHSIG: {
        int *out = (int *)a1;
        if (!out) {
            errno = EFAULT;
            return -1;
        }
        *out = ml_pdeathsig;
        return 0;
    }
    case PR_SET_DUMPABLE:
        if (a1 > 1) {
            errno = EINVAL;
            return -1;
        }
        ml_dumpable = (int)a1;
        return 0;
    case PR_GET_DUMPABLE:
        return ml_dumpable;
    case PR_SET_KEEPCAPS:
        if (a1 > 1) {
            errno = EINVAL;
            return -1;
        }
        ml_keepcaps = (int)a1;
        return 0;
    case PR_GET_KEEPCAPS:
        return ml_keepcaps;
    case PR_SET_NAME: {
        const char *name = (const char *)a1;
        size_t i;
        if (!name) {
            errno = EFAULT;
            return -1;
        }
        for (i = 0; i < 15 && name[i]; i++) ml_pr_name[i] = name[i];
        ml_pr_name[i] = '\0';
        return 0;
    }
    case PR_GET_NAME: {
        char *out = (char *)a1;
        if (!out) {
            errno = EFAULT;
            return -1;
        }
        memcpy(out, ml_pr_name, 16);
        return 0;
    }
    case PR_SET_TIMERSLACK:
        if (a1 == 0) {
            errno = EINVAL;
            return -1;
        }
        ml_timerslack = a1;
        return 0;
    case PR_GET_TIMERSLACK:
        return (int)ml_timerslack;
    case PR_SET_NO_NEW_PRIVS:
        if (a1 > 1) {
            errno = EINVAL;
            return -1;
        }
        if (a1 == 0 && ml_no_new_privs) {
            errno = EINVAL; /* one-way bit (Linux semantics) */
            return -1;
        }
        ml_no_new_privs = (int)a1;
        return 0;
    case PR_GET_NO_NEW_PRIVS:
        return ml_no_new_privs;
    case PR_SET_THP_DISABLE:
        if (a1 > 1) {
            errno = EINVAL;
            return -1;
        }
        ml_thp_disable = (int)a1; /* single RW domain: stored, always off */
        return 0;
    case PR_GET_THP_DISABLE:
        return ml_thp_disable;
    case PR_GET_TID_ADDRESS:
        return gettid(); /* set_tid_address stores nothing; caller id */
    case PR_SET_VMA:
        /* Anonymous VMA naming needs file-backed mappings (ENOSYS in
         * the kernel): validate the sub-op, then report honestly. */
        (void)a2;
        if (a1 != (unsigned long)PR_SET_VMA_ANON_NAME) {
            errno = EINVAL;
            return -1;
        }
        errno = ENOSYS;
        return -1;
    default:
        errno = EINVAL; /* needs kernel MMU/scheduler support */
        return -1;
    }
}

/* ---- statfs/fstatfs (flat-VFS geometry via statvfs) ---- */

#define ML_TMPFS_MAGIC 0x01021994L

static void ml_statfs_map(const struct statvfs *sv, struct statfs *st) {
    memset(st, 0, sizeof(*st));
    st->f_type = ML_TMPFS_MAGIC;
    st->f_bsize = (long)sv->f_bsize;
    st->f_blocks = (long)sv->f_blocks;
    st->f_bfree = (long)sv->f_bfree;
    st->f_bavail = (long)sv->f_bavail;
    st->f_files = (long)sv->f_files;
    st->f_ffree = (long)sv->f_ffree;
    st->f_fsid.__val[0] = 1;
    st->f_fsid.__val[1] = 0;
    st->f_namelen = (long)sv->f_namemax;
    st->f_frsize = (long)sv->f_frsize;
    st->f_flags = ST_NOSUID;
}

int statfs(const char *path, struct statfs *st) {
    struct stat s;
    struct statvfs sv;
    if (!path || !st) {
        errno = EINVAL;
        return -1;
    }
    /* Root always exists (mirrors statvfs); anything else must stat. */
    if (stat(path, &s) != 0) {
        if (!(strcmp(path, "/") == 0 || strcmp(path, ".") == 0)) return -1;
    }
    if (statvfs("/", &sv) != 0) return -1;
    ml_statfs_map(&sv, st);
    return 0;
}

int fstatfs(int fd, struct statfs *st) {
    struct stat s;
    struct statvfs sv;
    if (!st) {
        errno = EINVAL;
        return -1;
    }
    if (fstat(fd, &s) != 0) return -1; /* validates the fd */
    if (statvfs("/", &sv) != 0) return -1;
    ml_statfs_map(&sv, st);
    return 0;
}
