/* test_batch6 - host unit tests for batch 6 (sysstat: auxv,
 * personality, sysinfo, ftime, prctl, statfs; netif: getifaddrs +
 * net/if; stropts: STREAMS compat).
 *
 * Links the REAL libc sources; the raw-syscall layer is the host stub
 * (-ENOSYS), so kernel-dependent success paths are asserted as clean
 * failures while every validation/pure path is asserted exactly.
 * Diagnostics go to real stderr via dprintf (no managed-fd module is
 * linked, so dprintf(2,...) writes the kernel console path -> host
 * ENOSYS? No: stdio's dprintf falls back to host write on fd<=2...
 * see below: we use raw host write instead, like test_batch5).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/auxv.h>
#include <sys/personality.h>
#include <sys/sysinfo.h>
#include <sys/timeb.h>
#include <sys/prctl.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <stropts.h>

/* Heap backing for stdlib.c (brk/sbrk are ours to provide on host;
 * unistd.c's pair is weak so this strong one wins). */
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

/* Test-local diagnostics: raw host write, independent of the libc under
 * test. */
static void t6_puts(const char *s) {
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
    {
        /* Fallback: best effort via libc write (target builds). */
        extern ssize_t write(int, const void *, size_t);
        write(2, s, (size_t)n);
    }
#endif
}

static void t6_fail(const char *why, int line) {
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
    t6_puts("FAIL: ");
    t6_puts(b);
}

static int failures = 0;
#define CHECK(cond, why) do { \
    if (!(cond)) { t6_fail(why, __LINE__); failures++; } \
} while (0)

int main(void) {
    t6_puts("=== test_batch6 ===\n");

    /* ---- getauxval (fully real on host) ---- */
    {
        errno = 0;
        CHECK(getauxval(AT_PAGESZ) == 4096, "aux pagesz");
        CHECK(getauxval(AT_CLKTCK) == 100, "aux clktck");
        CHECK(getauxval(AT_UID) == 0, "aux uid");
        CHECK(getauxval(AT_EUID) == 0, "aux euid");
        CHECK(getauxval(AT_GID) == 0, "aux gid");
        CHECK(getauxval(AT_EGID) == 0, "aux egid");
        CHECK(getauxval(AT_SECURE) == 0, "aux secure");
        CHECK(getauxval(AT_HWCAP) == 0, "aux hwcap");
        CHECK(getauxval(AT_RANDOM) != 0, "aux random");
        CHECK(strcmp((const char *)getauxval(AT_EXECFN), "/init") == 0,
              "aux execfn");
        CHECK(getauxval(0xFFFFul) == 0 && errno == ENOENT,
              "aux unknown ENOENT");
    }

    /* ---- personality (fully real on host) ---- */
    {
        int old;
        CHECK(personality(0xFFFFFFFFul) == PER_LINUX, "pers query");
        old = personality(ADDR_NO_RANDOMIZE);
        CHECK(old == PER_LINUX, "pers set old");
        CHECK(personality(0xFFFFFFFFul) == ADDR_NO_RANDOMIZE,
              "pers set query");
        CHECK(personality(PER_LINUX) == ADDR_NO_RANDOMIZE,
              "pers restore old");
        CHECK(personality(0xFFFFFFFFul) == PER_LINUX, "pers restored");
        errno = 0;
        CHECK(personality(0x1234) == -1 && errno == EINVAL,
              "pers bad domain");
        CHECK(personality(0x80000000ul) == -1 && errno == EINVAL,
              "pers bad flags");
    }

    /* ---- sysinfo (real geometry; uptime 0 on host-sim) ---- */
    {
        struct sysinfo si;
        memset(&si, 0xAA, sizeof(si));
        CHECK(sysinfo(&si) == 0, "sysinfo ok");
        CHECK(si.totalram == 256ul * 1024ul * 1024ul, "sysinfo total");
        CHECK(si.freeram > 0 && si.freeram <= si.totalram,
              "sysinfo free");
        CHECK(si.mem_unit == 1, "sysinfo unit");
        CHECK(si.procs == 1, "sysinfo procs");
        CHECK(si.loads[0] == 0 && si.loads[1] == 0 && si.loads[2] == 0,
              "sysinfo loads");
        CHECK(si.uptime >= 0, "sysinfo uptime");
        CHECK(si.totalswap == 0 && si.freeswap == 0, "sysinfo swap");
        errno = 0;
        CHECK(sysinfo(0) == -1 && errno == EFAULT, "sysinfo null");
    }

    /* ---- ftime (host-sim: clock is ENOSYS, clean failure) ---- */
    {
        struct timeb tb;
        int r = ftime(&tb);
        if (r == 0) {
            CHECK(tb.time > 0, "ftime time");
            CHECK(tb.timezone == 0 && tb.dstflag == 0, "ftime utc");
        } else {
            CHECK(errno == ENOSYS, "ftime host ENOSYS");
        }
        errno = 0;
        CHECK(ftime(0) == -1 && errno == EFAULT, "ftime null");
    }

    /* ---- prctl (fully real on host: process-local cells) ---- */
    {
        char name[16];
        int v = 0;
        CHECK(prctl(PR_SET_NAME, "worker") == 0, "prctl set name");
        memset(name, 0, sizeof(name));
        CHECK(prctl(PR_GET_NAME, name) == 0 &&
                  strcmp(name, "worker") == 0,
              "prctl get name");
        CHECK(prctl(PR_SET_NAME, "12345678901234567890") == 0,
              "prctl long name");
        memset(name, 0, sizeof(name));
        CHECK(prctl(PR_GET_NAME, name) == 0 &&
                  strcmp(name, "123456789012345") == 0,
              "prctl name trunc");
        CHECK(prctl(PR_SET_NAME, (unsigned long)0) == -1,
              "prctl name null");
        CHECK(prctl(PR_GET_NAME, (unsigned long)0) == -1,
              "prctl getname null");
        CHECK(prctl(PR_GET_DUMPABLE) == 1, "prctl dumpable init");
        CHECK(prctl(PR_SET_DUMPABLE, 0) == 0, "prctl set dumpable");
        CHECK(prctl(PR_GET_DUMPABLE) == 0, "prctl dumpable 0");
        CHECK(prctl(PR_SET_DUMPABLE, 1) == 0, "prctl restore dump");
        CHECK(prctl(PR_SET_DUMPABLE, 2) == -1 && errno == EINVAL,
              "prctl dumpable EINVAL");
        CHECK(prctl(PR_GET_KEEPCAPS) == 0, "prctl keepcaps init");
        CHECK(prctl(PR_SET_KEEPCAPS, 1) == 0, "prctl set keepcaps");
        CHECK(prctl(PR_GET_KEEPCAPS) == 1, "prctl keepcaps 1");
        CHECK(prctl(PR_SET_KEEPCAPS, 0) == 0, "prctl clear keepcaps");
        CHECK(prctl(PR_SET_TIMERSLACK, 100000) == 0, "prctl slack");
        CHECK(prctl(PR_GET_TIMERSLACK) == 100000, "prctl get slack");
        CHECK(prctl(PR_SET_TIMERSLACK, 0) == -1, "prctl slack 0");
        CHECK(prctl(PR_GET_NO_NEW_PRIVS) == 0, "prctl nnp init");
        CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1) == 0, "prctl set nnp");
        CHECK(prctl(PR_GET_NO_NEW_PRIVS) == 1, "prctl nnp 1");
        CHECK(prctl(PR_SET_NO_NEW_PRIVS, 0) == -1, "prctl nnp oneway");
        CHECK(prctl(PR_GET_THP_DISABLE) == 0, "prctl thp init");
        CHECK(prctl(PR_SET_THP_DISABLE, 1) == 0, "prctl thp");
        CHECK(prctl(PR_GET_THP_DISABLE) == 1, "prctl thp 1");
        CHECK(prctl(PR_SET_THP_DISABLE, 0) == 0, "prctl thp clear");
        v = 0x1234;
        CHECK(prctl(PR_SET_PDEATHSIG, SIGTERM) == 0, "prctl pdeath");
        CHECK(prctl(PR_GET_PDEATHSIG, &v) == 0 && v == SIGTERM,
              "prctl get pdeath");
        CHECK(prctl(PR_SET_PDEATHSIG, 999) == -1, "prctl pdeath bad");
        CHECK(prctl(PR_GET_PDEATHSIG, (unsigned long)0) == -1,
              "prctl pdeath null");
        /* TID address is the real tid on both target and host-sim
         * (host-sim: both are -ENOSYS, still equal). */
        CHECK(prctl(PR_GET_TID_ADDRESS) == gettid(), "prctl tid");
        CHECK(prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0) == -1 &&
                  errno == ENOSYS,
              "prctl vma ENOSYS");
        CHECK(prctl(PR_SET_VMA, 0xFFFF, 0) == -1 && errno == EINVAL,
              "prctl vma subop");
        CHECK(prctl(0xFFFF) == -1 && errno == EINVAL, "prctl junk");
    }

    /* ---- statfs/fstatfs ---- */
    {
        struct statfs sfs;
        memset(&sfs, 0xAA, sizeof(sfs));
        CHECK(statfs("/", &sfs) == 0, "statfs root");
        CHECK(sfs.f_bsize == 4096 && sfs.f_frsize == 4096,
              "statfs bsize");
        CHECK(sfs.f_blocks == 256, "statfs blocks");
        CHECK(sfs.f_namelen == 31, "statfs namelen");
        CHECK(sfs.f_type == 0x01021994L, "statfs magic");
        CHECK(sfs.f_files == 64, "statfs files");
        CHECK(statfs(".", &sfs) == 0, "statfs dot");
        CHECK(statfs(0, &sfs) == -1 && errno == EINVAL,
              "statfs null path");
        CHECK(statfs("/", 0) == -1 && errno == EINVAL,
              "statfs null st");
        CHECK(statfs("/definitely-missing-xyz", &sfs) == -1,
              "statfs missing");
        CHECK(fstatfs(-1, &sfs) == -1, "statfs bad fd");
        CHECK(fstatfs(3, 0) == -1 && errno == EINVAL,
              "statfs fnull st");
    }

    /* ---- netif (fully real on host) ---- */
    {
        char buf[IFNAMSIZ];
        struct if_nameindex *ni;
        struct ifaddrs *list = 0;
        CHECK(if_nametoindex("lo") == 1, "lo index");
        CHECK(if_nametoindex("eth0") == 0, "eth0 missing");
        CHECK(if_nametoindex(0) == 0, "nametoindex null");
        CHECK(if_indextoname(1, buf) == buf && strcmp(buf, "lo") == 0,
              "indextoname");
        CHECK(if_indextoname(2, buf) == 0, "indextoname bad");
        CHECK(if_indextoname(1, 0) == 0, "indextoname null");
        ni = if_nameindex();
        CHECK(ni != 0, "nameindex");
        if (ni) {
            CHECK(ni[0].if_index == 1 &&
                      strcmp(ni[0].if_name, "lo") == 0,
                  "nameindex lo");
            CHECK(ni[1].if_index == 0 && ni[1].if_name == 0,
                  "nameindex term");
            if_freenameindex(ni);
        }
        if_freenameindex(0);
        CHECK(getifaddrs(&list) == 0 && list != 0, "getifaddrs");
        if (list) {
            struct sockaddr_in *a = (struct sockaddr_in *)list->ifa_addr;
            struct sockaddr_in *m =
                (struct sockaddr_in *)list->ifa_netmask;
            unsigned char *ab, *mb;
            CHECK(strcmp(list->ifa_name, "lo") == 0, "ifa name");
            CHECK((list->ifa_flags & (IFF_UP | IFF_LOOPBACK |
                                      IFF_RUNNING)) != 0,
                  "ifa flags");
            CHECK(a && a->sin_family == AF_INET, "ifa af");
            ab = (unsigned char *)&a->sin_addr;
            CHECK(ab[0] == 127 && ab[1] == 0 && ab[2] == 0 &&
                      ab[3] == 1,
                  "ifa loopback bytes");
            CHECK(m && m->sin_family == AF_INET, "ifa mask af");
            mb = (unsigned char *)&m->sin_addr;
            CHECK(mb[0] == 255 && mb[1] == 0 && mb[2] == 0 &&
                      mb[3] == 0,
                  "ifa mask bytes");
            CHECK(list->ifa_next == 0, "ifa single");
            freeifaddrs(list);
        }
        freeifaddrs(0);
        CHECK(getifaddrs(0) == -1 && errno == EFAULT,
              "getifaddrs null");
    }

    /* ---- stropts (validation exact; io needs the kernel) ---- */
    {
        struct strbuf ctl, dat;
        char cbuf[8], dbuf[32];
        int flags = 0, band = 0;
        CHECK(isastream(-1) == 0, "isastream bad");
        CHECK(isastream(9999) == 0, "isastream junk");
        CHECK(getmsg(3, 0, 0, 0) == -1 && errno == EFAULT,
              "getmsg null flags");
        ctl.maxlen = -1;
        ctl.len = 0;
        ctl.buf = cbuf;
        CHECK(getmsg(3, &ctl, 0, &flags) == -1 && errno == EINVAL,
              "getmsg bad ctl maxlen");
        ctl.maxlen = 8;
        ctl.len = 0;
        ctl.buf = 0;
        CHECK(getmsg(3, &ctl, 0, &flags) == -1 && errno == EFAULT,
              "getmsg null ctl buf");
        dat.maxlen = 0;
        dat.len = 0;
        dat.buf = 0;
        CHECK(getpmsg(3, 0, &dat, 0, &flags) == -1 &&
                  errno == EFAULT,
              "getpmsg null band");
        CHECK(getmsg(-1, 0, 0, &flags) == -1, "getmsg bad fd");
        /* Control payload has nowhere to go. */
        ctl.maxlen = 8;
        ctl.len = 4;
        ctl.buf = cbuf;
        dat.maxlen = 0;
        dat.len = 0;
        dat.buf = 0;
        CHECK(putmsg(3, &ctl, &dat, 0) == -1 && errno == EINVAL,
              "putmsg ctl EINVAL");
        ctl.len = 0;
        CHECK(putmsg(3, &ctl, &dat, 0x99) == -1 && errno == EINVAL,
              "putmsg flags EINVAL");
        CHECK(putpmsg(3, 0, 0, 7, 0) == -1 && errno == EINVAL,
              "putpmsg band EINVAL");
        CHECK(putmsg(-1, 0, 0, 0) == -1, "putmsg bad fd");
        /* Data part loops through write: with no kernel it fails
         * cleanly instead of half-writing. */
        dat.maxlen = (int)sizeof(dbuf);
        dat.len = 4;
        dat.buf = dbuf;
        memcpy(dbuf, "hi!\0", 4);
        CHECK(putmsg(-1, 0, &dat, 0) == -1, "putmsg nodata bad fd");
        CHECK(putmsg(-1, 0, &dat, RS_HIPRI) == -1,
              "putmsg hipri bad fd");
        /* Attach/detach: no STREAMS devices exist. */
        CHECK(fattach(3, 0) == -1 && errno == EFAULT,
              "fattach null path");
        CHECK(fdetach(0) == -1 && errno == EFAULT,
              "fdetach null path");
        CHECK(fattach(-1, "/nope-xyz") == -1, "fattach bad fd");
        CHECK(fdetach("/definitely-missing-xyz-123") == -1,
              "fdetach missing");
        (void)band;
    }

    if (failures == 0) t6_puts("ALL BATCH6 TESTS PASS\n");
    else t6_puts("FAIL: batch6 (see count above)\n");
    return failures ? 1 : 0;
}
