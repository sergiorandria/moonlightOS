/* test_batch5 - host unit tests for batch 5 (newly wired libc modules:
 * syscall gateway, crypt/SHA-crypt/DES, ether, execinfo, fmtmsg, libgen,
 * ndbm, search, sendfile, shadow, sysevent (eventfd/timerfd/signalfd/
 * inotify), sysvipc, utmpx, ptimer, aio).
 *
 * Links the REAL libc sources; the raw-syscall layer is the host stub
 * (-ENOSYS), so kernel-dependent success paths are asserted as clean
 * failures while every validation/pure path is asserted exactly.
 * Diagnostics go to real stderr via dprintf + the host console shim
 * (tests/host_console_shim.c, compiled with host headers only).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sys/inotify.h>
#include <sys/sem.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <crypt.h>
#include <netinet/ether.h>
#include <execinfo.h>
#include <fmtmsg.h>
#include <libgen.h>
#include <ndbm.h>
#include <search.h>
#include <shadow.h>
#include <utmpx.h>
#include <aio.h>

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

extern int dprintf(int fd, const char *fmt, ...);

/* Test-local diagnostics: raw host write, independent of the libc under
 * test (sysevent.c is linked here, so dprintf(2,...) would route into
 * the managed-fd layer and fall silent on host-sim ENOSYS). */
static void t5_puts(const char *s) {
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

static void t5_fail(const char *why, int line) {
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
    t5_puts("FAIL: ");
    t5_puts(b);
}

static int failures = 0;
#define CHECK(cond, why) do { \
    if (!(cond)) { t5_fail(why, __LINE__); failures++; } \
} while (0)

/* DES NIST KAT: hex string -> '0'/'1' bit string (MSB first). */
static void hex_to_bits(const char *hex, char *out) {
    static const char *d = "0123456789ABCDEF";
    int i = 0;
    for (; *hex; hex++) {
        const char *p = strchr(d, *hex);
        int v = p ? (int)(p - d) : 0, b;
        for (b = 3; b >= 0; b--) out[i++] = ((v >> b) & 1) ? '1' : '0';
    }
    out[i] = '\0';
}

static int cmp_int(const void *a, const void *b) {
    return *(const int *)a - *(const int *)b;
}

static int twalk_count = 0;
static void twalk_cb(const void *node, VISIT which, int depth) {
    (void)node;
    (void)depth;
    if (which == preorder || which == leaf) twalk_count++;
}

int main(void) {
    t5_puts("=== test_batch5 ===\n");

    /* ---- syscall gateway (host-sim: raw -ENOSYS) ---- */
    {
        CHECK(syscall(999999, 0, 0, 0, 0, 0, 0) == -ENOSYS,
              "syscall junk ENOSYS");
    }

    /* ---- crypt: SHA-crypt KATs (openssl reference values) ---- */
    {
        char *r;
        r = crypt("password", "$5$saltsalt");
        CHECK(r && strcmp(r, "$5$saltsalt$gOjOtoMpVhru2uyjeJSEc/JaL"
                           "QWOXMNmlOnj6T4AtC.") == 0,
              "crypt sha256 kat1");
        r = crypt("password", "$6$saltsalt");
        CHECK(r && strcmp(r, "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z"
                           "4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc."
                           "eoxqOmSuNp2xS0ktL3nh/") == 0,
              "crypt sha512 kat1");
        r = crypt("hello", "$5$abc12345");
        CHECK(r && strcmp(r, "$5$abc12345$.sxeKOi04ihTYYODSwbiAjmrfB"
                           "7twR7dbuMKO1hCDz3") == 0,
              "crypt sha256 kat2");
        r = crypt("hello", "$6$abc12345");
        CHECK(r && strcmp(r, "$6$abc12345$KFCXbpYdO/IFKoZwAZFSTFbV24"
                           "Fkm9L/bBqHQWkCemTybidit4so638iGijYVTBw/"
                           "M5Mu8FC97w/mMxHhYkSi.") == 0,
              "crypt sha512 kat2");
        r = crypt("password", "$5$xyz");
        CHECK(r && strcmp(r, "$5$xyz$ChenN6MXOtL.QbXYjUv2u2pCfLxljjy"
                           "1yq6W5xCiWaB") == 0,
              "crypt sha256 kat3");
        r = crypt("a longer passphrase with spaces", "$6$xyz");
        CHECK(r && strcmp(r, "$6$xyz$uUwb.kgnGZhy8fFmLmxI4qvh51OmtVZ"
                           "fBUTJo5cELQ8FhmpKk71qzXkjSArJGqdjaJFbv"
                           "xrBjnZdCDUtqpe751") == 0,
              "crypt sha512 long");
        {
            struct crypt_data cd;
            memset(&cd, 0, sizeof(cd));
            r = crypt_r("password", "$5$saltsalt", &cd);
            CHECK(r && strcmp(r, "$5$saltsalt$gOjOtoMpVhru2uyjeJSEc/"
                               "JaLQWOXMNmlOnj6T4AtC.") == 0,
                  "crypt_r kat");
            CHECK(crypt_r(0, "$5$saltsalt", &cd) == 0,
                  "crypt_r null key");
            CHECK(crypt_r("k", 0, &cd) == 0, "crypt_r null setting");
            CHECK(crypt_r("k", "$5$saltsalt", 0) == 0,
                  "crypt_r null data");
        }
        CHECK(crypt(0, "$5$x") == 0, "crypt null key");
        CHECK(crypt("k", 0) == 0, "crypt null setting");
        r = crypt("k", "$9$nosuch");
        CHECK(r && strcmp(r, "*0") == 0, "crypt bad setting");
    }

    /* ---- crypt: DES setkey/encrypt (NIST KAT + roundtrip) ---- */
    {
        char kb[65], pb[65], want[65];
        hex_to_bits("133457799BBCDFF1", kb);
        hex_to_bits("0123456789ABCDEF", pb);
        hex_to_bits("85E813540F0AB405", want);
        setkey(kb);
        encrypt(pb, 0);
        CHECK(strcmp(pb, want) == 0, "des encrypt kat");
        encrypt(pb, 1);
        hex_to_bits("0123456789ABCDEF", want);
        CHECK(strcmp(pb, want) == 0, "des decrypt roundtrip");
        setkey(0);
        pb[0] = '0';
        pb[1] = '\0';
        encrypt(pb, 0); /* no key: no-op, no crash */
        CHECK(pb[1] == '\0', "des nokey noop");
        encrypt(0, 0);
    }

    /* ---- ether ---- */
    {
        struct ether_addr *a, *b;
        char buf[32];
        a = ether_aton("01:23:45:67:89:ab");
        CHECK(a && a->ether_addr_octet[0] == 0x01 &&
                  a->ether_addr_octet[5] == 0xAB,
              "ether aton");
        CHECK(ether_aton("not-a-mac") == 0, "ether aton bad");
        CHECK(ether_aton(0) == 0, "ether aton null");
        b = ether_aton_r("de:ad:be:ef:00:01", 0);
        CHECK(b == 0, "ether aton_r null");
        {
            struct ether_addr e2;
            CHECK(ether_aton_r("de:ad:be:ef:00:01", &e2) == &e2 &&
                      e2.ether_addr_octet[1] == 0xAD,
                  "ether aton_r");
        }
        CHECK(ether_ntoa(a) != 0, "ether ntoa");
        CHECK(ether_ntoa_r(a, buf) == buf &&
                  strcmp(buf, "1:23:45:67:89:ab") == 0,
              "ether ntoa_r");
        CHECK(ether_ntoa(0) == 0, "ether ntoa null");
        CHECK(ether_ntoa_r(a, 0) == 0, "ether ntoa_r null");
        {
            struct ether_addr e3;
            char host[64];
            CHECK(ether_line("01:23:45:67:89:ab myhost", &e3,
                             host) == 0 &&
                      strcmp(host, "myhost") == 0,
                  "ether line");
            CHECK(ether_line("# comment", &e3, host) != 0,
                  "ether line comment");
            CHECK(ether_line(0, &e3, host) != 0, "ether line null");
        }
        /* No /etc/ethers on the build host: clean lookup failure. */
        CHECK(ether_hostton("definitely-not-a-host-zzz", a) != 0,
              "ether hostton missing");
        CHECK(ether_ntohost(buf, a) != 0, "ether ntohost missing");
    }

    /* ---- execinfo ---- */
    {
        void *bt[32];
        int n = backtrace(bt, 32);
        CHECK(n >= 1, "backtrace depth");
        CHECK(backtrace(0, 32) == 0, "backtrace null");
        CHECK(backtrace(bt, 0) == 0, "backtrace zero");
        {
            char **syms = backtrace_symbols(bt, n);
            CHECK(syms != 0, "backtrace symbols");
            if (syms) {
                int i;
                CHECK(syms[0] != 0, "symbols line0");
                for (i = 0; i < n; i++) free(syms[i]);
                free(syms);
            }
        }
        CHECK(backtrace_symbols(0, n) == 0, "symbols null");
        backtrace_symbols_fd(bt, 1, 2); /* one line to stderr, no crash */
        backtrace_symbols_fd(0, 1, 2);
    }

    /* ---- fmtmsg ---- */
    {
        CHECK(fmtmsg(MM_PRINT, "B5", MM_INFO, "batch5 probe",
                     MM_NULLACT, MM_NULLTAG) == MM_OK,
              "fmtmsg ok");
        CHECK(fmtmsg(MM_PRINT, "B5", 999, "x", 0, 0) == MM_NOTOK,
              "fmtmsg bad sev");
        CHECK(fmtmsg(MM_PRINT, "B5", MM_INFO, 0, 0, 0) == MM_NOMSG,
              "fmtmsg null text");
        CHECK(fmtmsg(MM_PRINT, "B5", MM_INFO, "", 0, 0) == MM_NOMSG,
              "fmtmsg empty text");
        CHECK(fmtmsg(0, "B5", MM_INFO, "x", 0, 0) == MM_NOCON,
              "fmtmsg nocon");
        CHECK(fmtmsg(MM_PRINT, "B5", MM_NOSEV, "nosev ok", 0, 0) ==
                  MM_OK,
              "fmtmsg nosev");
    }

    /* ---- libgen ---- */
    {
        char p1[] = "/a/b/c", p2[] = "/a/b/", p3[] = "a",
             p4[] = "/a/b", p5[] = "a/b/", p6[] = "/";
        CHECK(strcmp(basename(p1), "c") == 0, "basename file");
        CHECK(strcmp(basename(p2), "b") == 0, "basename trail");
        CHECK(strcmp(basename(p3), "a") == 0, "basename plain");
        CHECK(strcmp(basename(p6), "/") == 0, "basename root");
        CHECK(strcmp(basename(0), ".") == 0, "basename null");
        CHECK(strcmp(basename(""), ".") == 0, "basename empty");
        CHECK(strcmp(dirname(p4), "/a") == 0, "dirname dir");
        CHECK(strcmp(dirname(p3), ".") == 0, "dirname plain");
        CHECK(strcmp(dirname(p6), "/") == 0, "dirname root");
        CHECK(strcmp(dirname(p5), "a") == 0, "dirname trail");
        CHECK(strcmp(dirname(0), ".") == 0, "dirname null");
    }

    /* ---- ndbm (host: no kernel files, validation + clean failure) ---- */
    {
        DBM *db;
        datum k, v;
        errno = 0;
        CHECK(dbm_open(0, O_RDWR, 0600) == 0 && errno == EINVAL,
              "dbm open null");
        CHECK(dbm_open("/no/such/dir_xyz/f", O_RDWR, 0600) == 0,
              "dbm open host ENOSYS");
        dbm_close(0);
        CHECK(dbm_error(0) == 0, "dbm error null");
        dbm_clearerr(0);
        k.dptr = "k";
        k.dsize = 1;
        v = dbm_fetch(0, k);
        CHECK(v.dptr == 0, "dbm fetch null db");
        CHECK(dbm_firstkey(0).dptr == 0, "dbm firstkey null");
        CHECK(dbm_dirfno(0) == -1, "dbm dirfno null");
        CHECK(dbm_forder(0, k) == -1, "dbm forder null");
    }

    /* ---- search (fully real on host) ---- */
    {
        ENTRY e, *f;
        CHECK(hcreate(16) != 0, "hcreate");
        e.key = "k1";
        e.data = (void *)11;
        CHECK(hsearch(e, ENTER) != 0, "hsearch enter");
        e.key = "k1";
        f = hsearch(e, FIND);
        CHECK(f && f->data == (void *)11, "hsearch find");
        e.key = "missing";
        CHECK(hsearch(e, FIND) == 0, "hsearch find missing");
        hdestroy();
        {
            int arr[4] = {10, 20, 30, 0};
            size_t nel = 3;
            int key = 20, *r;
            r = lsearch(&key, arr, &nel, sizeof(int), cmp_int);
            CHECK(r && *r == 20, "lsearch found");
            key = 99;
            r = lsearch(&key, arr, &nel, sizeof(int), cmp_int);
            CHECK(r && nel == 4 && arr[3] == 99, "lsearch append");
            key = 10;
            CHECK(lfind(&key, arr, &nel, sizeof(int), cmp_int) != 0,
                  "lfind");
            key = 77;
            CHECK(lfind(&key, arr, &nel, sizeof(int), cmp_int) == 0,
                  "lfind missing");
        }
        {
            void *root = 0;
            int a = 5, b = 3, c = 7;
            void *fnd;
            tsearch(&a, &root, cmp_int);
            tsearch(&b, &root, cmp_int);
            tsearch(&c, &root, cmp_int);
            fnd = tfind(&b, &root, cmp_int);
            CHECK(fnd && *(int **)fnd == &b, "tfind");
            twalk_count = 0;
            twalk(root, twalk_cb);
            CHECK(twalk_count == 3, "twalk count");
            CHECK(tdelete(&b, &root, cmp_int) != 0, "tdelete");
            CHECK(tfind(&b, &root, cmp_int) == 0,
                  "tfind deleted");
            twalk_count = 0;
            twalk(root, twalk_cb);
            CHECK(twalk_count == 2, "twalk after delete");
        }
    }

    /* ---- sendfile (host: EBADF validation + ENOSYS passthrough) ---- */
    {
        off_t off = 7;
        CHECK(sendfile(-1, 3, 0, 100) == -1 && errno == EBADF,
              "sendfile bad out");
        CHECK(sendfile(3, -1, 0, 100) == -1 && errno == EBADF,
              "sendfile bad in");
        CHECK(sendfile(3, 4, 0, 0) == 0, "sendfile zero count");
        off = 7;
        CHECK(sendfile(3, 4, &off, 0) == 0 && off == 7,
              "sendfile zero offset kept");
        CHECK(sendfile(3, 4, 0, 100) == -1 && errno == ENOSYS,
              "sendfile host ENOSYS");
    }

    /* ---- shadow ---- */
    {
        struct spwd sp;
        char buf[256];
        struct spwd *g;
        CHECK(sgetspent("root:x:0:0:99999:7:::", &sp, buf,
                        sizeof(buf)) == 0 &&
                  strcmp(sp.sp_namp, "root") == 0 &&
                  sp.sp_max == 99999,
              "sgetspent full");
        CHECK(sgetspent("a:b", &sp, buf, sizeof(buf)) == 0 &&
                  sp.sp_lstchg == 0 && sp.sp_min == -1,
              "sgetspent short");
        CHECK(sgetspent(0, &sp, buf, sizeof(buf)) == -1,
              "sgetspent null");
        CHECK(sgetspent(":x:0", &sp, buf, sizeof(buf)) == -1,
              "sgetspent empty name");
        {
            char data[] = "# comment\nnobody:x:1:1:99999:7:::\n";
            FILE *fp = fmemopen(data, sizeof(data) - 1, "r");
            CHECK(fp != 0, "shadow fmemopen");
            if (fp) {
                CHECK(fgetspent(fp, &sp, buf, sizeof(buf)) == 0 &&
                          strcmp(sp.sp_namp, "nobody") == 0,
                      "fgetspent");
                fclose(fp);
            }
            CHECK(fgetspent(0, &sp, buf, sizeof(buf)) == -1,
                  "fgetspent null");
        }
        g = getspnam("root");
        CHECK(g && strcmp(g->sp_namp, "root") == 0,
              "getspnam root fallback");
        errno = 0;
        CHECK(getspnam("definitely-not-a-user-zzz") == 0 &&
                  errno == ENOENT,
              "getspnam missing");
        CHECK(getspnam(0) == 0, "getspnam null");
        setspent();
        endspent();
    }

    /* ---- sysvipc: semaphores (fully real on host) ---- */
    {
        int id = semget(IPC_PRIVATE, 2, 0600);
        struct sembuf op;
        CHECK(id >= 0, "semget");
        if (id >= 0) {
            CHECK(semctl(id, 0, SETVAL, 1) == 0, "sem setval");
            CHECK(semctl(id, 0, GETVAL) == 1, "sem getval");
            op.sem_num = 0;
            op.sem_op = -1;
            op.sem_flg = 0;
            CHECK(semop(id, &op, 1) == 0, "sem P");
            CHECK(semctl(id, 0, GETVAL) == 0, "sem val 0");
            op.sem_op = 1;
            CHECK(semop(id, &op, 1) == 0, "sem V");
            op.sem_num = 9;
            op.sem_op = 1;
            CHECK(semop(id, &op, 1) == -1, "sem bad num");
            CHECK(semctl(id, 0, IPC_RMID) == 0, "sem rmid");
            CHECK(semctl(id, 0, GETVAL) == -1, "sem removed");
        }
        CHECK(semget(IPC_PRIVATE, 300, 0600) == -1 &&
                  errno == EINVAL,
              "semget nsems");
        CHECK(semget(IPC_PRIVATE, -1, 0600) == -1, "semget neg");
        CHECK(semget(0x1234, 1, 0) == -1 && errno == ENOENT,
              "semget missing nocreate");
    }

    /* ---- sysvipc: messages (fully real on host) ---- */
    {
        struct {
            long mtype;
            char mtext[16];
        } msg, rcv;
        int id = msgget(IPC_PRIVATE, 0600);
        CHECK(id >= 0, "msgget");
        if (id >= 0) {
            msg.mtype = 7;
            memcpy(msg.mtext, "hello-ipc", 10);
            CHECK(msgsnd(id, &msg, 10, 0) == 0, "msgsnd");
            memset(&rcv, 0, sizeof(rcv));
            CHECK(msgrcv(id, &rcv, sizeof(rcv.mtext), 7, 0) ==
                      (ssize_t)10 &&
                      memcmp(rcv.mtext, "hello-ipc", 10) == 0,
                  "msgrcv");
            CHECK(msgrcv(id, &rcv, sizeof(rcv.mtext), 7,
                         IPC_NOWAIT) == -1 &&
                      errno == ENOMSG,
                  "msgrcv empty nowait");
            CHECK(msgctl(id, IPC_RMID, 0) == 0, "msg rmid");
            CHECK(msgsnd(id, &msg, 10, 0) == -1, "msgsnd removed");
        }
        CHECK(msgget(0x1234, 0) == -1 && errno == ENOENT,
              "msgget missing nocreate");
    }

    /* ---- sysvipc: ftok + shm (host: stat/mmap are ENOSYS) ---- */
    {
        errno = 0;
        CHECK(ftok(0, 1) == -1 && errno == EINVAL, "ftok null");
        CHECK(ftok("/no/such/file_xyz", 1) == -1, "ftok missing");
        CHECK(shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600) == -1,
              "shmget host ENOSYS");
        CHECK(shmat(-1, 0, 0) == (void *)-1, "shmat bad");
        CHECK(shmdt(0) == -1, "shmdt bad");
    }

    /* ---- sysevent: eventfd (fully real on host) ---- */
    {
        int efd = eventfd(0, 0);
        eventfd_t v = 0;
        CHECK(efd >= 0, "eventfd");
        if (efd >= 0) {
            CHECK(eventfd_write(efd, 5) == 0, "eventfd write");
            CHECK(eventfd_read(efd, &v) == 0 && v == 5,
                  "eventfd read");
            CHECK(eventfd_read(efd, 0) == -1, "eventfd read null");
            {
                char small[4];
                CHECK(read(efd, small, sizeof(small)) == -1 &&
                          errno == EINVAL,
                      "eventfd short read");
            }
            CHECK(close(efd) == 0, "eventfd close");
        }
        {
            int sfd = eventfd(0, EFD_SEMAPHORE | EFD_NONBLOCK);
            CHECK(sfd >= 0, "eventfd sem");
            if (sfd >= 0) {
                CHECK(eventfd_write(sfd, 3) == 0, "eventfd sem w");
                CHECK(eventfd_read(sfd, &v) == 0 && v == 1,
                      "eventfd sem r1");
                CHECK(eventfd_read(sfd, &v) == 0 && v == 1,
                      "eventfd sem r2");
                CHECK(eventfd_read(sfd, &v) == 0 && v == 1,
                      "eventfd sem r3");
                CHECK(eventfd_read(sfd, &v) == -1 &&
                          errno == EAGAIN,
                      "eventfd sem empty");
                CHECK(close(sfd) == 0, "eventfd sem close");
            }
        }
        CHECK(eventfd(0, 0xFFFF) == -1 && errno == EINVAL,
              "eventfd bad flags");
    }

    /* ---- sysevent: timerfd (disarm-only on host: no tick clock) ---- */
    {
        int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
        struct itimerspec cur, nv;
        CHECK(tfd >= 0, "timerfd create");
        if (tfd >= 0) {
            memset(&cur, 0xAA, sizeof(cur));
            CHECK(timerfd_gettime(tfd, &cur) == 0 &&
                      cur.it_value.tv_sec == 0 &&
                      cur.it_value.tv_nsec == 0,
                  "timerfd fresh zeros");
            memset(&nv, 0, sizeof(nv));
            CHECK(timerfd_settime(tfd, 0, &nv, 0) == 0,
                  "timerfd disarm");
            nv.it_value.tv_nsec = 1000000000L;
            CHECK(timerfd_settime(tfd, 0, &nv, 0) == -1 &&
                      errno == EINVAL,
                  "timerfd bad nsec");
            CHECK(timerfd_settime(tfd, 0, 0, 0) == -1,
                  "timerfd null newv");
            CHECK(timerfd_gettime(tfd, 0) == -1, "timerfd null cur");
            CHECK(close(tfd) == 0, "timerfd close");
        }
        CHECK(timerfd_create(999, 0) == -1 && errno == EINVAL,
              "timerfd bad clock");
        CHECK(timerfd_create(CLOCK_MONOTONIC, 0xFFFF) == -1,
              "timerfd bad flags");
    }

    /* ---- sysevent: signalfd (no live signals on host) ---- */
    {
        sigset_t m, m2;
        int sfd;
        sigemptyset(&m);
        sigaddset(&m, SIGUSR1);
        sfd = signalfd(-1, &m, SFD_NONBLOCK);
        CHECK(sfd >= 0, "signalfd create");
        if (sfd >= 0) {
            struct signalfd_siginfo si;
            sigemptyset(&m2);
            CHECK(signalfd(sfd, &m2, 0) == sfd, "signalfd update");
            CHECK(read(sfd, &si, sizeof(si)) == -1 &&
                      errno == EAGAIN,
                  "signalfd empty nowait");
            CHECK(close(sfd) == 0, "signalfd close");
        }
        CHECK(signalfd(-1, 0, 0) == -1 && errno == EINVAL,
              "signalfd null mask");
        CHECK(signalfd(-1, &m, 0xFFFF) == -1, "signalfd bad flags");
        CHECK(signalfd(999, &m, 0) == -1, "signalfd bad fd");
    }

    /* ---- sysevent: inotify (host: stat is ENOSYS, watch still registers) ---- */
    {
        int ifd = inotify_init();
        CHECK(ifd >= 0, "inotify init");
        if (ifd >= 0) {
            int wd = inotify_add_watch(ifd, "/tmp", IN_ALL_EVENTS);
            CHECK(wd >= 1, "inotify add");
            CHECK(inotify_add_watch(ifd, 0, IN_ALL_EVENTS) == -1,
                  "inotify null path");
            CHECK(inotify_add_watch(ifd, "", IN_ALL_EVENTS) == -1,
                  "inotify empty path");
            CHECK(inotify_add_watch(ifd, "/tmp", 0) == -1,
                  "inotify zero mask");
            CHECK(inotify_add_watch(999, "/tmp", IN_ALL_EVENTS) ==
                          -1,
                  "inotify bad fd");
            CHECK(inotify_rm_watch(ifd, 9999) == -1,
                  "inotify rm missing");
            if (wd >= 1)
                CHECK(inotify_rm_watch(ifd, wd) == 0, "inotify rm");
            CHECK(close(ifd) == 0, "inotify close");
        }
        CHECK(inotify_init1(0xFFFF) == -1, "inotify bad flags");
    }

    /* ---- utmpx (host: no utmp file, validation + clean NULLs) ---- */
    {
        errno = 0;
        CHECK(utmpxname(0) == -1 && errno == EINVAL,
              "utmpxname null");
        {
            char big[300];
            memset(big, 'a', sizeof(big) - 1);
            big[sizeof(big) - 1] = '\0';
            CHECK(utmpxname(big) == -1, "utmpxname long");
        }
        CHECK(utmpxname("/no/such/file_xyz.utmp") == 0,
              "utmpxname missing ok");
        CHECK(getutxent() == 0, "getutxent missing");
        CHECK(pututxline(0) == 0, "pututxline null");
        CHECK(getutxid(0) == 0, "getutxid null");
        CHECK(getutxline(0) == 0, "getutxline null");
        endutxent();
        setutxent();
        endutxent();
    }

    /* ---- ptimer (host: no tick clock, validation only — creating a
     * timer would spawn a manager thread spinning on ENOSYS) ---- */
    {
        timer_t tid = 0;
        struct sigevent ev;
        struct itimerspec ts;
        memset(&ev, 0, sizeof(ev));
        ev.sigev_notify = 999;
        CHECK(timer_create(999, 0, &tid) == -1 && errno == EINVAL,
              "ptimer bad clock");
        CHECK(timer_create(CLOCK_REALTIME, 0, 0) == -1,
              "ptimer null id");
        CHECK(timer_create(CLOCK_REALTIME, &ev, &tid) == -1,
              "ptimer bad notify");
        memset(&ts, 0, sizeof(ts));
        CHECK(timer_settime(-1, 0, &ts, 0) == -1, "ptimer set bad");
        CHECK(timer_settime(0, 0, 0, 0) == -1, "ptimer set null");
        CHECK(timer_gettime(-1, &ts) == -1, "ptimer get bad");
        CHECK(timer_gettime(0, 0) == -1, "ptimer get null");
        CHECK(timer_getoverrun(-1) == -1, "ptimer overrun bad");
        CHECK(timer_delete(-1) == -1, "ptimer delete bad");
    }

    /* ---- aio (host: validation only — submit needs kernel fds) ---- */
    {
        CHECK(aio_read(0) == -1 && errno == EINVAL, "aio read null");
        CHECK(aio_write(0) == -1, "aio write null");
        CHECK(aio_fsync(0, 0) == -1, "aio fsync null");
        CHECK(aio_error(0) == EINVAL, "aio error null");
        CHECK(aio_return(0) == -1, "aio return null");
        CHECK(aio_cancel(999, 0) == AIO_ALLDONE, "aio cancel empty");
        CHECK(lio_listio(LIO_WAIT, 0, 0, 0) == -1, "lio null");
        CHECK(lio_listio(999, 0, 0, 0) == -1, "lio bad mode");
        CHECK(aio_suspend(0, 1, 0) == -1, "aio suspend null");
    }

    if (failures == 0) t5_puts("ALL BATCH5 TESTS PASS\n");
    else t5_puts("FAIL: batch5 (see count above)\n");
    return failures ? 1 : 0;
}
