/* linux_demo - Linux-compatible application for MoonlightOS.
 *
 * Uses ONLY the Moonlight C library (<stdio.h>, <stdlib.h>, ...) with
 * Linux rv64 syscall numbers underneath. The same main() builds two ways:
 *  - standalone ELF (userspace/build/linux_demo.elf, _start -> main), and
 *  - in-kernel thread (linux_demo_main, spawned by boot.c like the
 *    servers; exit() parks the thread via the exit syscall).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/utsname.h>

/* Fail-fast: a NULL/EBADF must never flow into the next call (on a real
 * kernel the fault would wedge the hart - trap loop has no U-mode yet). */
#define CHECK(c, why) do { \
    if (!(c)) { printf("[LINUX-DEMO] FAIL: %s (line %d)\n", why, __LINE__); return 1; } \
} while (0)

static int cmp_int(const void *a, const void *b) {
    return *(const int *)a - *(const int *)b;
}

int main(void) {
    printf("[LINUX-DEMO] MoonlightOS Linux-compatible app\n");

    /* identity */
    {
        struct utsname uts;
        CHECK(getpid() > 0 || getpid() == 0, "getpid runs");
        CHECK(uname(&uts) == 0, "uname ok");
        CHECK(strcmp(uts.machine, "riscv64") == 0, "machine riscv64");
        printf("[LINUX-DEMO] pid=%d machine=%s\n", getpid(), uts.machine);
    }

    /* time */
    {
        struct timespec ts, res;
        struct timeval tv;
        CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0, "clock_gettime");
        CHECK(clock_getres(CLOCK_MONOTONIC, &res) == 0, "clock_getres");
        CHECK(gettimeofday(&tv, 0) == 0, "gettimeofday");
        printf("[LINUX-DEMO] time %ld.%09ld\n", (long)ts.tv_sec,
               ts.tv_nsec);
    }

    /* heap: malloc/free/calloc/realloc/qsort/strdup */
    {
        char *p = malloc(100);
        char *q;
        int *arr, i, sorted = 1;
        CHECK(p != 0, "malloc 100");
        strcpy(p, "heap-ok");
        CHECK(strcmp(p, "heap-ok") == 0, "heap usable");
        free(p);
        q = calloc(1, 64);
        CHECK(q != 0 && q[0] == 0 && q[63] == 0, "calloc zeroed");
        q = realloc(q, 4096);
        CHECK(q != 0, "realloc grow");
        memset(q, 0xAB, 4096);
        free(q);
        arr = malloc(50 * sizeof(int));
        CHECK(arr != 0, "malloc arr");
        srand(42);
        for (i = 0; i < 50; i++) arr[i] = rand() % 1000;
        qsort(arr, 50, sizeof(int), cmp_int);
        for (i = 1; i < 50; i++)
            if (arr[i - 1] > arr[i]) sorted = 0;
        CHECK(sorted, "qsort sorted");
        free(arr);
        {
            char *d = strdup("dup");
            CHECK(d != 0 && strcmp(d, "dup") == 0, "strdup");
            free(d);
        }
        printf("[LINUX-DEMO] heap ok\n");
    }

    /* brk/sbrk + mmap */
    {
        long b0 = (long)sbrk(0);
        char *m;
        CHECK(b0 != 0 && b0 != -1, "sbrk base");
        m = mmap(0, 16384, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(m != MAP_FAILED, "mmap anon");
        strcpy(m, "mmap-ok");
        CHECK(strcmp(m, "mmap-ok") == 0, "mmap usable");
        CHECK(munmap(m, 16384) == 0, "munmap");
        CHECK(mprotect(m, 4096, PROT_READ) == 0, "mprotect");
        printf("[LINUX-DEMO] mmap ok\n");
    }

    /* files: fopen/fwrite/fread/fseek/stat/unlink */
    {
        FILE *f = fopen("demo.txt", "w");
        struct stat st;
        char buf[32];
        CHECK(f != 0, "fopen w");
        CHECK(fwrite("hello-linux", 1, 11, f) == 11, "fwrite");
        CHECK(fclose(f) == 0, "fclose");
        CHECK(stat("demo.txt", &st) == 0, "stat");
        if (st.st_size != 11) {
            printf("[LINUX-DEMO] size=%ld mode=%o blksz=%ld\n",
                   (long)st.st_size, st.st_mode, (long)st.st_blksize);
            return 1;
        }
        CHECK((st.st_mode & 0777) == 0644, "stat mode");
        f = fopen("demo.txt", "r");
        CHECK(f != 0, "fopen r");
        memset(buf, 0, sizeof(buf));
        CHECK(fread(buf, 1, 11, f) == 11, "fread");
        CHECK(memcmp(buf, "hello-linux", 11) == 0, "file bytes");
        CHECK(fseek(f, 6, SEEK_SET) == 0, "fseek");
        CHECK(ftell(f) == 6, "ftell");
        memset(buf, 0, sizeof(buf));
        CHECK(fread(buf, 1, 5, f) == 5, "fread tail");
        CHECK(memcmp(buf, "linux", 5) == 0, "tail bytes");
        CHECK(fclose(f) == 0, "fclose r");
        CHECK(access("demo.txt", 0) == 0, "access F_OK");
        CHECK(unlink("demo.txt") == 0, "unlink");
        CHECK(access("demo.txt", 0) != 0, "gone");
        printf("[LINUX-DEMO] files ok\n");
    }

    /* printf formats + ctype + strtol */
    {
        char b[64];
        CHECK(snprintf(b, sizeof(b), "%d/%u/%x/%s/%c/%p", -42, 42u,
                       0xabcd, "s", 'q', (void *)0x1000) > 0,
              "snprintf");
        CHECK(strcmp(b, "-42/42/abcd/s/q/0x1000") == 0, "formats");
        CHECK(isalpha('a') && isdigit('7') && !isalnum('!'), "ctype");
        CHECK(tolower('A') == 'a' && toupper('z') == 'Z', "case");
        CHECK(strtol("0xff", 0, 0) == 255, "strtol hex");
        CHECK(strtol("077", 0, 0) == 63, "strtol oct");
        CHECK(atoi("-19") == -19, "atoi");
        printf("[LINUX-DEMO] libc ok: %s\n", b);
    }

    /* absolute paths land flat, getcwd is the single root */
    {
        char cwd[8];
        int fd = open("/tmp/abs.txt", O_CREAT | O_RDWR, 0644);
        CHECK(fd >= 0, "abs open flat");
        if (fd >= 0) {
            CHECK(write(fd, "A", 1) == 1, "abs write");
            close(fd);
            CHECK(unlink("abs.txt") == 0, "abs unlink flat");
        }
        CHECK(getcwd(cwd, sizeof(cwd)) != 0 && strcmp(cwd, "/") == 0,
              "getcwd /");
    }

    printf("[LINUX-DEMO] ALL PASS\n");
    return 0;
}

/* In-kernel thread entry (boot.c): run main, park via exit(). The run
 * counter distinguishes scheduler re-entry (counter rises) from console
 * duplication (counter stays 1). */
static int demo_runs = 0;
void linux_demo_main(void) {
    int rc;
    demo_runs++;
    printf("[LINUX-DEMO] run #%d\n", demo_runs);
    rc = main();
    exit(rc);
}
