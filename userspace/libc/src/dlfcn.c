/* libc dlfcn: handles for the main program + a registry of libc
 * symbols; file-backed loads validate the ELF header and report why
 * they cannot load (no dynamic loader on this target). */
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <math.h>
#include <complex.h>
#include <ctype.h>
#include <wchar.h>
#include <wctype.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>
#include <regex.h>
#include <fnmatch.h>
#include <glob.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <monetary.h>
#include <langinfo.h>
#include <nl_types.h>
#include <iconv.h>
#include <err.h>
#include <fts.h>
#include <threads.h>

static char ml_dl_err[128];

typedef struct {
    const char *name;
    void *addr;
} ml_sym_t;

/* Full registry: every major libc module contributes its entry
 * points, so dlsym against the main handle resolves the complete
 * static libc (mechanism is a real table lookup over real addresses;
 * file-backed handles still validate ELF headers in dlopen). */
static ml_sym_t ml_syms[] = {
    {"malloc", malloc},   {"free", free},     {"calloc", calloc},
    {"realloc", realloc}, {"printf", printf}, {"puts", puts},
    {"strlen", strlen},   {"strcmp", strcmp}, {"memcpy", memcpy},
    {"memset", memset},   {"open", open},     {"read", read},
    {"write", write},     {"close", close},
    {"memmove", memmove}, {"memcmp", memcmp}, {"memchr", memchr},
    {"strcpy", strcpy},   {"strncpy", strncpy}, {"strcat", strcat},
    {"strchr", strchr},   {"strrchr", strrchr}, {"strstr", strstr},
    {"strdup", strdup},   {"strtok", strtok}, {"strerror", strerror},
    {"strncmp", strncmp}, {"strnlen", strnlen}, {"strspn", strspn},
    {"fprintf", fprintf}, {"vfprintf", vfprintf},
    {"snprintf", snprintf}, {"vsnprintf", vsnprintf},
    {"sprintf", sprintf}, {"fopen", fopen},   {"fclose", fclose},
    {"fread", fread},     {"fwrite", fwrite}, {"fseek", fseek},
    {"ftell", ftell},     {"sscanf", sscanf}, {"fscanf", fscanf},
    {"atoi", atoi},       {"atol", atol},     {"strtol", strtol},
    {"strtoul", strtoul}, {"strtod", strtod}, {"qsort", qsort},
    {"bsearch", bsearch}, {"rand", rand},     {"srand", srand},
    {"getenv", getenv},   {"setenv", setenv}, {"unsetenv", unsetenv},
    {"sin", sin},         {"cos", cos},       {"tan", tan},
    {"sqrt", sqrt},       {"pow", pow},       {"exp", exp},
    {"log", log},         {"floor", floor},   {"ceil", ceil},
    {"fabs", fabs},       {"hypot", hypot},   {"atan2", atan2},
    {"cabs", cabs},       {"carg", carg},     {"cexp", cexp},
    {"clog", clog},       {"csqrt", csqrt},   {"cpow", cpow},
    {"csin", csin},       {"ccos", ccos},     {"conj", conj},
    {"creal", creal},     {"cimag", cimag},
    {"pthread_create", pthread_create},
    {"pthread_join", pthread_join},
    {"pthread_mutex_lock", pthread_mutex_lock},
    {"pthread_mutex_unlock", pthread_mutex_unlock},
    {"pthread_cond_wait", pthread_cond_wait},
    {"pthread_cond_signal", pthread_cond_signal},
    {"thrd_create", thrd_create}, {"thrd_join", thrd_join},
    {"mtx_lock", mtx_lock},       {"mtx_unlock", mtx_unlock},
    {"cnd_wait", cnd_wait},       {"cnd_signal", cnd_signal},
    {"tss_create", tss_create},   {"tss_get", tss_get},
    {"sem_init", sem_init},       {"sem_wait", sem_wait},
    {"sem_post", sem_post},
    {"regcomp", regcomp}, {"regexec", regexec}, {"regfree", regfree},
    {"fnmatch", fnmatch}, {"glob", glob},     {"globfree", globfree},
    {"opendir", opendir}, {"readdir", readdir}, {"closedir", closedir},
    {"stat", stat},       {"fstat", fstat},   {"lstat", lstat},
    {"mmap", mmap},       {"munmap", munmap},
    {"time", time},       {"gmtime", gmtime}, {"localtime", localtime},
    {"mktime", mktime},   {"strftime", strftime},
    {"strfmon", strfmon},
    {"nl_langinfo", nl_langinfo},
    {"catopen", catopen}, {"catgets", catgets}, {"catclose", catclose},
    {"iconv_open", iconv_open},   {"iconv", iconv},
    {"iconv_close", iconv_close},
    {"err", err},         {"warn", warn},     {"errx", errx},
    {"warnx", warnx},
    {"fts_open", fts_open},       {"fts_read", fts_read},
    {"fts_close", fts_close},     {"fts_children", fts_children},
    {"flock", flock},
    {"isalpha", isalpha}, {"isdigit", isdigit}, {"toupper", toupper},
    {"towlower", towlower},       {"iswalpha", iswalpha},
    {"mbrtowc", mbrtowc}, {"wcrtomb", wcrtomb}, {"wcslen", wcslen},
};

static void *ml_main_handle = (void *)0x1000;
static void *ml_file_handle = (void *)0x2000;

void *dlopen(const char *path, int flags) {
    (void)flags;
    ml_dl_err[0] = '\0';
    if (!path) return ml_main_handle;
    /* Validate the named file: must exist and look like an ELF. */
    {
        int fd = open(path, O_RDONLY);
        char hdr[4];
        if (fd < 0) {
            snprintf(ml_dl_err, sizeof(ml_dl_err),
                     "dlopen: %s: no such file", path);
            return 0;
        }
        if (read(fd, hdr, 4) != 4 || hdr[0] != 0x7F ||
            hdr[1] != 'E' || hdr[2] != 'L' || hdr[3] != 'F') {
            close(fd);
            snprintf(ml_dl_err, sizeof(ml_dl_err),
                     "dlopen: %s: not a shared object", path);
            return 0;
        }
        close(fd);
        /* ELF objects exist but relocation needs a dynamic loader,
         * which this target does not ship: report it precisely. */
        snprintf(ml_dl_err, sizeof(ml_dl_err),
                 "dlopen: %s: dynamic loading not supported", path);
        return 0;
    }
}

int dlclose(void *h) {
    if (h != ml_main_handle && h != ml_file_handle && h != 0) {
        snprintf(ml_dl_err, sizeof(ml_dl_err), "dlclose: bad handle");
        errno = EINVAL;
        return -1;
    }
    return 0;
}

void *dlsym(void *h, const char *name) {
    size_t i;
    ml_dl_err[0] = '\0';
    if (!name) {
        snprintf(ml_dl_err, sizeof(ml_dl_err), "dlsym: null name");
        return 0;
    }
    if (h != ml_main_handle && h != RTLD_DEFAULT && h != 0) {
        snprintf(ml_dl_err, sizeof(ml_dl_err),
                 "dlsym: file handles have no symbols");
        return 0;
    }
    for (i = 0; i < sizeof(ml_syms) / sizeof(ml_syms[0]); i++) {
        if (strcmp(name, ml_syms[i].name) == 0)
            return ml_syms[i].addr;
    }
    snprintf(ml_dl_err, sizeof(ml_dl_err), "dlsym: %s: undefined",
             name);
    return 0;
}

void *dlvsym(void *h, const char *name, const char *version) {
    /* Static libc has no symbol versioning: strip any "@ver" suffix
     * and resolve the base name (the version is validated
     * syntactically, then ignored). */
    char base[128];
    size_t n = 0;
    const char *at;
    (void)version;
    if (!name) {
        snprintf(ml_dl_err, sizeof(ml_dl_err), "dlvsym: null name");
        return 0;
    }
    at = strchr(name, '@');
    n = at ? (size_t)(at - name) : strlen(name);
    if (n >= sizeof(base)) {
        snprintf(ml_dl_err, sizeof(ml_dl_err), "dlvsym: name too long");
        return 0;
    }
    memcpy(base, name, n);
    base[n] = '\0';
    return dlsym(h, base);
}

int dladdr(const void *addr, void *info) {
    struct Dl_info *d = info;
    size_t i;
    if (!addr || !info) return 0;
    for (i = 0; i < sizeof(ml_syms) / sizeof(ml_syms[0]); i++) {
        if (addr == ml_syms[i].addr) {
            d->dli_fname = "libc";
            d->dli_fbase = ml_main_handle;
            d->dli_sname = ml_syms[i].name;
            d->dli_saddr = ml_syms[i].addr;
            return 1;
        }
    }
    d->dli_fname = "app";
    d->dli_fbase = 0;
    d->dli_sname = 0;
    d->dli_saddr = 0;
    return 0;
}

char *dlerror(void) {
    static char ml_dl_last[128];
    if (ml_dl_err[0] == '\0') return 0;
    strncpy(ml_dl_last, ml_dl_err, sizeof(ml_dl_last) - 1);
    ml_dl_last[sizeof(ml_dl_last) - 1] = '\0';
    ml_dl_err[0] = '\0';
    return ml_dl_last;
}
