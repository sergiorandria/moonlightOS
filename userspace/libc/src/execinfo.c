/* libc execinfo: backtraces via the return-address chain plus
 * dladdr symbols. Only level 0 (__builtin_return_address(0)) is used:
 * deeper levels walk the frame chain, which is only valid with frame
 * pointers kept (neither the host -O2 nor the target -O2 build keeps
 * them), so unwinding further reads garbage and can fault. A single
 * real caller address beats a deep fake one; .eh_frame unwinding is
 * future work. dladdr resolves what it can, addresses otherwise. */
#include <execinfo.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

int backtrace(void **buffer, int size) {
    void *a;
    if (!buffer || size <= 0) return 0;
    /* Level 0 is the only compiler-guaranteed address (deeper levels
     * need frame pointers; see above). */
    a = __builtin_return_address(0);
    if (!a) return 0;
    buffer[0] = a;
    return 1;
}

char **backtrace_symbols(void *const *buffer, int size) {
    char **syms;
    int i;
    if (!buffer || size <= 0) return 0;
    syms = malloc(sizeof(char *) * (size_t)size);
    if (!syms) return 0;
    for (i = 0; i < size; i++) {
        struct Dl_info info;
        char line[160];
        if (dladdr(buffer[i], &info) && info.dli_sname)
            snprintf(line, sizeof(line), "%s(%s+0x%lx) [%p]",
                     info.dli_fname ? info.dli_fname : "app",
                     info.dli_sname,
                     (unsigned long)((char *)buffer[i] -
                                     (char *)info.dli_saddr),
                     buffer[i]);
        else
            snprintf(line, sizeof(line), "app[%p]", buffer[i]);
        syms[i] = strdup(line);
        if (!syms[i]) {
            while (--i >= 0) free(syms[i]);
            free(syms);
            return 0;
        }
    }
    return syms;
}

void backtrace_symbols_fd(void *const *buffer, int size, int fd) {
    char **syms;
    int i;
    if (!buffer || size <= 0 || fd < 0) return;
    syms = backtrace_symbols(buffer, size);
    if (!syms) return;
    for (i = 0; i < size; i++) {
        write(fd, syms[i], strlen(syms[i]));
        write(fd, "\n", 1);
        free(syms[i]);
    }
    free(syms);
}
