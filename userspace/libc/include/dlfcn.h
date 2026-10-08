/* Moonlight libc - dlfcn. Handles for the main program resolve
 * against a registry of libc symbols; file-backed loads validate the
 * ELF header and report real errors (no dynamic loader on target). */
#pragma once

#define RTLD_LAZY 1
#define RTLD_NOW 2
#define RTLD_GLOBAL 0x100
#define RTLD_LOCAL 0
#define RTLD_DEFAULT ((void *)0)
#define RTLD_NEXT ((void *)-1)

void *dlopen(const char *path, int flags);
int dlclose(void *h);
void *dlsym(void *h, const char *name);
void *dlvsym(void *h, const char *name, const char *version);
int dladdr(const void *addr, void *info);
char *dlerror(void);

struct Dl_info {
    const char *dli_fname;
    void *dli_fbase;
    const char *dli_sname;
    void *dli_saddr;
};
