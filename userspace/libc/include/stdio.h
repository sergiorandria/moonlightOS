/* Moonlight libc - stdio (unbuffered FILE over fds + memory streams). */
#pragma once

#include <stddef.h>
#include <stdarg.h>
#include <sys/types.h>

/* Unbuffered: every read/write is a syscall, but up to ML_PBN chars of
 * pushback are kept (ungetc/vfscanf lookahead; the standard requires 1). */
#define ML_PBN 4

typedef struct __ML_FILE {
    int fd;           /* kind 0 only */
    int eof;
    int err;
    char pb[ML_PBN];  /* pushed-back chars (LIFO) */
    int npb;
    int kind;         /* 0 = fd, 1 = fmemopen (caller buffer), 2 = memstream,
                         4 = wide memstream (UTF-8 bytes in membuf + wide
                         view below; byte layer is always the exact UTF-8
                         encoding of the wide view) */
    char *membuf;
    size_t memcap;
    size_t memlen;    /* high-water readable length */
    size_t mempos;    /* cursor */
    int memowned;     /* free membuf on fclose */
    char **pmem;      /* open_memstream: user pointer slot */
    size_t *pmemlen;
    wchar_t *wbuf;    /* kind 4: wide view (wlen chars + NUL, owned) */
    size_t wcap;
    size_t wlen;
    wchar_t **pwmem;  /* open_wmemstream: user pointer slot */
    size_t *pwmemlen;
    char *tmpname;    /* tmpfile: unlink at fclose */
    int orient;       /* stream orientation: 0 unset, <0 byte, >0 wide */
} FILE;

/* Wide-memstream backend (stdio.c; wchar_t via <stddef.h> above).
 * __ml_wputc appends/overwrites one wide char (keeping both views in
 * sync) and returns it, or -1 (WEOF) on failure. */
FILE *__ml_wmemstream_create(wchar_t **ptr, size_t *len);
int __ml_wputc(FILE *f, wchar_t c);

typedef long fpos_t;

extern FILE *__stdin_ptr;
extern FILE *__stdout_ptr;
extern FILE *__stderr_ptr;
#define stdin __stdin_ptr
#define stdout __stdout_ptr
#define stderr __stderr_ptr

#define EOF (-1)
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#define FOPEN_MAX 16
#define L_tmpnam 32

int printf(const char *fmt, ...);
int fprintf(FILE *f, const char *fmt, ...);
int vfprintf(FILE *f, const char *fmt, va_list ap);
int sprintf(char *s, const char *fmt, ...);
int snprintf(char *s, size_t n, const char *fmt, ...);
int vsnprintf(char *s, size_t n, const char *fmt, va_list ap);
int vprintf(const char *fmt, va_list ap);
int asprintf(char **sp, const char *fmt, ...);
int vasprintf(char **sp, const char *fmt, va_list ap);
int dprintf(int fd, const char *fmt, ...);
int vdprintf(int fd, const char *fmt, va_list ap);
int puts(const char *s);
int putchar(int c);
int fputs(const char *s, FILE *f);
int putc(int c, FILE *f);
int fputc(int c, FILE *f);

FILE *fopen(const char *path, const char *mode);
FILE *freopen(const char *path, const char *mode, FILE *f);
FILE *fdopen(int fd, const char *mode);
FILE *fmemopen(void *buf, size_t size, const char *mode);
FILE *open_memstream(char **ptr, size_t *len);
FILE *tmpfile(void);
char *tmpnam(char *s);
int remove(const char *path);
int rename(const char *oldp, const char *newp);
int fclose(FILE *f);
size_t fread(void *buf, size_t sz, size_t n, FILE *f);
size_t fwrite(const void *buf, size_t sz, size_t n, FILE *f);
int fseek(FILE *f, long off, int whence);
long ftell(FILE *f);
int fgetpos(FILE *f, fpos_t *pos);
int fsetpos(FILE *f, const fpos_t *pos);
void rewind(FILE *f);
int feof(FILE *f);
int ferror(FILE *f);
void clearerr(FILE *f);
int fflush(FILE *f);
int fileno(FILE *f);
int setvbuf(FILE *f, char *buf, int mode, size_t n);
void setbuf(FILE *f, char *buf);
#define _IOFBF 0
#define _IOLBF 1
#define _IONBF 2
#define BUFSIZ 1024
int getc(FILE *f);
int fgetc(FILE *f);
int getchar(void);
int ungetc(int c, FILE *f);
char *fgets(char *s, int n, FILE *f);
ssize_t getdelim(char **line, size_t *n, int delim, FILE *f);
ssize_t getline(char **line, size_t *n, FILE *f);
int scanf(const char *fmt, ...);
int vscanf(const char *fmt, va_list ap);
int fscanf(FILE *f, const char *fmt, ...);
int vfscanf(FILE *f, const char *fmt, va_list ap);
int sscanf(const char *s, const char *fmt, ...);
int vsscanf(const char *s, const char *fmt, va_list ap);

void perror(const char *msg);
char *strerror(int e);
FILE *popen(const char *cmd, const char *mode);
int pclose(FILE *f);
