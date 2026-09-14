/* Moonlight libc - string. */
#pragma once

#include <stddef.h>

void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
void *memchr(const void *s, int c, size_t n);

size_t strlen(const char *s);
size_t strnlen(const char *s, size_t max);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
char *strcpy(char *d, const char *s);
char *strncpy(char *d, const char *s, size_t n);
char *strcat(char *d, const char *s);
char *strncat(char *d, const char *s, size_t n);
char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
char *strstr(const char *h, const char *n);
char *strdup(const char *s);
char *strndup(const char *s, size_t n);
char *strsep(char **sp, const char *delim);
void *memccpy(void *d, const void *s, int c, size_t n);
char *stpcpy(char *d, const char *s);
char *stpncpy(char *d, const char *s, size_t n);
char *strsignal(int sig);
int strerror_r(int e, char *buf, size_t n);
size_t strspn(const char *s, const char *acc);
size_t strcspn(const char *s, const char *rej);
char *strpbrk(const char *s, const char *acc);
char *strtok(char *s, const char *delim);
char *strtok_r(char *s, const char *delim, char **save);
char *strchrnul(const char *s, int c);
void *memmem(const void *h, size_t hn, const void *n, size_t nl);
size_t strlcpy(char *d, const char *s, size_t n);
size_t strlcat(char *d, const char *s, size_t n);
void explicit_bzero(void *s, size_t n);
/* No locale: collation is byte order (true in the C locale). */
int strcoll(const char *a, const char *b);
size_t strxfrm(char *d, const char *s, size_t n);
char *strerror(int e);
void *memrchr(const void *s, int c, size_t n);
int strverscmp(const char *a, const char *b);
char *strcasestr(const char *h, const char *n);
