/* Moonlight libc - crypt.h (SHA-crypt password hashing;
 * $5$ SHA-256 and $6$ SHA-512, implemented in src/crypt.c). */
#pragma once

#include <stddef.h>

struct crypt_data {
    char output[256];
    char setting[256];
    unsigned char internal[64];
    int initialized;
};

char *crypt(const char *key, const char *setting);
char *crypt_r(const char *key, const char *setting,
              struct crypt_data *data);
void setkey(const char *key);
void encrypt(char *block, int edflag);
