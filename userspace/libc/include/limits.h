/* Moonlight libc - limits (LP64; PATH/NAME from the flat VFS). */
#pragma once

#define CHAR_BIT 8
#define SCHAR_MIN (-127 - 1)
#define SCHAR_MAX 127
#define UCHAR_MAX 255
/* Target rv64 char is unsigned, host x86_64 signed: follow the compiler. */
#ifdef __CHAR_UNSIGNED__
#define CHAR_MIN 0
#define CHAR_MAX UCHAR_MAX
#else
#define CHAR_MIN SCHAR_MIN
#define CHAR_MAX SCHAR_MAX
#endif
#define MB_LEN_MAX 4 /* sole locale is UTF-8 (see wchar.h) */
#define SHRT_MIN (-32767 - 1)
#define SHRT_MAX 32767
#define USHRT_MAX 65535
#define INT_MIN (-2147483647 - 1)
#define INT_MAX 2147483647
#define UINT_MAX 4294967295u
#define LONG_MIN (-9223372036854775807l - 1l)
#define LONG_MAX 9223372036854775807l
#define ULONG_MAX 18446744073709551615ul
#define LLONG_MIN (-9223372036854775807ll - 1ll)
#define LLONG_MAX 9223372036854775807ll
#define ULLONG_MAX 18446744073709551615ull
#define SSIZE_MAX LONG_MAX

#define PATH_MAX 256
#define NAME_MAX 31
#define IOV_MAX 16
#define OPEN_MAX 16 /* VFS_FDS_PER_CLIENT (kernel/src/linux.c) */
#define TMP_MAX 1000
