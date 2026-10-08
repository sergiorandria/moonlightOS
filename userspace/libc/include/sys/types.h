/* Moonlight libc - sys/types. */
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef int64_t off_t;
typedef int64_t ssize_t;
typedef int64_t time_t;
typedef int pid_t;
typedef unsigned mode_t;
typedef unsigned uid_t;
typedef unsigned gid_t;
typedef uint64_t dev_t;
typedef uint64_t ino_t;
typedef unsigned nlink_t;
typedef int blksize_t; /* kernel-UAPI width (glibc widens; same offsets) */
typedef int64_t blkcnt_t;
typedef int clockid_t;
typedef long clock_t;
typedef int id_t;
typedef unsigned long useconds_t;
typedef long suseconds_t;
