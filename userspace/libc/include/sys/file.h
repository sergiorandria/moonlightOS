/* Moonlight libc - sys/file (BSD flock).
 * Real: implemented over fcntl record locks (whole-file). */
#pragma once

#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8

int flock(int fd, int op);
