/* Moonlight libc - ulimit.h (file-size limits via rlimit). */
#pragma once

#define UL_GETFSIZE 1
#define UL_SETFSIZE 2
#define UL_GMEMLIM 3
#define UL_GDESLIM 4

long ulimit(int cmd, ...);
