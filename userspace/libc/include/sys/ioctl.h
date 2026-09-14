/* Moonlight libc - sys/ioctl + fcntl additions. */
#pragma once

#include <sys/types.h>

int ioctl(int fd, unsigned req, ...);

struct winsize {
    unsigned short ws_row;
    unsigned short ws_col;
    unsigned short ws_xpixel;
    unsigned short ws_ypixel;
};

#define FIONREAD 0x541B
#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414
