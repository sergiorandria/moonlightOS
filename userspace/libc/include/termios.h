/* Moonlight libc - termios. Line discipline lives in the kernel
 * console path (TCSETS honors ECHO/ICANON); cfsetspeed stores the rate. */
#pragma once

#include <sys/types.h>

typedef unsigned tcflag_t;
typedef unsigned char cc_t;
typedef unsigned speed_t;

struct termios {
    tcflag_t c_iflag;
    tcflag_t c_oflag;
    tcflag_t c_cflag;
    tcflag_t c_lflag;
    cc_t c_cc[8];
};

#define VINTR 0
#define VQUIT 1
#define VERASE 2
#define VKILL 3
#define VEOF 4
#define VMIN 5
#define VTIME 6
#define VSTART 7

#define BRKINT 0000002
#define ICRNL 0000400
#define IGNCR 0000200
#define IGNPAR 0000004
#define INLCR 0000100
#define IXON 0002000
#define IXOFF 0001000
#define ISTRIP 0000040
#define PARMRK 0000010

#define OPOST 0000001
#define ONLCR 0000004
#define OCRNL 0000010
#define ONOCR 0000020
#define ONLRET 0000040

#define CSIZE 0000060
#define CS5 0000000
#define CS6 0000020
#define CS7 0000040
#define CS8 0000060
#define CSTOPB 0000100
#define CREAD 0000200
#define PARENB 0000400
#define PARODD 0001000
#define HUPCL 0002000
#define CLOCAL 0004000

#define ISIG 0000001
#define ICANON 0000002
#define ECHO 0000010
#define ECHOE 0000020
#define ECHOK 0000040
#define ECHONL 0000100
#define NOFLSH 0000200
#define IEXTEN 0100000
#define ECHOCTL 0001000

#define TCSANOW 0
#define TCSADRAIN 1
#define TCSAFLUSH 2
#define TCIFLUSH 0
#define TCOFLUSH 1
#define TCIOFLUSH 2
#define TCOOFF 0
#define TCOON 1
#define TCIOFF 2
#define TCION 3

#define B0 0
#define B50 50
#define B75 75
#define B110 110
#define B134 134
#define B150 150
#define B300 300
#define B600 600
#define B1200 1200
#define B2400 2400
#define B4800 4800
#define B9600 9600
#define B19200 19200
#define B38400 38400
#define B57600 57600
#define B115200 115200

speed_t cfgetispeed(const struct termios *t);
speed_t cfgetospeed(const struct termios *t);
int cfsetispeed(struct termios *t, speed_t s);
int cfsetospeed(struct termios *t, speed_t s);
int cfsetspeed(struct termios *t, speed_t s);
int tcgetattr(int fd, struct termios *t);
int tcsetattr(int fd, int action, const struct termios *t);
int tcsendbreak(int fd, int dur);
int tcdrain(int fd);
int tcflush(int fd, int what);
int tcflow(int fd, int action);
int tcflow(int fd, int action);
pid_t tcgetsid(int fd);
