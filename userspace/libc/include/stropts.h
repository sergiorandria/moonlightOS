/* Moonlight libc - stropts (STREAMS compat over fds).
 * No STREAMS modules exist on this target: isastream() reports the true
 * answer (0 after validating the fd), and the message functions run the
 * real pipe/socket byte stream through read/write with full validation
 * (implemented in src/stropts.c). */
#pragma once

#include <sys/types.h>

#define I_NREAD 0x5302
#define I_PUSH 0x5306
#define I_POP 0x5307
#define I_LOOK 0x5308
#define I_FLUSH 0x5309
#define I_SRDOPT 0x5344
#define I_GRDOPT 0x5345
#define I_STR 0x5350
#define I_SETSIG 0x5351
#define I_GETSIG 0x5352
#define I_FIND 0x5353
#define I_LINK 0x5354
#define I_UNLINK 0x5355
#define I_PEEK 0x5357
#define I_FDINSERT 0x5358
#define I_SENDFD 0x5359
#define I_RECVFD 0x535A
#define I_SWROPT 0x535B
#define I_GWROPT 0x535C
#define I_LIST 0x535D
#define I_ATMARK 0x535E
#define I_CKBAND 0x535F
#define I_GETBAND 0x5360
#define I_CANPUT 0x5361
#define I_SETCLTIME 0x5362
#define I_GETCLTIME 0x5363
#define I_SERROPT 0x5365
#define I_GERROPT 0x5366

#define FLUSHR 1
#define FLUSHW 2
#define FLUSHRW 3

#define MORECTL 1
#define MOREDATA 2

#define MSG_ANY 0
#define MSG_BAND 1
#define MSG_HIPRI 2

#define RS_HIPRI 1

#define S_INPUT 1
#define S_HIPRI 2
#define S_OUTPUT 4
#define S_MSG 8
#define S_ERROR 16
#define S_HANGUP 32
#define S_RDNORM 64
#define S_WRNORM 256
#define S_RDBAND 128
#define S_WRBAND 512
#define S_BANDURG 1024

#define MUXID_ALL (-1)

struct strbuf {
    int maxlen;
    int len;
    char *buf;
};

struct strpeek {
    struct strbuf ctlbuf;
    struct strbuf databuf;
    long flags;
};

struct strfdinsert {
    struct strbuf ctlbuf;
    struct strbuf databuf;
    long flags;
    int fildes;
    int offset;
};

struct strioctl {
    int ic_cmd;
    int ic_timout;
    int ic_len;
    char *ic_dp;
};

int isastream(int fd);
int getmsg(int fd, struct strbuf *ctl, struct strbuf *dat, int *flags);
int getpmsg(int fd, struct strbuf *ctl, struct strbuf *dat, int *band,
            int *flags);
int putmsg(int fd, const struct strbuf *ctl, const struct strbuf *dat,
           int flags);
int putpmsg(int fd, const struct strbuf *ctl, const struct strbuf *dat,
            int band, int flags);
int fattach(int fd, const char *path);
int fdetach(const char *path);
