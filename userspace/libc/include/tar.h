/* Moonlight libc - tar.h (USTAR format).
 * Header-only and complete: field offsets for readers/writers. */
#pragma once

#define TMAGIC "ustar"
#define TMAGLEN 6
#define TVERSION "00"
#define TVERSLEN 2

#define REGTYPE '0'
#define AREGTYPE '\0'
#define LNKTYPE '1'
#define SYMTYPE '2'
#define CHRTYPE '3'
#define BLKTYPE '4'
#define DIRTYPE '5'
#define FIFOTYPE '6'
#define CONTTYPE '7'

#define TSUID 04000
#define TSGID 02000
#define TSVTX 01000
#define TUREAD 0400
#define TUWRITE 0200
#define TUEXEC 0100
#define TGREAD 0040
#define TGWRITE 0020
#define TGEXEC 0010
#define TOREAD 0004
#define TOWRITE 0002
#define TOEXEC 0001

struct tar_header {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char pad[12];
};
