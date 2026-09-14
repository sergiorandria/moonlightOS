/* Moonlight libc - sys/personality (process-local execution domain). */
#pragma once

#define UNAME26 0x0020000
#define ADDR_NO_RANDOMIZE 0x0040000
#define READ_IMPLIES_EXEC 0x0400000
#define ADDR_COMPAT_LAYOUT 0x0200000
#define MMAP_PAGE_ZERO 0x010000
#define PER_LINUX 0x0000
#define PER_CLEAR_ON_SETID 0x1000000
#define ADDR_LIMIT_3GB 0x08000

int personality(unsigned long persona);
