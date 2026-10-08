/* Moonlight libc - sys/random.h (getrandom/getentropy live in
 * unistd.h; this header is the glibc-compatible alias). */
#pragma once

#include <unistd.h>
#include <stddef.h>

#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x1
#endif
#ifndef GRND_RANDOM
#define GRND_RANDOM 0x2
#endif
