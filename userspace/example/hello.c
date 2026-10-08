/* hello - minimal userspace app: says hi on the debug console, yields.
 * Freestanding: no libc, linked at 0x81000000 via user.ld. */
#include "moonlight.h"

static void puts(const char *s) {
    while (*s) moonlight_putc(*s++);
}

void hello_main(void) {
    puts("hello moonlight\n");
    moonlight_yield();
    for (;;) moonlight_yield();
}
