/* hello - minimal general-purpose app, dynamic thread + alloc */
#include "../lib/moonlight.h"
#include <stdint.h>

void _start(void) {
    // On real HW: purecap, every pointer is bounded
    char *msg = (char*)"hello moonlight\n";
    moonlight_call(1, msg);
    moonlight_yield();
    while(1) {}
}
