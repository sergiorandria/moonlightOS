/*
 * main.c - Console Service Entry Point
 *
 * Thread 11: Console Service
 * Manages text buffers, ANSI parsing, and screen rendering.
 */

#include "console.h"
#include "services/ipc_protocol.h"

/* Entry point called from v2_start.S */
void console_server_main(void) {
    /* Initialize console subsystem */
    console_init();
    
    /* Enter main event loop (never returns) */
    console_main();
}

/* Wrapper for v2_start.S compatibility */
void mem_server_main(void) {
    console_server_main();
}
