/*
 * main.c - TTY Service Entry Point
 *
 * Thread 12: TTY Service
 * Implements terminal line discipline, echo, and job control.
 */

#include "tty.h"
#include "services/ipc_protocol.h"

/* Entry point called from v2_start.S */
void tty_server_main(void) {
    /* Initialize TTY subsystem */
    tty_init();
    
    /* Enter main event loop (never returns) */
    tty_main();
}

/* Wrapper for v2_start.S compatibility */
void mem_server_main(void) {
    tty_server_main();
}
