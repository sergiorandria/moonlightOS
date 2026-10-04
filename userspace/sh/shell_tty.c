/*
 * shell_tty.c - moonsh Shell Application (Production Microkernel Version)
 *
 * Pure application - no direct hardware access, no console logic.
 * All I/O goes through TTY service via IPC.
 *
 * Thread 1: Shell (moonsh)
 */

#include <stdint.h>
#include "services/ipc_helpers.h"
#include "services/ipc_protocol.h"
#include "../lib/moonlight.h"

#define SHELL_LINE_MAX 256
#define SHELL_TTY_ID 0  /* Use TTY 0 (console F1) */
#define SHELL_TID 1     /* Shell is thread 1 */

/* Simple string functions */
static int str_eq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static int str_len(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

static int str_ncmp(const char *a, const char *b, int n) {
    for (int i = 0; i < n; i++) {
        if (a[i] != b[i] || a[i] == '\0') 
            return (unsigned char)a[i] - (unsigned char)b[i];
    }
    return 0;
}

/* TTY output wrappers (unused but kept for potential future use) */
__attribute__((unused))
static void shell_putc(char c) {
    tty_write(SHELL_TID, SHELL_TTY_ID, &c, 1);
}

static void shell_puts(const char *s) {
    int len = str_len(s);
    if (len > 0) {
        tty_write(SHELL_TID, SHELL_TTY_ID, s, len);
    }
}

/* Read one line from TTY (blocking) */
static int shell_read_line(char *buf, int max_len) {
    int len = tty_read(SHELL_TID, SHELL_TTY_ID, buf, max_len - 1);
    if (len < 0) len = 0;
    
    /* Remove trailing newline */
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        len--;
    }
    
    buf[len] = '\0';
    return len;
}

/* Command execution */
static void shell_exec_line(const char *line) {
    /* Skip leading spaces */
    while (*line == ' ') line++;
    
    /* Empty line */
    if (*line == '\0') return;
    
    /* Built-in commands */
    if (str_eq(line, "help")) {
        shell_puts("moonsh 0.3 - MoonlightOS Shell\n");
        shell_puts("Commands:\n");
        shell_puts("  help    - Show this help\n");
        shell_puts("  echo    - Echo arguments\n");
        shell_puts("  ver     - Show version\n");
        shell_puts("  clear   - Clear screen\n");
        shell_puts("  exit    - Exit shell\n");
        
    } else if (str_ncmp(line, "echo ", 5) == 0) {
        shell_puts(line + 5);
        shell_puts("\n");
        
    } else if (str_eq(line, "echo")) {
        shell_puts("\n");
        
    } else if (str_eq(line, "ver") || str_eq(line, "version")) {
        shell_puts("moonsh 0.3 on MoonlightOS\n");
        shell_puts("Production microkernel architecture\n");
        shell_puts("GUI → Console → TTY → Shell message flow\n");
        
    } else if (str_eq(line, "clear") || str_eq(line, "cls")) {
        /* Send clear screen ANSI sequence */
        shell_puts("\x1b[2J\x1b[H");
        
    } else if (str_eq(line, "exit") || str_eq(line, "quit")) {
        shell_puts("Goodbye!\n");
        /* In production, would exit cleanly. For now, just loop. */
        
    } else {
        shell_puts("moonsh: unknown command: ");
        shell_puts(line);
        shell_puts("\n");
        shell_puts("Type 'help' for available commands\n");
    }
}

/*
 * Shell main entry point
 */
void shell_main(void) {
    char line_buf[SHELL_LINE_MAX];
    
    /* Open TTY 0 */
    msg_app_open_t open_msg = {
        .msg_type = MSG_APP_OPEN,
        .tty_id = SHELL_TTY_ID,
        .flags = 0
    };
    
    msg_response_t resp;
    
    /* Send MSG_APP_OPEN - ipc_send_sync will receive first response */
    int ret = ipc_send_sync(SHELL_TID, SERVICE_TTY, &open_msg, sizeof(open_msg), 
                           &resp, sizeof(resp));
    
    if (ret < 0 || resp.msg_type != MSG_ACK) {
        /* Failed - yield forever */
        for (;;) {
            moonlight_yield();
        }
    }
    
    /* Print banner */
    shell_puts("\n");
    shell_puts("=====================================\n");
    shell_puts("  moonsh 0.3 - MoonlightOS Shell\n");
    shell_puts("  Production Microkernel Architecture\n");
    shell_puts("=====================================\n");
    shell_puts("\n");
    shell_puts("Type 'help' for available commands\n");
    shell_puts("\n");
    
    /* Main shell loop */
    for (;;) {
        /* Print prompt */
        shell_puts("moonsh> ");
        
        /* Read line (blocking) */
        int len = shell_read_line(line_buf, SHELL_LINE_MAX);
        
        if (len < 0) {
            /* Read error - retry */
            continue;
        }
        
        /* Execute command */
        shell_exec_line(line_buf);
    }
}

/* Wrapper for v2_start.S compatibility */
void mem_server_main(void) {
    shell_main();
}
