/*
 * shell_tty.c - moonsh Shell Application (Production Microkernel Version)
 *
 * Pure application - no direct hardware access, no console logic.
 * All I/O goes through TTY service via IPC.
 *
 * Command execution comes from the BusyBox-style engine in shell_core.h
 * (50+ applets on the embedded VFS); this file only owns the TTY
 * session: open, banner, prompt/read loop, and the three extern hooks
 * the engine needs (platform_write/putc/yield).
 *
 * Thread 1: Shell (moonsh)
 */

#include "services/ipc_helpers.h"
#include "services/ipc_protocol.h"
#include <stdint.h>

int moonlight_yield(void); /* from lib; putc comes from the TTY shim below */

#define TTY_LINE_MAX 256
#define SHELL_TTY_ID 0 /* Use TTY 0 (console F1) */
#define SHELL_TID 1    /* Shell is thread 1 */

/* Engine I/O hooks (shell_core.h externs), TTY-backed. Only
 * shell_platform_write and moonlight_yield are used on target
 * (the engine's putc declaration is currently uncalled). */
static unsigned tty_write_count;
__attribute__((noinline)) static void shell_platform_write(const char *s, int len)
{
    if (s && len > 0)
    {
        tty_write(SHELL_TID, SHELL_TTY_ID, s, (uint32_t)len);
        /* Paced output: bursts (help ~60 puts) overflow the 32-slot
         * queue while the consumer never runs (no preemption mid-exec),
         * dropping paint permanently. Yield regularly to let it drain. */
        if (++tty_write_count % 8u == 0u)
            moonlight_yield();
    }
}

#include "shell_core.h"

/* Read one line from TTY (blocking) */
static int shell_read_line(char *buf, int max_len)
{
    int len = tty_read(SHELL_TID, SHELL_TTY_ID, buf, max_len - 1);
    if (len < 0)
        len = 0;

    /* Remove trailing newline */
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
    {
        len--;
    }

    buf[len] = '\0';
    return len;
}

/*
 * Shell main entry point
 */
void shell_main(void)
{
    char line_buf[TTY_LINE_MAX];

    /* Open TTY 0 */
    msg_app_open_t open_msg = {.msg_type = MSG_APP_OPEN, .tty_id = SHELL_TTY_ID, .flags = 0};

    msg_response_t resp;

    /* Send MSG_APP_OPEN - ipc_send_sync will receive first response */
    int ret = ipc_send_sync(SHELL_TID, SERVICE_TTY, &open_msg, sizeof(open_msg), &resp, sizeof(resp));

    if (ret < 0 || resp.msg_type != MSG_ACK)
    {
        /* Failed - yield forever */
        for (;;)
        {
            moonlight_yield();
        }
    }

    /* Print banner */
    shell_platform_write("\n", 1);
    shell_platform_write("=====================================\n", 38);
    shell_platform_write("  moonsh 0.3 - MoonlightOS Shell\n", 32);
    shell_platform_write("  Production Microkernel Architecture\n", 39);
    shell_platform_write("=====================================\n", 38);
    shell_platform_write("\n", 1);
    shell_platform_write("Type 'help' or 'busybox' for available commands\n", 48);
    shell_platform_write("\n", 1);

    /* Main shell loop */
    for (;;)
    {
        /* Print prompt */
        shell_platform_write("moonsh> ", 8);

        /* Read line (blocking) */
        int len = shell_read_line(line_buf, TTY_LINE_MAX);

        if (len < 0)
        {
            /* Read error - retry */
            continue;
        }

        /* Execute via the BusyBox engine (empty lines are no-ops) */
        if (len > 0)
            shell_exec_line(line_buf);
    }
}

/* Wrapper for v2_start.S compatibility */
void mem_server_main(void)
{
    shell_main();
}
