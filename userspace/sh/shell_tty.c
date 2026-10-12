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

/* moonlight_yield comes from ipc_helpers.h (lib). */
#define TTY_LINE_MAX 256
#define SHELL_TTY_ID 0 /* Use TTY 0 (console F1) */
#define SHELL_TID 1    /* Shell is thread 1 */

/* Engine I/O hooks (shell_core.h externs), TTY-backed. Only
 * shell_platform_write and moonlight_yield are used on target
 * (the engine's putc declaration is currently uncalled). */
__attribute__((noinline)) static void shell_platform_write(const char *s, int len)
{
    if (s && len > 0)
    {
        /* Pacing now lives inside tty_write (one yield per 16-byte chunk:
         * 1:1 producer discipline, see there). */
        tty_write(SHELL_TID, SHELL_TTY_ID, s, (uint32_t)len);
    }
}

#include "shell_core.h"

/* Read one line from TTY (blocking). TTY returns at most TTY_BUF_SIZE
 * bytes per IPC round trip, so long lines arrive as multiple fragments:
 * keep reading until newline or the buffer is full. */
static int shell_read_line(char *buf, int max_len)
{
    int total = 0;
    int done = 0;

    while (!done && total < max_len - 1)
    {
        char frag[TTY_BUF_SIZE];
        int len = tty_read(SHELL_TID, SHELL_TTY_ID, frag, sizeof(frag));
        int i;

        if (len <= 0)
            break;
        for (i = 0; i < len && total < max_len - 1; i++)
        {
            buf[total++] = frag[i];
            if (frag[i] == '\n')
            {
                done = 1;
                break;
            }
        }
    }
    /* Over-long tail: discard through the newline so the next read starts
     * fresh instead of executing the tail as a new command. */
    while (!done)
    {
        char frag[TTY_BUF_SIZE];
        int len = tty_read(SHELL_TID, SHELL_TTY_ID, frag, sizeof(frag));
        int j;

        if (len <= 0)
            break;
        for (j = 0; j < len; j++)
        {
            if (frag[j] == '\n')
            {
                done = 1;
                break;
            }
        }
    }

    /* Remove trailing newline */
    while (total > 0 && (buf[total - 1] == '\n' || buf[total - 1] == '\r'))
    {
        total--;
    }

    buf[total] = '\0';
    return total;
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
