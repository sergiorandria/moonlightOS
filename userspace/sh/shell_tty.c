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

/* Print one liveness marker as an exact whole line: "LIVE: tid=N ok\n".
 * Emitted straight to the UART (moonlight_putc), not through TTY/console,
 * so a probe marker survives a dead TTY/console service. tools/verify.sh
 * asserts each with grep -qxF. */
static void shell_live_marker(uint32_t tid)
{
    moonlight_putc('L');
    moonlight_putc('I');
    moonlight_putc('V');
    moonlight_putc('E');
    moonlight_putc(':');
    moonlight_putc(' ');
    moonlight_putc('t');
    moonlight_putc('i');
    moonlight_putc('d');
    moonlight_putc('=');
    if (tid >= 10)
        moonlight_putc((char)('0' + (tid / 10) % 10));
    moonlight_putc((char)('0' + (tid % 10)));
    moonlight_putc(' ');
    moonlight_putc('o');
    moonlight_putc('k');
    moonlight_putc('\n');
}

/* Boot liveness round-trips (R0.5). Ping every IPC-serving service and wait
 * for its pong; print one whole-line marker per answered service. This
 * proves the service RUNS and SERVES IPC, which the load-time
 * "[spawn] X ELF ok" marker cannot.
 *
 * Pinged targets: mem_server (2), console (3), tty (4), vault (8), and
 * cryptblk (9). Expected to answer: the first four. cryptblk parks in its
 * boot-time vault-seed handoff before ever reaching its service loop, so it
 * is currently expected to stay silent (root cause + evidence:
 * .superpowers/sdd/2026-10-16-production-hardening/task-0.6-report.md §5.1,
 * pre-existing defect, not introduced here). Its load is still asserted via
 * "[spawn] cryptblk ELF ok".
 *   - cryptblk (9) is pinged anyway, but is NOT part of the drain's
 *     completion set: a silent tid 9 must never block this prober or
 *     deadlock boot. If it ever answers, its PONG is still printed (and
 *     tools/verify.sh pins "LIVE: tid=9 ok" ABSENT so any change to
 *     cryptblk liveness trips the gate).
 *   - gui (10): not an IPC server (no receive loop); covered by its three
 *     readiness markers.
 *
 * All pings are sent before the first wait so a service that never answers
 * leaves only its OWN marker missing. The wait is bounded by the four
 * expected replies; a wedged service is bounded by the gate's QEMU timeout,
 * since V2 has no timer-armed receive. */
static void shell_probe_services(void)
{
    static const uint32_t targets[] = {SERVICE_MEM, SERVICE_CONSOLE, SERVICE_TTY, SERVICE_VAULT, SERVICE_CRYPTBLK};
    /* targets[0 .. n_expected-1] are the ones we drain for. SERVICE_CRYPTBLK
     * (last) is deliberately outside the completion set. */
    const uint32_t n = (uint32_t)(sizeof(targets) / sizeof(targets[0]));
    const uint32_t n_expected = 4;
    const uint32_t want = (1u << n_expected) - 1u;
    ipc_msg_header_t ping = {.msg_type = MSG_PING, .msg_id = 0};
    uint32_t seen = 0;
    uint32_t i;

    for (i = 0; i < n; i++)
        (void)ipc_send_async(targets[i], &ping, sizeof(ping));

    while ((seen & want) != want)
    {
        ipc_message_t resp;
        uint32_t sender = 0;
        int len = ipc_recv(SHELL_TID, &resp, sizeof(resp), &sender);

        if (len < 0)
            break; /* receive error: report what already answered */
        if (resp.msg_type != MSG_PONG)
            continue; /* unrelated message: ignore. Assumes nothing sends to
                       * the shell before the MSG_APP_OPEN sync send below;
                       * an early-boot message would be dropped here. */

        for (i = 0; i < n; i++)
        {
            if (targets[i] == sender && !(seen & (1u << i)))
            {
                seen |= (1u << i);
                shell_live_marker(targets[i]);
            }
        }
    }
}

/*
 * Shell main entry point
 */
void shell_main(void)
{
    char line_buf[TTY_LINE_MAX];

    /* Prove each IPC service is live before anything else runs at the
     * prompt (and before the shell->TTY open send the gate polls for). */
    shell_probe_services();

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
