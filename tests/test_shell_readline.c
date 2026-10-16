/* test_shell_readline.c - shell_read_line must reassemble TTY fragments.
 *
 * tty_read returns at most TTY_BUF_SIZE (16) bytes per IPC round trip, but
 * a command line can be up to TTY_LINE_MAX-1 (255). A single tty_read per
 * shell_read_line executes a 75-char line as five separate commands.
 * The loop must keep reading until newline or buffer full.
 *
 * Run: gcc -Wall -Wextra -o /tmp/test_shell_readline tests/test_shell_readline.c && /tmp/test_shell_readline
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../userspace/include/services/ipc_protocol.h"

/* Scripted transport: each ipc_send_sync (MSG_APP_READ) returns the next
 * fragment; reads past the script return 0 readable bytes. */
static const char *read_script[] = {
    "echo ABCDEFGH", /* 12B, no newline: line continues */
    "IJKLMNOP\n",    /* 9B: completes "echo ABCDEFGHIJKLMNOP\n" */
};
static int read_step = 0;

int ipc_send_sync(uint32_t sender_tid, uint32_t target_tid, const void *msg, uint32_t msg_size, void *resp,
                  uint32_t resp_size)
{
    msg_app_read_resp_t *r = (msg_app_read_resp_t *)resp;
    (void)sender_tid;
    (void)target_tid;
    (void)msg;
    (void)msg_size;
    memset(r, 0, resp_size < sizeof(*r) ? resp_size : sizeof(*r));
    r->msg_type = 0;
    r->msg_id = 0;
    if (read_step < 2)
    {
        size_t n = strlen(read_script[read_step]);
        if (n > TTY_BUF_SIZE)
            n = TTY_BUF_SIZE;
        memcpy(r->data, read_script[read_step], n);
        r->len = (uint32_t)n;
        read_step++;
        return 0;
    }
    r->len = 0;
    return 0;
}

/* Unused by this test, but linked from the headers we pull in. */
int moonlight_asend(uint32_t ep_cptr, void *msg)
{
    (void)ep_cptr;
    (void)msg;
    return 0;
}

int ipc_send_async(uint32_t target_tid, const void *msg, uint32_t msg_size)
{
    (void)target_tid;
    (void)msg;
    (void)msg_size;
    return 0;
}

int moonlight_yield(void)
{
    return 0;
}

/* shell_platform_write is defined (static) by shell_tty.c itself. */

int moonlight_putc(char c)
{
    (void)c;
    return 0;
}

/* Pull in the real shell_read_line from the target TU. shell_tty.c also
 * pulls the full engine via shell_core.h; the stubs above satisfy it. */
#include "../userspace/sh/shell_tty.c"

int main(void)
{
    char buf[TTY_LINE_MAX];

    /* Long line split across two IPC fragments must come back whole,
     * WITHOUT the trailing newline, like a short line does. */
    int len = shell_read_line(buf, sizeof(buf));
    if (len != 21 || memcmp(buf, "echo ABCDEFGHIJKLMNOP", 21) != 0 || buf[21] != '\0')
    {
        printf("FAIL: long fragmented line: len=%d buf='%s' (want len=21 'echo ABCDEFGHIJKLMNOP')\n", len, buf);
        return 1;
    }
    printf("PASS: fragmented long line reassembled (%d bytes)\n", len);

    /* Reads past end-of-script return 0, not stale data. */
    len = shell_read_line(buf, sizeof(buf));
    if (len != 0)
    {
        printf("FAIL: empty read: len=%d (want 0)\n", len);
        return 1;
    }
    printf("PASS: empty read returns 0\n");

    printf("PASS: test_shell_readline\n");
    return 0;
}
