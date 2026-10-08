/*
 * tty.c - TTY Service Implementation
 *
 * Terminal line discipline and session management.
 *
 * Key design: blocking reads.
 *   When an application sends MSG_APP_READ and no line is ready yet,
 *   the TTY stashes the caller in pending_readers[] WITHOUT replying.
 *   When Enter is pressed (tty_process_enter), we flush all pending
 *   readers by sending them the completed line. This gives true blocking
 *   semantics without a busy-wait poll loop in the shell.
 */

#include "tty.h"
#include "services/ipc_helpers.h"
#include "services/ipc_protocol.h"
#include <stdint.h>

/* TTY state array */
static tty_state_t ttys[TTY_COUNT];

/* Forward declarations */
static void handle_console_input(const msg_console_input_t *msg);
static void handle_app_open(const msg_app_open_t *msg, uint32_t sender);
static void handle_app_read(const msg_app_read_t *msg, uint32_t sender);
static void handle_app_write(const msg_app_write_t *msg, uint32_t sender);
static void handle_app_ioctl(const msg_tty_ioctl_t *msg, uint32_t sender);

/* -----------------------------------------------------------------------
 * Debug helpers (UART ecall)
 * ----------------------------------------------------------------------- */
static inline void dbg_putc(char c) {
    asm volatile("li a7, 1; mv a0, %0; ecall" :: "r"((long)(unsigned char)c) : "a0", "a7");
}
static inline void dbg_puts(const char *s) {
    while (*s) dbg_putc(*s++);
}

/*
 * Initialize TTY service
 */
void tty_init(void) {
    for (uint32_t i = 0; i < TTY_COUNT; i++) {
        tty_state_t *tty = &ttys[i];

        /* Default flags: echo enabled, canonical mode */
        tty->flags = TTY_FLAG_ECHO | TTY_FLAG_CANON;
        tty->owner_tid = 0;

        /* Clear buffers */
        tty->input_head  = 0;
        tty->input_tail  = 0;
        tty->input_count = 0;
        tty->line_len    = 0;
        tty->line_ready  = 0;

        /* Associate with console */
        tty->console_id = i;

        /* Clear pending readers */
        tty->pending_count = 0;
        for (uint32_t j = 0; j < TTY_MAX_PENDING_READERS; j++) {
            tty->pending_readers[j].reader_tid = 0;
            tty->pending_readers[j].msg_id     = 0;
            tty->pending_readers[j].max_len    = 0;
        }
    }
}

/*
 * TTY service main loop
 */
void tty_main(void) {
    dbg_puts("TTY: service starting\n");

    ipc_message_t msg;
    uint32_t sender;

    while (1) {
        /* Wait for incoming message */
        int len = ipc_recv(SERVICE_TTY, &msg, sizeof(msg), &sender);

        if (len < 0) {
            dbg_putc('E');
            continue;
        }

        /* Dispatch based on message type */
        switch (msg.msg_type) {
            case MSG_CONSOLE_INPUT:
                handle_console_input(&msg.console_input);
                break;

            case MSG_APP_OPEN:
                handle_app_open(&msg.app_open, sender);
                break;

            case MSG_APP_READ:
                handle_app_read(&msg.app_read, sender);
                break;

            case MSG_APP_WRITE:
                handle_app_write(&msg.app_write, sender);
                break;

            case MSG_APP_IOCTL:
                handle_app_ioctl(&msg.tty_ioctl, sender);
                break;

            default:
                break;
        }
    }
}

/*
 * Handle input from console service.
 * Characters are processed through the line discipline; if a line becomes
 * ready, pending readers are woken immediately.
 */
static void handle_console_input(const msg_console_input_t *msg) {
    if (msg->tty_id >= TTY_COUNT) return;

    tty_state_t *tty = &ttys[msg->tty_id];

    for (uint32_t i = 0; i < msg->len; i++) {
        tty_input_char(tty, msg->data[i]);
    }
}

/*
 * Handle TTY open request from application
 */
static void handle_app_open(const msg_app_open_t *msg, uint32_t sender) {
    if (msg->tty_id >= TTY_COUNT) {
        msg_response_t resp = { .msg_type = MSG_ERROR, .msg_id = msg->msg_id, .status = 1 };
        ipc_reply(sender, &resp, sizeof(resp));
        return;
    }

    tty_state_t *tty = &ttys[msg->tty_id];
    tty->flags |= TTY_FLAG_OPEN;
    tty->owner_tid = sender;

    dbg_puts("TTY: opened by tid=");
    dbg_putc('0' + (sender % 10));
    dbg_putc('\n');

    msg_response_t resp = { .msg_type = MSG_ACK, .msg_id = msg->msg_id, .status = 0 };
    ipc_reply(sender, &resp, sizeof(resp));
}

/*
 * Handle read request from application.
 *
 * KEY CHANGE: if no line is ready, we stash the reader in pending_readers[]
 * and do NOT reply — the reply is deferred to tty_flush_pending_readers()
 * which is called from tty_process_enter() once a full line is available.
 */
static void handle_app_read(const msg_app_read_t *msg, uint32_t sender) {
    if (msg->tty_id >= TTY_COUNT) {
        msg_response_t resp = { .msg_type = MSG_ERROR, .msg_id = msg->msg_id, .status = 1 };
        ipc_reply(sender, &resp, sizeof(resp));
        return;
    }

    tty_state_t *tty = &ttys[msg->tty_id];

    /* If data is already available, reply immediately */
    if (tty->flags & TTY_FLAG_CANON) {
        if (tty->line_ready) {
            msg_app_read_resp_t resp;
            resp.msg_type = MSG_ACK;
            resp.msg_id   = msg->msg_id;
            resp.len = (uint32_t)tty_read_line(tty, resp.data, msg->max_len);
            ipc_reply(sender, &resp, sizeof(resp));
            return;
        }
    } else {
        if (tty->input_count > 0) {
            msg_app_read_resp_t resp;
            resp.msg_type = MSG_ACK;
            resp.msg_id   = msg->msg_id;
            resp.len = (uint32_t)tty_read_raw(tty, resp.data, msg->max_len);
            ipc_reply(sender, &resp, sizeof(resp));
            return;
        }
    }

    /* No data yet — stash this reader for a deferred reply */
    if (tty->pending_count < TTY_MAX_PENDING_READERS) {
        tty_pending_read_t *slot = &tty->pending_readers[tty->pending_count++];
        slot->reader_tid = sender;
        slot->msg_id     = msg->msg_id;
        slot->max_len    = msg->max_len > TTY_BUF_SIZE ? TTY_BUF_SIZE : msg->max_len;
        dbg_puts("TTY: read deferred for tid=");
        dbg_putc('0' + (sender % 10));
        dbg_putc('\n');
        /* DO NOT reply here - we will reply when line is ready */
    } else {
        /* Queue full - reply with empty data so caller doesn't hang forever */
        msg_app_read_resp_t resp;
        resp.msg_type = MSG_ACK;
        resp.msg_id   = msg->msg_id;
        resp.len      = 0;
        ipc_reply(sender, &resp, sizeof(resp));
    }
}

/*
 * Handle write request from application.
 * Writes text via TTY line discipline to the console.
 * Note: tty_write() in ipc_helpers.h is fire-and-forget async — we do NOT reply.
 */
static void handle_app_write(const msg_app_write_t *msg, uint32_t sender) {
    (void)sender;  /* No reply for async writes */

    if (msg->tty_id >= TTY_COUNT) {
        return;  /* silently drop invalid tty_id for async writes */
    }

    tty_state_t *tty = &ttys[msg->tty_id];

    /* Write to console via TTY → Console service */
    tty_output_string(tty, msg->data, msg->len);
}

/*
 * Handle ioctl request from application
 */
static void handle_app_ioctl(const msg_tty_ioctl_t *msg, uint32_t sender) {
    if (msg->tty_id >= TTY_COUNT) {
        msg_response_t resp = { .msg_type = MSG_ERROR, .status = 1 };
        ipc_reply(sender, &resp, sizeof(resp));
        return;
    }

    tty_state_t *tty = &ttys[msg->tty_id];

    switch (msg->cmd) {
        case TTY_IOCTL_ECHO:
            if (msg->arg) {
                tty->flags |= TTY_FLAG_ECHO;
            } else {
                tty->flags &= ~TTY_FLAG_ECHO;
            }
            break;

        case TTY_IOCTL_CANON:
            if (msg->arg) {
                tty->flags |= TTY_FLAG_CANON;
                tty->flags &= ~TTY_FLAG_RAW;
            } else {
                tty->flags &= ~TTY_FLAG_CANON;
            }
            break;

        case TTY_IOCTL_RAW:
            if (msg->arg) {
                tty->flags |= TTY_FLAG_RAW;
                tty->flags &= ~TTY_FLAG_CANON;
            } else {
                tty->flags &= ~TTY_FLAG_RAW;
            }
            break;

        case TTY_IOCTL_CLEAR:
            tty->input_count = 0;
            tty->input_head  = 0;
            tty->input_tail  = 0;
            tty->line_len    = 0;
            tty->line_ready  = 0;
            break;
    }

    msg_response_t resp = { .msg_type = MSG_ACK, .status = 0 };
    ipc_reply(sender, &resp, sizeof(resp));
}

/*
 * Process input character (with line discipline)
 */
void tty_input_char(tty_state_t *tty, char ch) {
    /* Raw mode: buffer directly, no processing */
    if (tty->flags & TTY_FLAG_RAW) {
        if (tty->input_count < TTY_INPUT_BUF_SIZE) {
            tty->input_buf[tty->input_head] = ch;
            tty->input_head = (tty->input_head + 1) % TTY_INPUT_BUF_SIZE;
            tty->input_count++;
        }
        /* Flush any pending raw readers immediately */
        tty_flush_pending_readers(tty);
        return;
    }

    /* Canonical mode: line editing */
    if (ch == CHAR_CTRL_C) {
        tty_output_string(tty, "^C\n", 3);
        tty->line_len = 0;
        return;
    }

    if (ch == CHAR_CTRL_D) {
        if (tty->line_len == 0) {
            /* EOF: mark line ready and flush readers with empty line */
            tty->line_ready = 1;
            tty_flush_pending_readers(tty);
        }
        return;
    }

    if (ch == CHAR_BACKSPACE || ch == CHAR_DELETE) {
        tty_process_backspace(tty);
        return;
    }

    if (ch == CHAR_CR || ch == CHAR_LF) {
        tty_process_enter(tty);
        return;
    }

    /* Regular character: add to line buffer */
    if (tty->line_len < TTY_LINE_BUF_SIZE - 1) {
        tty->line_buf[tty->line_len++] = ch;

        /* Echo character if enabled */
        if (tty->flags & TTY_FLAG_ECHO) {
            tty_output_char(tty, ch);
        }
    }
}

/*
 * Process backspace
 */
void tty_process_backspace(tty_state_t *tty) {
    if (tty->line_len > 0) {
        tty->line_len--;

        /* Echo backspace sequence: BS + space + BS */
        if (tty->flags & TTY_FLAG_ECHO) {
            tty_output_string(tty, "\b \b", 3);
        }
    }
}

/*
 * Process Enter key (line complete).
 * Copies line to input ring, marks line_ready, and flushes pending readers.
 */
void tty_process_enter(tty_state_t *tty) {
    /* Echo newline */
    if (tty->flags & TTY_FLAG_ECHO) {
        tty_output_string(tty, "\n", 1);
    }

    /* Copy line to input ring buffer */
    for (uint32_t i = 0; i < tty->line_len && tty->input_count < TTY_INPUT_BUF_SIZE; i++) {
        tty->input_buf[tty->input_head] = tty->line_buf[i];
        tty->input_head = (tty->input_head + 1) % TTY_INPUT_BUF_SIZE;
        tty->input_count++;
    }

    /* Add newline to input ring buffer */
    if (tty->input_count < TTY_INPUT_BUF_SIZE) {
        tty->input_buf[tty->input_head] = '\n';
        tty->input_head = (tty->input_head + 1) % TTY_INPUT_BUF_SIZE;
        tty->input_count++;
    }

    /* Mark line as ready */
    tty->line_ready = 1;
    tty->line_len   = 0;

    dbg_puts("TTY: line ready\n");

    /* Wake any readers that were waiting for this line */
    tty_flush_pending_readers(tty);
}

/*
 * Flush pending blocked read requests.
 * Called after a line becomes available; sends deferred replies to every
 * reader in pending_readers[].
 */
void tty_flush_pending_readers(tty_state_t *tty) {
    uint32_t i = 0;
    while (i < tty->pending_count) {
        tty_pending_read_t *pr = &tty->pending_readers[i];
        if (pr->reader_tid == 0) {
            i++;
            continue;
        }

        /* Check if data is available for this reader */
        int have_data = 0;
        if (tty->flags & TTY_FLAG_CANON) {
            have_data = tty->line_ready && (tty->input_count > 0);
        } else {
            have_data = (tty->input_count > 0);
        }

        if (!have_data) {
            i++;
            continue;
        }

        /* Build and send the reply */
        msg_app_read_resp_t resp;
        resp.msg_type = MSG_ACK;
        resp.msg_id   = pr->msg_id;

        if (tty->flags & TTY_FLAG_CANON) {
            resp.len = (uint32_t)tty_read_line(tty, resp.data, pr->max_len);
        } else {
            resp.len = (uint32_t)tty_read_raw(tty, resp.data, pr->max_len);
        }

        dbg_puts("TTY: waking reader tid=");
        dbg_putc('0' + (pr->reader_tid % 10));
        dbg_puts(", len=");
        dbg_putc('0' + (resp.len % 10));
        dbg_putc('\n');

        ipc_reply(pr->reader_tid, &resp, sizeof(resp));

        /* Remove from pending list (compact) */
        pr->reader_tid = 0;
        /* Shift remaining entries down */
        for (uint32_t j = i; j + 1 < tty->pending_count; j++) {
            tty->pending_readers[j] = tty->pending_readers[j + 1];
        }
        tty->pending_readers[tty->pending_count - 1].reader_tid = 0;
        tty->pending_count--;
        /* Don't advance i: slot[i] is now the next entry */
    }
}

/*
 * Read line from TTY (canonical mode).
 * Returns 0 if no line ready (shouldn't happen after flush, but safe).
 */
int tty_read_line(tty_state_t *tty, char *buf, uint32_t max_len) {
    if (!tty->line_ready) {
        return 0;
    }

    uint32_t count = 0;
    while (count < max_len && tty->input_count > 0) {
        char ch = tty->input_buf[tty->input_tail];
        tty->input_tail  = (tty->input_tail + 1) % TTY_INPUT_BUF_SIZE;
        tty->input_count--;

        buf[count++] = ch;

        if (ch == '\n') {
            break;
        }
    }

    /* Reset line_ready once the buffer is drained */
    if (tty->input_count == 0) {
        tty->line_ready = 0;
    }

    return (int)count;
}

/*
 * Read raw characters from TTY (raw mode)
 */
int tty_read_raw(tty_state_t *tty, char *buf, uint32_t max_len) {
    uint32_t count = 0;

    while (count < max_len && tty->input_count > 0) {
        buf[count++] = tty->input_buf[tty->input_tail];
        tty->input_tail  = (tty->input_tail + 1) % TTY_INPUT_BUF_SIZE;
        tty->input_count--;
    }

    return (int)count;
}

/*
 * Output single character to console
 */
void tty_output_char(tty_state_t *tty, char ch) {
    msg_tty_write_t msg = {
        .msg_type = MSG_TTY_WRITE,
        .tty_id   = tty->console_id,
        .len      = 1,
    };
    msg.data[0] = ch;

    ipc_send_async(SERVICE_CONSOLE, &msg, sizeof(msg));
}

/*
 * Output string to console
 */
void tty_output_string(tty_state_t *tty, const char *str, uint32_t len) {
    uint32_t sent = 0;
    while (sent < len) {
        msg_tty_write_t msg = {
            .msg_type = MSG_TTY_WRITE,
            .tty_id   = tty->console_id,
            .len      = 0,
        };

        while (msg.len < TTY_BUF_SIZE && sent < len) {
            msg.data[msg.len++] = str[sent++];
        }

        ipc_send_async(SERVICE_CONSOLE, &msg, sizeof(msg));
    }
}
