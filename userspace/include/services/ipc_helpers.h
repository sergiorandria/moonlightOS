/*
 * ipc_helpers.h - Helper functions for service IPC
 *
 * Provides convenience wrappers around v2_ipc_call/v2_ipc_recv
 * for sending/receiving structured messages between services.
 */

#ifndef IPC_HELPERS_H
#define IPC_HELPERS_H

#include "ipc_protocol.h"
#include <stdint.h>

/* Cooperative pacing hook (ecall on target, no-op stub in host tests).
 * Declared here (mirrors lib/moonlight.h) so paced helpers below see it
 * regardless of include order at each TU. */
int moonlight_yield(void);

/* ============================================================================
 * Low-level IPC wrappers (to be implemented in ipc_helpers.c)
 * ============================================================================ */

/**
 * Send a message to a service and wait for response.
 *
 * @param sender_tid Our TID (for receiving the reply)
 * @param target_tid Target thread ID
 * @param msg        Pointer to message structure
 * @param msg_size   Size of message in bytes
 * @param resp       Pointer to response buffer (can be NULL)
 * @param resp_size  Size of response buffer
 * @return 0 on success, negative on error
 */
int ipc_send_sync(uint32_t sender_tid, uint32_t target_tid, const void *msg, uint32_t msg_size, void *resp,
                  uint32_t resp_size);

/**
 * Send a message to a service without waiting for response.
 *
 * @param target_tid Target thread ID
 * @param msg        Pointer to message structure
 * @param msg_size   Size of message in bytes
 * @return 0 on success, negative on error
 */
int ipc_send_async(uint32_t target_tid, const void *msg, uint32_t msg_size);

/**
 * Wait for incoming message from any service.
 *
 * @param my_tid    This thread's TID (used as receive endpoint)
 * @param msg       Pointer to message buffer
 * @param msg_size  Size of message buffer
 * @param sender    Pointer to store sender TID (can be NULL)
 * @return Number of bytes received, negative on error
 */
int ipc_recv(uint32_t my_tid, void *msg, uint32_t msg_size, uint32_t *sender);

/**
 * Reply to a received message.
 *
 * @param target_tid TID of sender to reply to
 * @param resp       Pointer to response structure
 * @param resp_size  Size of response in bytes
 * @return 0 on success, negative on error
 */
int ipc_reply(uint32_t target_tid, const void *resp, uint32_t resp_size);

/**
 * Check flow control status (queue pressure notification).
 *
 * @param my_tid This thread's TID
 * @return Non-zero if flow control notification is pending (bit 0), 0 otherwise
 */
uint32_t ipc_check_flow_control(uint32_t my_tid);

/* ============================================================================
 * High-level service-specific helpers
 * ============================================================================ */

/* GUI Service helpers */
static inline int gui_send_key_event(uint32_t keycode, uint32_t ascii, uint32_t modifiers, uint32_t pressed)
{
    msg_key_event_t msg = {
        .msg_type = MSG_GUI_KEY_EVENT, .keycode = keycode, .ascii = ascii, .modifiers = modifiers, .pressed = pressed};
    return ipc_send_async(SERVICE_CONSOLE, &msg, sizeof(msg));
}

static inline int gui_send_mouse_event(int32_t dx, int32_t dy, uint32_t buttons, int32_t x, int32_t y)
{
    msg_mouse_event_t msg = {.msg_type = MSG_GUI_MOUSE_EVENT, .dx = dx, .dy = dy, .buttons = buttons, .x = x, .y = y};
    return ipc_send_async(SERVICE_CONSOLE, &msg, sizeof(msg));
}

/* Console Service helpers. NOTE: per-cell PUTC and CLEAR senders were
 * removed (PUTS row runs / FILL cover them); tags 0x2000/0x2004 stay
 * parsed for wire compat. */

static inline int console_send_fill(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color)
{
    msg_console_fill_t msg = {.msg_type = MSG_CONSOLE_FILL, .x = x, .y = y, .width = w, .height = h, .color = color};
    return ipc_send_async(SERVICE_GUI, &msg, sizeof(msg));
}

/* Scroll the screen up by lines (single RPC: a full repaint would be
 * hundreds of PUTS and overflow the 32-deep queue, dropping paint). */
static inline int console_send_scroll(uint32_t lines)
{
    msg_console_scroll_t msg = {.msg_type = MSG_CONSOLE_SCROLL, .lines = lines, .top = 0, .bottom = 0};
    return ipc_send_async(SERVICE_GUI, &msg, sizeof(msg));
}

static inline int console_send_cursor(uint32_t x, uint32_t y, uint32_t visible)
{
    msg_console_cursor_t msg = {.msg_type = MSG_CONSOLE_CURSOR, .x = x, .y = y, .visible = visible};
    return ipc_send_async(SERVICE_GUI, &msg, sizeof(msg));
}

/* TTY Service helpers */

static inline int console_send_puts(uint32_t x, uint32_t y, uint32_t pal, const char *data, uint32_t len)
{
    msg_console_puts_t msg;
    if (len > 16)
        len = 16;
    msg.msg_type = MSG_CONSOLE_PUTS;
    msg.msg_id = 0;
    msg.xy = (x << 16) | (y & 0xFFFFu);
    msg.lenpal = (len & 0xFFu) | ((pal & 0xFFFFu) << 8);
    for (uint32_t i = 0; i < 16; i++)
        msg.data[i] = i < len ? data[i] : 0;
    return ipc_send_async(SERVICE_GUI, &msg, sizeof(msg));
}

/* Write data to TTY. Automatically chunks long strings into TTY_BUF_SIZE
 * segments for inline-only IPC (32-byte limit). */
static inline int tty_write(uint32_t sender_tid, uint32_t tty_id, const char *data, uint32_t len)
{
    (void)sender_tid; /* Not needed for async send */
    uint32_t sent = 0;
    while (sent < len)
    {
        msg_app_write_t msg = {.msg_type = MSG_APP_WRITE, .tty_id = tty_id, .len = 0};
        while (msg.len < TTY_BUF_SIZE && sent < len)
        {
            msg.data[msg.len++] = data[sent++];
        }
        /* Fire-and-forget async — TTY does NOT reply for writes */
        int ret = ipc_send_async(SERVICE_TTY, &msg, sizeof(msg));
        if (ret < 0)
            return ret;
        /* 1:1 producer pacing (help-burst loss): one yield per chunk keeps
         * our burst inside the consumer's drain rate instead of pinning
         * the 32-deep queue until it silently drops newlines/whole lines.
         * Companion pacing lives in tty.c (per-forward) and console.c
         * (PUTS batching + per-chunk yield discipline). */
        moonlight_yield();
    }
    return 0;
}

static inline int tty_read(uint32_t sender_tid, uint32_t tty_id, char *buf, uint32_t max_len)
{
    msg_app_read_t msg = {
        .msg_type = MSG_APP_READ, .tty_id = tty_id, .max_len = max_len > TTY_BUF_SIZE ? TTY_BUF_SIZE : max_len};
    msg_app_read_resp_t resp;

    int ret = ipc_send_sync(sender_tid, SERVICE_TTY, &msg, sizeof(msg), &resp, sizeof(resp));
    if (ret < 0)
        return ret;

    /* Copy response data to caller's buffer */
    for (uint32_t i = 0; i < resp.len && i < max_len; i++)
    {
        buf[i] = resp.data[i];
    }
    return resp.len;
}

/* Kernel boot log helper (used by kernel during boot) */
static inline int kernel_send_boot_log(const char *msg, uint32_t len)
{
    msg_kernel_boot_log_t log_msg = {.msg_type = MSG_KERNEL_BOOT_LOG,
                                     .len = len > KERNEL_LOG_SIZE ? KERNEL_LOG_SIZE : len};
    for (uint32_t i = 0; i < log_msg.len; i++)
    {
        log_msg.data[i] = msg[i];
    }
    return ipc_send_async(SERVICE_CONSOLE, &log_msg, sizeof(log_msg));
}

#endif /* IPC_HELPERS_H */
