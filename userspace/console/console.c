/*
 * console.c - Console Service Implementation
 *
 * Text rendering and buffer management for MoonlightOS.
 * Receives input from GUI, outputs rendering commands to GUI.
 * Provides text I/O interface to TTY service.
 */

#include "console.h"
#include "services/ipc_helpers.h"
#include "services/ipc_protocol.h"
#include <stdint.h>

/* Console state (12 virtual consoles) */
static console_state_t consoles[CONSOLE_COUNT];
static uint32_t active_console = 0; /* Currently visible console (0-11) */

/* Forward declarations */
static void handle_gui_key_event(const msg_key_event_t *msg);
static void handle_gui_mouse_event(const msg_mouse_event_t *msg);
static void handle_tty_write(const msg_tty_write_t *msg);
static void handle_kernel_boot_log(const msg_kernel_boot_log_t *msg);

/* Flush the pending paint run as one MSG_CONSOLE_PUTS (active console
 * only; inactive consoles repaint from cells on switch). Always resets
 * the run: cells already hold the truth. Bold is pre-resolved to a
 * bright palette index (same rule the old per-cell path used) so the GUI stays a
 * dumb painter. The GUI draws the cursor at the run end, so no separate
 * CURSOR RPC is needed on the hot path. */
static void console_flush_run(console_state_t *cons)
{
    if (cons->prun_active && cons->prun_len > 0 && cons == &consoles[active_console])
    {
        uint32_t fgi = cons->prun_fg;
        uint32_t pal;
        if (cons->prun_attr & ATTR_BOLD)
            fgi = (fgi & 0x7u) | (uint32_t)COLOR_BRIGHT;
        pal = (fgi & 0xFu) | (((uint32_t)cons->prun_bg & 0xFu) << 4);
        console_send_puts(cons->prun_x, cons->prun_y, pal, cons->prun_data, cons->prun_len);
        cons->puts_sent++;
    }
    cons->prun_active = 0;
    cons->prun_len = 0;
}

/* Accumulate one cell into the pending run, flushing first on any run
 * break (new row, colors/attr change, run full). */
static void console_run_put(console_state_t *cons, uint32_t x, uint32_t y, char ch, uint8_t fg, uint8_t bg,
                            uint8_t attr)
{
    if (!(cons->prun_active && cons->prun_len < 16 && cons->prun_x + (uint32_t)cons->prun_len == x &&
          cons->prun_y == y && cons->prun_fg == fg && cons->prun_bg == bg && cons->prun_attr == attr))
    {
        console_flush_run(cons);
        cons->prun_active = 1;
        cons->prun_x = x;
        cons->prun_y = y;
        cons->prun_fg = fg;
        cons->prun_bg = bg;
        cons->prun_attr = attr;
        cons->prun_len = 0;
    }
    cons->prun_data[cons->prun_len++] = ch;
}

/*
 * Initialize console service
 */
void console_init(void)
{
    /* Initialize all consoles */
    for (uint32_t i = 0; i < CONSOLE_COUNT; i++)
    {
        console_state_t *cons = &consoles[i];

        /* Clear screen buffer */
        for (uint32_t y = 0; y < CONSOLE_HEIGHT; y++)
        {
            for (uint32_t x = 0; x < CONSOLE_WIDTH; x++)
            {
                cons->cells[y][x].ch = ' ';
                cons->cells[y][x].fg = COLOR_WHITE;
                cons->cells[y][x].bg = COLOR_BLACK;
                cons->cells[y][x].attr = 0;
            }
        }

        /* Initialize cursor and colors */
        cons->cursor_x = 0;
        cons->cursor_y = 0;
        cons->cursor_visible = 1;
        cons->fg_color = COLOR_WHITE;
        cons->bg_color = COLOR_BLUE;
        cons->attr = 0;

        /* Scroll region = entire screen */
        cons->scroll_top = 0;
        cons->scroll_bottom = CONSOLE_HEIGHT - 1;

        /* ANSI parser reset */
        cons->ansi_state = 0;
        cons->ansi_param_count = 0;

        /* Boot log (console 0 only) */
        cons->boot_log_len = 0;
    }

    /* Clear GUI framebuffer */
    console_clear(&consoles[0]);
    console_render_all(&consoles[0]);
}

/*
 * Console service main loop
 */
void console_main(void)
{
    ipc_message_t msg;
    uint32_t sender;

    while (1)
    {
        /* Wait for incoming message */
        int len = ipc_recv(SERVICE_CONSOLE, &msg, sizeof(msg), &sender);
        if (len < 0)
            continue;

        /* Dispatch based on message type */
        switch (msg.msg_type)
        {
        case MSG_GUI_KEY_EVENT:
            handle_gui_key_event(&msg.key_event);
            break;

        case MSG_GUI_MOUSE_EVENT:
            handle_gui_mouse_event(&msg.mouse_event);
            break;

        case MSG_TTY_WRITE:
            handle_tty_write(&msg.tty_write);
            break;

        case MSG_KERNEL_BOOT_LOG:
            handle_kernel_boot_log(&msg.kernel_boot_log);
            break;

        default:
            /* Unknown message - ignore */
            break;
        }

        /* 1:1 consumer pacing (help-burst loss): one yield per handled
         * message keeps our PUTS emission inside the GUI's MMIO-bound
         * drain rate. Without it this loop burst-drains a full backlog
         * into the 32-deep GUI queue in one slice and the tail drops.
         * Companion pacing: shell/TTY yield per chunk (producers). */
        moonlight_yield();
    }
}

/*
 * Handle keyboard event from GUI
 */
static void handle_gui_key_event(const msg_key_event_t *msg)
{
    if (!msg->pressed)
        return; /* Only process key down events */

    /* Check for console switch (Alt+F1 through Alt+F12) */
    if (msg->modifiers & KEY_MOD_ALT)
    {
        if (msg->keycode >= 0x3B && msg->keycode <= 0x46)
        { /* F1-F12 */
            uint32_t new_console = msg->keycode - 0x3B;
            /* Fail closed: CONSOLE_COUNT is 1, so consoles[1..] do not
             * exist — switching there reads OOB and faults the console
             * thread (dead UI + dead input). Ignore out-of-range targets. */
            if (new_console >= (uint32_t)CONSOLE_COUNT)
                return;
            if (new_console != active_console)
            {
                active_console = new_console;
                console_render_all(&consoles[active_console]);
            }
            return;
        }
    }

    /* Forward ASCII input to TTY service */
    if (msg->ascii > 0)
    {
        msg_console_input_t input = {
            .msg_type = MSG_CONSOLE_INPUT,
            .tty_id = active_console,
            .len = 1,
        };
        input.data[0] = (char)msg->ascii;
        ipc_send_async(SERVICE_TTY, &input, sizeof(input));
    }
}

/*
 * Handle mouse event from GUI (currently unused by console)
 */
static void handle_gui_mouse_event(const msg_mouse_event_t *msg)
{
    /* Mouse events can be used for selection/copy-paste in future */
    (void)msg;
}

/*
 * Handle write request from TTY
 */
static void handle_tty_write(const msg_tty_write_t *msg)
{
    if (msg->tty_id >= CONSOLE_COUNT)
        return;

    console_state_t *cons = &consoles[msg->tty_id];
    uint32_t ox = cons->cursor_x, oy = cons->cursor_y, os = cons->puts_sent;
    console_write(cons, msg->data, msg->len);

    /* Paint the tail run: the shell blocks on its next read right after a
     * burst, so an unflushed tail would leave the prompt invisible until
     * more output arrives. Cursor position rides each PUTS (GUI draws the
     * underline at the run end), so no CURSOR RPC is needed here — unless
     * the chunk moved the cursor without painting anything (bare newlines,
     * tabs), in which case the underline would lag one chunk behind. */
    console_flush_run(cons);
    if (cons->puts_sent == os && (cons->cursor_x != ox || cons->cursor_y != oy) && msg->tty_id == active_console)
        console_update_cursor(cons);
}

/*
 * Handle kernel boot log message
 */
static void handle_kernel_boot_log(const msg_kernel_boot_log_t *msg)
{
    console_state_t *cons = &consoles[0]; /* Boot log goes to console 0 */

    /* Append to boot log buffer */
    for (uint32_t i = 0; i < msg->len && cons->boot_log_len < 4096; i++)
    {
        cons->boot_log[cons->boot_log_len++] = msg->data[i];
    }

    /* Display immediately */
    console_write(cons, msg->data, msg->len);
    console_flush_run(cons);

    /* Update display if console 0 is active */
    if (active_console == 0)
    {
        console_update_cursor(cons);
    }
}

/*
 * Write string to console (with ANSI parsing)
 */
void console_write(console_state_t *cons, const char *data, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++)
    {
        console_putchar(cons, data[i]);
    }
}

/*
 * Write single character to console
 */
void console_putchar(console_state_t *cons, char ch)
{
    /* ANSI escape sequence processing */
    if (cons->ansi_state > 0)
    {
        console_process_ansi(cons, ch);
        return;
    }

    /* Handle control characters */
    if (ch == '\n')
    {
        cons->cursor_x = 0;
        cons->cursor_y++;
        if (cons->cursor_y >= CONSOLE_HEIGHT)
        {
            console_scroll_up(cons, 1);
            cons->cursor_y = CONSOLE_HEIGHT - 1;
        }
        return;
    }
    else if (ch == '\r')
    {
        cons->cursor_x = 0;
        return;
    }
    else if (ch == '\b')
    {
        if (cons->cursor_x > 0)
            cons->cursor_x--;
        return;
    }
    else if (ch == '\t')
    {
        cons->cursor_x = (cons->cursor_x + 8) & ~7;
        if (cons->cursor_x >= CONSOLE_WIDTH)
        {
            cons->cursor_x = 0;
            cons->cursor_y++;
            /* Same scroll discipline as \n/wrap: tab at bottom must
             * scroll, not run cursor_y out of bounds (OOB cells write
             * corrupts state and overwrites visible rows). Ref: BusyBox
             * ash tab handling advances to next tab stop with wrap. */
            if (cons->cursor_y >= CONSOLE_HEIGHT)
            {
                console_scroll_up(cons, 1);
                cons->cursor_y = CONSOLE_HEIGHT - 1;
            }
        }
        return;
    }
    else if (ch == 0x1B)
    { /* ESC - start ANSI sequence (flush: colors may change) */
        console_flush_run(cons);
        cons->ansi_state = 1;
        return;
    }

    /* Printable character: store the cell, accumulate the paint run (one
     * PUTS per same-row/same-color run, up to 16 cells). Post-advance rows
     * flush lazily on the next char or at chunk end; scroll paths flush
     * explicitly since coords go stale. */
    if (ch >= 0x20 && ch <= 0x7E)
    {
        cons->cells[cons->cursor_y][cons->cursor_x].ch = ch;
        cons->cells[cons->cursor_y][cons->cursor_x].fg = cons->fg_color;
        cons->cells[cons->cursor_y][cons->cursor_x].bg = cons->bg_color;
        cons->cells[cons->cursor_y][cons->cursor_x].attr = cons->attr;

        console_run_put(cons, cons->cursor_x, cons->cursor_y, ch, cons->fg_color, cons->bg_color, cons->attr);

        /* Advance cursor */
        cons->cursor_x++;
        if (cons->cursor_x >= CONSOLE_WIDTH)
        {
            cons->cursor_x = 0;
            cons->cursor_y++;
            if (cons->cursor_y >= CONSOLE_HEIGHT)
            {
                console_scroll_up(cons, 1);
                cons->cursor_y = CONSOLE_HEIGHT - 1;
            }
        }
    }
}

/*
 * Process ANSI escape sequence
 */
void console_process_ansi(console_state_t *cons, char ch)
{
    if (cons->ansi_state == 1)
    { /* After ESC */
        if (ch == '[')
        {
            cons->ansi_state = 2;
            cons->ansi_param_count = 0;
            for (int i = 0; i < 8; i++)
                cons->ansi_params[i] = 0;
        }
        else
        {
            cons->ansi_state = 0; /* Unknown sequence, reset */
        }
        return;
    }

    if (cons->ansi_state == 2)
    { /* Inside CSI sequence */
        if (ch >= '0' && ch <= '9')
        {
            /* Build parameter */
            if (cons->ansi_param_count < 8)
            {
                cons->ansi_params[cons->ansi_param_count] = cons->ansi_params[cons->ansi_param_count] * 10 + (ch - '0');
            }
        }
        else if (ch == ';')
        {
            /* Next parameter */
            cons->ansi_param_count++;
        }
        else
        {
            /* Command character */
            cons->ansi_param_count++;

            switch (ch)
            {
            case 'H': /* Cursor position */
            case 'f':
                console_flush_run(cons);
                cons->cursor_y = cons->ansi_params[0] > 0 ? cons->ansi_params[0] - 1 : 0;
                cons->cursor_x = cons->ansi_params[1] > 0 ? cons->ansi_params[1] - 1 : 0;
                if (cons->cursor_y >= CONSOLE_HEIGHT)
                    cons->cursor_y = CONSOLE_HEIGHT - 1;
                if (cons->cursor_x >= CONSOLE_WIDTH)
                    cons->cursor_x = CONSOLE_WIDTH - 1;
                break;

            case 'J': /* Erase display */
                if (cons->ansi_params[0] == 2)
                {
                    console_clear(cons);
                }
                break;

            case 'm': /* Graphics mode (colors: flush, rest of run is stale) */
                console_flush_run(cons);
                for (uint32_t i = 0; i < cons->ansi_param_count; i++)
                {
                    uint32_t param = cons->ansi_params[i];
                    if (param == 0)
                    { /* Reset */
                        cons->fg_color = COLOR_WHITE;
                        cons->bg_color = COLOR_BLUE;
                        cons->attr = 0;
                    }
                    else if (param >= 30 && param <= 37)
                    { /* Foreground */
                        cons->fg_color = param - 30;
                    }
                    else if (param >= 40 && param <= 47)
                    { /* Background */
                        cons->bg_color = param - 40;
                    }
                    else if (param == 1)
                    { /* Bold */
                        cons->attr |= ATTR_BOLD;
                    }
                }
                break;
            }

            cons->ansi_state = 0; /* End sequence */
        }
    }
}

/*
 * Clear console
 */
void console_clear(console_state_t *cons)
{
    /* Discard (do not flush) any pending run: cells are blanked below, so
     * painting the stale run after the FILL would resurrect text. */
    cons->prun_active = 0;
    cons->prun_len = 0;
    for (uint32_t y = 0; y < CONSOLE_HEIGHT; y++)
    {
        for (uint32_t x = 0; x < CONSOLE_WIDTH; x++)
        {
            cons->cells[y][x].ch = ' ';
            cons->cells[y][x].fg = cons->fg_color;
            cons->cells[y][x].bg = cons->bg_color;
            cons->cells[y][x].attr = 0;
        }
    }
    cons->cursor_x = 0;
    cons->cursor_y = 0;

    if (cons == &consoles[active_console])
    {
        /* Preserve background: FILL with the console's current bg
         * (default BLUE) instead of CLEAR (GUI hardcodes black).
         * Ref: Linux fbcon clear uses current bg; BusyBox clear keeps
         * attributes. This fixes "clear resets background". */
        console_send_fill(0, 0, 800, 600, vga_palette[cons->bg_color & 0xF]);
    }
}
/*
 * Scroll console up by N lines
 */
void console_scroll_up(console_state_t *cons, uint32_t lines)
{
    if (lines == 0)
        return;
    /* Flush first: cells move below, so pending run coords go stale. */
    console_flush_run(cons);
    if (lines > CONSOLE_HEIGHT)
        lines = CONSOLE_HEIGHT;
    /* Move lines up: flat single pass over (HEIGHT-lines)*WIDTH cells.
     * dest < src, forward copy is memmove-safe. Ref: BusyBox scrolling
     * text buffer; single loop replaces nested row/col branches. */
    {
        uint32_t move_cells = (CONSOLE_HEIGHT - lines) * (uint32_t)CONSOLE_WIDTH;
        uint32_t stride = lines * (uint32_t)CONSOLE_WIDTH;
        console_cell_t *flat = &cons->cells[0][0];
        uint32_t i;
        for (i = 0; i < move_cells; i++) /* bound: 2000 */
            flat[i] = flat[i + stride];
    }

    /* Clear bottom lines: flat single pass over lines*WIDTH cells. */
    {
        uint32_t base = (CONSOLE_HEIGHT - lines) * (uint32_t)CONSOLE_WIDTH;
        uint32_t total = lines * (uint32_t)CONSOLE_WIDTH;
        console_cell_t *flat = &cons->cells[0][0];
        uint32_t i;
        for (i = 0; i < total; i++) /* bound: 2000 */
        {
            flat[base + i].ch = ' ';
            flat[base + i].fg = cons->fg_color;
            flat[base + i].bg = cons->bg_color;
            flat[base + i].attr = 0;
        }
    }

    if (cons == &consoles[active_console])
    {
        /* Single RPC, not a 2000-cell repaint (queue is 32 deep). */
        console_send_scroll(lines);
    }
}

/*
 * Render entire console to GUI
 */
void console_render_all(console_state_t *cons)
{
    /* A switch-time repaint from cells (7500 PUTCs) is the same burst
     * disease as help output: repaint row by row with PUTS runs. */
    cons->prun_active = 0;
    cons->prun_len = 0;

    /* Clear screen first */
    console_send_fill(0, 0, 800, 600, vga_palette[cons->bg_color & 0xF]);

    /* Repaint all cells, one PUTS run per same-color row segment.
     * Trailing blank runs are skipped: the FILL above already cleared to
     * cons->bg_color, so repainting spaces over it is pure queue pressure
     * (a blank 80x25 screen costs zero PUTS, not ~375). Only trailing
     * blanks are skipped — a blank run is never skipped on the live path,
     * where pixel state is only guaranteed by painting. */
    for (uint32_t y = 0; y < CONSOLE_HEIGHT; y++)
    {
        uint32_t last = 0;
        uint32_t x;
        for (x = 0; x < CONSOLE_WIDTH; x++)
        {
            console_cell_t *cell = &cons->cells[y][x];
            if (cell->ch != ' ' || cell->bg != (cons->bg_color & 0xF))
                last = x + 1;
        }
        for (x = 0; x < last; x++)
        {
            console_cell_t *cell = &cons->cells[y][x];
            console_run_put(cons, x, y, (char)cell->ch, cell->fg, cell->bg, cell->attr);
        }
        console_flush_run(cons);
        /* Paced repaint: ~500 PUTS at once would pin the GUI queue the
         * same way help output did pre-batching. */
        moonlight_yield();
    }
    console_flush_run(cons);

    console_update_cursor(cons);
}

/*
 * Update cursor position in GUI
 */
void console_update_cursor(console_state_t *cons)
{
    console_send_cursor(cons->cursor_x, cons->cursor_y, cons->cursor_visible);
}
