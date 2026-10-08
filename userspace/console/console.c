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
static uint32_t active_console = 0;  /* Currently visible console (0-11) */

/* Forward declarations */
static void handle_gui_key_event(const msg_key_event_t *msg);
static void handle_gui_mouse_event(const msg_mouse_event_t *msg);
static void handle_tty_write(const msg_tty_write_t *msg);
static void handle_kernel_boot_log(const msg_kernel_boot_log_t *msg);

/*
 * Initialize console service
 */
void console_init(void) {
    /* Initialize all consoles */
    for (uint32_t i = 0; i < CONSOLE_COUNT; i++) {
        console_state_t *cons = &consoles[i];
        
        /* Clear screen buffer */
        for (uint32_t y = 0; y < CONSOLE_HEIGHT; y++) {
            for (uint32_t x = 0; x < CONSOLE_WIDTH; x++) {
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
        cons->bg_color = COLOR_BLACK;
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
void console_main(void) {
    ipc_message_t msg;
    uint32_t sender;
    
    while (1) {
        /* Wait for incoming message */
        int len = ipc_recv(SERVICE_CONSOLE, &msg, sizeof(msg), &sender);
        if (len < 0) continue;
        
        /* Dispatch based on message type */
        switch (msg.msg_type) {
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
    }
}

/*
 * Handle keyboard event from GUI
 */
static void handle_gui_key_event(const msg_key_event_t *msg) {
    if (!msg->pressed) return;  /* Only process key down events */
    
    /* Check for console switch (Alt+F1 through Alt+F12) */
    if (msg->modifiers & KEY_MOD_ALT) {
        if (msg->keycode >= 0x3B && msg->keycode <= 0x46) {  /* F1-F12 */
            uint32_t new_console = msg->keycode - 0x3B;
            if (new_console != active_console) {
                active_console = new_console;
                console_render_all(&consoles[active_console]);
            }
            return;
        }
    }
    
    /* Forward ASCII input to TTY service */
    if (msg->ascii > 0) {
        msg_console_input_t input = {
            .msg_type = MSG_CONSOLE_INPUT,
            .tty_id = active_console,
            .len = 1,
        };
        input.data[0] = (char)msg->ascii;
        ipc_send_async(SERVICE_TTY, &input, sizeof(input));
        // Debug visual marker: red asterisk at top‑left corner
        console_send_putc(0, 0, '*', COLOR_RED, COLOR_BLACK);
    }
}

/*
 * Handle mouse event from GUI (currently unused by console)
 */
static void handle_gui_mouse_event(const msg_mouse_event_t *msg) {
    /* Mouse events can be used for selection/copy-paste in future */
    (void)msg;
}

/*
 * Handle write request from TTY
 */
static void handle_tty_write(const msg_tty_write_t *msg) {
    if (msg->tty_id >= CONSOLE_COUNT) return;
    
    console_state_t *cons = &consoles[msg->tty_id];
    console_write(cons, msg->data, msg->len);
    
    /* Update display if this is the active console */
    if (msg->tty_id == active_console) {
        console_update_cursor(cons);
    }
}

/*
 * Handle kernel boot log message
 */
static void handle_kernel_boot_log(const msg_kernel_boot_log_t *msg) {
    console_state_t *cons = &consoles[0];  /* Boot log goes to console 0 */
    
    /* Append to boot log buffer */
    for (uint32_t i = 0; i < msg->len && cons->boot_log_len < 4096; i++) {
        cons->boot_log[cons->boot_log_len++] = msg->data[i];
    }
    
    /* Display immediately */
    console_write(cons, msg->data, msg->len);
    
    /* Update display if console 0 is active */
    if (active_console == 0) {
        console_update_cursor(cons);
    }
}

/*
 * Write string to console (with ANSI parsing)
 */
void console_write(console_state_t *cons, const char *data, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        console_putchar(cons, data[i]);
    }
}

/*
 * Write single character to console
 */
void console_putchar(console_state_t *cons, char ch) {
    /* ANSI escape sequence processing */
    if (cons->ansi_state > 0) {
        console_process_ansi(cons, ch);
        return;
    }
    
    /* Handle control characters */
    if (ch == '\n') {
        cons->cursor_x = 0;
        cons->cursor_y++;
        if (cons->cursor_y >= CONSOLE_HEIGHT) {
            console_scroll_up(cons, 1);
            cons->cursor_y = CONSOLE_HEIGHT - 1;
        }
        return;
    } else if (ch == '\r') {
        cons->cursor_x = 0;
        return;
    } else if (ch == '\b') {
        if (cons->cursor_x > 0) cons->cursor_x--;
        return;
    } else if (ch == '\t') {
        cons->cursor_x = (cons->cursor_x + 8) & ~7;
        if (cons->cursor_x >= CONSOLE_WIDTH) {
            cons->cursor_x = 0;
            cons->cursor_y++;
        }
        return;
    } else if (ch == 0x1B) {  /* ESC - start ANSI sequence */
        cons->ansi_state = 1;
        return;
    }
    
    /* Printable character */
    if (ch >= 0x20 && ch <= 0x7E) {
        cons->cells[cons->cursor_y][cons->cursor_x].ch = ch;
        cons->cells[cons->cursor_y][cons->cursor_x].fg = cons->fg_color;
        cons->cells[cons->cursor_y][cons->cursor_x].bg = cons->bg_color;
        cons->cells[cons->cursor_y][cons->cursor_x].attr = cons->attr;
        
        /* Render if active console */
        if (cons == &consoles[active_console]) {
            console_render_cell(cons, cons->cursor_x, cons->cursor_y);
        }
        
        /* Advance cursor */
        cons->cursor_x++;
        if (cons->cursor_x >= CONSOLE_WIDTH) {
            cons->cursor_x = 0;
            cons->cursor_y++;
            if (cons->cursor_y >= CONSOLE_HEIGHT) {
                console_scroll_up(cons, 1);
                cons->cursor_y = CONSOLE_HEIGHT - 1;
            }
        }
    }
}

/*
 * Process ANSI escape sequence
 */
void console_process_ansi(console_state_t *cons, char ch) {
    if (cons->ansi_state == 1) {  /* After ESC */
        if (ch == '[') {
            cons->ansi_state = 2;
            cons->ansi_param_count = 0;
            for (int i = 0; i < 8; i++) cons->ansi_params[i] = 0;
        } else {
            cons->ansi_state = 0;  /* Unknown sequence, reset */
        }
        return;
    }
    
    if (cons->ansi_state == 2) {  /* Inside CSI sequence */
        if (ch >= '0' && ch <= '9') {
            /* Build parameter */
            if (cons->ansi_param_count < 8) {
                cons->ansi_params[cons->ansi_param_count] = 
                    cons->ansi_params[cons->ansi_param_count] * 10 + (ch - '0');
            }
        } else if (ch == ';') {
            /* Next parameter */
            cons->ansi_param_count++;
        } else {
            /* Command character */
            cons->ansi_param_count++;
            
            switch (ch) {
                case 'H':  /* Cursor position */
                case 'f':
                    cons->cursor_y = cons->ansi_params[0] > 0 ? cons->ansi_params[0] - 1 : 0;
                    cons->cursor_x = cons->ansi_params[1] > 0 ? cons->ansi_params[1] - 1 : 0;
                    if (cons->cursor_y >= CONSOLE_HEIGHT) cons->cursor_y = CONSOLE_HEIGHT - 1;
                    if (cons->cursor_x >= CONSOLE_WIDTH) cons->cursor_x = CONSOLE_WIDTH - 1;
                    break;
                
                case 'J':  /* Erase display */
                    if (cons->ansi_params[0] == 2) {
                        console_clear(cons);
                    }
                    break;
                
                case 'm':  /* Graphics mode (colors) */
                    for (uint32_t i = 0; i < cons->ansi_param_count; i++) {
                        uint32_t param = cons->ansi_params[i];
                        if (param == 0) {  /* Reset */
                            cons->fg_color = COLOR_WHITE;
                            cons->bg_color = COLOR_BLACK;
                            cons->attr = 0;
                        } else if (param >= 30 && param <= 37) {  /* Foreground */
                            cons->fg_color = param - 30;
                        } else if (param >= 40 && param <= 47) {  /* Background */
                            cons->bg_color = param - 40;
                        } else if (param == 1) {  /* Bold */
                            cons->attr |= ATTR_BOLD;
                        }
                    }
                    break;
            }
            
            cons->ansi_state = 0;  /* End sequence */
        }
    }
}

/*
 * Clear console
 */
void console_clear(console_state_t *cons) {
    for (uint32_t y = 0; y < CONSOLE_HEIGHT; y++) {
        for (uint32_t x = 0; x < CONSOLE_WIDTH; x++) {
            cons->cells[y][x].ch = ' ';
            cons->cells[y][x].fg = cons->fg_color;
            cons->cells[y][x].bg = cons->bg_color;
            cons->cells[y][x].attr = 0;
        }
    }
    cons->cursor_x = 0;
    cons->cursor_y = 0;
    
    if (cons == &consoles[active_console]) {
        console_render_all(cons);
    }
}

/*
 * Scroll console up by N lines
 */
void console_scroll_up(console_state_t *cons, uint32_t lines) {
    /* Move lines up */
    for (uint32_t i = 0; i < CONSOLE_HEIGHT - lines; i++) {
        for (uint32_t x = 0; x < CONSOLE_WIDTH; x++) {
            cons->cells[i][x] = cons->cells[i + lines][x];
        }
    }
    
    /* Clear bottom lines */
    for (uint32_t y = CONSOLE_HEIGHT - lines; y < CONSOLE_HEIGHT; y++) {
        for (uint32_t x = 0; x < CONSOLE_WIDTH; x++) {
            cons->cells[y][x].ch = ' ';
            cons->cells[y][x].fg = cons->fg_color;
            cons->cells[y][x].bg = cons->bg_color;
            cons->cells[y][x].attr = 0;
        }
    }
    
    if (cons == &consoles[active_console]) {
        console_render_all(cons);
    }
}

/*
 * Render single character cell to GUI
 */
void console_render_cell(console_state_t *cons, uint32_t x, uint32_t y) {
    console_cell_t *cell = &cons->cells[y][x];
    uint32_t fg = vga_palette[cell->fg & 0xF];
    uint32_t bg = vga_palette[cell->bg & 0xF];
    
    /* Apply bold attribute (brighter colors) */
    if (cell->attr & ATTR_BOLD) {
        fg = vga_palette[(cell->fg & 0x7) | COLOR_BRIGHT];
    }
    
    console_send_putc(x, y, cell->ch, fg, bg);
}

/*
 * Render entire console to GUI
 */
void console_render_all(console_state_t *cons) {
    /* Clear screen first */
    console_send_fill(0, 0, 800, 600, vga_palette[cons->bg_color & 0xF]);
    
    /* Render all cells */
    for (uint32_t y = 0; y < CONSOLE_HEIGHT; y++) {
        for (uint32_t x = 0; x < CONSOLE_WIDTH; x++) {
            console_render_cell(cons, x, y);
        }
    }
    
    console_update_cursor(cons);
}

/*
 * Update cursor position in GUI
 */
void console_update_cursor(console_state_t *cons) {
    console_send_cursor(cons->cursor_x, cons->cursor_y, cons->cursor_visible);
}
