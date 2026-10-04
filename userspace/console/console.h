/*
 * console.h - Console Service Interface
 *
 * The Console service sits between GUI hardware and TTY/applications.
 * Responsibilities:
 *   - Text buffer management (80x25 or 100x75)
 *   - Character rendering via GUI service
 *   - ANSI escape sequence parsing
 *   - Scroll regions and cursor management
 *   - Kernel boot message buffering
 *   - Multiple virtual consoles (F1-F12)
 */

#ifndef CONSOLE_H
#define CONSOLE_H

#include <stdint.h>
#include "services/ipc_protocol.h"

/* Console configuration */
#define CONSOLE_WIDTH   80      /* Characters per row (reduced for memory) */
#define CONSOLE_HEIGHT  25      /* Rows per console (reduced for memory) */
#define CONSOLE_COUNT   1       /* Virtual consoles (reduced to 1 for MVP) */

/* Character cell attributes */
#define ATTR_BOLD       (1 << 0)
#define ATTR_UNDERLINE  (1 << 1)
#define ATTR_BLINK      (1 << 2)
#define ATTR_REVERSE    (1 << 3)

/* ANSI color codes (VGA 16-color palette) */
#define COLOR_BLACK     0
#define COLOR_RED       1
#define COLOR_GREEN     2
#define COLOR_YELLOW    3
#define COLOR_BLUE      4
#define COLOR_MAGENTA   5
#define COLOR_CYAN      6
#define COLOR_WHITE     7
#define COLOR_BRIGHT    8  /* Add to base color for bright variants */

/* Character cell (text + attributes) */
typedef struct {
    uint8_t  ch;        /* ASCII character */
    uint8_t  fg;        /* Foreground color (0-15) */
    uint8_t  bg;        /* Background color (0-15) */
    uint8_t  attr;      /* Attribute flags */
} console_cell_t;

/* Console state (one per virtual console) */
typedef struct {
    console_cell_t cells[CONSOLE_HEIGHT][CONSOLE_WIDTH];
    uint32_t cursor_x;
    uint32_t cursor_y;
    uint32_t cursor_visible;
    uint8_t  fg_color;      /* Current foreground color */
    uint8_t  bg_color;      /* Current background color */
    uint8_t  attr;          /* Current attributes */
    uint32_t scroll_top;    /* Top of scroll region */
    uint32_t scroll_bottom; /* Bottom of scroll region */
    
    /* ANSI parser state */
    uint32_t ansi_state;    /* 0=normal, 1=escape, 2=bracket, 3=params */
    uint32_t ansi_params[8];
    uint32_t ansi_param_count;
    
    /* Boot log buffer (for console 0 only) */
    char     boot_log[4096];
    uint32_t boot_log_len;
} console_state_t;

/* VGA 16-color palette (ANSI colors) */
static const uint32_t vga_palette[16] = {
    0xFF000000,  /* 0: Black */
    0xFFAA0000,  /* 1: Red */
    0xFF00AA00,  /* 2: Green */
    0xFFAAAA00,  /* 3: Yellow */
    0xFF0000AA,  /* 4: Blue */
    0xFFAA00AA,  /* 5: Magenta */
    0xFF00AAAA,  /* 6: Cyan */
    0xFFAAAAAA,  /* 7: White */
    0xFF555555,  /* 8: Bright Black (Gray) */
    0xFFFF5555,  /* 9: Bright Red */
    0xFF55FF55,  /* 10: Bright Green */
    0xFFFFFF55,  /* 11: Bright Yellow */
    0xFF5555FF,  /* 12: Bright Blue */
    0xFFFF55FF,  /* 13: Bright Magenta */
    0xFF55FFFF,  /* 14: Bright Cyan */
    0xFFFFFFFF,  /* 15: Bright White */
};

/* Console service functions */
void console_init(void);
void console_main(void);

/* Internal console operations */
void console_putchar(console_state_t *cons, char ch);
void console_write(console_state_t *cons, const char *data, uint32_t len);
void console_clear(console_state_t *cons);
void console_scroll_up(console_state_t *cons, uint32_t lines);
void console_render_cell(console_state_t *cons, uint32_t x, uint32_t y);
void console_render_all(console_state_t *cons);
void console_update_cursor(console_state_t *cons);

/* ANSI escape sequence handling */
void console_process_ansi(console_state_t *cons, char ch);

#endif /* CONSOLE_H */
