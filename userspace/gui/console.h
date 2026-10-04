/* userspace/gui/console.h - Minimal text console for GUI server (S4c).
 * 100×37 character grid (800×592 usable area in 800×600 framebuffer),
 * 8×16 VGA font rendering, scroll-on-overflow, no attributes (monochrome).
 * Production console would add color attributes, cursor blinking, escape
 * sequence parsing (ANSI/VT100). This is MVP: printable ASCII only. */

#ifndef CONSOLE_H
#define CONSOLE_H

#include <stdint.h>
#include "font_8x16.h"

/* Console geometry: 800×600 framebuffer, 8×16 font → 100×37 cells.
 * Real usable: 800÷8=100 cols, 592÷16=37 rows (last 8 scanlines black).
 * Each cell stores one ASCII character (uint8_t). No attributes yet. */
#define CONSOLE_COLS 100
#define CONSOLE_ROWS 37

/* Console state: character buffer + cursor position.
 * cursor_x and cursor_y track where next character will be written.
 * When cursor_x reaches CONSOLE_COLS, wrap to next row. When cursor_y
 * reaches CONSOLE_ROWS, scroll entire buffer up one row. */
typedef struct {
    uint8_t cells[CONSOLE_ROWS][CONSOLE_COLS]; /* Character buffer */
    int cursor_x;                                /* Cursor column (0..99) */
    int cursor_y;                                /* Cursor row (0..36) */
} console_t;

/* Initialize console: clear buffer, reset cursor to (0,0). */
static inline void console_init(console_t *con) {
    for (int r = 0; r < CONSOLE_ROWS; r++) { /* bound: CONSOLE_ROWS (37) */
        for (int c = 0; c < CONSOLE_COLS; c++) { /* bound: CONSOLE_COLS (100) */
            con->cells[r][c] = ' '; /* Fill with spaces */
        }
    }
    con->cursor_x = 0;
    con->cursor_y = 0;
}

/* Scroll console up one row: move rows [1..36] to [0..35], clear row 36.
 * Called when cursor_y reaches CONSOLE_ROWS after printing last line. */
static inline void console_scroll(console_t *con) {
    /* Shift rows up: row 0 discarded, rows 1-36 become 0-35 */
    for (int r = 0; r < CONSOLE_ROWS - 1; r++) { /* bound: CONSOLE_ROWS-1 (36) */
        for (int c = 0; c < CONSOLE_COLS; c++) { /* bound: CONSOLE_COLS (100) */
            con->cells[r][c] = con->cells[r + 1][c];
        }
    }
    /* Clear bottom row (now row 36) */
    for (int c = 0; c < CONSOLE_COLS; c++) { /* bound: CONSOLE_COLS (100) */
        con->cells[CONSOLE_ROWS - 1][c] = ' ';
    }
}

/* Put one character at cursor position, advance cursor.
 * Control character handling:
 *   '\n' (0x0A): move to start of next line (CR+LF behavior)
 *   '\r' (0x0D): move to start of current line (ignored if followed by \n)
 *   '\b' (0x08): backspace (move cursor left, erase character)
 *   '\t' (0x09): tab (align to next 8-column boundary)
 * Printable characters (0x20-0x7E): write to buffer, advance cursor.
 * Non-printable characters (0x00-0x1F except above, 0x7F-0xFF): ignored. */
static inline void console_putc(console_t *con, char ch) {
    if (ch == '\n') {
        /* Newline: move to start of next row */
        con->cursor_x = 0;
        con->cursor_y++;
        if (con->cursor_y >= CONSOLE_ROWS) {
            console_scroll(con);
            con->cursor_y = CONSOLE_ROWS - 1;
        }
    } else if (ch == '\r') {
        /* Carriage return: move to start of current row */
        con->cursor_x = 0;
    } else if (ch == '\b') {
        /* Backspace: move cursor left, erase character */
        if (con->cursor_x > 0) {
            con->cursor_x--;
            con->cells[con->cursor_y][con->cursor_x] = ' ';
        } else if (con->cursor_y > 0) {
            /* Backspace at column 0: move to end of previous row */
            con->cursor_y--;
            con->cursor_x = CONSOLE_COLS - 1;
            con->cells[con->cursor_y][con->cursor_x] = ' ';
        }
    } else if (ch == '\t') {
        /* Tab: align to next 8-column boundary (traditional tab stop) */
        int next_tab = (con->cursor_x + 8) & ~7;
        while (con->cursor_x < next_tab && con->cursor_x < CONSOLE_COLS) { /* bound: <=8 steps */
            con->cells[con->cursor_y][con->cursor_x] = ' ';
            con->cursor_x++;
        }
        if (con->cursor_x >= CONSOLE_COLS) {
            con->cursor_x = 0;
            con->cursor_y++;
            if (con->cursor_y >= CONSOLE_ROWS) {
                console_scroll(con);
                con->cursor_y = CONSOLE_ROWS - 1;
            }
        }
    } else if (ch >= 0x20 && ch <= 0x7E) {
        /* Printable ASCII: write character, advance cursor */
        con->cells[con->cursor_y][con->cursor_x] = (uint8_t)ch;
        con->cursor_x++;
        if (con->cursor_x >= CONSOLE_COLS) {
            /* Wrap to next row at right edge */
            con->cursor_x = 0;
            con->cursor_y++;
            if (con->cursor_y >= CONSOLE_ROWS) {
                console_scroll(con);
                con->cursor_y = CONSOLE_ROWS - 1;
            }
        }
    }
    /* All other characters (control chars, high ASCII) ignored */
}

/* Write string to console (convenience wrapper for console_putc). */
static inline void console_puts(console_t *con, const char *str) {
    while (*str) { /* bound: NUL-terminated rodata/banner literal */
        console_putc(con, *str);
        str++;
    }
}

/* Render console buffer to 32-bit XRGB8888 framebuffer (800×600).
 * Framebuffer layout: 800 pixels/row × 4 bytes/pixel = 3200 bytes/row.
 * Font: 8×16 pixels per character. Foreground=white (0xFFFFFFFF),
 * background=black (0xFF000000). No alpha blending (opaque pixels).
 * 
 * Performance notes:
 * - Full redraw every frame: 100×37×16 = 59200 character scanlines.
 * - Could optimize with dirty regions (track changed cells), but for
 *   S4c MVP, full redraw is acceptable (≈5ms on modern CPU). */
static inline void console_render(const console_t *con, volatile uint32_t *fb) {
    const uint32_t fg = 0xFFFFFFFF; /* White (XRGB: opaque white) */
    const uint32_t bg = 0xFF000000; /* Black (XRGB: opaque black) */

    /* Clear framebuffer to black (paranoid: font may not cover all pixels) */
    for (int y = 0; y < 600; y++) { /* bound: 600 */
        for (int x = 0; x < 800; x++) { /* bound: 800 */
            fb[y * 800 + x] = bg;
        }
    }

    /* Render each character cell: iterate rows, then columns */
    for (int row = 0; row < CONSOLE_ROWS; row++) { /* bound: CONSOLE_ROWS (37) */
        for (int col = 0; col < CONSOLE_COLS; col++) { /* bound: CONSOLE_COLS (100) */
            uint8_t ch = con->cells[row][col];
            /* Mask to 0x7F: the table holds 128 glyphs (upper-half CP437
             * is honest remainder, absent); putc/init only store < 0x7F,
             * so the mask is defense-in-depth, never a live path. */
            const uint8_t *glyph = font_8x16[ch & 0x7F]; /* 16 bytes: one per scanline */

            /* Character top-left corner in framebuffer coordinates */
            int char_x = col * 8;
            int char_y = row * 16;

            /* Render 16 scanlines of 8 pixels each */
            for (int scan = 0; scan < 16; scan++) { /* bound: 16 */
                uint8_t row_bits = glyph[scan];
                int fb_y = char_y + scan;
                if (fb_y >= 600) break; /* Paranoid bounds check */

                /* Render 8 pixels: bit 7 (leftmost) to bit 0 (rightmost) */
                for (int bit = 0; bit < 8; bit++) { /* bound: 8 */
                    int fb_x = char_x + bit;
                    if (fb_x >= 800) break; /* Paranoid bounds check */

                    /* Test bit 7-bit (left-to-right): 0x80 >> bit */
                    uint32_t color = (row_bits & (0x80 >> bit)) ? fg : bg;
                    fb[fb_y * 800 + fb_x] = color;
                }
            }
        }
    }
}

/* Render console with visible cursor (block cursor at cursor position).
 * Cursor: inverted colors at (cursor_x, cursor_y). Production console
 * would add blinking cursor (toggle every 500ms), cursor shape options
 * (block/underline/bar), and hide-cursor flag. S4c: static block only. */
static inline void console_render_with_cursor(const console_t *con, volatile uint32_t *fb) {
    /* First render normal console */
    console_render(con, fb);

    /* Overlay cursor: invert colors of character at cursor position */
    const uint32_t cursor_fg = 0xFF000000; /* Black on white */
    const uint32_t cursor_bg = 0xFFFFFFFF; /* White background */

    if (con->cursor_y >= 0 && con->cursor_y < CONSOLE_ROWS &&
        con->cursor_x >= 0 && con->cursor_x < CONSOLE_COLS) {
        uint8_t ch = con->cells[con->cursor_y][con->cursor_x];
        const uint8_t *glyph = font_8x16[ch & 0x7F]; /* masked: 128-glyph table (see above) */

        int char_x = con->cursor_x * 8;
        int char_y = con->cursor_y * 16;

        for (int scan = 0; scan < 16; scan++) { /* bound: 16 */
            uint8_t row_bits = glyph[scan];
            int fb_y = char_y + scan;
            if (fb_y >= 600) break;

            for (int bit = 0; bit < 8; bit++) { /* bound: 8 */
                int fb_x = char_x + bit;
                if (fb_x >= 800) break;

                /* Invert: foreground pixels → cursor_fg, background → cursor_bg */
                uint32_t color = (row_bits & (0x80 >> bit)) ? cursor_fg : cursor_bg;
                fb[fb_y * 800 + fb_x] = color;
            }
        }
    }
}

/* Clear console and reset cursor (equivalent to console_init, but preserves
 * console_t structure for in-place reset). */
static inline void console_clear(console_t *con) {
    console_init(con);
}

#endif /* CONSOLE_H */
