/* userspace/gui/input.h - Keyboard and mouse input handling for S4c.
 * Converts Linux input events (VirtIO-input) to console input (ASCII chars)
 * and mouse state (x,y,buttons). Includes keycode→ASCII tables, modifier
 * tracking (Shift/Ctrl/Alt), and mouse cursor rendering (16×16 arrow). */

#ifndef INPUT_H
#define INPUT_H

#include <stdint.h>
#include "virtio_input.h"

/* Keyboard modifier state: track Shift/Ctrl/Alt press status.
 * Updated on KEY_LEFTSHIFT/KEY_RIGHTSHIFT/KEY_LEFTCTRL/etc press/release. */
typedef struct {
    int shift;  /* Left or right Shift pressed */
    int ctrl;   /* Left or right Ctrl pressed */
    int alt;    /* Left or right Alt pressed */
} kbd_modifiers_t;

/* Mouse state: position (x,y) and button press status (left/right/middle).
 * Position clamped to framebuffer bounds (0..799, 0..599). */
typedef struct {
    int x;          /* Cursor X position (0..799) */
    int y;          /* Cursor Y position (0..599) */
    int left;       /* Left button pressed (1=down, 0=up) */
    int right;      /* Right button pressed */
    int middle;     /* Middle button pressed */
} mouse_state_t;

/* Keycode→ASCII translation table: unshifted (lowercase, digits, symbols).
 * Indexed by Linux keycode (KEY_* from virtio_input.h). Entries 0-127 only;
 * higher keycodes (arrows, function keys) handled separately. Returns 0 for
 * non-printable keys (Shift, Ctrl, etc). US QWERTY layout. */
static const char keycode_to_ascii_unshifted[128] = {
    [KEY_RESERVED] = 0,
    [KEY_ESC] = 0x1B,        /* Escape */
    [KEY_1] = '1',
    [KEY_2] = '2',
    [KEY_3] = '3',
    [KEY_4] = '4',
    [KEY_5] = '5',
    [KEY_6] = '6',
    [KEY_7] = '7',
    [KEY_8] = '8',
    [KEY_9] = '9',
    [KEY_0] = '0',
    [KEY_MINUS] = '-',
    [KEY_EQUAL] = '=',
    [KEY_BACKSPACE] = '\b',
    [KEY_TAB] = '\t',
    [KEY_Q] = 'q',
    [KEY_W] = 'w',
    [KEY_E] = 'e',
    [KEY_R] = 'r',
    [KEY_T] = 't',
    [KEY_Y] = 'y',
    [KEY_U] = 'u',
    [KEY_I] = 'i',
    [KEY_O] = 'o',
    [KEY_P] = 'p',
    [KEY_LEFTBRACE] = '[',
    [KEY_RIGHTBRACE] = ']',
    [KEY_ENTER] = '\n',
    [KEY_LEFTCTRL] = 0,      /* Modifier: no ASCII */
    [KEY_A] = 'a',
    [KEY_S] = 's',
    [KEY_D] = 'd',
    [KEY_F] = 'f',
    [KEY_G] = 'g',
    [KEY_H] = 'h',
    [KEY_J] = 'j',
    [KEY_K] = 'k',
    [KEY_L] = 'l',
    [KEY_SEMICOLON] = ';',
    [KEY_APOSTROPHE] = '\'',
    [KEY_GRAVE] = '`',
    [KEY_LEFTSHIFT] = 0,     /* Modifier: no ASCII */
    [KEY_BACKSLASH] = '\\',
    [KEY_Z] = 'z',
    [KEY_X] = 'x',
    [KEY_C] = 'c',
    [KEY_V] = 'v',
    [KEY_B] = 'b',
    [KEY_N] = 'n',
    [KEY_M] = 'm',
    [KEY_COMMA] = ',',
    [KEY_DOT] = '.',
    [KEY_SLASH] = '/',
    [KEY_RIGHTSHIFT] = 0,    /* Modifier: no ASCII */
    [KEY_KPASTERISK] = '*',
    [KEY_LEFTALT] = 0,       /* Modifier: no ASCII */
    [KEY_SPACE] = ' ',
    [KEY_CAPSLOCK] = 0,      /* Toggle: not handled yet */
    /* Function keys, arrow keys: indices 59+ are 0 (non-printable) */
};

/* Keycode→ASCII translation table: shifted (uppercase, shifted symbols).
 * US QWERTY layout: Shift+1='!', Shift+2='@', etc. */
static const char keycode_to_ascii_shifted[128] = {
    [KEY_RESERVED] = 0,
    [KEY_ESC] = 0x1B,
    [KEY_1] = '!',
    [KEY_2] = '@',
    [KEY_3] = '#',
    [KEY_4] = '$',
    [KEY_5] = '%',
    [KEY_6] = '^',
    [KEY_7] = '&',
    [KEY_8] = '*',
    [KEY_9] = '(',
    [KEY_0] = ')',
    [KEY_MINUS] = '_',
    [KEY_EQUAL] = '+',
    [KEY_BACKSPACE] = '\b',
    [KEY_TAB] = '\t',
    [KEY_Q] = 'Q',
    [KEY_W] = 'W',
    [KEY_E] = 'E',
    [KEY_R] = 'R',
    [KEY_T] = 'T',
    [KEY_Y] = 'Y',
    [KEY_U] = 'U',
    [KEY_I] = 'I',
    [KEY_O] = 'O',
    [KEY_P] = 'P',
    [KEY_LEFTBRACE] = '{',
    [KEY_RIGHTBRACE] = '}',
    [KEY_ENTER] = '\n',
    [KEY_LEFTCTRL] = 0,
    [KEY_A] = 'A',
    [KEY_S] = 'S',
    [KEY_D] = 'D',
    [KEY_F] = 'F',
    [KEY_G] = 'G',
    [KEY_H] = 'H',
    [KEY_J] = 'J',
    [KEY_K] = 'K',
    [KEY_L] = 'L',
    [KEY_SEMICOLON] = ':',
    [KEY_APOSTROPHE] = '"',
    [KEY_GRAVE] = '~',
    [KEY_LEFTSHIFT] = 0,
    [KEY_BACKSLASH] = '|',
    [KEY_Z] = 'Z',
    [KEY_X] = 'X',
    [KEY_C] = 'C',
    [KEY_V] = 'V',
    [KEY_B] = 'B',
    [KEY_N] = 'N',
    [KEY_M] = 'M',
    [KEY_COMMA] = '<',
    [KEY_DOT] = '>',
    [KEY_SLASH] = '?',
    [KEY_RIGHTSHIFT] = 0,
    [KEY_KPASTERISK] = '*',
    [KEY_LEFTALT] = 0,
    [KEY_SPACE] = ' ',
    [KEY_CAPSLOCK] = 0,
};

/* Convert Linux keycode + modifiers to ASCII character.
 * Returns 0 for non-printable keys (modifiers, function keys, arrows).
 * Handles Shift (uppercase), Ctrl (control codes 0x01-0x1A for Ctrl+A-Z). */
static inline char keycode_to_ascii(uint16_t keycode, const kbd_modifiers_t *mods) {
    /* Ctrl+letter: generate control codes (Ctrl+A=0x01, Ctrl+Z=0x1A) */
    if (mods->ctrl && keycode >= KEY_A && keycode <= KEY_Z) {
        return (char)(keycode - KEY_A + 1); /* 0x01 to 0x1A */
    }

    /* Shift: use shifted table; otherwise unshifted */
    if (keycode < 128) {
        return mods->shift ? keycode_to_ascii_shifted[keycode]
                           : keycode_to_ascii_unshifted[keycode];
    }

    /* High keycodes (arrows, F-keys): not mapped to ASCII */
    return 0;
}

/* Update keyboard modifier state based on key press/release event.
 * Call this for every EV_KEY event before calling keycode_to_ascii. */
static inline void update_modifiers(kbd_modifiers_t *mods, uint16_t keycode, int pressed) {
    switch (keycode) {
    case KEY_LEFTSHIFT:
    case KEY_RIGHTSHIFT:
        mods->shift = pressed;
        break;
    case KEY_LEFTCTRL:
    case KEY_RIGHTCTRL:
        mods->ctrl = pressed;
        break;
    case KEY_LEFTALT:
    case KEY_RIGHTALT:
        mods->alt = pressed;
        break;
    }
}

/* Update mouse position based on relative motion event (REL_X, REL_Y).
 * Delta values are signed (positive=right/down, negative=left/up).
 * Position clamped to framebuffer bounds (0..799, 0..599). */
static inline void mouse_move(mouse_state_t *mouse, int dx, int dy) {
    mouse->x += dx;
    mouse->y += dy;

    /* Clamp to framebuffer bounds */
    if (mouse->x < 0) mouse->x = 0;
    if (mouse->x > 799) mouse->x = 799;
    if (mouse->y < 0) mouse->y = 0;
    if (mouse->y > 599) mouse->y = 599;
}

/* Update mouse button state based on button press/release event. */
static inline void mouse_button(mouse_state_t *mouse, uint16_t button, int pressed) {
    switch (button) {
    case BTN_LEFT:
        mouse->left = pressed;
        break;
    case BTN_RIGHT:
        mouse->right = pressed;
        break;
    case BTN_MIDDLE:
        mouse->middle = pressed;
        break;
    }
}

/* Mouse cursor bitmap: 16×16 white arrow with black outline.
 * Standard left-pointing arrow cursor (same as X11 default). Each row is
 * a 16-bit value: bit 15=leftmost pixel, bit 0=rightmost. 1=white, 0=transparent.
 * Black outline stored separately for anti-aliasing (draw outline first, then
 * white fill). Production cursor would use ARGB with alpha blending; S4c uses
 * opaque pixels (draw outline, then white, skip transparent). */
static const uint16_t cursor_bitmap_white[16] = {
    0x8000, /* 1...............  */
    0xC000, /* 11..............  */
    0xE000, /* 111.............  */
    0xF000, /* 1111............  */
    0xF800, /* 11111...........  */
    0xFC00, /* 111111..........  */
    0xFE00, /* 1111111.........  */
    0xFF00, /* 11111111........  */
    0xFF80, /* 111111111.......  */
    0xFFC0, /* 1111111111......  */
    0xFC00, /* 111111..........  */
    0xEC00, /* 1110 11..........  */
    0xCC00, /* 1100 11..........  */
    0x8600, /* 1000 011.........  */
    0x0600, /* 0000 011.........  */
    0x0300, /* 0000 0011........  */
};

/* Black outline for cursor (1 pixel wider than white fill).
 * Drawn first to create black border around white arrow. */
static const uint16_t cursor_bitmap_black[16] = {
    0xC000, /* 11..............  */
    0xE000, /* 111.............  */
    0xF000, /* 1111............  */
    0xF800, /* 11111...........  */
    0xFC00, /* 111111..........  */
    0xFE00, /* 1111111.........  */
    0xFF00, /* 11111111........  */
    0xFF80, /* 111111111.......  */
    0xFFC0, /* 1111111111......  */
    0xFFE0, /* 11111111111.....  */
    0xFE00, /* 1111111.........  */
    0xFE00, /* 1111111.........  */
    0xEE00, /* 11101110........  */
    0xCF00, /* 11001111........  */
    0x0F00, /* 00001111........  */
    0x0780, /* 00000111 1.......  */
};

/* Render mouse cursor at (x,y) on framebuffer (16×16 pixels).
 * Two-pass: draw black outline, then white fill. Transparent pixels (bit=0)
 * leave framebuffer unchanged. Cursor hotspot at (0,0) (top-left corner).
 * Clipping: cursor may extend beyond framebuffer edge (draw partial). */
static inline void cursor_render(volatile uint32_t *fb, int x, int y) {
    const uint32_t black = 0xFF000000;
    const uint32_t white = 0xFFFFFFFF;

    /* Pass 1: draw black outline */
    for (int row = 0; row < 16; row++) { /* bound: 16 */
        int fb_y = y + row;
        if (fb_y < 0 || fb_y >= 600) continue;

        uint16_t row_bits = cursor_bitmap_black[row];
        for (int col = 0; col < 16; col++) { /* bound: 16 */
            int fb_x = x + col;
            if (fb_x < 0 || fb_x >= 800) continue; /* Clip horizontally */

            if (row_bits & (0x8000 >> col)) {
                fb[fb_y * 800 + fb_x] = black;
            }
        }
    }

    /* Pass 2: draw white fill (on top of black outline) */
    for (int row = 0; row < 16; row++) { /* bound: 16 */
        int fb_y = y + row;
        if (fb_y < 0 || fb_y >= 600) continue;

        uint16_t row_bits = cursor_bitmap_white[row];
        for (int col = 0; col < 16; col++) { /* bound: 16 */
            int fb_x = x + col;
            if (fb_x < 0 || fb_x >= 800) continue;

            if (row_bits & (0x8000 >> col)) {
                fb[fb_y * 800 + fb_x] = white;
            }
        }
    }
}

/* Initialize mouse state: center of screen, no buttons pressed. */
static inline void mouse_init(mouse_state_t *mouse) {
    mouse->x = 400;
    mouse->y = 300;
    mouse->left = 0;
    mouse->right = 0;
    mouse->middle = 0;
}

/* Initialize keyboard modifiers: all released. */
static inline void kbd_modifiers_init(kbd_modifiers_t *mods) {
    mods->shift = 0;
    mods->ctrl = 0;
    mods->alt = 0;
}

#endif /* INPUT_H */
