/* tests/test_input.c - KATs for gui/input.h (key/mouse) + gui/console.h (grid). */
#include <stdio.h>
#include <string.h>
#include "../userspace/gui/input.h"
#include "../userspace/gui/console.h"
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

int main(void) {
    kbd_modifiers_t m = {0, 0, 0};
    CHECK(keycode_to_ascii(KEY_1, &m) == '1');
    CHECK(keycode_to_ascii(KEY_ESC, &m) == 0x1B);
    update_modifiers(&m, KEY_LEFTSHIFT, 1);
    CHECK(m.shift == 1);
    CHECK(keycode_to_ascii(KEY_A, &m) == 'A');
    update_modifiers(&m, KEY_LEFTSHIFT, 0);
    m.ctrl = 1;
    CHECK(keycode_to_ascii(KEY_A, &m) == 0x01);
    /* M-4 Ctrl evidence (Task 3 ad-hoc vectors, folded in): table-derived,
     * contiguous-range bug stays dead (SEMICOLON/GRAVE/SHIFT/BACKSLASH and
     * digits are not letters even under Ctrl). */
    CHECK(keycode_to_ascii(KEY_Z, &m) == 0x1A);
    CHECK(keycode_to_ascii(KEY_SEMICOLON, &m) == 0);
    CHECK(keycode_to_ascii(KEY_1, &m) == 0);
    CHECK(keycode_to_ascii(200, &m) == 0);
    m.ctrl = 0;
    CHECK(keycode_to_ascii(200, &m) == 0);
    mouse_state_t ms = {0, 0, 0, 0, 0};
    mouse_move(&ms, -50, -50);
    CHECK(ms.x == 0 && ms.y == 0);
    mouse_move(&ms, 5000, 5000);
    CHECK(ms.x == 799 && ms.y == 599);
    mouse_button(&ms, BTN_LEFT, 1);
    CHECK(ms.left == 1);
    console_t con;
    console_init(&con);
    CHECK(con.cursor_x == 0 && con.cursor_y == 0);
    for (int i = 0; i < 40; i++) { /* bound: 40 > 37 rows, forces scroll */
        char w[8]; w[0] = 'x'; w[1] = '\n'; w[2] = 0;
        console_puts(&con, w);
    }
    CHECK(con.cursor_y == 36);
    printf("PASS: test_input\n");
    return 0;
}
