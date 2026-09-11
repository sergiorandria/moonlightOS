/* test_kbd - host-sim for the keyboard driver core.
 * Exercises kbd_put_event (press/release, shift/caps/ctrl, ASCII + ANSI),
 * the shared ring, overflow accounting and status. The virtio-mmio
 * transport is __riscv-only; on host kbd_virtio_init() reports ERR_NO_MEM
 * (UART-only fallback), which is also asserted here.
 */
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "../kernel/include/kbd.h"

static int fails;

#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
    else { printf("PASS: %s\n", msg); } \
} while (0)

static void press(uint16_t code) { kbd_put_event(KBD_EV_KEY, code, KBD_KEY_PRESS); }
static void release(uint16_t code) { kbd_put_event(KBD_EV_KEY, code, KBD_KEY_RELEASE); }
static void tap(uint16_t code) { press(code); release(code); }

/* Drain up to n bytes into buf, NUL-terminate. Returns count. */
static int drain(char *buf, int n) {
    int i = 0, c;
    while (i < n - 1) {
        c = kbd_getc();
        if (c < 0) break;
        buf[i++] = (char)c;
    }
    buf[i] = '\0';
    return i;
}

int main(void) {
    char buf[512];
    kbd_status_t st;

    kbd_init();

    /* No virtio on host: UART-only fallback. */
    CHECK(kbd_virtio_init(NULL) == ERR_INVALID_ARG, "virtio init rejects NULL vspace");
    {
        vspace_t vs;
        memset(&vs, 0, sizeof(vs));
        CHECK(kbd_virtio_init(&vs) == ERR_NO_MEM, "virtio absent on host -> ERR_NO_MEM");
    }
    kbd_status(&st);
    CHECK(st.present == 0, "not present on host");
    CHECK(st.ring_used == 0, "ring empty after init");

    /* Plain letter. */
    tap(30); /* a */
    CHECK(drain(buf, sizeof(buf)) == 1 && strcmp(buf, "a") == 0, "tap a -> a");
    CHECK(kbd_getc() == -1, "getc empty -> -1");

    /* Release alone emits nothing. */
    release(30);
    CHECK(kbd_getc() == -1, "release alone -> nothing");

    /* Shift + letter -> upper. */
    press(42); /* left shift */
    press(30);
    release(30);
    release(42);
    CHECK(drain(buf, sizeof(buf)) == 1 && strcmp(buf, "A") == 0, "shift+a -> A");

    /* Right shift works too. */
    press(54);
    tap(48); /* b */
    release(54);
    CHECK(drain(buf, sizeof(buf)) == 1 && strcmp(buf, "B") == 0, "rshift+b -> B");

    /* Caps lock toggles on press, not on repeat. */
    tap(58); /* caps on */
    tap(46); /* c */
    CHECK(drain(buf, sizeof(buf)) == 1 && strcmp(buf, "C") == 0, "caps+c -> C");
    kbd_put_event(KBD_EV_KEY, 58, KBD_KEY_REPEAT); /* hold: must not toggle */
    tap(44); /* z -> still caps */
    CHECK(drain(buf, sizeof(buf)) == 1 && strcmp(buf, "Z") == 0, "caps repeat no toggle");
    tap(58); /* caps off */
    tap(44);
    CHECK(drain(buf, sizeof(buf)) == 1 && strcmp(buf, "z") == 0, "caps off -> z");

    /* Shift + caps cancel out. */
    tap(58);
    press(42);
    tap(30);
    release(42);
    tap(58);
    CHECK(drain(buf, sizeof(buf)) == 1 && strcmp(buf, "a") == 0, "shift^caps -> a");

    /* Digits + shifted symbols. */
    tap(2); /* 1 */
    CHECK(drain(buf, sizeof(buf)) == 1 && strcmp(buf, "1") == 0, "tap 1");
    press(42);
    tap(2); /* ! */
    release(42);
    CHECK(drain(buf, sizeof(buf)) == 1 && strcmp(buf, "!") == 0, "shift+1 -> !");
    press(42);
    tap(53); /* ? */
    release(42);
    CHECK(drain(buf, sizeof(buf)) == 1 && strcmp(buf, "?") == 0, "shift+/ -> ?");
    tap(12); /* - */
    press(42);
    tap(12); /* _ */
    release(42);
    CHECK(drain(buf, sizeof(buf)) == 2 && strcmp(buf, "-_") == 0, "minus pair");

    /* Whitespace / control. */
    tap(28); /* enter */
    tap(15); /* tab */
    tap(57); /* space */
    tap(1);  /* esc */
    tap(14); /* backspace -> DEL */
    {
        int e = kbd_getc(), t = kbd_getc(), s = kbd_getc(), x = kbd_getc(), b = kbd_getc();
        CHECK(e == '\n' && t == '\t' && s == ' ' && x == 0x1b && b == 0x7f,
              "enter/tab/space/esc/backspace");
    }

    /* Ctrl+letter -> control code. */
    press(29); /* left ctrl */
    tap(46);   /* c -> ETX */
    release(29);
    CHECK(kbd_getc() == 0x03, "ctrl+c -> ETX");
    press(97); /* right ctrl */
    tap(44);   /* z -> SUB */
    release(97);
    CHECK(kbd_getc() == 0x1a, "rctrl+z -> SUB");

    /* Arrows + navigation as ANSI escapes. */
    tap(103); /* up */
    CHECK(drain(buf, sizeof(buf)) == 3 && memcmp(buf, "\x1b[A", 3) == 0, "up -> ESC[A");
    tap(108);
    CHECK(drain(buf, sizeof(buf)) == 3 && memcmp(buf, "\x1b[B", 3) == 0, "down -> ESC[B");
    tap(105);
    CHECK(drain(buf, sizeof(buf)) == 3 && memcmp(buf, "\x1b[D", 3) == 0, "left -> ESC[D");
    tap(106);
    CHECK(drain(buf, sizeof(buf)) == 3 && memcmp(buf, "\x1b[C", 3) == 0, "right -> ESC[C");
    tap(111);
    CHECK(drain(buf, sizeof(buf)) == 4 && memcmp(buf, "\x1b[3~", 4) == 0, "delete -> ESC[3~");
    tap(102);
    CHECK(drain(buf, sizeof(buf)) == 3 && memcmp(buf, "\x1b[H", 3) == 0, "home -> ESC[H");

    /* F-keys and unknown codes: counted, not typed. */
    tap(59);  /* F1 */
    tap(200); /* out of range-ish vendor code */
    CHECK(kbd_getc() == -1, "F1/vendor -> nothing typed");

    /* Non-key event types ignored. */
    kbd_put_event(KBD_EV_SYN, 0, 0);
    kbd_put_event(KBD_EV_LED, 0, 1);
    kbd_put_event(99, 30, 1);
    CHECK(kbd_getc() == -1, "SYN/LED/bogus type ignored");

    /* Autorepeat value behaves like press. */
    kbd_put_event(KBD_EV_KEY, 30, KBD_KEY_REPEAT);
    CHECK(drain(buf, sizeof(buf)) == 1 && strcmp(buf, "a") == 0, "repeat -> a");

    /* UART-merge path: raw bytes pass through. */
    kbd_push_ascii('X');
    kbd_push_ascii('\n');
    CHECK(drain(buf, sizeof(buf)) == 2 && strcmp(buf, "X\n") == 0, "push_ascii");

    /* Status accounting. */
    kbd_status(&st);
    CHECK(st.ev_total > 0, "ev_total counted");
    CHECK(st.ascii_total > 0, "ascii_total counted");
    CHECK(st.last_code == 30, "last_code tracked");
    CHECK(st.drops == 0, "no drops yet");

    /* Overflow: ring holds 256, drops counted, FIFO order kept. */
    {
        int i;
        for (i = 0; i < 300; i++) kbd_push_ascii('A' + (char)(i % 26));
        kbd_status(&st);
        CHECK(st.drops == 44, "44 drops on 300 into 256");
        CHECK(st.ring_used == 256, "ring full");
        for (i = 0; i < 256; i++) {
            int c = kbd_getc();
            if (c != 'A' + (i % 26)) break;
        }
        CHECK(i == 256, "FIFO order preserved under overflow");
        CHECK(kbd_getc() == -1, "ring drained");
    }

    if (fails) {
        printf("KBD TESTS: %d FAILURES\n", fails);
        return 1;
    }
    printf("ALL KBD TESTS PASS\n");
    return 0;
}
