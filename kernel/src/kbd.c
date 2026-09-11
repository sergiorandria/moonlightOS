/* kbd - virtio-input keyboard + UART merged console input.
 *
 * Transport: virtio-mmio (QEMU riscv-virt 0x10001000 + i*0x1000, 8 slots).
 * Device 18 (virtio input), split virtqueues: q0 = eventq (device->driver),
 * q1 = statusq (driver->device, parked empty). Polled used-ring drain, no
 * interrupts yet - see kbd.h for the roadmap.
 *
 * Ring/translation core is plain C (host-testable); MMIO is __riscv-only.
 */
#include "../include/kbd.h"
#include "../include/flush.h"
#include "../include/console.h"
#include <string.h>

/* ---- shared ring + modifier state (all targets) ---- */
static uint8_t kbd_ring[KBD_RING_SIZE];
static uint16_t kbd_head, kbd_tail, kbd_used;
static uint8_t kbd_shift, kbd_ctrl, kbd_alt, kbd_caps;
static kbd_status_t kbd_st;

#define KBD_KEY_RIGHTCTRL 97
#define KBD_KEY_RIGHTALT  100

static void ring_push(uint8_t b) {
    if (kbd_used >= KBD_RING_SIZE) {
        kbd_st.drops++;
        return;
    }
    kbd_ring[kbd_head] = b;
    kbd_head = (uint16_t)((kbd_head + 1u) & (KBD_RING_SIZE - 1u));
    kbd_used++;
    kbd_st.ascii_total++;
}

static void push_esc_seq(char a, char b) {
    ring_push(0x1b);
    ring_push((uint8_t)'[');
    ring_push((uint8_t)a);
    if (b) ring_push((uint8_t)b);
}

/* Letter codes -> 'a'..'z' (Linux KEY_*). 0 = not a letter. */
static char key_letter(uint16_t code) {
    switch (code) {
        case 16: return 'q'; case 17: return 'w'; case 18: return 'e';
        case 19: return 'r'; case 20: return 't'; case 21: return 'y';
        case 22: return 'u'; case 23: return 'i'; case 24: return 'o';
        case 25: return 'p'; case 30: return 'a'; case 31: return 's';
        case 32: return 'd'; case 33: return 'f'; case 34: return 'g';
        case 35: return 'h'; case 36: return 'j'; case 37: return 'k';
        case 38: return 'l'; case 44: return 'z'; case 45: return 'x';
        case 46: return 'c'; case 47: return 'v'; case 48: return 'b';
        case 49: return 'n'; case 50: return 'm';
        default: return 0;
    }
}

/* Non-letter printables, unshifted. 0 = special-cased or ignored. */
static char key_plain(uint16_t code) {
    switch (code) {
        case 2: return '1'; case 3: return '2'; case 4: return '3';
        case 5: return '4'; case 6: return '5'; case 7: return '6';
        case 8: return '7'; case 9: return '8'; case 10: return '9';
        case 11: return '0'; case 12: return '-'; case 13: return '=';
        case 14: return 0x7f; /* backspace */
        case 15: return '\t';
        case 26: return '['; case 27: return ']';
        case 28: return '\n';
        case 39: return ';'; case 40: return '\'';
        case 41: return '`'; case 43: return '\\';
        case 51: return ','; case 52: return '.';
        case 53: return '/'; case 57: return ' ';
        case 1: return 0x1b; /* esc */
        default: return 0;
    }
}

/* Non-letter printables, shifted. */
static char key_shifted(uint16_t code) {
    switch (code) {
        case 2: return '!'; case 3: return '@'; case 4: return '#';
        case 5: return '$'; case 6: return '%'; case 7: return '^';
        case 8: return '&'; case 9: return '*'; case 10: return '(';
        case 11: return ')'; case 12: return '_'; case 13: return '+';
        case 14: return 0x7f;
        case 15: return '\t';
        case 26: return '{'; case 27: return '}';
        case 28: return '\n';
        case 39: return ':'; case 40: return '"';
        case 41: return '~'; case 43: return '|';
        case 51: return '<'; case 52: return '>';
        case 53: return '?'; case 57: return ' ';
        case 1: return 0x1b;
        default: return 0;
    }
}

static int is_modifier(uint16_t code) {
    return code == KBD_KEY_LEFTSHIFT || code == KBD_KEY_RIGHTSHIFT ||
           code == KBD_KEY_LEFTCTRL || code == KBD_KEY_RIGHTCTRL ||
           code == KBD_KEY_LEFTALT || code == KBD_KEY_RIGHTALT;
}

void kbd_put_event(uint16_t type, uint16_t code, int32_t value) {
    if (type != KBD_EV_KEY) return; /* EV_SYN/LED/REP framing: nothing to do */
    kbd_st.ev_total++;
    kbd_st.last_code = code;
    kbd_st.last_value = (value < -1) ? -1 : (int16_t)(value > 32767 ? 32767 : value);

    if (value == KBD_KEY_RELEASE) {
        if (code == KBD_KEY_LEFTSHIFT || code == KBD_KEY_RIGHTSHIFT) kbd_shift = 0;
        if (code == KBD_KEY_LEFTCTRL || code == KBD_KEY_RIGHTCTRL) kbd_ctrl = 0;
        if (code == KBD_KEY_LEFTALT || code == KBD_KEY_RIGHTALT) kbd_alt = 0;
        return;
    }
    if (value != KBD_KEY_PRESS && value != KBD_KEY_REPEAT) return;

    if (code == KBD_KEY_LEFTSHIFT || code == KBD_KEY_RIGHTSHIFT) {
        kbd_shift = 1;
        return;
    }
    if (code == KBD_KEY_LEFTCTRL || code == KBD_KEY_RIGHTCTRL) {
        kbd_ctrl = 1;
        return;
    }
    if (code == KBD_KEY_LEFTALT || code == KBD_KEY_RIGHTALT) {
        kbd_alt = 1;
        return;
    }
    if (code == KBD_KEY_CAPSLOCK) {
        if (value == KBD_KEY_PRESS) kbd_caps ^= 1u; /* no toggle on autorepeat */
        return;
    }
    if (is_modifier(code)) return;

    /* Ctrl+letter -> control code (Ctrl+C = ETX, Ctrl+U = NAK, ...). */
    {
        char base = key_letter(code);
        if (base && kbd_ctrl) {
            ring_push((uint8_t)(base & 0x1f));
            return;
        }
    }
    /* Letters honor shift XOR caps. */
    {
        char base = key_letter(code);
        if (base) {
            int upper = (kbd_shift ^ kbd_caps) != 0;
            ring_push((uint8_t)(upper ? (char)(base - 32) : base));
            return;
        }
    }
    /* Punctuation/digits/whitespace via shift tables. */
    {
        char ch = kbd_shift ? key_shifted(code) : key_plain(code);
        if (ch) {
            ring_push((uint8_t)ch);
            return;
        }
    }
    /* Navigation / editing keys as ANSI escapes (same bytes a serial
     * terminal sends, so moonsh parses one format from both sources). */
    switch (code) {
        case KBD_KEY_UP: push_esc_seq('A', 0); break;
        case KBD_KEY_DOWN: push_esc_seq('B', 0); break;
        case KBD_KEY_RIGHT: push_esc_seq('C', 0); break;
        case KBD_KEY_LEFT: push_esc_seq('D', 0); break;
        case KBD_KEY_HOME: push_esc_seq('H', 0); break;
        case KBD_KEY_END: push_esc_seq('F', 0); break;
        case KBD_KEY_DELETE: push_esc_seq('3', '~'); break;
        case KBD_KEY_PAGEUP: push_esc_seq('5', '~'); break;
        case KBD_KEY_PAGEDOWN: push_esc_seq('6', '~'); break;
        default: break; /* F-keys, logo keys, media: counted, not typed */
    }
}

void kbd_push_ascii(char c) {
    ring_push((uint8_t)c);
}

void kbd_init(void) {
    memset(kbd_ring, 0, sizeof(kbd_ring));
    memset(&kbd_st, 0, sizeof(kbd_st));
    kbd_head = kbd_tail = kbd_used = 0;
    kbd_shift = kbd_ctrl = kbd_alt = kbd_caps = 0;
    kbd_st.last_value = -1;
}

void kbd_status(kbd_status_t *out) {
    if (!out) return;
    *out = kbd_st;
    out->ring_used = kbd_used;
}

int kbd_is_present(void) {
    return kbd_st.present ? 1 : 0;
}

/* ---- virtio-mmio transport (__riscv only) ---- */
#ifdef __riscv

#define VIRTIO_MMIO_BASE   ((uintptr_t)0x10001000u)
#define VIRTIO_MMIO_STRIDE ((uintptr_t)0x1000u)
#define VIRTIO_MMIO_SLOTS  8u
#define VIRTIO_INPUT_DEV   18u

#define VMM_MAGIC      0x000u
#define VMM_VERSION    0x004u
#define VMM_DEVICE_ID  0x008u
#define VMM_FEAT       0x010u
#define VMM_FEAT_SEL   0x014u
#define VMM_DRV_FEAT   0x020u
#define VMM_DRV_SEL    0x024u
#define VMM_GUEST_PAGE 0x028u /* legacy only: PFN shift; MUST be set or all
                               * queue addresses land <<0 (see x-query) */
#define VMM_QSEL       0x030u
#define VMM_QMAX       0x034u
#define VMM_QNUM       0x038u
#define VMM_QALIGN     0x03cu /* legacy only */
#define VMM_QPFN       0x040u /* legacy only: queue page number */
#define VMM_QREADY     0x044u /* modern only */
#define VMM_QNOTIFY    0x050u
#define VMM_ISTATUS    0x060u
#define VMM_IACK       0x064u
#define VMM_STATUS     0x070u
#define VMM_QDESC_LO   0x080u /* modern only */
#define VMM_QDESC_HI   0x084u
#define VMM_QDRV_LO    0x090u
#define VMM_QDRV_HI    0x094u
#define VMM_QDEV_LO    0x0a0u
#define VMM_QDEV_HI    0x0a4u

#define VIRTIO_MAGIC_VAL 0x74726976u
#define VIRTIO_F_VERSION_1 (32u)

#define VSTAT_ACK       1u
#define VSTAT_DRIVER    2u
#define VSTAT_DRIVER_OK 4u
#define VSTAT_FEAT_OK   8u
#define VSTAT_FAILED    128u

#define VQ_F_WRITE 2u
#define KBD_QSIZE  64u
#define KBD_EV_LEN 8u

struct vq_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};

struct vq_avail_q {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[KBD_QSIZE];
};

struct vq_used_elem {
    uint32_t id;
    uint32_t len;
};

struct vq_used_q {
    uint16_t flags;
    uint16_t idx;
    struct vq_used_elem ring[KBD_QSIZE];
};

struct vio_event {
    uint16_t type;
    uint16_t code;
    uint32_t value;
};

/* Static queue/event storage: identity-mapped .bss, DMA-visible to the
 * device. Modern layout uses separate desc/avail + used pages; legacy
 * (MMIO version 1) needs one contiguous region per queue with the used
 * ring at +4096 (vring ALIGN formula: 16*64 + avail <= 4096). */
static struct vq_desc q0_desc[KBD_QSIZE] __attribute__((aligned(16)));
static struct vq_avail_q q0_avail __attribute__((aligned(2)));
static volatile struct vq_used_q q0_used __attribute__((aligned(4096)));
static struct vq_desc q1_desc[KBD_QSIZE] __attribute__((aligned(16)));
static struct vq_avail_q q1_avail __attribute__((aligned(2)));
static volatile struct vq_used_q q1_used __attribute__((aligned(4096)));
static uint8_t q0_leg_mem[8192] __attribute__((aligned(4096)));
static uint8_t q1_leg_mem[8192] __attribute__((aligned(4096)));
static struct vio_event q0_evbuf[KBD_QSIZE] __attribute__((aligned(8)));

/* Live eventq view (points at the modern pages or the legacy regions). */
static struct vq_desc *q_desc;
static struct vq_avail_q *q_avail;
static volatile struct vq_used_q *q_used;

static volatile uint32_t *kbd_regs;
static uint16_t kbd_q0_n, kbd_q1_n, kbd_q0_seen;

static inline void vio_fence(void) {
    __asm__ volatile("fence iorw,iorw" ::: "memory");
}

static inline uint32_t vio_r(uint32_t off) {
    return *(volatile uint32_t *)((uintptr_t)kbd_regs + off);
}

static inline void vio_w(uint32_t off, uint32_t v) {
    *(volatile uint32_t *)((uintptr_t)kbd_regs + off) = v;
}

static void vio_w64(uint32_t lo_off, uint64_t v) {
    vio_w(lo_off, (uint32_t)(v & 0xffffffffu));
    vio_w(lo_off + 4u, (uint32_t)(v >> 32));
    vio_fence();
}

/* Negotiate one modern queue: returns element count or 0 on failure. */
static uint16_t vio_setup_queue(uint32_t qsel, struct vq_desc *desc,
                                struct vq_avail_q *avail,
                                volatile struct vq_used_q *used) {
    uint32_t max;
    vio_w(VMM_QSEL, qsel);
    max = vio_r(VMM_QMAX);
    if (max == 0 || max > 1024u) return 0;
    uint16_t n = (max > KBD_QSIZE) ? KBD_QSIZE : (uint16_t)max;
    memset(desc, 0, sizeof(struct vq_desc) * n);
    memset(avail, 0, sizeof(struct vq_avail_q));
    memset((void *)used, 0, sizeof(struct vq_used_q));
    vio_w(VMM_QNUM, n);
    vio_w64(VMM_QDESC_LO, (uint64_t)(uintptr_t)desc);
    vio_w64(VMM_QDRV_LO, (uint64_t)(uintptr_t)avail);
    vio_w64(VMM_QDEV_LO, (uint64_t)(uintptr_t)used);
    vio_w(VMM_QREADY, 1u);
    vio_fence();
    return n;
}

/* Negotiate one legacy (MMIO version 1) queue inside an 8K region:
 * desc/avail at +0, used ring at +4096. Returns count or 0. */
static uint16_t vio_setup_queue_leg(uint32_t qsel, uint8_t *mem) {
    uint32_t max;
    vio_w(VMM_QSEL, qsel);
    max = vio_r(VMM_QMAX);
    if (max == 0 || max > 1024u) return 0;
    uint16_t n = (max > KBD_QSIZE) ? KBD_QSIZE : (uint16_t)max;
    memset(mem, 0, 8192);
    vio_w(VMM_QNUM, n);
    /* Legacy PFNs are guest-page numbers: tell the device our 4K pages
     * BEFORE QueuePFN, or desc/avail/used all decode <<0 and events
     * silently never complete (avail idx reads 0 from below RAM). */
    vio_w(VMM_GUEST_PAGE, 4096u);
    vio_w(VMM_QALIGN, 4096u);
    vio_w(VMM_QPFN, (uint32_t)((uintptr_t)mem >> 12));
    vio_fence();
    q_desc = (struct vq_desc *)mem;
    q_avail = (struct vq_avail_q *)(mem + sizeof(struct vq_desc) * n);
    q_used = (volatile struct vq_used_q *)(mem + 4096);
    return n;
}

static void vio_offer_events(void) {
    /* Offer every eventq descriptor (device-writable, 8 bytes each). */
    for (uint16_t i = 0; i < kbd_q0_n; i++) {
        q_desc[i].addr = (uint64_t)(uintptr_t)&q0_evbuf[i];
        q_desc[i].len = KBD_EV_LEN;
        q_desc[i].flags = VQ_F_WRITE;
        q_desc[i].next = 0;
        q_avail->ring[i] = i;
    }
    vio_fence();
    q_avail->idx = kbd_q0_n;
    vio_fence();
    vio_w(VMM_QNOTIFY, 0u);
    vio_fence();
}

static kerror_t vio_features_ok(int legacy) {
    vio_w(VMM_FEAT_SEL, 0u);
    (void)vio_r(VMM_FEAT);
    if (legacy) {
        /* 32-bit legacy features: we need nothing optional. */
        vio_w(VMM_DRV_SEL, 0u);
        vio_w(VMM_DRV_FEAT, 0u);
    } else {
        /* We need nothing beyond VERSION_1 (bit 32 -> selector 1). */
        vio_w(VMM_DRV_SEL, 1u);
        vio_w(VMM_DRV_FEAT, 1u);
        vio_w(VMM_DRV_SEL, 0u);
        vio_w(VMM_DRV_FEAT, 0u);
    }
    vio_w(VMM_STATUS, VSTAT_ACK | VSTAT_DRIVER | VSTAT_FEAT_OK);
    vio_fence();
    if (!(vio_r(VMM_STATUS) & VSTAT_FEAT_OK)) return ERR_INVALID_ARG;
    return ERR_OK;
}

static void vio_fail(void) {
    vio_w(VMM_STATUS, VSTAT_ACK | VSTAT_DRIVER | VSTAT_FAILED);
    vio_fence();
    kbd_regs = NULL;
}

static kerror_t vio_bind_device(uintptr_t base, uint32_t slot, int legacy) {
    kbd_regs = (volatile uint32_t *)base;

    vio_w(VMM_STATUS, 0u);
    vio_fence();
    vio_w(VMM_STATUS, VSTAT_ACK | VSTAT_DRIVER);
    vio_fence();

    if (vio_features_ok(legacy) != ERR_OK) {
        vio_fail();
        return ERR_INVALID_ARG;
    }

    if (legacy) {
        kbd_q0_n = vio_setup_queue_leg(0u, q0_leg_mem);
        if (kbd_q0_n == 0) {
            vio_fail();
            return ERR_NO_MEM;
        }
        /* statusq: configured but parked empty (LED updates unused). */
        vio_w(VMM_QSEL, 1u);
        if (vio_r(VMM_QMAX) == 0) {
            vio_fail();
            return ERR_NO_MEM;
        }
        {
            uint32_t max1 = vio_r(VMM_QMAX);
            uint16_t n1 = (max1 > KBD_QSIZE) ? KBD_QSIZE : (uint16_t)max1;
            memset(q1_leg_mem, 0, 8192);
            vio_w(VMM_QNUM, n1);
            vio_w(VMM_GUEST_PAGE, 4096u);
            vio_w(VMM_QALIGN, 4096u);
            vio_w(VMM_QPFN, (uint32_t)((uintptr_t)q1_leg_mem >> 12));
            vio_fence();
            kbd_q1_n = n1;
        }
    } else {
        kbd_q0_n = vio_setup_queue(0u, q0_desc, &q0_avail, &q0_used);
        if (kbd_q0_n == 0) {
            vio_fail();
            return ERR_NO_MEM;
        }
        q_desc = q0_desc;
        q_avail = &q0_avail;
        q_used = &q0_used;
        kbd_q1_n = vio_setup_queue(1u, q1_desc, &q1_avail, &q1_used);
        if (kbd_q1_n == 0) {
            vio_fail();
            return ERR_NO_MEM;
        }
    }

    vio_offer_events();

    vio_w(VMM_STATUS, VSTAT_ACK | VSTAT_DRIVER | VSTAT_FEAT_OK | VSTAT_DRIVER_OK);
    vio_fence();

    kbd_q0_seen = 0;
    kbd_st.present = 1;
    kbd_st.transport = (uint8_t)slot;
    kbd_st.device_id = VIRTIO_INPUT_DEV;
    return ERR_OK;
}

/* Drain the used ring (bounded: at most 32 completions per call). */
static void vio_drain(void) {
    uint32_t isr;
    uint16_t used_idx;
    uint32_t n = 0;

    if (!kbd_regs || !kbd_st.present || !q_used || !q_avail) return;
    isr = vio_r(VMM_ISTATUS);
    if (isr) vio_w(VMM_IACK, isr);
    vio_fence();

    used_idx = q_used->idx;
    while (kbd_q0_seen != used_idx && n < 32u) {
        struct vq_used_elem e = q_used->ring[kbd_q0_seen % kbd_q0_n];
        uint32_t id = e.id;
        vio_fence();
        if (id < (uint32_t)kbd_q0_n) {
            uint16_t et = q0_evbuf[id].type;
            uint16_t ec = q0_evbuf[id].code;
            int32_t ev = (int32_t)q0_evbuf[id].value;
            kbd_put_event(et, ec, ev);
            /* Repost the buffer. */
            q_avail->ring[q_avail->idx % kbd_q0_n] = (uint16_t)id;
            vio_fence();
            q_avail->idx++;
        }
        kbd_q0_seen++;
        n++;
    }
    if (n) {
        vio_fence();
        vio_w(VMM_QNOTIFY, 0u);
    }
}

kerror_t kbd_virtio_init(vspace_t *vs) {
    int found = 0;
    kerror_t bind_err = ERR_NO_MEM;
    if (!vs) return ERR_INVALID_ARG;
    /* Map all 8 virtio-mmio transports (RW, no exec). color 0 = kernel. */
    if (vspace_map(vs, VIRTIO_MMIO_BASE, VIRTIO_MMIO_BASE,
                   VIRTIO_MMIO_SLOTS * VIRTIO_MMIO_STRIDE, 0x3, 0) != ERR_OK)
        return ERR_NO_MEM;
    vio_fence();
    for (uint32_t s = 0; s < VIRTIO_MMIO_SLOTS; s++) {
        uintptr_t base = VIRTIO_MMIO_BASE + (uintptr_t)s * VIRTIO_MMIO_STRIDE;
        uint32_t magic = *(volatile uint32_t *)(base + VMM_MAGIC);
        uint32_t ver, dev;
        if (magic != VIRTIO_MAGIC_VAL) continue;
        /* Accept legacy (1) and modern (2) transports; this QEMU reports 1. */
        ver = *(volatile uint32_t *)(base + VMM_VERSION);
        if (ver != 1u && ver != 2u) continue;
        dev = *(volatile uint32_t *)(base + VMM_DEVICE_ID);
        if (dev != VIRTIO_INPUT_DEV) continue;
        found = 1;
        if (vio_bind_device(base, s, ver == 1u) == ERR_OK) return ERR_OK;
        bind_err = ERR_INVALID_ARG; /* device here, but bind failed */
    }
    /* Absent (UART-only fallback) vs present-but-broken: different codes. */
    return found ? bind_err : ERR_NO_MEM;
}

void kbd_poll(void) {
    int c, drained = 0;
    vio_drain();
    if (console_is_split()) return; /* window shell: virtio only */
    /* Drain UART RX too (bounded): serial and virtio share one ring. */
    while (drained < 32) {
        c = uart_getc();
        if (c < 0) break;
        ring_push((uint8_t)(c & 0xff));
        drained++;
    }
}

int kbd_getc(void) {
    int c;
    kbd_poll();
    if (kbd_used == 0) return -1;
    c = kbd_ring[kbd_tail];
    kbd_tail = (uint16_t)((kbd_tail + 1u) & (KBD_RING_SIZE - 1u));
    kbd_used--;
    return c;
}

#else /* host-sim: no MMIO, UART always empty */

kerror_t kbd_virtio_init(vspace_t *vs) {
    if (!vs) return ERR_INVALID_ARG;
    return ERR_NO_MEM;
}

void kbd_poll(void) {
}

int kbd_getc(void) {
    if (kbd_used == 0) return -1;
    int c = kbd_ring[kbd_tail];
    kbd_tail = (uint16_t)((kbd_tail + 1u) & (KBD_RING_SIZE - 1u));
    kbd_used--;
    return c;
}

#endif

/* ---- moonsh weak-hook impl (strong here; userspace ELF has none) ---- */
static unsigned kbd_dec(char *dst, unsigned room, uint32_t v) {
    char tmp[10];
    unsigned n = 0, w = 0;
    if (v == 0) {
        if (room) dst[0] = '0';
        return room ? 1u : 0u;
    }
    while (v && n < sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    while (n && w < room) {
        dst[w++] = tmp[--n];
    }
    return w;
}

static unsigned kbd_puts(char *dst, unsigned room, unsigned at, const char *s) {
    while (*s && at < room) dst[at++] = *s++;
    return at;
}

/* One-line driver status for `kbd`. Always NUL-terminates when len > 0. */
int moonsh_kbd_status(char *buf, unsigned len) {
    kbd_status_t s;
    unsigned at = 0;
    if (!buf || !len) return 0;
    kbd_status(&s);
    if (s.present) {
        at = kbd_puts(buf, len - 1u, at, "virtio-input slot=");
        at += kbd_dec(buf + at, len - 1u - at, s.transport);
        at = kbd_puts(buf, len - 1u, at, " ev=");
        at += kbd_dec(buf + at, len - 1u - at, s.ev_total);
        at = kbd_puts(buf, len - 1u, at, " ascii=");
        at += kbd_dec(buf + at, len - 1u - at, s.ascii_total);
        at = kbd_puts(buf, len - 1u, at, " drops=");
        at += kbd_dec(buf + at, len - 1u - at, s.drops);
        at = kbd_puts(buf, len - 1u, at, " ring=");
        at += kbd_dec(buf + at, len - 1u - at, s.ring_used);
#ifdef __riscv
        /* Live transport diagnostics (M-mode, MMIO still mapped). */
        if (kbd_regs && q_used) {
            uint32_t sr = vio_r(VMM_STATUS);
            uint16_t uq = q_used->idx;
            at = kbd_puts(buf, len - 1u, at, " sr=");
            for (int sh = 28; sh >= 0 && at < len - 1u; sh -= 4) {
                unsigned n = (sr >> (unsigned)sh) & 0xF;
                buf[at++] = n < 10 ? (char)('0' + n) : (char)('a' + n - 10);
            }
            at = kbd_puts(buf, len - 1u, at, " uq=");
            at += kbd_dec(buf + at, len - 1u - at, uq);
            at = kbd_puts(buf, len - 1u, at, " seen=");
            at += kbd_dec(buf + at, len - 1u - at, kbd_q0_seen);
        }
#endif
    } else {
        at = kbd_puts(buf, len - 1u, at, "virtio-input absent (UART-only); ascii=");
        at += kbd_dec(buf + at, len - 1u - at, s.ascii_total);
        at = kbd_puts(buf, len - 1u, at, " drops=");
        at += kbd_dec(buf + at, len - 1u - at, s.drops);
        at = kbd_puts(buf, len - 1u, at, " ring=");
        at += kbd_dec(buf + at, len - 1u - at, s.ring_used);
    }
    buf[at] = '\0';
    return (int)at;
}
