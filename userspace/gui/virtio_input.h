/* userspace/gui/virtio_input.h - VirtIO input device protocol definitions.
 * Minimal VirtIO-input driver for keyboard and mouse (S4c). Covers MMIO
 * register layout, event structures (Linux input_event), and virtqueue
 * basics. No full virtio library: this is a single-purpose implementation
 * for the GUI server (tid 10) only. */

#ifndef VIRTIO_INPUT_H
#define VIRTIO_INPUT_H

#include <stdint.h>

/* VirtIO MMIO register offsets (VirtIO v1.1 spec, section 4.2.2).
 * Base address: KBD_MMIO_UVA 0x81200000 or MOUSE_MMIO_UVA 0x81400000.
 * All registers are 32-bit (uint32_t), aligned, volatile. */
#define VIRTIO_MMIO_MAGIC 0x000          /* 0x74726976 ("virt") */
#define VIRTIO_MMIO_VERSION 0x004        /* 0x2 for modern (v1.0+) */
#define VIRTIO_MMIO_DEVICE_ID 0x008      /* 18 for input */
#define VIRTIO_MMIO_VENDOR_ID 0x00c      /* 0x554d4551 (QEMU) */
#define VIRTIO_MMIO_DEVICE_FEATURES 0x010
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL 0x014
#define VIRTIO_MMIO_DRIVER_FEATURES 0x020
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL 0x024
#define VIRTIO_MMIO_QUEUE_SEL 0x030
#define VIRTIO_MMIO_QUEUE_NUM_MAX 0x034
#define VIRTIO_MMIO_QUEUE_NUM 0x038
#define VIRTIO_MMIO_QUEUE_READY 0x044
#define VIRTIO_MMIO_QUEUE_NOTIFY 0x050
#define VIRTIO_MMIO_INTERRUPT_STATUS 0x060
#define VIRTIO_MMIO_INTERRUPT_ACK 0x064
#define VIRTIO_MMIO_STATUS 0x070
#define VIRTIO_MMIO_QUEUE_DESC_LOW 0x080
#define VIRTIO_MMIO_QUEUE_DESC_HIGH 0x084
#define VIRTIO_MMIO_QUEUE_DRIVER_LOW 0x090
#define VIRTIO_MMIO_QUEUE_DRIVER_HIGH 0x094
#define VIRTIO_MMIO_QUEUE_DEVICE_LOW 0x0a0
#define VIRTIO_MMIO_QUEUE_DEVICE_HIGH 0x0a4
#define VIRTIO_MMIO_CONFIG_GENERATION 0x0fc

/* VirtIO device status bits (VIRTIO_MMIO_STATUS register) */
#define VIRTIO_STATUS_ACKNOWLEDGE 1
#define VIRTIO_STATUS_DRIVER 2
#define VIRTIO_STATUS_FAILED 128
#define VIRTIO_STATUS_FEATURES_OK 8
#define VIRTIO_STATUS_DRIVER_OK 4
#define VIRTIO_STATUS_DEVICE_NEEDS_RESET 64
#define VIRTIO_F_VERSION_1 32u

/* VirtIO input event structure (Linux input_event, 8 bytes).
 * VirtIO-input spec (v1.1 section 5.8) uses the Linux input subsystem
 * event format. Device writes events to the eventq (queue 0). */
struct virtio_input_event {
    uint16_t type;   /* Event type: EV_SYN, EV_KEY, EV_REL, EV_ABS */
    uint16_t code;   /* Event code: KEY_*, BTN_*, REL_*, ABS_* */
    uint32_t value;  /* Event value: 0=release, 1=press, 2=repeat (key); delta (rel) */
};

/* Linux input event types (include/uapi/linux/input-event-codes.h) */
#define EV_SYN 0   /* Synchronization event (marks event batch boundary) */
#define EV_KEY 1   /* Key/button press or release */
#define EV_REL 2   /* Relative axis (mouse movement) */
#define EV_ABS 3   /* Absolute axis (touchscreen, tablet) */

/* Linux input event codes for EV_REL (relative axes, mouse movement) */
#define REL_X 0    /* Relative X axis (mouse horizontal movement) */
#define REL_Y 1    /* Relative Y axis (mouse vertical movement) */
#define REL_WHEEL 8 /* Scroll wheel vertical */

/* Linux input event codes for EV_KEY (buttons) */
#define BTN_LEFT 0x110     /* Left mouse button */
#define BTN_RIGHT 0x111    /* Right mouse button */
#define BTN_MIDDLE 0x112   /* Middle mouse button */

/* Linux input event codes for EV_KEY (keyboard scancodes).
 * Partial table: common ASCII keys + modifiers. Full table in Linux
 * include/uapi/linux/input-event-codes.h (KEY_*). Values are Linux
 * keycodes, NOT scancodes (USB HID usage IDs). */
#define KEY_RESERVED 0
#define KEY_ESC 1
#define KEY_1 2
#define KEY_2 3
#define KEY_3 4
#define KEY_4 5
#define KEY_5 6
#define KEY_6 7
#define KEY_7 8
#define KEY_8 9
#define KEY_9 10
#define KEY_0 11
#define KEY_MINUS 12
#define KEY_EQUAL 13
#define KEY_BACKSPACE 14
#define KEY_TAB 15
#define KEY_Q 16
#define KEY_W 17
#define KEY_E 18
#define KEY_R 19
#define KEY_T 20
#define KEY_Y 21
#define KEY_U 22
#define KEY_I 23
#define KEY_O 24
#define KEY_P 25
#define KEY_LEFTBRACE 26
#define KEY_RIGHTBRACE 27
#define KEY_ENTER 28
#define KEY_LEFTCTRL 29
#define KEY_A 30
#define KEY_S 31
#define KEY_D 32
#define KEY_F 33
#define KEY_G 34
#define KEY_H 35
#define KEY_J 36
#define KEY_K 37
#define KEY_L 38
#define KEY_SEMICOLON 39
#define KEY_APOSTROPHE 40
#define KEY_GRAVE 41
#define KEY_LEFTSHIFT 42
#define KEY_BACKSLASH 43
#define KEY_Z 44
#define KEY_X 45
#define KEY_C 46
#define KEY_V 47
#define KEY_B 48
#define KEY_N 49
#define KEY_M 50
#define KEY_COMMA 51
#define KEY_DOT 52
#define KEY_SLASH 53
#define KEY_RIGHTSHIFT 54
#define KEY_KPASTERISK 55
#define KEY_LEFTALT 56
#define KEY_SPACE 57
#define KEY_CAPSLOCK 58
#define KEY_RIGHTCTRL 97
#define KEY_RIGHTALT 100
#define KEY_UP 103
#define KEY_LEFT 105
#define KEY_RIGHT 106
#define KEY_DOWN 108

/* VirtIO descriptor flags (virtq_desc.flags) */
#define VIRTQ_DESC_F_NEXT 1      /* Descriptor continues via next field */
#define VIRTQ_DESC_F_WRITE 2     /* Device writes (buffer is write-only) */
#define VIRTQ_DESC_F_INDIRECT 4  /* Buffer contains list of descriptors */

/* Simplified virtqueue descriptor (VirtIO v1.1 section 2.6.5).
 * S4c uses a minimal setup: single-descriptor chains (no NEXT),
 * statically allocated rings. Production virtio drivers use dynamic
 * multi-descriptor chains and indirect descriptors for scatter-gather. */
typedef struct {
    uint64_t addr;   /* Physical address (guest-physical) */
    uint32_t len;    /* Buffer length in bytes */
    uint16_t flags;  /* VIRTQ_DESC_F_* */
    uint16_t next;   /* Next descriptor index (if VIRTQ_DESC_F_NEXT) */
} virtq_desc_t;

/* Virtqueue available ring (driver->device, VirtIO v1.1 section 2.6.6).
 * Driver writes descriptor indices here; device reads them. */
typedef struct {
    uint16_t flags;     /* VIRTQ_AVAIL_F_NO_INTERRUPT */
    uint16_t idx;       /* Next available slot (wraps at 65536) */
    uint16_t ring[16];  /* Descriptor indices (size = queue size) */
} virtq_avail_t;

/* Virtqueue used ring (device->driver, VirtIO v1.1 section 2.6.8).
 * Device writes completed descriptor IDs here; driver reads them. */
typedef struct {
    uint16_t flags;     /* VIRTQ_USED_F_NO_NOTIFY */
    uint16_t idx;       /* Next used slot (wraps at 65536) */
    struct {
        uint32_t id;    /* Descriptor ID */
        uint32_t len;   /* Bytes written to descriptor buffer */
    } ring[16];         /* Size = queue size */
} virtq_used_t;

/* UVA definitions (kernel-mapped, tid 10 only; kernel/kboot.c line ~168).
 * KBD_MMIO_UVA maps to the first found dev-18 (keyboard), MOUSE_MMIO_UVA
 * to the second. Both map 8 transport pages (one l0 leaf each) covering
 * 0x10001000+i*0x1000. The actual transport index depends on QEMU's
 * device attachment order (last-first for virtio-mmio backends). */
#define KBD_MMIO_UVA 0x81200000UL   /* l1_t[10][9] = VPN[1] index 9 */
#define MOUSE_MMIO_UVA 0x81400000UL /* l1_t[10][10] = VPN[1] index 10 */

/* VirtIO eventq ring state (kbd and mouse each have independent rings).
 * S4c uses statically allocated flat rings with 16 slots each. */
typedef struct {
    virtq_desc_t desc[16];  /* Descriptor ring (16 slots) */
    virtq_avail_t avail;    /* Available ring (driver→device) */
    volatile virtq_used_t used; /* Device-written ring */
    volatile struct virtio_input_event events[16]; /* Device-written buffers */
    uint16_t last_used_idx; /* Last processed used.idx (for polling) */
} virtio_input_ring_t;

/* VirtIO input device initialization and polling functions.
 * These must be provided by the GUI implementation (virtio_input.c or inline).
 * Forward declarations for input state types (defined in input.h). */
struct kbd_modifiers;
struct mouse_state;

int virtio_input_init(volatile uint32_t *mmio, virtio_input_ring_t *ring, int queue_size);
void virtio_input_ack(volatile uint32_t *mmio);
void virtio_input_notify(volatile uint32_t *mmio);
/* Return 1 with a validated completion, 0 if empty, or -1 on corrupt state. */
static inline int virtio_input_next(virtio_input_ring_t *ring, uint16_t queue_size,
                                    uint16_t *desc_id)
{
    uint16_t pending;
    uint16_t used_slot;
    uint32_t id;
    if (!ring || !desc_id || queue_size == 0 || queue_size > 16 ||
        (queue_size & (queue_size - 1u)) != 0)
        return -1;
    pending = (uint16_t)(ring->used.idx - ring->last_used_idx);
    if (pending == 0)
        return 0;
    if (pending > queue_size)
        return -1;
    used_slot = (uint16_t)(ring->last_used_idx % queue_size);
    id = ring->used.ring[used_slot].id;
    if (id >= queue_size ||
        ring->used.ring[used_slot].len < sizeof(struct virtio_input_event) ||
        ring->desc[id].len < sizeof(struct virtio_input_event) ||
        !(ring->desc[id].flags & VIRTQ_DESC_F_WRITE))
        return -1;
    *desc_id = (uint16_t)id;
    return 1;
}

/* Recycle exactly the current completion after the event has been consumed. */
static inline int virtio_input_recycle(virtio_input_ring_t *ring, uint16_t queue_size,
                                       uint16_t desc_id)
{
    uint16_t pending;
    uint16_t used_slot;
    if (!ring || queue_size == 0 || queue_size > 16 ||
        (queue_size & (queue_size - 1u)) != 0 || desc_id >= queue_size)
        return 0;
    pending = (uint16_t)(ring->used.idx - ring->last_used_idx);
    if (pending == 0 || pending > queue_size)
        return 0;
    used_slot = (uint16_t)(ring->last_used_idx % queue_size);
    if (ring->used.ring[used_slot].id != desc_id)
        return 0;
    ring->avail.ring[ring->avail.idx % queue_size] = desc_id;
    ring->avail.idx++;
    ring->last_used_idx++;
    return 1;
}

#endif /* VIRTIO_INPUT_H */
