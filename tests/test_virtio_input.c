#include <stdio.h>
#include <string.h>
#include "../userspace/gui/virtio_input.h"

#define CHECK(condition) do { \
    if (!(condition)) { \
        printf("FAIL line %d: %s\n", __LINE__, #condition); \
        return 1; \
    } \
} while (0)

static void init_ring(virtio_input_ring_t *ring, uint16_t queue_size)
{
    memset(ring, 0, sizeof(*ring));
    for (uint16_t i = 0; i < queue_size; i++) {
        ring->desc[i].len = sizeof(struct virtio_input_event);
        ring->desc[i].flags = VIRTQ_DESC_F_WRITE;
        ring->avail.ring[i] = i;
    }
    ring->avail.idx = queue_size;
}

int main(void)
{
    virtio_input_ring_t ring;
    uint16_t id;
    init_ring(&ring, 4);

    /* Used descriptors may complete out of submission order. */
    ring.used.ring[0].id = 2;
    ring.used.ring[0].len = sizeof(struct virtio_input_event);
    ring.used.ring[1].id = 0;
    ring.used.ring[1].len = sizeof(struct virtio_input_event);
    ring.used.ring[2].id = 3;
    ring.used.ring[2].len = sizeof(struct virtio_input_event);
    ring.used.idx = 3;
    CHECK(virtio_input_next(&ring, 4, &id) == 1 && id == 2);
    CHECK(virtio_input_recycle(&ring, 4, id));
    CHECK(virtio_input_next(&ring, 4, &id) == 1 && id == 0);
    CHECK(virtio_input_recycle(&ring, 4, id));
    CHECK(virtio_input_next(&ring, 4, &id) == 1 && id == 3);
    CHECK(virtio_input_recycle(&ring, 4, id));
    CHECK(virtio_input_next(&ring, 4, &id) == 0);
    CHECK(ring.last_used_idx == 3 && ring.avail.idx == 7);
    CHECK(ring.avail.ring[0] == 2 && ring.avail.ring[1] == 0 &&
          ring.avail.ring[2] == 3);

    /* 16-bit ring indices wrap; slots remain modulo queue size. */
    init_ring(&ring, 4);
    ring.last_used_idx = UINT16_MAX;
    ring.used.idx = 0;
    ring.used.ring[3].id = 1;
    ring.used.ring[3].len = sizeof(struct virtio_input_event);
    ring.avail.idx = UINT16_MAX;
    CHECK(virtio_input_next(&ring, 4, &id) == 1 && id == 1);
    CHECK(virtio_input_recycle(&ring, 4, id));
    CHECK(ring.last_used_idx == 0 && ring.avail.idx == 0);
    CHECK(ring.avail.ring[3] == 1);

    /* Reject invalid queue shape, impossible distance, bad IDs, and short buffers. */
    CHECK(virtio_input_next(&ring, 3, &id) == -1);
    ring.last_used_idx = 0;
    ring.used.idx = 5;
    CHECK(virtio_input_next(&ring, 4, &id) == -1);
    ring.used.idx = 1;
    ring.used.ring[0].id = 4;
    ring.used.ring[0].len = sizeof(struct virtio_input_event);
    CHECK(virtio_input_next(&ring, 4, &id) == -1);
    ring.used.ring[0].id = 1;
    ring.used.ring[0].len = sizeof(struct virtio_input_event) - 1;
    CHECK(virtio_input_next(&ring, 4, &id) == -1);
    ring.used.ring[0].len = sizeof(struct virtio_input_event);
    CHECK(!virtio_input_recycle(&ring, 4, 2));

    puts("PASS: test_virtio_input");
    return 0;
}