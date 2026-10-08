/* tests/test_dev_leaves.c - live vs reserved MMIO catalog. */
#include <stdio.h>
#include "../kernel/dev_leaves.h"
#include "../kernel/virtio_ident.h"

#define CHECK(c)                                                               \
    do                                                                         \
    {                                                                          \
        if (!(c))                                                              \
        {                                                                      \
            printf("FAIL line %d: %s\n", __LINE__, #c);                        \
            return 1;                                                          \
        }                                                                      \
    } while (0)

int main(void)
{
    int i;
    CHECK(v2_virtio_dev_known(VIRTIO_DEV_GPU));
    CHECK(v2_virtio_dev_known(VIRTIO_DEV_SOUND));
    CHECK(!v2_virtio_dev_live(VIRTIO_DEV_GPU));
    CHECK(v2_virtio_dev_live(VIRTIO_DEV_NET));
    CHECK(v2_virtio_owner_tid(VIRTIO_DEV_NET) == T_NET);
    CHECK(v2_virtio_owner_tid(VIRTIO_DEV_GPU) < 0);
    CHECK(virtio_ident_match(VIRTIO_MAGIC, VIRTIO_VERSION_MODERN, 1, VIRTIO_DEV_NET));
    CHECK(!virtio_ident_match(0, 2, 1, VIRTIO_DEV_NET));
    CHECK(virtio_ident_irq(0) == 1);
    CHECK(virtio_ident_irq(8) == VIRTIO_IRQ_NOT_FOUND);
    CHECK(v2_dev_leaves_mapped_count() >= 4);
    for (i = 0; i < DEV_LEAVES_MAX; i++)
    {
        if (v2_dev_leaves[i].owner == DEV_LEAF_UNOWNED)
            CHECK(!v2_dev_leaf_mapped(&v2_dev_leaves[i]));
        else
            CHECK(v2_dev_leaves[i].owner <= (uint8_t)T_GUI);
    }
    puts("PASS: test_dev_leaves");
    return 0;
}
