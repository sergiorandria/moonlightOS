/* kernel/irq.h - IRQ → (tid, notify-bit) routing. Mechanism only.
 *
 * The kernel claims the PLIC, looks up a bound route, OR-accumulates a
 * notify badge, and wakes WAIT-blocked owners. It never programs a
 * device. Unbound sources stay fail-closed (no wake). Stub routes
 * (IRQ_KIND_STUB) complete the IRQ without waking anyone — reserved
 * for devices that exist on the bus before a driver thread exists.
 *
 * Host-testable: table ops have no MMIO. irq_plic_* is target-only.
 */
#ifndef V2_IRQ_H
#define V2_IRQ_H

#include <stdint.h>

#include "platform.h"

#define IRQ_KIND_NONE 0u
#define IRQ_KIND_NET 1u
#define IRQ_KIND_BLK 2u
#define IRQ_KIND_INPUT 3u
#define IRQ_KIND_STUB 4u /* known, no owner thread yet */

#define IRQ_ROUTES_MAX 16

typedef struct
{
    uint32_t irq;   /* VIRTIO_IRQ_NOT_FOUND = empty slot */
    uint8_t tid;    /* owning driver thread; ignored for STUB */
    uint8_t kind;   /* IRQ_KIND_* */
    uint64_t bits;  /* notify badge */
} irq_route_t;

void irq_init(void);
int irq_bind(uint32_t irq, uint8_t tid, uint8_t kind, uint64_t bits);
int irq_lookup(uint32_t irq, uint8_t *tid, uint8_t *kind, uint64_t *bits);
void irq_plic_enable(uint32_t irq);

/* Live kinds wake the owner; STUB completes the IRQ with no notify. */
static inline int irq_kind_wakes(uint8_t kind)
{
    return kind == IRQ_KIND_NET || kind == IRQ_KIND_BLK || kind == IRQ_KIND_INPUT;
}

#endif /* V2_IRQ_H */
