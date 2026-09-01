#include "../kernel/include/cap.h"
#include "../kernel/include/cnode.h"
#include "../kernel/include/alloc.h"
#include "../kernel/include/sched.h"
#include "../kernel/include/iommu.h"
#include "../kernel/include/irq.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("=== Moonlight capability tests ===\n");

    /* Cap derive attenuation must fail when gaining rights */
    cap_t parent = {0};
    parent.type = CAP_FRAME; parent.rights = CAP_RIGHTS_READ; parent.is_valid=1;
    parent.hw_cap.tag=1; parent.hw_cap.sealed=0; parent.hw_cap.base=0x80000000; parent.hw_cap.top=0x80001000; parent.hw_cap.addr=0x80000000;
    cap_t child = cap_derive(parent, CAP_RIGHTS_READ|CAP_RIGHTS_WRITE, 0);
    assert(!child.is_valid); /* cannot gain WRITE */
    printf("PASS: attenuation monotonic\n");

    child = cap_derive(parent, CAP_RIGHTS_READ, 42);
    assert(child.is_valid && child.badge==42);
    printf("PASS: valid derive\n");

    /* CNode copy must enforce rights */
    cnode_t cn1, cn2;
    assert(cnode_init(&cn1,0,8)==ERR_OK);
    assert(cnode_init(&cn2,0,8)==ERR_OK);
    cn1.slots[0]=parent; cn1.slots[0].is_valid=1;
    assert(cnode_copy(&cn2, 0, &cn1, 0, CAP_RIGHTS_READ)==ERR_OK);
    assert(cnode_copy(&cn2, 1, &cn1, 0, CAP_RIGHTS_WRITE)==ERR_NO_RIGHTS);
    printf("PASS: CNode rights check\n");

    /* Allocator color isolation */
    frame_alloc_t fa;
    alloc_init(&fa, 0x80000000, 0x100000);
    cap_t f0, f1;
    assert(alloc_frame(&fa, 0, 4096, &f0)==ERR_OK);
    assert(alloc_frame(&fa, 1, 4096, &f1)==ERR_OK);
    assert(f0.color != f1.color);
    assert(alloc_color_is_valid(0, f0.color));
    assert(!alloc_color_is_valid(0, f1.color));
    printf("PASS: cache coloring partition 0 color=%u part1 color=%u\n", f0.color, f1.color);

    /* Scheduler: overlapping partitions must fail */
    sched_state_t s;
    sched_init(&s);
    assert(sched_partition_create(&s, 0, 0, 6000, 1)==ERR_OK);
    assert(sched_partition_create(&s, 1, 6000, 2000, 3)==ERR_OK);
    assert(sched_partition_create(&s, 2, 5000, 2000, 2)==ERR_INVALID_ARG); /* overlap */
    assert(sched_is_schedulable(&s));
    assert(sched_context_bind(&s, 0, 1, 0, 1000, 2000, 10)==ERR_OK);
    assert(sched_context_bind(&s, 1, 2, 0, 1500, 2000, 20)==ERR_OK);
    assert(!sched_is_schedulable(&s)); /* util 1.25 > 1 */
    printf("PASS: scheduler overlap + EDF check\n");

    /* IOMMU: dev cannot access outside window */
    iommu_state_t iommu={0};
    cap_t iocap={0}; iocap.type=CAP_IOMMU; iocap.is_valid=1; iocap.rights=CHERI_PERM_LOAD|CHERI_PERM_STORE;
    iocap.hw_cap.tag=1; iocap.hw_cap.base=0x90000000; iocap.hw_cap.top=0x90010000;
    assert(iommu_map(&iommu, &iocap, 0x01, 0x90000000, 4096, CHERI_PERM_LOAD)==ERR_OK);
    assert(iommu_check(&iommu, 0x01, 0x90000000, 512, false)==true);
    assert(iommu_check(&iommu, 0x01, 0x90001000, 512, false)==false);
    assert(iommu_check(&iommu, 0x02, 0x90000000, 512, false)==false); /* wrong dev */
    printf("PASS: IOMMU isolation\n");

    /* IRQ bind */
    irq_state_t irq={0};
    cap_t irqcap={0}; irqcap.type=CAP_IRQ; irqcap.is_valid=1; irqcap.u.frame.paddr=5;
    assert(irq_bind(&irq, &irqcap, 10, 1, 99)==ERR_OK);
    assert(irq_bind(&irq, &irqcap, 11, 1, 99)==ERR_REVOKE_NEEDED);
    printf("PASS: IRQ bind exclusive\n");

    printf("ALL TESTS PASS\n");
    return 0;
}
