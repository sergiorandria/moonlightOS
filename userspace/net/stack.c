/* userspace/net/stack.c - Net stack stub (no sockets, no kernel MMIO).
 * Classifies frames already delivered by the firewall→net path. */
#include "stack.h"

static int net_stack_up;

int net_stack_init(void)
{
    net_stack_up = 1;
    return 0;
}

int net_stack_rx(const uint8_t *f, unsigned long len)
{
    int c;
    if (!net_stack_up)
        return NET_CLASS_DROP;
    c = net_classify(f, len);
    /* Stub: drop everything except well-formed classes. No reply. */
    return c;
}
