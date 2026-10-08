/* userspace/net/sock.c - Socket table with port demux. UDP only; TCP refused. */
#include "sock.h"

/* 1-slot fair-share: each open socket owns one slot carved from the
 * 4-slot datagram queue, so the 5th concurrent open fails. */
#define NET_SOCK_FAIR_MAX 4

static net_sock_t net_socks[NET_SOCK_MAX];

/* One waiter per socket slot, indexed by sock_id. Absolute deadline
 * (now+timeout); expiry uses wrap-safe unsigned compare. */
static struct net_waiter net_waiters[NET_SOCK_MAX];

void net_waiter_clear(int sock_id)
{
    if (sock_id < 0 || sock_id >= NET_SOCK_MAX)
        return;
    net_waiters[sock_id].armed = 0;
    net_waiters[sock_id].sock_id = 0;
    net_waiters[sock_id].owner = 0;
    net_waiters[sock_id].deadline = 0;
}

int net_sock_open(unsigned kind, uint16_t port, unsigned owner)
{
    unsigned i;
    unsigned used = 0;
    if (kind != NET_SOCK_UDP)
        return -1;
    for (i = 0; i < NET_SOCK_MAX; i++)
    {
        if (!net_socks[i].used)
            continue;
        if (net_socks[i].port == port)
            return -1;
        used++;
    }
    if (used >= NET_SOCK_FAIR_MAX)
        return -1;
    for (i = 0; i < NET_SOCK_MAX; i++)
    {
        if (net_socks[i].used)
            continue;
        net_socks[i].used = 1;
        net_socks[i].kind = (uint8_t)kind;
        net_socks[i].port = port;
        net_socks[i].owner = owner;
        return (int)i;
    }
    return -1;
}

int net_sock_close(int id)
{
    if (id < 0 || id >= NET_SOCK_MAX)
        return -1;
    if (!net_socks[id].used)
        return -1;
    net_socks[id].used = 0;
    net_socks[id].kind = NET_SOCK_NONE;
    net_socks[id].port = 0;
    net_socks[id].owner = 0;
    net_waiter_clear(id);
    return 0;
}

int net_sock_demux(uint16_t dport)
{
    unsigned i;
    for (i = 0; i < NET_SOCK_MAX; i++)
    {
        if (net_socks[i].used && net_socks[i].port == dport)
            return (int)i;
    }
    return -1;
}

int net_sock_send(int id, const uint8_t *buf, unsigned long len)
{
    (void)buf;
    (void)len;
    if (id < 0 || id >= NET_SOCK_MAX || !net_socks[id].used)
        return -1;
    return -1;
}

int net_waiter_arm(int sock_id, unsigned owner, uint64_t now, uint64_t timeout)
{
    if (sock_id < 0 || sock_id >= NET_SOCK_MAX)
        return -1;
    if (!net_socks[sock_id].used)
        return -1;
    if (net_socks[sock_id].owner != owner)
        return -1;
    if (timeout == 0)
        return 1;
    net_waiters[sock_id].armed = 1;
    net_waiters[sock_id].sock_id = sock_id;
    net_waiters[sock_id].owner = owner;
    net_waiters[sock_id].deadline = now + timeout;
    return 0;
}

int net_waiter_match(uint16_t dport, unsigned *owner_out)
{
    unsigned i;
    for (i = 0; i < NET_SOCK_MAX; i++)
    {
        int sid;
        if (!net_waiters[i].armed)
            continue;
        sid = net_waiters[i].sock_id;
        if (sid < 0 || sid >= NET_SOCK_MAX)
            continue;
        if (!net_socks[sid].used)
            continue;
        if (net_socks[sid].port != dport)
            continue;
        if (owner_out)
            *owner_out = net_waiters[i].owner;
        return sid;
    }
    return -1;
}

int net_waiter_expire(uint64_t now, int *sock_out, unsigned *owner_out)
{
    unsigned i;
    for (i = 0; i < NET_SOCK_MAX; i++)
    {
        int sid;
        if (!net_waiters[i].armed)
            continue;
        /* Wrap-safe absolute-deadline compare: expired iff now is at or
         * past deadline in modular arithmetic (timeouts << 2^63). */
        if ((int64_t)(now - net_waiters[i].deadline) < 0)
            continue;
        sid = net_waiters[i].sock_id;
        if (sock_out)
            *sock_out = sid;
        if (owner_out)
            *owner_out = net_waiters[i].owner;
        net_waiters[i].armed = 0;
        net_waiters[i].sock_id = 0;
        net_waiters[i].owner = 0;
        net_waiters[i].deadline = 0;
        return sid;
    }
    return -1;
}
