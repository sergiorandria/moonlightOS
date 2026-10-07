/* userspace/net/sock.c - Socket table with port demux. UDP only; TCP refused. */
#include "sock.h"

/* 1-slot fair-share: each open socket owns one slot carved from the
 * 4-slot datagram queue, so the 5th concurrent open fails. */
#define NET_SOCK_FAIR_MAX 4

static net_sock_t net_socks[NET_SOCK_MAX];

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
