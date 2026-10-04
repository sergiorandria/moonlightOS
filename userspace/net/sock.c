/* userspace/net/sock.c - Socket stub. Always ENOSYS-shaped (-1). */
#include "sock.h"

static net_sock_t net_socks[NET_SOCK_MAX];

int net_sock_open(unsigned kind, uint16_t port)
{
    (void)kind;
    (void)port;
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
    return 0;
}

int net_sock_send(int id, const uint8_t *buf, unsigned long len)
{
    (void)buf;
    (void)len;
    if (id < 0 || id >= NET_SOCK_MAX || !net_socks[id].used)
        return -1;
    return -1;
}
