/* userspace/net/sock.h - Socket table stub. Fail-closed: no bind/listen.
 * The live net ELF owns the NIC; sockets wait on a later RPC, never a
 * kernel syscall. */
#ifndef NET_SOCK_H
#define NET_SOCK_H

#include <stdint.h>

#define NET_SOCK_MAX 8
#define NET_SOCK_NONE 0
#define NET_SOCK_UDP 1
#define NET_SOCK_TCP 2

typedef struct
{
    uint8_t kind;
    uint8_t used;
    uint16_t port;
} net_sock_t;

int net_sock_open(unsigned kind, uint16_t port);
int net_sock_close(int id);
int net_sock_send(int id, const uint8_t *buf, unsigned long len);

#endif /* NET_SOCK_H */
