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
    unsigned owner;
} net_sock_t;

struct net_waiter
{
    int armed;
    int sock_id;
    unsigned owner;
    uint64_t deadline;
};

int net_sock_open(unsigned kind, uint16_t port, unsigned owner);
int net_sock_close(int id);
int net_sock_demux(uint16_t dport);
int net_sock_send(int id, const uint8_t *buf, unsigned long len);
int net_waiter_arm(int sock_id, unsigned owner, uint64_t now, uint64_t timeout);
int net_waiter_match(uint16_t dport, unsigned *owner_out);
int net_waiter_expire(uint64_t now, int *sock_out, unsigned *owner_out);
void net_waiter_clear(int sock_id);

#endif /* NET_SOCK_H */
