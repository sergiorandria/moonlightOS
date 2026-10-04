/* tests/test_net_stack.c - classify + socket stub. */
#include <stdio.h>
#include <string.h>
#include "../userspace/net/stack.h"
#include "../userspace/net/stack.c"
#include "../userspace/net/sock.c"

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
    uint8_t arp[42];
    uint8_t ip[34];
    memset(arp, 0, sizeof(arp));
    arp[12] = 0x08;
    arp[13] = 0x06;
    arp[14] = 0x00;
    arp[15] = 0x01;
    arp[16] = 0x08;
    arp[17] = 0x00;
    arp[18] = 6;
    arp[19] = 4;
    arp[20] = 0x00;
    arp[21] = 0x01;
    CHECK(net_classify(arp, sizeof(arp)) == NET_CLASS_ARP);
    memset(ip, 0, sizeof(ip));
    ip[12] = 0x08;
    ip[13] = 0x00;
    ip[14] = 0x45;
    ip[16] = 0x00;
    ip[17] = 20;
    ip[23] = IP_PROTO_TCP;
    /* TCP header min 20 after IHL 20: need 14+20+20 = 54 bytes */
    {
        uint8_t tcp[54];
        memset(tcp, 0, sizeof(tcp));
        memcpy(tcp, ip, 34);
        tcp[17] = 40; /* tot = 40 */
        tcp[23] = IP_PROTO_TCP;
        tcp[14 + 20 + 12] = 0x50; /* data offset 5 */
        CHECK(net_stack_init() == 0);
        CHECK(net_stack_rx(tcp, sizeof(tcp)) == NET_CLASS_TCP);
    }
    CHECK(net_sock_open(NET_SOCK_UDP, 53) < 0);
    CHECK(net_sock_send(0, ip, 4) < 0);
    puts("PASS: test_net_stack");
    return 0;
}
