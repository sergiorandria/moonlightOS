/* tests/test_net_stack.c - classify + socket stub. */
#include "../userspace/net/cksum.h"
#include "../userspace/net/sock.c"
#include "../userspace/net/stack.c"
#include "../userspace/net/stack.h"
#include <stdio.h>
#include <string.h>

#define CHECK(c)                                                                                   \
    do                                                                                             \
    {                                                                                              \
        if (!(c))                                                                                  \
        {                                                                                          \
            printf("FAIL line %d: %s\n", __LINE__, #c);                                            \
            return 1;                                                                              \
        }                                                                                          \
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
    /* RFC-style fixed vectors: IPv4 header checksum (field zeroed). */
    {
        static const uint8_t hdr[20] = {0x45, 0x00, 0x00, 0x29, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11,
                                        0x00, 0x00, 0x0A, 0x00, 0x02, 0x0F, 0x0A, 0x00, 0x02, 0x02};
        CHECK(net_ip_checksum(hdr, sizeof(hdr)) == 0x1080u);
    }
    /* UDP pseudo-header checksum: odd 21B segment (13B "Hello, world!"
     * payload, trailing byte padded as high-order octet). */
    {
        static const uint8_t seg[21] = {0x12, 0x34, 0x00, 0x35, 0x00, 0x15, 0x00,
                                        0x00, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C,
                                        0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21};
        CHECK(net_udp_checksum(0x0A00020Fu, 0x0A000202u, seg, sizeof(seg)) == 0x93FEu);
    }
    /* UDP pseudo-header checksum: even 12B segment (4B "test" payload). */
    {
        static const uint8_t seg[12] = {0x12, 0x34, 0x00, 0x35, 0x00, 0x0C,
                                        0x00, 0x00, 0x74, 0x65, 0x73, 0x74};
        CHECK(net_udp_checksum(0x0A00020Fu, 0x0A000202u, seg, sizeof(seg)) == 0xED82u);
    }
    puts("PASS: test_net_stack");
    return 0;
}
