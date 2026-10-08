/* userspace/net/dhcp.h - DHCPv4 client codec (RFC 2131, udhcpc discipline).
 * Pure C, host-testable, libc-free (stdint.h only) for freestanding use:
 * fixed header + magic cookie, bounded TLV option scan (END/PADDING
 * tolerant, zero-length skip, overrun rejects), fits-checked builders. */
#ifndef NET_DHCP_H
#define NET_DHCP_H

#include <stdint.h>

#define DHCP_OP_REQUEST 1u
#define DHCP_HTYPE_ETH 1u
#define DHCP_HLEN_ETH 6u
#define DHCP_FLAGS_BCAST 0x8000u
#define DHCP_COOKIE_0 99u
#define DHCP_COOKIE_1 130u
#define DHCP_COOKIE_2 83u
#define DHCP_COOKIE_3 99u
#define DHCP_OPT_PAD 0u
#define DHCP_OPT_END 255u
#define DHCP_OPT_MSG_TYPE 53u
#define DHCP_OPT_SERVER_ID 54u
#define DHCP_OPT_PARAM_REQ 55u
#define DHCP_OPT_SUBNET 1u
#define DHCP_OPT_ROUTER 3u
#define DHCP_OPT_DNS 6u
#define DHCP_OPT_REQ_IP 50u
#define DHCP_OPT_LEASE 51u
#define DHCP_MSG_DISCOVER 1u
#define DHCP_MSG_OFFER 2u
#define DHCP_MSG_REQUEST 3u
#define DHCP_MSG_ACK 5u
#define DHCP_HDR_LEN 236u
#define DHCP_MIN_MSG 300u /* bootp + options, padded (udhcpc: 300-octet floor) */
#define DHCP_CLIENT_PORT 68u
#define DHCP_SERVER_PORT 67u

struct net_dhcp_lease
{
    uint32_t yiaddr;
    uint32_t server;
    uint32_t subnet;
    uint32_t router;
    uint32_t dns;
    uint32_t lease_sec;
};

int net_dhcp_build_discover(uint32_t xid, uint8_t *out, unsigned long *outlen);
int net_dhcp_build_request(uint32_t xid, const struct net_dhcp_lease *ls, uint8_t *out,
                           unsigned long *outlen);
int net_dhcp_parse_offer(const uint8_t *f, unsigned long len, uint32_t xid,
                         struct net_dhcp_lease *out);
int net_dhcp_parse_ack(const uint8_t *f, unsigned long len, uint32_t xid,
                       struct net_dhcp_lease *out);
void net_dhcp_apply(const struct net_dhcp_lease *ls);

#endif /* NET_DHCP_H */
