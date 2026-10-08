/* userspace/net/cksum.h - IPv4/UDP one's-complement checksums.
 * Pure C, host-testable. No MMIO, no threads, no endpoints.
 *
 * Byte order: inputs are wire (network-order) byte strings; the returned
 * value is the numeric checksum. Store it big-endian (hdr[10]=c>>8,
 * hdr[11]=c&0xFF for IPv4; udp[6..7] likewise for UDP).
 *
 * Callers must zero the checksum field before computing:
 *   IPv4 bytes 10..11, UDP bytes 6..7 of the segment.
 * Summing a received datagram including its stored checksum folds to
 * 0xFFFF, so these helpers return 0x0000 for a valid on-wire buffer.
 *
 * Odd trailing byte is padded as the high-order octet per RFC 768
 * (i.e. added as byte<<8), matching the pseudo-header padding rule. */
#ifndef NET_CKSUM_H
#define NET_CKSUM_H

#include <stdint.h>

/* Fold a 32-bit one's-complement sum and return its complement. */
static inline uint16_t net_cksum_fold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)~sum;
}

/* IPv4 header checksum over hlen header bytes (checksum field zeroed). */
static inline uint16_t net_ip_checksum(const uint8_t *hdr, unsigned hlen)
{
    uint32_t sum = 0;
    unsigned i;
    if (!hdr)
        return 0;
    for (i = 0; i + 1 < hlen; i += 2)
        sum += (uint32_t)(((uint16_t)hdr[i] << 8) | (uint16_t)hdr[i + 1]);
    if (i < hlen)
        sum += (uint32_t)((uint16_t)hdr[i] << 8);
    return net_cksum_fold(sum);
}

/* UDP checksum over the pseudo-header plus the ulen-byte UDP segment
 * (8-byte header with checksum field zeroed + payload).
 * src_ip/dst_ip are IPv4 addresses with the first octet most significant
 * (e.g. 10.0.2.15 == 0x0A00020F). */
static inline uint16_t net_udp_checksum(uint32_t src_ip, uint32_t dst_ip, const uint8_t *udp,
                                        unsigned ulen)
{
    uint32_t sum;
    unsigned i;
    if (!udp)
        return 0;
    sum = ((src_ip >> 16) & 0xFFFFu) + (src_ip & 0xFFFFu) + ((dst_ip >> 16) & 0xFFFFu) +
          (dst_ip & 0xFFFFu) + 17u + (uint32_t)(uint16_t)ulen;
    for (i = 0; i + 1 < ulen; i += 2)
        sum += (uint32_t)(((uint16_t)udp[i] << 8) | (uint16_t)udp[i + 1]);
    if (i < ulen)
        sum += (uint32_t)((uint16_t)udp[i] << 8);
    return net_cksum_fold(sum);
}

#endif /* NET_CKSUM_H */
