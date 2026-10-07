/* userspace/net/dns.h - Minimal RFC 1035 query builder + first-A parser.
 * Pure C, host-testable, libc-free (stdint.h only, byte loops) so the
 * freestanding net ELF may share it. No threads, no endpoints.
 *
 * Errors reuse the stack.h code points (same numeric values, guarded so
 * including both headers never conflicts):
 *   -(NET_ERR_TRUNC) on TC-set / short / malformed input,
 *   -(NET_ERR_EMPTY) on a well-formed response with no usable A record.
 * "Malformed" maps to TRUNC: there is no separate code point, and a
 * truncated (TC=1) response must never yield a half-parsed address.
 *
 * net_dns_build_query: one-question query, recursion-desired, QTYPE A /
 * QCLASS IN. Caller must provide >= NET_DNS_QUERY_MAX bytes at out;
 * *out_len is output-only (bytes written). Label limits: 63/label,
 * 255 wire total (length bytes + terminating root). A single trailing
 * dot is accepted ("example.com." == "example.com"); "." queries root.
 *
 * net_dns_parse_a: skips QDCOUNT questions, then returns the first
 * TYPE-A/CLASS-IN RDATA as a uint32 (first octet most significant,
 * e.g. 93.184.216.34 == 0x5DB8D822, matching the cksum.h convention).
 * NAME compression follows exactly one 0xC0 pointer level; a chained
 * (pointer-to-pointer) or out-of-bounds pointer is malformed. TXID and
 * RCODE are not validated here (the caller matches TXIDs); a nonzero
 * RCODE with no usable A simply yields EMPTY. */
#ifndef NET_DNS_H
#define NET_DNS_H

#include <stdint.h>

#define NET_DNS_QTYPE_A 1u
#define NET_DNS_QCLASS_IN 1u
#define NET_DNS_QUERY_MAX 512u
#define NET_DNS_LABEL_MAX 63u
#define NET_DNS_NAME_MAX 255u

#ifndef NET_ERR_EMPTY
#define NET_ERR_EMPTY 1
#endif
#ifndef NET_ERR_TRUNC
#define NET_ERR_TRUNC 2
#endif

int net_dns_build_query(const char *name, uint16_t txid, uint8_t *out, unsigned long *out_len);
int net_dns_parse_a(const uint8_t *resp, unsigned long len, uint32_t *out_ip);

#endif /* NET_DNS_H */
