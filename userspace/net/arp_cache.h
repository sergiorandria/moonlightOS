/* userspace/net/arp_cache.h - 8-entry ARP table (IP -> MAC).
 * Pure C, host-testable, libc-free (stdint.h only) so the freestanding
 * net ELF may include it. No threads, no endpoints.
 *
 * Canonical wire identity (QEMU SLIRP defaults, matching the gratuitous
 * ARP in v2_main.c:404-419). Later tasks include this header instead of
 * redefining these. IPv4 values store the first octet most significant
 * (10.0.2.15 == 0x0A00020F), matching cksum.h convention.
 *
 * Timebase: net_arp_learn stamps entries with the latest net_arp_tick
 * value; entries older than NET_ARP_TIMEOUT_TICKS (60s @10MHz rdtime,
 * the QEMU virt timebase shared with NET_IRQ_TIMEOUT_TICKS) go stale.
 * Table-full inserts evict the oldest entry. A request for NET_IP_SELF
 * arms one pending reply slot drained by net_arp_need_reply. */
#ifndef NET_ARP_CACHE_H
#define NET_ARP_CACHE_H

#include <stdint.h>

#define NET_ARP_MAX 8u
#define NET_ARP_FRAME_LEN 42u
#define NET_ARP_TIMEOUT_TICKS 600000000ULL

extern const uint8_t NET_MAC_SELF[6];
extern uint32_t NET_IP_SELF;
extern uint32_t NET_IP_GW;
extern uint32_t NET_IP_DNS;
extern uint32_t NET_IP_SUBNET;

void net_arp_init(void);
void net_arp_invalidate(uint32_t ip);
int net_arp_lookup(uint32_t ip, uint8_t *mac_out);
void net_arp_learn(const uint8_t *frame, unsigned long len);
int net_arp_need_reply(uint32_t *sender_ip, uint8_t *sender_mac);
int net_arp_build_request(uint32_t target_ip, uint8_t *frame_out);
int net_arp_build_reply(const uint8_t *req, unsigned long reqlen, uint8_t *frame_out);
void net_arp_tick(uint64_t now_ticks);

#endif /* NET_ARP_CACHE_H */
