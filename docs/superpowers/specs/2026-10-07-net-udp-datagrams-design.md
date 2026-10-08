# Net UDP Datagrams (RX + ARP + UDP) — Phase 1 Design (2026-10-07)

## 1. Intent (agreed)
- Deliver UDP datagrams over the real wire as the first network-stack
  slice, judged by live frames; BSD-style sockets are the next slice.
- Approach A: extend the tid-6 net server in place (no new threads or
  endpoints; NTHREADS=11 is full).
- Ground truth: RFC 768 (UDP), RFC 826 (ARP), RFC 791 (IPv4 subset)
  plus the existing virtio-net phase-2 bring-up in
  `userspace/net/v2_main.c:314-455`.

What was said vs assumed:
- Said: go for network stack.
- Agreed: UDP sockets as goal; datagrams-first slice (RX+ARP+UDP codec,
  minimal `net_stack_udp_send` / `net_udp_recv` interface, no socket API).
- Assumed (locked Sec 1-4): two-frame RX reuse, 8-entry ARP seeded
  with gateway, single pending datagram, 4-slot RX queue, host-vector
  tests + `NET: rx ok` live marker. Correct me if wrong.

Success = host suite green on byte-exact codec vectors; on QEMU the
boot log shows `NET: link up`, `NET: tx ok`, then `NET: rx ok` on the
first valid inbound UDP datagram.

## 2. RX-from-wire (Sec 1, approved)
- Reuse the two DMA frames `net_phase2` already allocates (TX frame +
  RX frame, `NET_TX_VA` / `NET_RX_VA`): post 2 chained RX descriptors
  with 1514B buffers into queue 0 (RX) instead of leaving it empty.
- Completion joins the existing TX used-ring poll (rdtime deadline +
  `V2_YIELD`, never a spin); ISR ack + `V2_WAIT` notify consumption
  unchanged (`v2_main.c:427-454` pattern).
- RX-from-firewall `T_FWD` stub loop (`net_main`) untouched; wire-RX
  feeds `net_stack_rx` directly.
- Out of scope: RX multi-queue, interrupt coalescing, zero-copy.

## 3. ARP table (Sec 2, approved)
- 8-entry IP->MAC table in `userspace/net/stack.c`, seeded at boot
  with gateway `10.0.2.2` + QEMU OUI MAC (`52:54:00:12:34:56`,
  matching the hardcoded ARP in `v2_main.c:404-419`).
- Send to unknown IP: emit ARP request via the TX queue, park the
  datagram in a single pending slot; drop it if no reply within the
  IRQ-timeout Ack window (no queue — best-effort, fail-explicit).
- Inbound ARP: replies learn/update entries; requests for our
  `10.0.2.15` get replies; others drop.
- Expiry: entries older than 60s of kernel ticks go stale (re-request
  on next send). No gratuitous-ARP refresh in Phase 1.

## 4. UDP codec + datagram interface (Sec 3, approved)
- `net_stack_udp_send(dst_ip, dst_port, src_port, payload, len)`:
  builds eth (our MAC, dest from ARP table) + IPv4 (IHL 5, TTL 64,
  protocol 17, header checksum) + UDP (pseudo-header checksum,
  zero-checksum transmit allowed per RFC 768? No — always compute)
  and hands the frame to the TX queue path.
- RX: `net_stack_rx` classifies eth->IP->UDP, validates total length,
  IHL, and both checksums; bad frames drop silently with no marker
  (spoofed/corrupt wire bytes are noise, same discipline as the
  `T_FWD` stub).
- Delivery: 4-slot datagram queue (payload + src ip/port + len);
  `net_udp_recv(buf, cap, *src)` returns bytes or `-ERR_EMPTY` /
  `-ERR_TRUNC` with an explicit truncation flag — never silent.
  Overflow drops newest (fail-explicit via counter, no block).
- Non-UDP frames: current classify-and-drop behavior preserved.

## 5. Tests (Sec 4, approved)
- Extend `tests/test_net_stack.c` (host-only, no QEMU):
  ARP request/reply byte vectors, IP/UDP header+checksum vectors
  (including odd-length payload for pseudo-header padding),
  truncation + empty-queue paths, ARP learn/expire/pending-drop.
- Live-wire proof: `NET: rx ok` marker on first valid UDP; existing
  `NET: link up` / `NET: tx ok` markers unchanged.
- Kernel build untouched; no new threads/endpoints/qube policy.

## 6. Next slice (not built now)
- BSD-style socket API (`net_sock_open/bind/send/recv/close` real
  implementations over this queue), then ICMP ping, then DHCP.

## 7. Risks
- QEMU SLIRP UDP delivery quirks (port forwarding needed for inbound)
  — document the exact `-netdev` line used for `rx ok`.
- 1514B MTU only; IP fragmentation reassembly explicitly out of scope
  (fragments drop).
- Single pending ARP datagram loses bursts during resolution — accepted
  for Phase 1 (best-effort datagrams, no retransmission anyway).
