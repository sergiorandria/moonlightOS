# Net Socket API (IPC RPC + DNS client) — Design (2026-10-07)

## 1. Intent (agreed)
- Expose Phase-1 UDP datagrams to other servers through a small IPC
  socket API, proven by a DNS client resolving a real name.
- Approach A: tag-switched RPC on ep 6 with non-blocking
  `S_TRYRECV`; blocking `S_RECV` is the next slice, not this one.
- Ground truth: RFC 1035 §4 (query/response), RFC 768 (UDP),
  plus the proven `T_FWD`/`T_DONE` rendezvous pattern in
  `userspace/net/v2_main.c:457-507`.

What was said vs assumed:
- Said: socket API next, DNS client first, IPC message RPC shape.
- Agreed: S_OPEN/S_SEND/S_TRYRECV/S_CLOSE tags, QX-gated;
  per-socket slots from the 4-slot queue; DNS with timeout, no
  retries in Phase 1.
- Assumed (locked Sec 1-4): exact tag layouts below, 1-slot
  fair-share, first-A-record parsing. Correct me if wrong.

Success = host suite green on tag/table/DNS vectors; on QEMU the
net log shows a resolved A record for the queried name.

## 2. Tags / wire format on ep 6 (Sec 1, approved)
- `S_OPEN [S_OPEN, kind, port, 0]` -> `[S_OK, sock_id, 0, 0]`.
  `kind` is `NET_SOCK_UDP` only (`NET_SOCK_TCP` -> error reply).
- `S_SEND [S_SEND, sock_id, ip, port]` with payload in a granted
  frame slot announced like `T_FWD` (same MAP/verify discipline).
- `S_TRYRECV [S_TRYRECV, sock_id, 0, 0]` ->
  `[S_DATA, len, 0, 0]` (+ payload via granted slot) or
  `[S_EMPTY, 0, 0, 0]`.
- `S_CLOSE [S_CLOSE, sock_id, 0, 0]` -> `[S_OK, ...]`; unknown
  sock_id -> error reply, never a wedge.
- All calls gated on sender QX (same `qube_has_qx` check as
  `T_FWD`); unknown tags or unprivileged senders silently drop.
- Tag numbers: pick above `T_DONE` (`T_FWD=6, T_DONE=7`):
  `S_OPEN=8, S_SEND=9, S_TRYRECV=10, S_CLOSE=11, S_OK=12,
  S_DATA=13, S_EMPTY=14, S_ERR=15`.

## 3. Socket table (Sec 2, approved)
- Extend `net_sock_t` (`userspace/net/sock.h`, `NET_SOCK_MAX 8`)
  with `owner` tid + `bound` port; each open socket owns 1 slot
  carved from the 4-slot datagram queue (fair-share; 5th+ open
  fails with error reply while all slots are held).
- Inbound UDP demultiplexes by destination port to the bound
  socket; datagrams for unbound ports drop (no owner, no marker).
- `S_CLOSE` frees the entry and discards its queued slot.
- `sock.c` stops being a stub for UDP: `net_sock_open/close`
  become table operations (still no TCP).

## 4. DNS client (Sec 3, approved)
- New `userspace/net/dns.c`: `net_dns_query(name, *out_ip)`
  builds one-question RFC 1035 query (recursion-desired, fixed
  TXID from rdtime low bits) via `S_SEND` to gateway `10.0.2.2:53`
  from an ephemeral bound port.
- Polls `S_TRYRECV` with an rdtime deadline (~2s, same source as
  `NET_IRQ_TIMEOUT_TICKS`) + `V2_YIELD` between polls, never a spin.
- Parses the first A record (follows one compression pointer
  level); returns IPv4 or `-ERR_TIMEOUT` / `-ERR_MALFORMED`.
- No retries, no TCP fallback, no search domains in Phase 1.

## 5. Tests (Sec 4, approved)
- Host vectors in `tests/test_net_stack.c`: tag encode/decode
  round-trips, table open/bind/close + port demux + unbound drop,
  DNS query byte-exactness, canned-response parse (first A,
  truncated response, malformed → error codes).
- Live proof on QEMU (SLIRP forwards UDP/53 to the gateway):
  queried name's A record printed by the DNS client path.
- Kernel build untouched; no new threads/endpoints.

## 6. Next slice (not built now)
- Blocking `S_RECV` with server-side waiter + timeout; then ICMP
  ping; then DHCP.

## 7. Risks
- SLIRP must actually forward the DNS UDP to `10.0.2.2:53` —
  document the exact `-netdev` line that yields a resolution.
- 4-slot queue with 1-slot fair-share caps concurrent sockets at
  4 datagrams in flight — accepted (DNS needs 1).
- DNS over UDP only; truncated (`TC=1`) responses report
  `-ERR_TRUNCATED`, no TCP retry in this slice.
