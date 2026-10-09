# Net TCP Socket-API Seam — Design (2026-10-09)

## 1. Intent (agreed)
Complete approach B: unify the socket-API seam so TCP sockets are first-class
table entries before data flows. The existing single-TCB active-open handshake
(`userspace/net/tcp.h: net_tcp_syn / net_tcp_input`, RFC 793, lwIP-grounded
single-TCB shape) binds to the socket entry; `net_sock_send` stops always
returning -1. No new threads/endpoints (NTHREADS=11 full). TDD with host
vectors. Bounded loops. 32-byte IPC preserved.

What was said vs assumed:
- Said: socket-API seam first, then TCP data path.
- Agreed: Sec 1 table+tags, Sec 2 handshake bind + send seam, Sec 3 RX demux +
  waiter wakeup + tests below. No retransmit buffer in this slice.
- Assumed: tag numbers/layouts unchanged from 2026-10-07/08 specs. Correct me
  if wrong.

Success = host suite green on table/handshake/send/demux/waiter vectors;
existing UDP vectors stay green; QEMU blocking-recv TCP byte flow prints.

## 2. Socket table + tags (Sec 1, approved)
- Keep everything on ep 6, same thread. Tags unchanged: `S_OPEN=8`,
  `S_SEND=9`, `S_TRYRECV=10`, `S_CLOSE=11`, `S_OK=12`, `S_DATA=13`,
  `S_EMPTY=14`, `S_ERR=15`, `S_RECV=16` (`userspace/net/v2_main.c:95-125`).
- `sock.c` accepts `NET_SOCK_UDP` or `NET_SOCK_TCP` in `net_sock_open`;
  still 8 slots (`NET_SOCK_MAX`), still 1-slot fair-share from the 4-slot
  queue (`NET_SOCK_FAIR_MAX`), still owner-checked. Duplicate port,
  table-full, bad kind -> `S_ERR`. `S_CLOSE` frees + clears waiter.
- Files: `userspace/net/sock.h`, `userspace/net/sock.c`.

## 3. Handshake bind + send seam (Sec 2, approved)
- `S_OPEN(kind=TCP)` allocates the table slot (CLOSED) and arms the one
  `net_tcp_conn`. The boot SYN proof (`v2_main.c:1104-1161`) becomes the
  per-socket open path: same MSS 536, same ISS source, same RST-abort to
  CLOSED, same SYN-ACK check (`ack == snd_nxt`, port/IP match, checksums).
- `S_SEND` routing phase unchanged (`[S_SEND, sock, ip, port]` pins `pend`,
  payload follows as literal `T_FWD` under MAP/verify; `pend` ~2s expiry).
  `net_sock_send(id,…)` delegates: UDP -> `net_stack_udp_send` as today;
  TCP requires ESTABLISHED + owner, else `S_ERR`, then emits one in-order
  segment via the TCB `snd_nxt` frame builder, payload capped at
  `TCP_MSS_DEFAULT` 536 (total frame <= 1514, same bound as SYN path).
  QX gate unchanged.
- Stale `tests/test_tcp.c` (`listen/connect/accept` APIs that do not exist
  in `sock.h`) is rewritten to the real `net_tcp_*` + table vectors.

## 4. RX demux + waiter wakeup + tests (Sec 3, approved)
- `stack.c: net_stack_rx` classifies TCP via `tcp_hdr_ok`; demuxes by dport
  to the bound TCP socket (drop-newest per socket when full; unbound ports
  drop silently, same as UDP carve).
- In-order PSH/ACK in ESTABLISHED advances `rcv_nxt`/`snd_nxt`; OOO and
  duplicates drop with duplicate-ACK. No retransmit buffer in this slice; a
  dropped segment stalls until the peer retransmits.
- Waiter discipline from 2026-10-08 spec unchanged: per-socket waiter,
  immediate hit -> `S_DATA` at once, miss + timeout 0 -> `S_EMPTY`, miss +
  timeout>0 -> arm + later `S_DATA`/`S_TIMEOUT` (expiry fires once,
  wrap-safe ticks). `S_CLOSE` clears waiter + slot. Dead owner on reply ->
  clear waiter, drop datagram, continue.
- Tests in `tests/test_net_stack.c`: TCP open/duplicate/full/close-clears;
  SYN->SYN-ACK->ACK byte flow; RST->CLOSED; pre-ESTABLISHED send rejected;
  two-socket isolation; waiter register/replace/clear; fake-tick expiry
  once; no double reply. Live QEMU proof: blocking-recv TCP byte flow.
- Kernel build untouched.

## 5. Risks
- Single TCB stays single: second concurrent TCP open fails closed until a
  table/TCB expansion slice lands.
- No retransmit means loss stalls; documented, not retried here.
- `test_tcp.c` rewrite deletes stale expectations; kept as host vectors for
  the real API, not the imagined one.
