# Net Blocking S_RECV + Multi-Socket Hardening — Design (2026-10-08)

## 1. Intent (agreed)
- Add blocking `S_RECV` with server-side timeout to the socket RPC,
  closing the parked multi-socket notes (N1 demux skip, N2 per-socket
  carve, N3 pending timeout) through the same code paths.
- Approach A: waiter table beside the socket table, per-iteration
  deadline checks, no new threads.
- Ground truth: the proven `T_DONE`-style reply rendezvous in
  `userspace/net/v2_main.c`, `NET_IRQ_TIMEOUT_TICKS` as the tick
  source, Phase-1 queue semantics in `userspace/net/stack.c`.

What was said vs assumed:
- Said: blocking recv slice, resolve N1/N2/N3 with it.
- Agreed: one waiter per socket, server owns timeouts, timeout 0 =
  single no-wait check, per-socket slots tagged with dport.
- Assumed (locked Sec 1-4): tag/queue/timeout/test details below.
  Correct me if wrong.

Success = host suite green on waiter/isolation/timeout vectors;
on QEMU a blocking-recv DNS resolution prints its A record.

## 2. Waiter lifecycle (Sec 1, approved)
- `S_RECV [S_RECV, sock_id, timeout_ticks, 0]` from the socket
  owner registers (or replaces) that socket's waiter
  `{sock_id, owner, deadline_ticks, active}`.
- Immediate hit (datagram already queued for the socket) replies
  `S_DATA` at once, waiter never activates.
- Each loop pass matches new RX against active waiters before
  parking; `S_CLOSE` clears waiter + slot.
- Replies go to the owner ep via rendezvous SEND (`S_DATA` with
  payload grant, `S_TIMEOUT [S_TIMEOUT, sock_id, 0, 0]` on expiry).

## 3. Per-socket carve (Sec 2, approved — closes N1/N2)
- Queue slots carry `dport` set at enqueue; RX demuxes by port to
  the bound socket's slot (drop-newest per socket when full).
- Unbound-port datagrams drop silently — the loopback drain uses
  the same gate (N1 falls out: no special skip needed).
- `S_TRYRECV` and waiter wakeups read only their own socket's slot.

## 4. Timeouts (Sec 3, approved — closes N3)
- Waiter deadlines in rdtime ticks, checked every loop pass
  (same source as `NET_IRQ_TIMEOUT_TICKS`); expiry SENDs
  `S_TIMEOUT` once and clears the waiter (late RX never
  double-replies: waiter already inactive).
- `pend_valid` (S_SEND routing phase) expires after ~2s the same
  way, so one stuck sender can't wedge others.
- `timeout_ticks == 0` means a single no-wait check
  (`S_TRYRECV`-equivalent), never parks a waiter.

## 5. Tests (Sec 4, approved)
- Host vectors in `tests/test_net_stack.c`: waiter
  register/replace/clear; two-socket isolation (datagram for A
  invisible to B); fake-tick expiry fires once; post-expiry RX
  causes no second reply; `pend` expiry; existing suite green.
- Live proof on QEMU: blocking-recv DNS resolution prints the A
  record (SLIRP UDP/53 forwarding as in the sockets slice).
- Kernel build untouched; no new threads/endpoints.

## 6. Risks
- Reply-SEND to an owner that already parking-lot exited: rendezvous
  SEND blocks until the owner RECVs — a dead owner would wedge the
  server loop. Mitigation: waiter/SEND paths re-check owner
  liveness (thread state) before SENDing; dead owner → clear waiter,
  drop datagram, continue.
- Tick wrap (`rdtime` 64-bit): deadline compare uses
  `(now - start) > timeout` unsigned arithmetic — wrap-safe.
