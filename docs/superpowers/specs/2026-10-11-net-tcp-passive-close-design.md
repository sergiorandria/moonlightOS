# Net TCP Passive Close — Design (2026-10-11)

## 1. Intent (agreed)
Add graceful passive close to the single-TCB TCP seam (approach A:
CLOSE_WAIT + LAST_ACK). Grounded in RFC 793 §3.5 and the active-close
machinery in `userspace/net/tcp.h` / `sock.c` / `v2_main.c`. No new
threads/endpoints (NTHREADS=11 full). TDD with host vectors. Bounded
loops. Tags and 32-byte IPC unchanged.

What was said vs assumed:
- Said: passive close (approach A).
- Agreed: Sec 1 states+transitions, Sec 2 wire/retry/waiter semantics
  below. No TIME_WAIT/2MSL in this slice.
- Assumed: retry `~2s × 5 then RST` and waiter exactly-once discipline
  from the active path. Correct me if wrong.

Success = host suite green on CLOSE_WAIT/LAST_ACK vectors; today’s
silently-dropped peer FIN in ESTABLISHED becomes a graceful close.

## 2. States + transitions (Sec 1, approved)
- New states `CLOSE_WAIT`, `LAST_ACK`. `ESTABLISHED` + in-order peer FIN
  → CLOSE_WAIT. Bytes before the FIN stay queued/deliverable; the FIN
  consumes `rcv_nxt + 1` and is never delivered as data.
- `S_CLOSE` in CLOSE_WAIT sends our FIN → LAST_ACK. Peer ACK of our FIN
  in LAST_ACK → CLOSED. RST anywhere → CLOSED + disarm, unchanged.
- `S_SEND` in CLOSE_WAIT/LAST_ACK answers `S_ERR`. Second concurrent
  open still fails closed (single TCB).
- Files: `userspace/net/tcp.h`, `userspace/net/sock.c`,
  `userspace/net/v2_main.c` (route ESTABLISHED FIN frames to the seam).

## 3. Wire/retry/waiter semantics (Sec 2, approved)
- Our LAST_ACK FIN reuses the active path: header-only `FIN|ACK`,
  `seq=snd_nxt`, parked-frame resend `~2s × 5`, RST-abort on exhaustion
  (MSS 536, frame <= 1514 untouched).
- Peer FIN is ACKed on entering CLOSE_WAIT; duplicate peer FINs get
  duplicate ACKs and never re-close.
- Reader side: queued bytes drain normally; drained `S_RECV` on
  CLOSE_WAIT answers `S_EMPTY` with a FIN-pending indication the app
  turns into `S_CLOSE` (exact tag shape fixed when writing the spec’s
  implementation plan, reusing `S_EMPTY`/`S_ERR` — no new tags).
- Waiter wakes exactly once (data, `S_TIMEOUT`, `S_ERR` on abort);
  dead-owner gate unchanged.
- Tests in `tests/test_net_stack.c` + `tests/test_tcp.c`: FIN with data
  preserved, LAST_ACK ACK close, duplicate-FIN drop, exhaustion RST from
  LAST_ACK, waiter `S_ERR` on abort, full suite green + riscv build.
  QEMU proof manual. Kernel untouched.

## 4. Risks
- Single TCB stays single; concurrent closes fail closed.
- No TIME_WAIT: a belated duplicate could alias a quickly reopened
  connection; accepted until multi-TCB lands.
- Off-window FIN validation follows the active path’s simplified close;
  full window tracking stays a follow-up.
