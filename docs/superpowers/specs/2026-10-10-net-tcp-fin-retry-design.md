# Net TCP Active-FIN + Retry — Design (2026-10-10)

## 1. Intent (agreed)
Add active-close FIN plus bounded retransmit to the single-TCB TCP seam
(approach A: tick-driven in the service loop). Grounded in RFC 793
(§3.5 close, §3.7 retransmission) and the lwIP single-TCB shape behind
`userspace/net/tcp.h`. No new threads/endpoints (NTHREADS=11 full). TDD
with host vectors. Bounded loops. 32-byte IPC and existing tags unchanged.

What was said vs assumed:
- Said: active FIN + retry (approach A).
- Agreed: Sec 1 states+timers, Sec 2 wire+waiter semantics below. No
  passive-close states (CLOSE_WAIT/LAST_ACK/TIME_WAIT) in this slice.
- Assumed: `rdtime` + `NET_IRQ_TIMEOUT_TICKS` (~2s @10MHz) timebase, 5
  retries max. Correct me if wrong.

Success = host suite green on FIN/retry vectors; QEMU active-close
against the gateway prints the close.

## 2. States + timers (Sec 1, approved)
- New state `FIN_WAIT` only: `ESTABLISHED -> FIN_WAIT -> CLOSED`.
  `CLOSED`/`SYN_SENT` semantics unchanged.
- TCB gains `retry_deadline` (rdtime ticks) + `retry_count`, checked on
  the same service-loop pass that pumps RX. Spacing ~2s
  (`NET_IRQ_TIMEOUT_TICKS`), at most 5 retries, then RST-abort.
- `S_CLOSE` on ESTABLISHED sends FIN and enters FIN_WAIT (replacing RST
  for the graceful path); peer ACK or FIN-ACK of our FIN closes. RST at
  any time aborts to CLOSED and disarms. Retransmits resend the parked
  frame verbatim. Exhaustion RST-aborts and wakes any armed waiter once
  with `S_ERR`.
- Files: `userspace/net/tcp.h`, `userspace/net/sock.c`,
  `userspace/net/v2_main.c`.

## 3. Wire frames + waiter/error semantics (Sec 2, approved)
- FIN is header-only (`FIN|ACK`, `seq=snd_nxt`, no payload) via the
  existing checksum/frame path (total <= 1514, MSS cap 536 untouched).
- `S_SEND` in FIN_WAIT answers `S_ERR` (no new data). `S_RECV` on drained
  data follows existing empty/timeout rules. Close is idempotent.
- Waiter wakes exactly once: data, `S_TIMEOUT`, or `S_ERR` on abort.
  Wrap-safe `rdtime` compares as today. Dead owner on wakeup clears and
  drops, never wedges (existing gate).
- Tests in `tests/test_net_stack.c` + `tests/test_tcp.c`: FIN->ACK close,
  FIN->FIN-ACK close, duplicate-FIN drop, `S_SEND`-in-FIN_WAIT rejected,
  waiter `S_ERR` on abort, retry-exhaustion RST. QEMU proof: active-close
  prints the close. Kernel untouched.

## 4. Risks
- Single TCB stays single; a second concurrent close fails closed.
- No passive close: peer-initiated FIN outside FIN_WAIT drops (documented,
  next slice).
- Lost-FIN recovery depends on retry cap; 5 x ~2s bounds the stall.
