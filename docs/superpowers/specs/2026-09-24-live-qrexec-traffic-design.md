# Live qrexec traffic: real T_CALL→ASK→DECIDE→DELIVER over EP0 (S2/S3 deferred-A)

**Status:** Design approved 2026-09-24, awaiting implementation plan
**Depends on:** S2 BUILT (qrexec broker + AdminVM, `Qubes_B`), S3 BUILT
(arg-carrying ask/decide, `Qubes_C`), FDE BUILT (vault `T_DELIVER`
handling, `Qubes_D`)
**Decides:** Thread-A-driven live EP0 demo (qube-0 client, one new QX
grant); ask leg via `keys.sign`, deny leg via `clipboard`; no new
threads, rows, or RPCs
**Constraints (binding):** microkernel intact (kernel: stamps + caps +
scheduling only; all policy/demo logic in userspace); NTHREADS stays
10 (at the `V2_CAP_THREADS` cap); Qubes isolation intact (labels on
every IPC, default-deny, no ambient authority); `verify.sh` stays the
single entry (new markers in `[4/4]`, no new SKIP)

---

## 1. Goal

Today's S2/S3/FDE demos are in-kernel model calls (`qube_decide` /
`qube_ask_enqueue` / `qube_decide_idx` in `kboot.c`, no IPC). The real
broker loop (`userspace/qrexec_server/v2_main.c`: kernel-stamped RECV,
hash-pinned ask queue, `T_ASK`/`T_DELIVER` backpressure SENDs) has never
run live. This stage drives REAL EP0 traffic through it at boot and
gates the transcript, closing the "specified but ungated" gap
(`NET: fwd ok` precedent).

**Theorems:** none new. `Qubes_B` (`c_q_call`, `c_decide_eq`,
preservation) already proves the semantics; this stage pins the wire
path. Any proof delta discovered during implementation replays
`Qubes_B` only.

**Demos (QEMU text markers, fail-closed like current smoke):**
- `VAULT: live ok` (vault received the brokered `T_DELIVER` for
  `keys.sign` over EP0 with kernel-stamped sender/qube)
- `AUD: deny rpc=2` (broker denied the live `clipboard` call; exact
  existing deny-print shape, no delivery, no new marker needed beyond
  the gated audit line)

---

## 2. Background / what exists

- Broker (`userspace/qrexec_server/v2_main.c`): RECVs EP0 with stamped
  `(sender_tid, sender_qube)`; `T_CALL [1, rpc, arg0, arg1]` →
  `qube_decide` → ALLOW forwards `T_DELIVER` immediately, ASK enqueues
  + SENDs `T_ASK [3, idx, rpc, hash]` (blocks until admin RECVs),
  `T_DECIDE [2, idx, approve, hash]` re-checks the pinned hash then
  DELIVERs or deny-audits. All SENDs are blocking rendezvous
  (backpressure, never drop).
- AdminVM (`userspace/adminvm/v2_main.c`): HELLO-registers at boot,
  displays the ask hash prompt, auto-approves (no GETC in the UABI —
  display-only discipline, unchanged).
- Vault (`userspace/vault/v2_main.c`): handles approved `T_DELIVER`
  (per-label unwrap → `T_KEY`-by-grant handoff; handoff path is
  print-free). A second, live-triggered handoff is idempotent
  (re-grant, re-read, re-revoke, re-wipe) — no special-casing.
- Client: `kernel/user.c` threads A/B (qube 0) run the Stage-2
  ping-pong first (`B00pn`, `A10pg`, `W1`), then park. Scheduler is
  lowest-Runnable; blocking rendezvous makes call timing order-safe:
  an early SEND waits, nothing is lost, no sleep/wake protocol.
- Policy rows needed already exist: `work(0) → vault keys.sign ask`,
  `clipboard deny` (S2 boot table).

---

## 3. Architecture

```
U-mode, after ping-pong parks:
  thread A (qube 0, NEW QX grant to qrexec)
    -- T_CALL keys.sign --> qrexec -- T_ASK --> adminvm
                               <-- T_DECIDE --   (auto-approve)
    -- T_DELIVER -------------> vault  ("VAULT: live ok")
  thread A -- T_CALL clipboard --> qrexec --> DENY ("AUD: deny rpc=2")
Kernel (S-mode): unchanged — stamps, raw-gate check (new grant),
  rendezvous blocking, scheduling.
```

Boot wiring delta (mirrors the S1/S2/FDE grant shape, one grant):
`v2_grant` qube-0 → qrexec QX on the boot tables beside the existing
asserts. No `caps.h`/`qube.h` bound changes; `qube_next` untouched.

---

## 4. Components

### 4.1 Thread-A live legs (extend `kernel/user.c`, U-mode code)

After `W1`, thread A (not B — single driver, no interleaving):
1. `SEND [T_CALL, keys.sign=1, 0, 0]` on EP0; block for `R_OK` /
   `R_PENDING` reply (broker replies `R_PENDING` on ask-enqueue).
   Fail-closed: any `R_DENY` or timeout parks with NO marker (gate
   misses `VAULT: live ok`).
2. `SEND [T_CALL, clipboard=2, 0, 0]`; expect `R_DENY`. Fail-closed:
   anything else parks marker-free.
3. Park. (Existing `no runnable left; parking cpu` tail unchanged.)

Bounds: straight-line, no loops beyond the two SENDs; UABI only
(`u_send`/`u_recv`); no new syscalls.

### 4.2 Vault live marker (one `u_puts` in the approved-deliver arm)

In the existing `T_DELIVER` arm, switch on rpc (see §5): `keys.sign`
(rpc==1, the S2 demo row) → print `VAULT: live ok`, no state change,
no handoff; `VAULT_UNWRAP` (7) → existing handoff (no marker);
anything else → INVALID. The rpc==1 gate is what keeps the marker
honest: the boot unlock uses rpc 7, never rpc 1. Reviewer verifies no
other sender can forge rpc 1 with a qube-0 stamp except thread A
(policy row pins src==0).

### 4.3 No kernel changes beyond the one grant

`kernel/kboot.c`: mint QX (qube 0 → qrexec) + assert print beside the
existing `QUB:` asserts (fail-closed `[demo] FAIL` on mint failure).
No SPAWN changes, no new stacks, no bound changes.

---

## 5. Data flow (the two live legs)

1. Boot as today through `CRYPT: unlock ok` (TEST_KEYS path untouched).
2. Ping-pong parks (`W1`); servers print up; A SENDs the keys.sign
   call and blocks for the broker reply (`R_PENDING` on ask-enqueue).
   Broker: stamp (tid 0, qube 0) → decide Ask → enqueue (hash pinned
   over the 4 words) → `T_ASK` to admin → admin displays +
   auto-approves → `T_DECIDE` (idx, approve=1, hash) → hash recheck
   ok → `T_DELIVER [5, 1, 0, 0]` to vault → vault's deliver-switch
   sees rpc==1 → prints `VAULT: live ok`, no state change, no
   handoff (handoff runs only for rpc==7).
3. A SENDs clipboard call → broker decide Deny → `AUD: deny rpc=2`,
   reply `R_DENY`, no delivery, no state change.
4. A parks. Smoke gate asserts `VAULT: live ok` + `AUD: deny rpc=2`.

---

## 6. Error handling (all fail closed unless noted)

| Case | Behavior |
|---|---|
| Broker not yet listening when A calls | Rendezvous blocks; no timeout, no marker loss |
| Ask queue full (shouldn't be: single-flight) | Broker replies `R_DENY`, A parks marker-free → gate FAILs |
| `T_DECIDE` hash mismatch / bad idx | Broker deny-audits (`AUD: deny spoofed-decide`), no deliver, A parks marker-free → gate FAILs |
| Vault receives rpc≠1/7 deliver | INVALID, no print, no state change |
| Clipboard leg delivers (mustn't) | Any `T_DELIVER` to a service on the deny leg = defect; gate has no allow-marker so it passes silently — reviewer checks the deny arm sends no forward (code review + existing `test_qube_policy` deny pins) |
| AdminVM down | Broker blocks in `T_ASK` SEND; system parks without markers → gate FAILs (fail closed, never half-open) |

---

## 7. Testing

- Host unit: extend `tests/test_qube_policy.c`?? No new policy rows —
  instead assert the boot-grant wiring shape (qube-0 QX→qrexec present,
  exactly one new grant) wherever the existing grant tests live; plus a
  vault-deliver-switch unit (rpc 1 → marker path, rpc 7 → handoff,
  else INVALID) compiled from `vault/v2_main.c` handlers if separable,
  else covered by smoke + review (implementer reports which).
- QEMU smoke (`verify.sh [4/4]`, 2 lines): `VAULT: live ok`,
  `AUD: deny rpc=2`. Missing marker ==> FAIL. All existing markers
  stay green; single cmdline; no new SKIP.
- Production gates unchanged. No key material in logs (existing
  `T_KEY` grep discipline covers the untouched handoff).
- Isabelle: no new theory. If the implementer finds a semantic gap
  (e.g., the rpc-switch needs a model), the fallback is 2–3
  `c_`-level lemmas in `Qubes_B.thy` (never a new session member
  without reviewer sign-off).

---

## 8. Non-goals (this spec)

Audit-cap modeling (B), lifecycle alias (C), demo-robustness (D),
prompter console (GETC), new RPCs/rows/threads/qubes, allow-path live
leg (no allow row fits ask+deny minimalism — a future stage can drive
`net.send` live when `NET: fwd ok` gets gated), RX-from-wire, SMP.

---

## 9. Exit criteria

- [ ] One QX grant (qube 0 → qrexec) minted at boot, asserted
      fail-closed; no bound changes (`NTHREADS`/`V2_CAP_THREADS`/
      `V2_QUBES_MAX` untouched).
- [ ] Thread A drives both legs live over EP0 post-`W1`;
      `VAULT: live ok` (rpc==1-gated) + `AUD: deny rpc=2` green in
      `verify.sh [4/4]`; full suite green, zero FAIL, no new SKIP.
- [ ] Vault deliver-switch (1 → marker, 7 → handoff, else INVALID)
      reviewed + host-covered or smoke-covered (implementer reports).
- [ ] Docs: `V2_DESIGN.md` §9 / `QUBES_ISOLATION_PLAN.md` §11 deferred
      list shrinks (A flips to BUILT with paths + markers + lemma
      names or "no new theory" note); B/C/D stay listed with owners.
