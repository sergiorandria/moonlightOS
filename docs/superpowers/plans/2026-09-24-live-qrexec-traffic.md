# Live qrexec traffic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build addressed endpoints (one EP per thread) with a replayed V2_C proof, then drive live T_CALL→ASK→DECIDE→DELIVER traffic from thread A through the real broker, gated by smoke markers.

**Architecture:** Phase 1 (Tasks 1–4) converts the single static EP0 into `eps[V2_NEP]` with a RECV-own-EP rule, migrates every U-mode party to its own EP (transcript must stay byte-identical), and replays V2_C endpoint-indexed with new separation theorems. Phase 2 (Tasks 5–6) mints two QX grants, adds an admin→A NOTIFY handshake, extends thread A with two live legs, switches vault delivery on rpc, gates three markers, and closes docs.

**Tech Stack:** C (freestanding rv64imac stock clang `-Werror`; host clang/gcc for unit tests), RISC-V S-mode traps/pagetables (existing handlers only), Isabelle/HOL (session V2), bash (verify.sh/mkinitrd.sh/run_qemu.sh).

**Spec:** `docs/superpowers/specs/2026-09-24-live-qrexec-traffic-design.md`

## Global Constraints

- Freestanding only for kernel/ELF code: `-ffreestanding -nostdlib -fno-builtin -Wall -Wextra -Werror`; includes from clang resource dir + in-tree headers only.
- C subset: no `float`, no function-pointer dispatch (switch on op/tag), no recursion, every loop carries a `/* bound: N */` comment tied to a named constant.
- `kernel/user.c` constraint (unchanged): no string literals, no globals — immediates + stack locals only (literals would land in kernel .rodata, U=0, fault on U access).
- Fail closed: validation failure returns `V2_ERR_INVALID`/`V2_ERR_OVERFLOW` (kernel) or `INVALID`/`DENY` (servers) with no partial state; missing QEMU markers flip the smoke gate to FAIL (never add a marker without gating it, never gate a marker that can print on a lie).
- Bounds stay: `NTHREADS == V2_CAP_THREADS == 10`, `V2_QUBES_MAX == 8`, `V2_FRAMES_MAX == 32`. New constant `V2_NEP == 10` rides the thread cap (`_Static_assert(V2_NEP <= V2_CAP_THREADS)`).
- `tools/verify.sh` is the single entry: host tests already gated, new markers in `[4/4]`, single QEMU cmdline, no new SKIP branches (CHERI SKIP is pre-existing).
- Proofs: zero `sorry`/`axiomatization`, no `True`-definitions, mutant witness per new invariant.
- Reply codes (qrexec broker, `userspace/qrexec_server/v2_main.c:46-48`): `R_OK 0`, `R_PENDING 1`, `R_DENY -1`. RPC ids: `T_CALL 1`, `T_DECIDE 2`, `T_ASK 3`, `T_HELLO 4`, `T_DELIVER 5`; `keys.sign 1`, `clipboard 2`, `VAULT_UNWRAP 7`.
- TIDs/EPs/qubes (boot wiring, `kernel/kboot.c` + `kernel/user.c`): A0 B1 mem2 qrexec3 admin4 fw5 net6 scratch7 vault8 cryptblk9; qubes: demo0 mem1 qrexec2 admin3 fw4 net5 vault6 cryptblk7.

---

## File Map

| File | Responsibility |
|---|---|
| Modify `kernel/ipc.h` | `V2_NEP 10`, widen `v2_ep_ok` to `< V2_NEP`. Primitives unchanged (per-EP queues already re-entrant). |
| Modify `tests/test_v2ipc.c` | EP-gate + cross-EP isolation tests over `ipc.h` primitives. |
| Modify `kernel/kboot.c` | `static v2_ep_t eps[V2_NEP]`; SEND/RECV handlers index by ep + RECV-own-EP rule; raw gates with d = dst EP; QDESTROY sweeps all EPs; init all EPs at boot. |
| Modify `kernel/user.c` | A↔B EP args (A SEND dst=1 / RECV ep=0; B SEND dst=0 / RECV ep=1); mem `urecv` ep=2; Phase-2 live legs in `user_a_main` (post-`W1` WAIT + two SENDs, reply-checked, marker-free park). |
| Modify `userspace/qrexec_server/v2_main.c` | RECV EP3; `svc_of_qube[8]` table; `T_ASK` SEND→EP4; `T_DELIVER` SEND→`svc_of_qube[dst]` with q0/≥8 guard. |
| Modify `userspace/adminvm/v2_main.c` | RECV EP4; HELLO SEND→EP3; check HELLO reply `== 0`, then NOTIFY tid 0 bit 2; add 5-line NOTIFY wrapper. |
| Modify `userspace/firewall/v2_main.c` | RECV own EP5 (one constant). |
| Modify `userspace/net/v2_main.c` | RECV own EP6 (one constant). |
| Modify `userspace/vault/v2_main.c` | RECV own EP8; deliver-switch: rpc==1 → `VAULT: live ok`, rpc==7 → existing handoff, else INVALID. |
| Modify `userspace/cryptblk/v2_main.c` | RECV own EP9 (one constant; find the service-loop `u_recv(0, ...)`). |
| Modify `kernel/isabelle/V2_C.thy` | Endpoint-indexed `esendq`/`erecvq`, `max_eps = 10`, `c_send s dst m` / `c_recv r own`, replayed lemmas + `ep_separation` + `no_cross_deliver` + snoop mutant + evals. |
| Modify `tools/verify.sh` | `[4/4]` +3 lines: `QREXEC: admin registered`, `VAULT: live ok`, `AUD: deny rpc=2`. |
| Modify `docs/V2_DESIGN.md`, `docs/QUBES_ISOLATION_PLAN.md`, `docs/ARCHITECTURE.md`, `docs/BUILD.md` | Deferred-A → BUILT with paths + markers + lemma names. |

**Scope note:** Tasks 1–4 (Phase 1) ship with zero transcript change — the existing `[4/4]` gate passing UNCHANGED is the acceptance proof. Task 5 (Phase 2) adds the markers. Task 6 closes docs.

---

### Task 1: ipc.h multi-EP + test_v2ipc EP isolation (host-only, no boot)

**Files:**
- Modify: `kernel/ipc.h` (`v2_ep_ok` + `V2_NEP` define)
- Modify: `tests/test_v2ipc.c` (append EP block before the final printf)
- Test: `tests/test_v2ipc.c` (already gated at `tools/verify.sh:35`, no verify edit needed)

**Interfaces:**
- Consumes: nothing (primitives already re-entrant; `v2_ep_t` holds one EP's queues).
- Produces: `V2_NEP 10`, `v2_ep_ok(ep) = (ep < V2_NEP)` consumed by Task 2 (kboot bounds) and Task 3 (EP-arg validity).

- [ ] **Step 1: Write the failing EP tests** — append before `printf("test_v2ipc: ALL PASS\n")`:

```c
    /* Addressed EPs: gate + cross-EP isolation (Phase 1). */
    CHECK(v2_ep_ok(0) && v2_ep_ok(9));
    CHECK(!v2_ep_ok(10));
    CHECK(!v2_ep_ok(99));
    {
        v2_ep_t epa, epb;
        v2_ep_init(&epa);
        v2_ep_init(&epb);
        w[0] = 41; w[1] = 42;
        CHECK(v2_q_send(&epa, 3, w, 2) == V2_OK);
        /* EP-B sees nothing: cross-EP invisibility. */
        CHECK(v2_q_take_send(&epb, &s) == V2_ERR_OVERFLOW);
        /* EP-A round-trips its own bytes, sender stamped. */
        CHECK(v2_q_take_send(&epa, &s) == V2_OK);
        CHECK(s.sender == 3 && s.len == 2 && s.words[0] == 41 && s.words[1] == 42);
        /* Waiter pairing is per-EP: oldest waiter OF THAT EP. */
        CHECK(v2_q_wait(&epa, 8) == V2_OK);
        CHECK(v2_q_wait(&epb, 9) == V2_OK);
        CHECK(v2_q_take_waiter(&epa, &tid) == V2_OK && tid == 8);
        CHECK(v2_q_take_waiter(&epb, &tid) == V2_OK && tid == 9);
        /* Queue-full on one EP leaves the other working. */
        v2_ep_init(&epa);
        v2_ep_init(&epb);
        for (int i = 0; i < V2_IPC_Q; i++)
            CHECK(v2_q_send(&epa, 0, w, 1) == V2_OK);
        CHECK(v2_q_send(&epa, 0, w, 1) == V2_ERR_OVERFLOW);
        CHECK(v2_q_send(&epb, 0, w, 1) == V2_OK);
    }
```

- [ ] **Step 2: Run, watch fail**

Run: `clang -Wall -Wextra -Werror -o /tmp/test_v2ipc tests/test_v2ipc.c 2>&1 && /tmp/test_v2ipc`
Expected: FAIL — old test body asserts `!v2_ep_ok(1)` at line 23 (now a legal EP).

- [ ] **Step 3: Implement** — in `kernel/ipc.h`:

```c
#define V2_NEP 10 /* one endpoint per thread (EP i owned by tid i); rides V2_CAP_THREADS */
```

and change `v2_ep_ok` to:

```c
static inline int v2_ep_ok(unsigned long ep) { return ep < (unsigned long)V2_NEP; }
```

Fix the old test line 23 (`CHECK(!v2_ep_ok(1));` → delete it; line 24 `CHECK(!v2_ep_ok(99));` stays, and `!v2_ep_ok(10)` is covered in the new block).

- [ ] **Step 4: Run green**

Run: `clang -Wall -Wextra -Werror -o /tmp/test_v2ipc tests/test_v2ipc.c 2>&1 && /tmp/test_v2ipc`
Expected: `test_v2ipc: ALL PASS`.

- [ ] **Step 5: Commit**

```bash
git add kernel/ipc.h tests/test_v2ipc.c
git commit -m "live-qrexec: addressed EP gate + isolation tests"
```

### Task 2: kboot endpoint array + handlers + sweep (kernel, no U-mode yet)

**Files:**
- Modify: `kernel/kboot.c` (ep0 → eps array, SEND/RECV handlers, QDESTROY sweep, boot init)
- Test: `make -C kernel` (must build; behavior verified in Task 3 smoke)

**Interfaces:**
- Consumes: Task 1 (`V2_NEP`, widened `v2_ep_ok`).
- Produces: per-EP queues with RECV-own-EP rule consumed by Task 3 (U-mode EP args must match or every RECV fails closed).

- [ ] **Step 1: Replace the static endpoint** — find `static v2_ep_t ep0;` (~line 391) and replace with:

```c
static v2_ep_t eps[V2_NEP];
_Static_assert(V2_NEP <= V2_CAP_THREADS,
               "endpoint count rides the thread cap (EP i owned by tid i)");
```

Find the boot `v2_ep_init` call on ep0 and replace with:

```c
    for (int e = 0; e < V2_NEP; e++) /* bound: V2_NEP (10) */
        v2_ep_init(&eps[e]);
```

- [ ] **Step 2: SEND handler** — in the `V2_SEND` arm (~lines 700–761): after the existing `v2_ep_ok(ep)` check passes, add the destination liveness + ownership-compatible bound (EP count == thread cap, so `ep < NTHREADS` always holds at NTHREADS=10; assert it fail-closed for future cap splits):

```c
            if (ep >= (unsigned long)NTHREADS) {
                threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                return;
            }
            v2_ep_t *e = &eps[ep];
```

then replace every `ep0.` in that arm with `e->`. The raw-gate peek becomes: waiter `peek` on THIS ep, gate `(cur → peek)` unchanged otherwise (`qube_raw_ok(qube_of, NTHREADS, cur, peek, qube_has_qx(cur))`, deny prints `QUB: xread denied`).

- [ ] **Step 3: RECV handler** — in the `V2_RECV` arm (~lines 762–834): after the `v2_ep_ok(ep)` check, add the ownership rule FIRST (before any queue touch — fail closed with no state change):

```c
            if (ep != (unsigned long)cur) {
                threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                return;
            }
            v2_ep_t *e = &eps[ep];
```

then replace every `ep0.` in that arm with `e->`. Keep the RECV-side raw gate as-is (defense in depth; with ownership it can only see same-EP sends).

- [ ] **Step 4: QDESTROY sweep** — find the sweep loops (~lines 1365–1380, `for` over `ep0.send_len`/`recv_len` with `/* bound: V2_IPC_Q */`): wrap them in an outer EP loop:

```c
                for (int e = 0; e < V2_NEP; e++) { /* bound: V2_NEP (10) */
                    v2_ep_t *e = &eps[e];
                    ... existing sweep body with ep0. -> e-> ...
                }
```

(Careful: the existing body may declare `int idx`/`w` — keep names, only re-point the struct.)

- [ ] **Step 5: Build**

Run: `make -C kernel 2>&1 | tail -n 3`
Expected: clean build, `kernel/build/moonlight.elf` relinked. (Do NOT run QEMU yet — U-mode still uses EP0 args; every server RECV would fail closed. Task 3 migrates them.)

- [ ] **Step 6: Commit**

```bash
git add kernel/kboot.c
git commit -m "live-qrexec: per-thread endpoint array + own-EP rule"
```

### Task 3: U-mode EP migration + broker table (byte-identical transcript)

**Files:**
- Modify: `kernel/user.c` (A↔B EP args, mem `urecv` ep)
- Modify: `userspace/qrexec_server/v2_main.c` (RECV EP3, `svc_of_qube`, T_ASK→EP4, T_DELIVER→svc EP + guard)
- Modify: `userspace/adminvm/v2_main.c` (RECV EP4, HELLO→EP3)
- Modify: `userspace/firewall/v2_main.c` (RECV EP5), `userspace/net/v2_main.c` (RECV EP6), `userspace/vault/v2_main.c` (RECV EP8), `userspace/cryptblk/v2_main.c` (RECV EP9)
- Test: `make -C userspace && make -C kernel`, QEMU transcript markers UNCHANGED (existing `[4/4]` gate is the test)

**Interfaces:**
- Consumes: Task 2 (per-EP queues + own-EP rule).
- Produces: all parties on own EPs; dormant `svc_of_qube` table consumed by Task 5.

- [ ] **Step 1: A↔B migration** — in `kernel/user.c` `user_a_main`: `usend(0, ping, 2)` → `usend(1, ping, 2)` (dst = B's EP); `urecv(0, out, ...)` → `urecv(0, out, ...)` UNCHANGED (A owns EP0). In `user_b_main`: `urecv(0, buf, ...)` → `urecv(1, buf, ...)` (B owns EP1); `usend(0, pong, 2)` → `usend(0, pong, 2)` UNCHANGED (dst = A's EP0). In `mem_server_main`: `urecv(0, buf, ...)` → `urecv(2, buf, ...)`; its `usend(0, resp, 1)` replies: replies pair with the (SEND-blocked) caller, not an EP — check `u_reply`/`usend` semantics in tree: mem's `usend(0, resp, 1)` — the `0` here is a DST EP under the new rule! Find mem's reply path and set dst = stamped `snd` (the caller's tid == its EP). Same audit for every `u_send`/`usend`/`u_reply` in ALL servers: reply-to-caller uses dst = stamped sender tid; initiated sends use the fixed table below. (If `u_reply` is a separate syscall that auto-targets, leave it — read the helper first, don't guess.)

- [ ] **Step 2: Broker table + dst wiring** — in `userspace/qrexec_server/v2_main.c`: `u_recv(0, ...)` → `u_recv(3, ...)` (own EP). Add near the T_ defines:

```c
/* Deliver-target table: dst qube -> service tid (= its EP). q0 (demo
 * qube) maps to 0 and is never a deliver target: no allow/ask row has
 * dst qube 0 (boot policy + FDE rows 7-9 audited). Mirrors boot wiring;
 * reviewer checks against kboot qube_of assignments. */
static const unsigned long svc_of_qube[8] = {0, 2, 3, 4, 5, 6, 8, 9};
```

`T_ASK` send: `u_send(0, na, 4)` → `u_send(4, na, 4)` (admin EP, constant — admin is always tid 4). `T_DELIVER` sends (allow-forward arm ~line 285, approve arm ~line 237): compute `dst` from the decided row's dst qube (`pol.pending[idx]` / policy lookup — read the exact variable in each arm), guard:

```c
if (dstq >= 8UL || dstq == 0UL) { /* never a service: deny-audit, no SEND */
    ... existing deny-audit path ...
} else {
    u_send(svc_of_qube[dstq], fwd, 4);
}
```

Keep the backpressure comment (SEND blocks until the service RECVs).

- [ ] **Step 3: Remaining servers, one constant each** — admin `u_recv(0, ...)` → `u_recv(4, ...)`; admin HELLO `u_send(0, hello, 1)` → `u_send(3, hello, 1)`; admin `u_send(0, dec, 4)` (T_DECIDE) → `u_send(3, dec, 4)`; admin put-back `u_send(0, buf, n)` → `u_send(3, buf, n)` (stays dormant; EP now addressed so it can only ever return to the broker — note in commit message). Firewall RECV → 5; net RECV → 6; vault RECV → 8; cryptblk service-loop RECV → 9. For each server's *initiated* sends, set dst EP by the same rule as Step 1 (reply-to-stamped-sender else fixed table/constant): firewall `T_FWD` → 6; net `T_DONE` → 5; vault `T_KEY` notice → 9; cryptblk `T_KEY_ACK` → 8. (Verify each against the file — if a send's target is genuinely ambiguous, STOP and ask rather than guess.)

- [ ] **Step 4: Build + byte-identical smoke**

Run: `make -C userspace 2>&1 | tail -n 2 && make -C kernel 2>&1 | tail -n 2`
Expected: clean.
Run: `tools/verify.sh 2>&1 | grep -E "FAIL|verify done"`
Expected: zero FAIL. Acceptance = the EXISTING `[4/4]` markers all pass with NO verify.sh change (proves addressing changed nothing observable).

- [ ] **Step 5: Commit**

```bash
git add kernel/user.c userspace/qrexec_server userspace/adminvm userspace/firewall userspace/net userspace/vault userspace/cryptblk
git commit -m "live-qrexec: U-mode parties onto own EPs, broker svc table"
```

### Task 4: V2_C endpoint-indexed replay + separation (proofs)

**Files:**
- Modify: `kernel/isabelle/V2_C.thy`
- Modify (ONLY if build breaks): `kernel/isabelle/Qubes_A/B/C/D.thy`, minimal bound-ripple diffs
- Test: `isabelle build -D kernel/isabelle -v` + anti-vacuity greps

**Interfaces:**
- Consumes: Tasks 1–3 (Plumbing semantics: per-EP FIFO, own-EP RECV, guarded SEND).
- Produces: `ep_separation`, `no_cross_deliver` + replayed integrity lemmas consumed by Task 6 docs.

- [ ] **Step 1: Index the state** — replace the single `sendq`/`recvq` record fields with per-EP functions:

```isabelle
definition max_eps :: nat where "max_eps = 10"
```

`sendq :: "nat ⇒ (nat × nat list) list"`, `recvq :: "nat ⇒ nat list"` (functions from EP index; empty EP = `[]`). `c_send s dst m st` requires `dst < max_eps` (else state unchanged — fail closed); `c_recv r own bl st` requires `own = r`... model the ownership guard as a premise: deliver/suspend only when the call targets the caller's own EP, else unchanged. Keep `max_msg_len = 4`, `max_ipc_q = 16` PER EP (matches `V2_IPC_Q` per `v2_ep_t`).

- [ ] **Step 2: Replay every existing lemma with one extra index** — same proof scripts + `max_eps_def`; `init` sets all EPs to `[]`. (Read the current theory first — ~590-line shape like Qubes_C; keep names, add the index.)

- [ ] **Step 3: New separation theorems + mutants + evals**

```isabelle
lemma ep_separation: ops on EP i leave every EP j≠i bit-identical
lemma no_cross_deliver: RECV on EP j returns only EP-j-queued bytes
snoop mutant: RECV on EP 5 with bytes queued on EP 3 returns none
foreign mutant: c_recv with own ≠ r leaves state unchanged
eval pins: same-EP round-trip; cross-EP invisibility; queue-full on one EP leaves others working
```

Zero `sorry`, no True-defs, mutant per new invariant, Allow+Deny still pinned (existing pins replay).

- [ ] **Step 4: Build**

Run: `isabelle build -D kernel/isabelle -v 2>&1 | tail -n 3`
Expected: `Finished V2`, all theories incl. replayed `V2_C` at 100%. (FDE lesson: never `eval` a giant numeral — keep all demo constants small; `FDE_MAGIC`-style pins use `simp`.)
Run: `grep -rn "sorry\|axiomatization\|quick_and_dirty\|oops" kernel/isabelle/; grep -rn "equiv> True" kernel/isabelle/*.thy; echo "gate done"`
Expected: empty before `gate done`.

- [ ] **Step 5: Commit**

```bash
git add kernel/isabelle/V2_C.thy kernel/isabelle/Qubes_A.thy kernel/isabelle/Qubes_B.thy kernel/isabelle/Qubes_C.thy kernel/isabelle/Qubes_D.thy
git commit -m "live-qrexec: V2_C endpoint-indexed + separation proofs"
```

(Stage files unchanged by the replay — the commit still lists them so reviewers see the ripple was assessed. If a Qubes file DID need a ripple fix, name it in the message.)

### Task 5: Live legs — grants, handshake, vault switch, markers (the demo)

**Files:**
- Modify: `kernel/kboot.c` (qube0→admin grant; REUSE FDE tid-3 line)
- Modify: `userspace/adminvm/v2_main.c` (NOTIFY wrapper + HELLO-reply RECV + notify)
- Modify: `kernel/user.c` (`user_a_main` post-`W1` WAIT + SEND+RECV legs)
- Modify: `userspace/qrexec_server/v2_main.c` (`rpc_svc` routing: rows carry service dsts, lookup key, audit dsts; retire collapsed-dst)
- Modify: `userspace/vault/v2_main.c` (rpc-switch: 1 → marker, 7 → handoff, else INVALID)
- Modify: `tools/verify.sh` (`[4/4]` +3 lines)
- Test: QEMU smoke with the three markers

**Interfaces:**
- Consumes: Tasks 1–4 (addressed EPs, broker table shell, proven separation).
- Produces: `QREXEC: admin registered` (genuinely live) + `VAULT: live ok` + `AUD: deny rpc=2`, consumed by Task 6 docs.

**Corrections to the original brief (ruling 2026-09-24, code is
authority — verified against `kboot.c:742,815`, `caps.h:221-222`,
broker arms): (a) `usend` returns `V2_OK` on handoff, never the
broker's reply code — legs are SEND (expect 0) + RECV EP0 for the
one-word reply; (b) admin must RECV EP4 for the HELLO `[R_OK]` before
WAITing or the broker's reply SEND deadlocks; (c) collapsed-dst
(`QREXEC_QUBE=1` = mem's qube) misroutes delivers — replaced by
`rpc_svc` with service-dst rows; (d) tid-3 slot-9 grant exists (FDE)
— reuse, never re-add (`v2_grant` fails on occupied dst).

- [ ] **Step 1: Two QX grants — with a reuse, not two adds** — after the FDE cryptblk-grant block in `kernel/kboot.c`:

```c
    /* Live-traffic QX grant (deferred-A): QX is holder-based. Thread A's
     * T_CALL leg reuses the FDE vault-grant line above
     * (v2_grant(&caps, 0, 9, 3, 9)): v2_grant fails on an occupied dst
     * (caps.h), so a second grant into tid 3 slot 9 ALWAYS fails — the
     * FDE line's assert comment is extended to cover this leg instead.
     * One grant is ADDED here:
     *   qube0 -> admin (tid 4 slot 9): HELLO + T_DECIDE to the broker.
     * Same slot-9 shape (user/admin tables hold no caps; MAP rejects
     * QX-bit caps). Fail-closed like every grant block here. */
    if (v2_grant(&caps, 0, 9, 4, 9) != V2_OK || !qube_has_qx(4)) {
        kputs("[demo] FAIL live qx grants\n");
    }
```

plus extend the FDE `v2_grant(&caps, 0, 9, 3, 9)` assert comment to name thread A's T_CALL leg as a second covered path. No bound changes.

- [ ] **Step 2: Admin HELLO + R_OK RECV + NOTIFY handshake** — in `userspace/adminvm/v2_main.c`, add (mirrors the file's `u_wait`/`u_send` helpers; `V2_NOTIFY` is 5 — verify against the file's `#define`s, do not guess the number):

```c
static long u_notify(unsigned long t, unsigned long bits)
{
    return u_ecall3(V2_NOTIFY, (long)t, (long)bits, 0);
}
```

Then replace the fire-and-forget registration with a handshake (the broker's HELLO-reply SEND would otherwise embrace the WAIT below forever — broker reply needs a RECV waiter):

```c
    /* Register with the broker, then wake the live client. SEND pairs
     * with the broker's EP3 RECV (queues + blocks otherwise); the
     * broker's [R_OK] reply needs THIS RECV — without it the reply
     * SEND wedges the broker while we WAIT below. On [0] the broker
     * is live, so notify the live client (thread 0, ADMIN_LIVE_BIT 2
     * — distinct from thread B's bit-1 ping notify, already consumed
     * by A's first WAIT); else fall into WAIT without notifying and
     * the gate fails on the missing markers. */
    hello[0] = T_HELLO;
    if (u_send(3, hello, 1) == 0) {
        uint64_t rep[4];
        unsigned long s = 0, q = 0, o = 0;
        if (u_recv(4, rep, 4, &s, &q, &o) >= 1 && rep[0] == 0)
            u_notify(LIVE_CLIENT_TID, ADMIN_LIVE_BIT);
    }
```

(`#define ADMIN_LIVE_BIT 2` + `#define LIVE_CLIENT_TID 0` with comments. HELLO SEND→EP3, reply RECV on own EP4, NOTIFY tid 0.)

- [ ] **Step 3: Broker rpc→service routing (retire collapsed-dst)** — in `userspace/qrexec_server/v2_main.c`. The S2-era `QREXEC_QUBE 1` is stale (qube 1 is mem's qube today): every deliver currently routes to `svc_of_qube[1] = 2` = mem_server, so the vault marker is unreachable. Replace with service-dst rows + an rpc-keyed table (the PROVEN `qube_decide` call shape is preserved, so `Qubes_B` still models the C exactly):

```c
/* RPC -> service qube. Rows below address the SERVICE qube as dst;
 * the lookup key is rpc_svc[rpc]. Indexed by rpc id (<10, else
 * INVALID). AS-BUILT values (verified against this file's rpc
 * defines; Task-5 review): [1]=6 keys.sign->vault, [2]=6
 * clipboard->vault (DENY row still fires), [3]=5 net.send->net,
 * [4]=0 INVALID (wire tag, no row), [5]=4 filter.reload->fw,
 * [6]=0 INVALID (wire tag, no row), [7,8]=6 unwrap/rewrap->vault,
 * [9]=7 format->cryptblk. Mirrors boot wiring; reviewer checks
 * each entry against the row table below. */
static const unsigned long rpc_svc[10] = {0, 6, 6, 5, 0, 4, 0, 6, 6, 7};
```

(Verify the rpc ids for net.send/filter.reload against the boot row table first — lines ~184-193 use `QREXEC_QUBE` dsts with specific rpc numbers; read them, do not guess. If any id above is wrong, set it from the file and report the correction.) Then: (a) rewrite every boot row's `.dst` from `QREXEC_QUBE` to its service qube per this table (keys.sign rows → 6, clipboard row → 6 with DENY, net.send → 5, filter.reload → 4, unwrap/rewrap → 6, format → 7); (b) change the three `qube_decide(&pol, sqb, QREXEC_QUBE, rpc)` call sites to resolve `svc = (rpc < 10) ? rpc_svc[rpc] : 8 /* invalid qube */` first (rpc ≥ 10 or svc == 0 with... careful: svc 0 is invalid (demo qube, never a deliver target) — treat `svc == 0 || svc >= 8` as INVALID + deny-audit, no SEND) and call `qube_decide(&pol, sqb, svc, rpc)`; (c) change the two deliver arms to send to `svc_of_qube[svc]` (same variable, not `svc_of_qube[dstq]`); (d) change the `qube_audit(..., QREXEC_QUBE, ...)` dst args to the resolved `svc` (honest audit); (e) delete `#define QREXEC_QUBE 1` iff no references remain (reviewer confirms via grep), else leave with a `/* stale: do not use for routing */` comment. Rewrite the `dst is always QREXEC_QUBE` comment block (~lines 167-168) to describe service-dst rows.

- [ ] **Step 4: Thread-A legs as SEND+RECV call/response** — in `kernel/user.c` `user_a_main`, after the `W1` print and BEFORE `upark()`, insert (immediates only, no literals, no prints — marker-free park on any deviation; `usend` returns `V2_OK`=0 on handoff, NEVER the broker's reply — replies arrive as one-word SENDs on EP0):

```c
    /* Live qrexec legs (deferred-A): wait for the admin handshake
     * (ADMIN_LIVE_BIT 2), then drive ask + deny over EP3 as
     * SEND + RECV call/response pairs. */
    bits = uwait();
    if (bits != 2)
        upark();
    {
        uint64_t call[4];
        uint64_t rep[4];
        unsigned long s = 0, q = 0, o = 0;
        long n;
        call[0] = 1; /* T_CALL */
        call[1] = 1; /* keys.sign */
        call[2] = 0;
        call[3] = 0;
        if (usend(3, call, 4) != 0)
            upark();
        n = urecv(0, rep, 4, &s, &q, &o);
        if (n < 1 || rep[0] != 1) /* R_PENDING: ask enqueued */
            upark();
        call[1] = 2; /* clipboard */
        if (usend(3, call, 4) != 0)
            upark();
        n = urecv(0, rep, 4, &s, &q, &o);
        if (n < 1 || rep[0] != (uint64_t)-1) /* R_DENY: denied */
            upark();
    }
    upark();
```

(Reply check via RECV'd words, never the syscall return: `R_DENY == -1 == V2_ERR_INVALID`, so return-checking would confuse a gate reject with a broker deny.)

- [ ] **Step 5: Vault rpc-switch** — in `userspace/vault/v2_main.c`, after the `VAULT_REWRAP` arm and before the VOL_FORMAT comment (~line 501), insert:

```c
        if ((unsigned long)buf[1] == 1UL) { /* keys.sign: live-traffic
            * probe (S2 row), NOT an unwrap — print the end-to-end
            * marker, no state change, no handoff (handoff runs only
            * for VAULT_UNWRAP). Boot unlock uses rpc 7, so this marker
            * is honest. */
            u_puts("VAULT: live ok\n");
            continue;
        }
```

(`1UL` gets a `#define KEYSSIGN_LIVE 1UL` with an S2-row comment. The existing fallthrough already drops rpc 9 + others silently.)

- [ ] **Step 6: Smoke gate** — in `tools/verify.sh [4/4]` after the `BLKMMIO` line (mirror the existing one-line style):

```bash
    echo "$V2LOG" | grep -q "QREXEC: admin registered" && echo "v2 smoke: admin live" || { echo "v2 smoke: FAIL (no admin registered)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "VAULT: live ok" && echo "v2 smoke: vault live" || { echo "v2 smoke: FAIL (no vault live)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "AUD: deny rpc=2" && echo "v2 smoke: live deny" || { echo "v2 smoke: FAIL (no live deny)"; QEMU_FAIL=1; }
```

(Check whether the exact `AUD: deny rpc=` print shape exists in the broker deny arm — the plan assumes `u_puts("AUD: deny rpc="); u_putdec(rpc);` — read it; if the shape differs, match the gate to the code, not vice versa. The in-kernel model demo prints `QREXEC: deny` (different string, no clash).)

- [ ] **Step 7: Build + smoke**

Run: `make -C userspace 2>&1 | tail -n 2 && tools/mkinitrd.sh >/dev/null 2>&1 && make -C kernel 2>&1 | tail -n 2`
Expected: clean. (mkinitrd between the builds is MANDATORY: `make -C kernel` does not regenerate tracked `kernel/initrd_data.c`, or QEMU boots stale ELFs — Task 3 ruling.)
Run: `tools/verify.sh 2>&1 | grep -E "v2 smoke:|FAIL|verify done"`
Expected: all old markers + 3 new PASS, zero FAIL.

- [ ] **Step 8: Commit**

```bash
git add kernel/kboot.c kernel/user.c userspace/adminvm userspace/qrexec_server userspace/vault tools/verify.sh
git commit -m "live-qrexec: thread-A live ask+deny legs + markers"
```

### Task 6: Docs + full verify (stage closure)

**Files:**
- Modify: `docs/V2_DESIGN.md` (§9: deferred-A → BUILT + refinements + B/C/D still listed), `docs/QUBES_ISOLATION_PLAN.md` (§11 deferred list shrinks; mapping table row if a live-traffic row fits, else BUILT note), `docs/ARCHITECTURE.md` (endpoint-per-thread subsection + live-legs paragraph + verification list), `docs/BUILD.md` (transcript: admin-registered/live-ok/deny lines + WAIT/NOTIFY handshake note)
- Test: `tools/verify.sh` end-to-end

**Interfaces:**
- Consumes: Tasks 1–5 artifacts.

- [ ] **Step 1: Update docs** — every BUILT names test/marker/lemma/path; refinements list (per-thread EPs, RECV-own-EP rule, `svc_of_qube` + `rpc_svc` routing with collapsed-dst retired, V2_C replay + separation, grant reuse + admin grant, NOTIFY handshake with R_OK RECV, SEND+RECV call/response legs, rpc-switch, admin put-back arm now dormant-but-harmless); honest remainder (B/C/D still open with owners; S3/FDE latent misdelivery + dead admin registration closed by addressing — name both closed holes).
- [ ] **Step 2: Full verification**

Run: `tools/verify.sh 2>&1 | tail -n 12`
Expected: host PASS (incl. extended `test_v2ipc`), gates PASS, kernel PASS, QEMU PASS with all markers, Isabelle PASS or pre-existing SKIP only, zero FAIL, no new SKIP.

- [ ] **Step 3: Commit**

```bash
git add docs/V2_DESIGN.md docs/QUBES_ISOLATION_PLAN.md docs/ARCHITECTURE.md docs/BUILD.md
git commit -m "live-qrexec: docs mark deferred-A built with proof/test links"
```

---

## Self-Review

- **Spec coverage:** §0 finding → Tasks 1–4 (nothing rides EP0 anymore); §2 arch (NEP/ownership/widened gate) → Tasks 1–2; A↔B migration (§2) → Task 3; §3 svc table + guard → Task 3 Step 2; §4 V2_C delta + separation/mutants/evals → Task 4; Phase-2 handshake/grants/legs/switch/markers (§Phase 2 + error table) → Task 5 (each table row owned: pre-registration impossible by WAIT; no-register → marker-free park; grant fail → `[demo] FAIL`; queue-full/hash-mismatch → marker-free park; foreign rpc → INVALID; clipboard-delivers → review + deny pins; reply mismatch → park); §7 non-goals → none tasked (deliberate); §8 exit → Tasks 1–6 gates.
- **Placeholder scan:** no TBD/TODO/later/appropriate/edge-cases/similar-to; every code step ships concrete constants (EP ids = tids, `svc_of_qube` values, reply codes, bit 2, slot 9, rpc ids), commands and expected outputs. Open investigation points are owned explicitly (u_reply-vs-usend reply path, `v2_grant` double-grant, `AUD: deny rpc=` print shape, V2_NOTIFY number) with STOP-and-ask fallbacks, not guesses.
- **Type consistency:** `V2_NEP 10` == `V2_CAP_THREADS` (asserted); EP id == owner tid everywhere (A0 B1 mem2 qrexec3 admin4 fw5 net6 vault8 cryptblk9; scratch7 unused); `svc_of_qube[8] = {0,2,3,4,5,6,8,9}` matches boot tids; `R_PENDING 1`/`R_DENY -1` match broker defines; `max_eps = 10` matches `V2_NEP`.
