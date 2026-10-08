# Moonlight Qubes S1/S2: caps-as-qubes isolation + qrexec policy engine

**Status:** Design drafted 2026-09-19, awaiting user review before implementation plan
**Depends on:** V2 Stage 3 BUILT (per-thread VSpaces, SPAWN/FORK/EXEC, initrd mem_server), `Qubes_A` S0 spec green
**Decides:** QUBES open-question #1 (H-ext deferred, caps-as-qubes now), #2 (qrexec as own qube, AdminVM confirms only)
**Phasing:** Phase 1 = Approach A (caps-as-qubes S1 core) + Approach C bundled (S2 policy engine on top); Approach B (H-ext two-stage) deferred to post-1.0, documented in §8

---

## 1. Goal

Turn today's threads into **qubes** (mutually distrustful compartments) with a **typed, policy-gated cross-qube RPC layer**, reusing the proven VSpace/cap/IPC machinery instead of building a hypervisor.

**Theorems to discharge (mirrors `Qubes_A` + extends `V2_C`/`V2_D`):**
- Deny-closed + default-deny: no rule match ==> Deny, never Allow (fail closed).
- Ask-suspends / ask-no-bypass: an Ask decision never delivers data; only `q_decide(approve)` delivers.
- Authority confinement over qube labels: a qube's writes/maps/grants affect only objects reachable from its caps (labels ride on kernel-stamped senders, never user-supplied).
- Destroy-denies-inflight: destroying a qube drops its pending asks and appends Deny audit entries (no orphaned approvals).

**Demos (each a QEMU text marker, fail-closed like current smoke):**
- S1: two qubes boot, cross-qube raw read faults and is contained (`QUB: xread denied` + fault park, other qube continues).
- S2: work→vault `keys.sign` raises AdminVM prompt, approve delivers / deny blocks (`QREXEC: ask/allow/deny` markers); direct work→net clipboard attempt denied without prompt.

---

## 2. Background / what exists

- Threads: `uctx_t threads[NTHREADS]` (`NTHREADS=4`, `V2_CAP_THREADS=8`), states Runnable/Parked/Blocked, lowest-Runnable scheduler, SBI timer preemption.
- VSpaces: per-thread `root_pt_t/l1_t/l0_u_t`, `satp` switched in `enter_thread`, frame window `0x80800000 + vpn*4096` backed by real frames at `0x81000000 + f*4096`, W^X enforced in model + PTE install.
- IPC: static `ep0` (`ipc.h`: `sendq/recvq`, `V2_MSG_MAX=4`, `V2_IPC_Q=16`), kernel-stamped `slot.sender` (tid), wait-kind gating (NOTIFY wakes only WAITers), validate-then-copy via SUM window.
- Invoke ops 1–13 (`MINT..READ`, `ELF_MAP/SPAWN/FORK/EXEC`); `SPAWN` = fresh thread + VSpace + ELF, stale caps/mappings/IPC cleared; `FORK` = COW; reserved args must be zero.
- Userspace: `mem_server` (initrd index 0, SPAWNed as thread 2 at boot, `MEM-SRV` banner), `moonsh/ls/cat` ELFs packed by `tools/mkinitrd.sh` (TOC + 4096 padding, blob in kernel `.data`).
- Spec: `Qubes_A.thy` (qubes list max 16, policy first-match-wins, pending max 32, audit append-only, all transitions total, 35 lemmas, 0 axioms).

---

## 3. Architecture

```
U-mode qubes (threads 0..3 today, NTHREADS grows to 8):
  work / personal / vault / net ... each = 1+ threads + 1 label + own VSpace + own caps
Kernel (S-mode): qube table + label stamping + raw-IPC deny gate + new Invoke ops
qrexec_server (U-mode qube, own VSpace): policy table + pending-ask queue + audit ring
AdminVM (U-mode qube): confirm prompts + audit export + template/update client (later stages)
```

No H-ext, no hypervisor mode, no PMP changes (firmware owns PMP). Isolation = per-thread VSpace + caps + kernel label checks. This is the "proof reuse" branch of open-question #1.

---

## 4. Components

### 4.1 Kernel qube table + labels (S1 core)

- `qube_of[tid]`: `uint8_t` label per thread, minted at create, immutable thereafter. Thread 0/1 (current A/B demo) become qube 0/1; mem_server thread 2 becomes its own qube; `qrexec_server` + AdminVM get fresh qubes via SPAWN path.
- `V2_INV_QCREATE (14)`: args `(initrd_idx, qube_label_slot, reserved=0, reserved=0)`. Reuses `build_child_vspace` + ELF load; clears stale caps/mappings/IPC (same as SPAWN); assigns label; fails `V2_ERR_OVERFLOW` when threads/qubes full, `V2_ERR_INVALID` on bad index/unaligned/nonzero-reserved. Bound: `NTHREADS` scan.
- `V2_INV_QDESTROY (15)`: args `(qube_label, 0, 0, 0)`. Parks all threads of the qube (T_DEAD), drops their pending IPC queue entries, revokes their non-root caps + mappings (reuse `v2_revoke` drain), appends kernel audit note. Destroying qube 0 (boot) is `V2_ERR_INVALID`.
- Label stamping: `V2_RECV` already returns kernel-stamped `sender` (tid) in a1; extend to also return `sender_qube` in a2 (shifting `ovf` to a3 — UABI bump, documented; old `u_recv` wrappers updated). Labels never cross from userspace.
- Raw-IPC deny gate (the S1 security rule): `V2_SEND` to a thread in a *different* qube returns `V2_ERR_INVALID` unless the sender holds a `QREXEC_GRANT` cap for `(dst_qube, rpc)` — i.e. raw cross-qube rendezvous is denied by default; only qrexec-mediated delivery passes. Same-qube SEND/RECV unchanged. NOTIFY/WAIT unchanged (intra-qube only; cross-qube signaling is qrexec RPC, never badges).

### 4.2 qrexec_server (S2, own qube)

- Freestanding rv64 ELF (`userspace/qrexec_server/v2_main.c`, `v2_user.ld`, packed after mem_server in `mkinitrd.sh`), SPAWNed at boot as thread 3 (or first QCREATE).
- State (stack-local + private frames, no globals crossing qubes): policy table (first-match-wins, default-deny — mirrors `find_decision`), pending-ask queue (bounded 32, full ==> Deny + audit, mirrors `q_call`), audit ring (append-only, bounded, exportable to AdminVM/vault).
- RPC schema (data, adversarial-length tested from day one): `(src_label, dst_label, rpc_id, arg_ptr, arg_len, arg_hash)`. Args copied at call time via `u_copy_in` path; hash (`FNV-1a` 64-bit, no new crypto dep) pinned for the confirm prompt (no TOCTOU: prompt shows hash, delivery re-checks hash).
- Message flow: caller `V2_SEND(qrexec_ep, rpc_desc)` → server validates labels (kernel-stamped) → policy lookup → Allow: forward to dst qube + audit Allow; Ask: enqueue + `V2_NOTIFY(AdminVM)` + audit pending; Deny: reply error + audit Deny. `q_decide` arrives from AdminVM (`approve` bool) → on approve, deliver + audit Allow; on deny, drop + audit Deny. Bad indices/unknown qubes: no-op + audit Deny (total functions, never undefined).
- Policy table lives in qrexec-owned frames; AdminVM updates it via a single `POLICY_RELOAD` RPC (versioned blob, length-checked, atomic swap — failed parse keeps old table).

### 4.3 AdminVM (S2 thin end)

- Freestanding ELF (`userspace/adminvm/v2_main.c`), own qube, no net, no user parsers. Duties only: render confirm prompts (via SBI console for now — GUI chrome is S4), answer `q_decide`, export audit ring on request. No policy evaluation (that is qrexec's job); no ambient caps.
- Confirm path: `V2_WAIT` for notify → `V2_RECV` ask descriptor (hash shown) → operator approve/deny (console `y/n` in S2 demo; trusted chrome later) → `V2_SEND(qrexec, decision)`. Suspended calls never deliver until decided (ask-suspends).

### 4.4 `caps.h` / `ipc.h` deltas

- New cap right `V2_RIGHT_QX` (cross-qube grant bit): `v2_mint`/`v2_grant` can attenuate it; `MAP` rejects it (not a memory right); raw-SEND gate checks it. W^X untouched.
- `V2_QUBES_MAX = 8` (<= `V2_CAP_THREADS`), `V2_POLICY_MAX = 32`, `V2_PENDING_MAX = 32` — mirrors `max_qubes/max_pending`, `_Static_assert` bound so WCET re-analysis triggers on growth (same pattern as sched bitmap bound).
- All new loops carry `/* bound: N */` comments; no function-pointer dispatch (switch on op); every user pointer via `copy_from/to_user` validate-then-copy; `grep` gate for raw dereference still passes.

---

## 5. Data flow (S2 demo: work→vault sign)

1. work qube: `V2_SEND(qrexec_ep, {dst=vault, rpc=keys.sign, args, hash})` (kernel stamps src=work).
2. qrexec: policy `work vault keys.sign ask` matches → enqueue ask, `V2_NOTIFY(AdminVM)`, reply work `PENDING`.
3. AdminVM: prompt `work wants a signature [hash…] y/n` → `y` → `V2_SEND(qrexec, {approve, ask_idx})`.
4. qrexec: hash re-check → deliver to vault qube → audit Allow → notify work `DELIVERED`.
5. Deny path: same to step 3 with `n` → drop + audit Deny → work gets `V2_ERR_INVALID`.
6. Bypass attempt: work `V2_SEND(vault_ep_direct, …)` → kernel raw-gate rejects (`V2_ERR_INVALID`) + `QUB: xread denied` marker; no prompt, audit Deny.

---

## 6. Error handling (all fail closed)

| Case | Behavior |
|---|---|
| Unknown qube / bad thread id | No-op, `V2_ERR_INVALID`, audit Deny |
| Policy table full / pending full | `V2_ERR_OVERFLOW`, request Deny-audited, old state kept |
| Oversize / unaligned / cross-region args | `V2_ERR_INVALID`, no copy, no state change |
| Hash mismatch at decide time | Treat as Deny (TOCTOU kill), audit Deny |
| Destroy with inflight asks | Drops them, appends Deny entries (mirrors `q_destroy`), parked threads never resume |
| Reserved Invoke args nonzero | `V2_ERR_INVALID` (same rule as SPAWN/FORK/EXEC) |
| qrexec/AdminVM dead | Cross-qube calls block then fail `V2_ERR_INVALID`; same-qube IPC unaffected |

---

## 7. Testing

- Host unit (new, `tests/test_qube_policy.c` + `tests/test_qlabels.c`, wired into `verify.sh [1f]`): policy matrix (allow/ask/deny × label pairs incl. wildcards), malformed lengths, caller-spoof attempt (user-supplied label must fail — kernel stamp wins), pending-full fail-closed, destroy-drops-inflight, hash-mismatch deny. Mirror style of `test_v2ipc/test_v2caps` (pure C, include `ipc.h`/`caps.h` + new `qube.h` header, no asm/SBI).
- QEMU smoke (extend fail-closed gate in `verify.sh [4/4]`): `QUB: qube0 qube1 up`, `QUB: xread denied`, `QREXEC: ask`, `QREXEC: allow`, `QREXEC: deny`, `AUD: 3 entries`. Every missing marker flips FAIL (same discipline as current MEM/CAP/OK/DU/NP markers).
- Production gates unchanged (linker layout, `user.c` rodata ban) plus: new U-mode ELFs (`qrexec`, `adminvm`) must be immediates-clean where they touch shared text (same `llvm-readelf` rodata check extended to their objects); `mkinitrd.sh` order asserted (mem_server index 0, qrexec present).
- Isabelle deltas: `Qubes_B.thy` (new): qube-label confinement over kernel ops (create/destroy/send-gate), `q_call/q_decide/q_destroy` refinement from `Qubes_A` to C table ops; `V2_C`/`V2_D` preservation replays with label dimension. Anti-vacuity rules apply (mutant per invariant, 0 sorry, max-3 named axioms). Gated in `verify.sh [2b/2c]` + CI isabelle job.

---

## 8. Deferred: H-ext two-stage (Approach B)

Frozen decision: **not in S1/S2**. Rationale: QEMU `-M virt` H-ext + hypervisor-mode trap rewrite + `V2_B` re-proof before any userspace win. Revisit when (a) qube-escape red test exists that caps-as-qubes cannot close, or (b) silicon with H+CHERI+IOMMU is the boot target. The qube-label abstraction is forward-compatible: labels become VMIDs, the raw-gate becomes stage-2 fault policy, `qrexec` RPC schema unchanged.

---

## 9. Non-goals (this spec)

Net/firewall/USB split (S3), GUI chrome + focus + clipboard RPC (S4), templates/overlays/disposables/updates/backup (S5), CBMC-in-CI + fuzz (S6), DICE + sealed storage + release (S7), SMP/hart-per-qube, seamless windows, Linux guests.

---

## 10. Exit criteria

- [ ] Kernel `QCREATE/QDESTROY` + label stamp + raw-gate, host-tested, QEMU markers green.
- [ ] `qrexec_server` + AdminVM ELFs boot from initrd, S2 demo transcript green (ask/allow/deny + direct-bypass denied).
- [ ] `Qubes_B.thy` builds clean, anti-vacuity gate passes, CI isabelle green.
- [ ] `tools/verify.sh` full-pass discipline kept (new tests in `[1f]`, new markers in `[4/4]`, no new SKIP branches).
- [ ] Docs: `V2_DESIGN.md` §9 S1/S2 entries marked BUILT with refinements; `QUBES_ISOLATION_PLAN.md` mechanism rows S1/S2 flipped `[TODO]`→`[HAVE]` with paths.
