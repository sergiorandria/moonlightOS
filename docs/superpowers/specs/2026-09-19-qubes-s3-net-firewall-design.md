# Moonlight Qubes S3: net/firewall split (phased: loopback policy first, NIC bring-up second)

**Status:** Design drafted 2026-09-19, awaiting user review before implementation plan
**Depends on:** Qubes S1/S2 BUILT (branch `qubes-s1-s2`: labels, raw gate, qrexec + AdminVM, `Qubes_B`)
**Decides:** packet data plane (granted single-frame packets + `v2_qask_t` arg extension, closing S2 deferred (c)); firewall trust rule (net accepts only firewall-stamped forwards); Phase-2 IRQ path (PLIC claim/complete → `NOTIFY` badge)
**Phasing:** Phase 1 (policy/routing/audit, loopback net stub, zero kernel changes) ships independently; Phase 2 (virtio-net-device bring-up) builds on it

---

## 1. Goal

Split networking the Qubes way: exactly one qube (`net`) touches the wire, exactly one qube (`firewall`) decides what crosses, AppVMs reach the network only through the chain AppVM → firewall → net, and every crossing is policy-gated with an audit trail.

**Theorems to discharge (new `Qubes_C.thy`):**
- Packet integrity: bytes delivered to `net` equal bytes the AppVM stored, modulo explicit firewall allow (no forge, no splice — grant chain + kernel-stamped labels).
- Firewall default-deny: no ruleset match ==> drop + Deny audit, never forward.
- Net trust rule: `net` acts only on frames announced by `firewall` (sender_qube check); a direct AppVM grant to `net` is ignored (never mapped, never read).

**Demos (QEMU text markers, fail-closed like current smoke):**
- Phase 1: AppVM fetch through the chain (`FW: allow`, `NET: up`, `AUD:` entries); direct AppVM→net bypass denied (`LEAK: denied`); spoofed firewall announcement ignored (`SPOOF: ignored`).
- Phase 2: `NET: link up`, `NET: tx ok`, `NET: irq ok` on SLIRP user-net (deterministic: negotiate + link + TX-complete; no external fetch asserted).

---

## 2. Background / what exists

- S1/S2: per-thread VSpaces + frame window (`0x80800000 + vpn*4096`, real frames at `0x81000000 + f*4096`), `V2_INV_PT_ALLOC/MINT/GRANT/MAP/UNMAP/REVOKE/READ/WRITE`, kernel-stamped `(sender, sender_qube)` on RECV, raw cross-qube SEND denied without QX, qrexec policy (first-match-wins, default-deny, bounded ask queue, append-only audit), FNV-1a `qube_fnv1a`, `T_DECIDE` forwards zeros (S2 deferred (c): `v2_qask_t` stores only `rpc/hash`).
- v1 `userspace/drivers/virtio_net.c` (492 lines, frozen-ABI host-sim + `-Werror` gate, never booted): queue core + IOMMU-window discipline portable to V2; transport/MMIO/IRQ halves are not.
- Kernel maps only UART MMIO (`0x10000000`, `l1_m[128]`); no virtio-MMIO region, no PLIC mapping, no S-external (`scause=9`) path. QEMU cmdline and verify smoke attach no net device (block disk only).
- RISC-V `virt` facts used (standard, no probing): virtio transports at `0x10001000 + i*0x1000` (use index 0: `0x10001000`, IRQ 1), PLIC at `0x0c000000` (claim/complete `0x0c200004`).

---

## 3. Architecture

```
Phase 1 (no kernel changes, no QEMU changes):
  AppVM qube --GRANT frame(R)--> firewall qube --GRANT frame(R)--> net qube (stub)
       \--control RPC via qrexec--/      \--forward announcement--/
  qrexec policy rows gate the control RPCs; data moves by grants, never by copy.

Phase 2 (adds: QEMU netdev, kernel MMIO map + PLIC→notify, V2 UABI virtio driver):
  net qube (stub → real driver): virtio-MMIO mapped exact-bounds into its VSpace only;
  TX/RX rings in frame-window DMA buffers; completion IRQ → kernel PLIC claim/complete → NOTIFY badge.
```

No H-ext, no hardware IOMMU, no TCP stack in `net` (L2/raw frames only; SLIRP user-net handles L3+ outside the guest). Jumbo/multi-frame packets explicitly out of scope: max packet 1514B fits one 4KB frame.

---

## 4. Components

### 4.1 Packet plane: granted single-frame packets (Phase 1 core)

- Send (AppVM, all existing ops): `V2_INV_PT_ALLOC` → `V2_INV_MAP` at a free vpn → store packet bytes with direct U-mode stores to `0x80800000 + vpn*4096` (no syscall per byte; `WRITE` word-ops are NOT the data path) → `qube_fnv1a` over `len` bytes → `V2_INV_GRANT` frame cap (R only, QX clear) to the firewall thread → `V2_SEND` control descriptor `(rpc=net.send, frame_id, len, hash)` to firewall EP (cross-qube: AppVM holds a QX grant for firewall, minted at qube creation by AdminVM policy).
- Receive (firewall): two accepted inputs, everything else replied DENY/ignored per tag. (a) `T_DELIVER` with `rpc==net.send` AND kernel-stamped `sender_qube==2` (true qrexec label — the approved path): take `(slot=arg0, len=arg1)`, require `slot==FW_IN_SLOT`, `V2_INV_MAP` at the scratch vpn (rejection ==> drop, no state change), `fw_decide` over the bytes. (b) Direct `T_CALL(net.send, …)` (any sender): reply INVALID — this forces the ASK path through qrexec; processing direct calls would bypass the ask the policy mandates. Hash note: the firewall does NOT compare a frame hash — `T_DELIVER` carries no expected hash (control-word pinning lives in qrexec's ask/decide). Authorization here is approval + R-only grant + `len` bound; byte integrity is verified net-side where the expected hash IS present. Trust root for grant provenance: only qube 0 holds QX→firewall in this boot (multi-AppVM provenance tracking is future work).
- Forward (firewall → net): ruleset verdict Allow → `h=fnv(bytes)`, `V2_INV_GRANT` (R) to `(net_tid, NET_IN_SLOT)`, `V2_SEND T_FWD[slot, len, h]` direct to net (QX firewall→net minted at boot); unmap scratch. Net checks `sender_qube == 4`, slot/len bounds, maps, recomputes `h'` and compares to the announcement — mismatch is a silent drop (`SPOOF: ignored` class, no oracle); match prints `NET: fwd ok`, unmaps, and sends `T_DONE` back (QX net→firewall minted at boot) so the firewall audit-notes completion, closing ask→allow→forward→done. Malformed or unexpected input anywhere: drop + unmap, never forward.
- Length rule: `len <= 1514` checked at every hop (AppVM store bound, firewall re-check, net re-check); oversize ==> `V2_ERR_INVALID`, no map, no audit append (malformed input is dropped, not logged — audit is for policy decisions).
- Frame lifecycle: allocator (AppVM) revokes after net signals completion (`net.done` announcement); firewall/net never retain caps past one packet (revoke-on-complete, reuse `v2_revoke` drain semantics).

### 4.2 `v2_qask_t` arg extension (closes S2 deferred (c))

- Extend `v2_qask_t` with `arg0` (frame_id) + `arg1` (len); `qube_ask_enqueue`/`qube_decide_idx` carry them; `T_DECIDE` delivery re-attaches `(frame_id, len)` and re-checks the hash before forwarding. Pending entry stays ≤32B; `V2_PENDING_MAX=32` unchanged.
- Control RPCs that need Ask (`AppVM → firewall net.send` under `ask` rows) now survive the suspend/resume with payload intact; arg-less RPCs (`keys.sign`) are unaffected (args zero).

### 4.3 Firewall ruleset (data, versioned, AdminVM-owned)

- Blob format (mirrors policy table style): ordered rules `(src_qube, proto, dport, decision)` + `default: deny`; initial rows: `(work, udp, 53, allow[DNS pinned 9.9.9.9])`, `(work, tcp, 80/443, ask)`, `(*, *, *, deny)`. Header parse only (first 34B: eth14 + IP20 min); payload never inspected (no parsers in the filter — S6 fuzzes what S4+ adds).
- Update: AdminVM `FILTER_RELOAD` RPC (versioned blob, length-checked ≤2 frames, atomic swap; failed parse keeps old table + `FW: reload kept`). Ruleset lives in firewall-owned frames; audit ring records version flips.
- Leak tests (host + QEMU): AppVM→net direct SEND ==> raw-gate `V2_ERR_INVALID` (`LEAK: denied`); AppVM grants frame to net without firewall announcement ==> net ignores (`SPOOF: ignored`); firewall-compromise containment is out of scope (one filter, reviewed as data — S6).

### 4.4 qrexec policy rows (new)

The broker collapses dst: it calls `qube_decide` with `dst=QREXEC_QUBE`
always (S2-established; the rpc id names the service). Rows are therefore
addressed to the broker, never to the ultimate destination:

```
appvm(0)  qrexec  net.send        ask     "appvm wants network"
adminvm(3) qrexec filter.reload  ask     "reload firewall ruleset?"
```

No `net.fwd` row: the firewall forwards directly via its boot-minted QX
grant to `net` (no qrexec hop — see §4.1), and `net` authenticates the
announcement by kernel-stamped `sender_qube`, not by policy. No catch-all
row: unmatched rpcs already hit default-deny. (An earlier draft addressed
rows to firewall/net labels; those can never match the broker's collapsed
call and were removed.)

### 4.5 Phase-2 NIC bring-up (net stub → real driver)

- QEMU (`tools/run_qemu.sh` + verify smoke cmdline): `-device virtio-net-device,netdev=n0 -netdev user,id=n0` (SLIRP, no host privileges). Smoke boots WITH netdev once Phase 2 lands (single cmdline — no forked configurations).
- Kernel (`kernel/kboot.c`, pagetable + trap): map `0x10001000` (4KB, RW, no X, no U — S-only, net qube reaches it via a dedicated exact-bounds U-leaf installed only in its `l1_t`, mirroring the UART pattern but per-thread); map PLIC claim page S-only; new `scause=9` branch: PLIC claim → if source == virtio0 IRQ → `NOTIFY(net_thread, NET_IRQ_BIT)` + wake only WAIT-kind waiters (existing discipline) → PLIC complete → `sfence` not needed (MMIO, no TLB). Unknown sources: park nothing, log `IRQ: unexpected <id>`, keep running (fail-open logging would be an oracle; unexpected-IRQ storms are S6 work).
- Driver (`userspace/net/v2_main.c`, new ELF, initrd index 3): port the v1 queue core (feature negotiate, virtqueue setup in two DMA frames from the frame window, TX/RX kick/poll); transport/MMIO via the mapped U-leaf with exact-bounds asserts (base+len checked once at init, never re-derived); completion via `V2_WAIT` on the IRQ badge (no polling loops — bounded wait with timer fallback: if no IRQ in N ticks, `NET: irq timeout` + fail closed, never spin).
- Boot order: qrexec → AdminVM → firewall → net (net prints `NET: up` after link-status bit reads 1; firewall prints `FW: up` after ruleset v0 load; demo fetch runs once, then park).
- Thread budget: `NTHREADS` grows 6→8, exactly `== V2_CAP_THREADS` (tids 0/1 demo, 2 mem, 3 qrexec, 4 adminvm, 5 firewall, 6 net, 7 QCREATE scratch). The existing `_Static_assert(NTHREADS <= V2_CAP_THREADS)` still holds at equality; any further growth forces a `V2_CAP_THREADS` bump plus WCET re-analysis and proof replay — no silent extension.
- Qube labels 4 (firewall) and 5 (net) are boot constants: assigned at spawn in boot order and asserted (`qube_of[5]==4 && qube_of[6]==5` prints `NETQ: labels ok`); `net`'s `sender_qube == 4` check keys off this constant, never off a value received over IPC.
- Deterministic smoke contract: assert `NET: link up` + `NET: tx ok` (TX-complete IRQ after sending one gratuitous ARP) + `NET: irq ok`; RX-from-wire and external fetch are manual-only (documented `tools/run_qemu.sh` recipe, never CI).

---

## 5. Data flow (Phase-1 demo: AppVM fetch)

1. AppVM allocs/maps/stores a 64B probe packet, grants R into firewall slot 8, `SEND T_CALL(net.send, slot=8, len)` to the waiting qrexec → row `ask` → pending + AdminVM prompt (demo auto-approves, same display-only discipline as S2).
2. `T_DECIDE(approve)` re-attaches `(slot, len)`, re-checks control hash → `T_DELIVER(net.send, slot, len)` to firewall → firewall maps slot 8, ruleset `allow` → grants R into net slot 8, `SEND T_FWD(8, len, h)`.
3. Net (stub) checks `sender_qube == 4`, verifies `h`, prints `NET: fwd ok`, unmaps, sends `T_DONE` → firewall audit-notes done. Markers: `FW: allow`, `NET: up`, `NET: fwd ok`, `AUD:` ring holds ask→allow→forward→done. (AppVM frame reclaim + completion notification to AppVM are future work; the demo frame stays mapped with a comment.)
4. Deny leg: same to step 2 with `deny` (or no-match proto) → drop + `FW: deny` + Deny audit, frame unmapped un-read.
5. Bypass legs: direct AppVM→net SEND → raw gate `LEAK: denied`; direct grant + forged announcement → `sender_qube != firewall` → `SPOOF: ignored`.

---

## 6. Error handling (all fail closed unless noted)

| Case | Behavior |
|---|---|
| Control-hash mismatch at decide (qrexec) | Drop, Deny audit, pending entry removed |
| Frame-byte hash mismatch at net (`h' != h`) | `UNMAP`, silent drop (spoof-class, no oracle) |
| `len > 1514` or `len == 0` | `V2_ERR_INVALID`, no map, no audit |
| Grant without announcement / announcement without grant | Ignore (no map, no read); silent at net, Deny-audit at firewall |
| Pending/frame-pool exhaustion | `V2_ERR_OVERFLOW`, requester keeps old state, demo prints `NET: busy` and parks |
| Virtio feature mismatch / link down (Phase 2) | `NET: no link`, net qube parks, chain returns `unreachable` (no retry storm) |
| IRQ storm / unexpected source (Phase 2) | Log once + rate-limit; storm containment is S6 |
| Ruleset reload parse failure | Keep old table, `FW: reload kept`, Deny audit on the reload RPC |

---

## 7. Testing

- Host unit (`tests/test_netfw.c`, `verify.sh [1f]`): ruleset matrix (allow/ask/deny × proto/dport incl. default-deny), oversize/zero-len, hash-mismatch drop, grant-without-announcement ignore, spoofed-sender ignore, pending-full, `v2_qask_t` arg round-trip through ask/decide, reload atomicity (bad blob keeps old).
- QEMU smoke (fail-closed markers in `[4/4]`): Phase 1 `NETQ: labels ok`, `FW: allow`, `FW: deny`, `FW: up`, `NET: up`, `LEAK: denied`, `SPOOF: ignored`, `AUD:`; Phase 2 adds `NET: link up`, `NET: tx ok`, `NET: irq ok` (and gates live `NET: fwd ok` once forwarded traffic exists — never a phantom assert). Missing marker ==> FAIL.
- Production gates unchanged + two more: net ELF immediates-clean (same rodata check), virtio-MMIO U-leaf present ONLY in net qube's tables (python gate over `llvm-readelf`/symbols or a boot-print `NETMMIO: tid=5 only` asserted in smoke — implementer's choice, documented).
- Isabelle (`Qubes_C.thy`): packet integrity over the grant chain, firewall default-deny, net trust rule; refinement of `qube_ask_enqueue/decide_idx` with args; mutants per invariant; 0 sorry; C(≤8 qubes, 1-frame packets) ⇒ spec bounds explicit.

---

## 8. Non-goals (this spec)

USB HCI + `usb` qube, GUI/focus/clipboard (S4), templates/overlays/disposables (S5), TCP/IP stack in guest, multi-frame/jumbo packets, hardware IOMMU / H-ext funneling, CBMC/fuzz (S6), DICE/sealed storage (S7), SMP/hart-per-qube, RX-from-wire CI assertions, IPv6 (non-IPv4 ethertypes hit default-deny like any other no-match).

---

## 9. Exit criteria

- [ ] Phase 1: granted-frame plane + arg-extended ask/decide + firewall ruleset + qrexec rows, host-tested, loopback demo green (`NETQ:`/`FW:`/`NET: up`/`LEAK:`/`SPOOF:`/`AUD:`; live `NET: fwd ok` specified but ungated until forwarded traffic exists).
- [ ] Phase 2: QEMU netdev + kernel MMIO/PLIC→notify + V2 UABI driver + deterministic link/tx/irq smoke green.
- [ ] `Qubes_C.thy` builds clean, anti-vacuity gate passes.
- [ ] `tools/verify.sh` full-pass discipline kept (new tests in `[1f]`, new markers in `[4/4]`, single QEMU cmdline, no new SKIP).
- [ ] Docs: `V2_DESIGN.md` §9 / `QUBES_ISOLATION_PLAN.md` S3 rows flipped `[TODO]`→`[HAVE]` with paths + refinements; S2 deferred (c) marked closed.
