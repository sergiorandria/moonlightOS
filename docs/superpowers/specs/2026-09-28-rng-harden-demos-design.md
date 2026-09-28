# RNG + Demo-Hardening: vault-owned virtio-rng, harden-in-place

**Status:** Design approved 2026-09-28 (sections 1-5 approved in chat), awaiting
implementation plan
**Depends on:** S4a BUILT (GUIMMIO leaf pattern, bump-set discipline), S3 BUILT
(virtio scan-then-bind, exact-bounds MMIO U-leaf), FDE BUILT (vault/cryptblk
DRBG ownership, TEST_KEYS honesty notes), live-qrexec BUILT (addressed EPs,
QX holder model + server-side sqb check)
**Decides:** virtio-rng via vault-owned driver with HW+env mixer; demo pools
and TEST_KEYS replaced in place; no new thread, no cap bump
**Constraints (binding):** Harden + keep behavior — same markers/proofs green;
microkernel intact (drivers in userspace, kernel maps leaves only); serial
console stays primary; `verify.sh` single entry (markers in `[4/4]`, single
cmdline extended with rng device, no new SKIP); C subset; fail closed

---

## 1. Goal

Replace demo-grade entropy and allocation with production-grade sources
without changing observable behavior. Vault owns the only RNG path and
proves it with markers. Everything else (surfaces, sched, exec) builds on
the hardened vault, the endpoint, and the unchanged caps.

**Theorems:** no new ones. Replay `V2_C` unchanged (no EP bump); add
`rng_mmio_covers`-style bound lemma in the style of `pci_scan_covers`.
Mutants per new invariant; 0 sorry.

**Demos (QEMU text markers, fail-closed):** `RNG: up` (vault bound RNG and
serves), `RNGMMIO: tid=8 only` (U-leaf exclusivity asserted at boot like
`NETMMIO`/`BLKMMIO`/`GUIMMIO`). All prior markers unchanged (ping-pong,
MEM/CAP/DU/NP, QUB/QREXEC/FW/NET/VAULT/CRYPT/GUI/live/audit-full/clean park).

## 2. Background / what exists

- QEMU virt offers virtio-rng (MMIO transport, device-ID 4); `run_qemu.sh`
  wires net/blk/keyboard/display but no rng yet. `drivers/virtio_mmio.h`
  owns the transport (magic/version/ID, features, queues, DRIVER_OK) —
  host-sim stubs guard MMIO touches.
- `userspace/vault/v2_main.c` + `userspace/cryptblk/v2_main.c` own DRBG
  state (`CRYPT_DRBG_DEFINE`, single-owner rule in `kdf.h`); both note
  test-grade DRBG + fixed `CRYPTFMT1` seed + `TEST_KEYS` KEK derivation
  as smoke-only honesty notes.
- `userspace/sh/shell.c:43,580` mints from tiny demo pool (production:
  Untyped retype via invoke); `userspace/vfs_server/server.c:668`
  registers placeholder "sh" on demo pool frame.
- `kernel/kboot.c` maps LFB+ECAM leaves to tid10, transport leaves to
  tid6/9, S-leaf covers virtio-mmio range. NTHREADS == V2_CAP_THREADS
  == 11 (at cap), V2_NEP == max_eps == 11, V2_QUBES_MAX == 9,
  V2_FRAMES_MAX == 40. No free tid: a new rng server would force a
  full bump set — avoided by vault ownership.
- Entropy on hand: `rdtime` (kernel + vault/cryptblk `u_rdtime`),
  IRQ arrival timing, DICE `expected_hash` boot seed, `sha256` + `pbkdf2`
  in tree.

## 3. Architecture — vault-owned, microkernel-faithful

```
Layer                  Owner            Hardware touch   IPC
L0 address mechanics   kernel           maps rng leaf    none (existing gates)
                                          ONLY to tid8
L1 entropy server      vault tid8/q6    binds virtio-   serves RANDOM on EP8,
                       (existing)       rng, owns MMIO   replies R_OK/R_DENY
L2 key consumer        cryptblk tid9    NONE — seed only via vault
                       shell/VFS        NONE — frames via Untyped Invoke
L3+ (later)            future ELFs      via vault RPCs   new RPCs, own bumps
```

Microkernel invariants (binding — this stage must not break them):
- Exactly one hardware path: rng transport U-leaf maps ONLY into tid8
  tables (boot-asserted `RNGMMIO: tid=8 only`, same shape as
  `NETMMIO`/`BLKMMIO`/`GUIMMIO`); kernel holds no RNG code (no mixer,
  no DRBG — mechanics only); no ambient caps (vault reach from
  boot-minted mappings, reviewable at wiring site).
- All cross-layer traffic is addressed IPC with kernel-stamped senders:
  cryptblk→vault `RANDOM_REQ` on EP8 (raw-gated qube7→qube6 via existing
  QX grants, holder-based + server-side `sqb` allowlist), vault→cryptblk
  `RANDOM_RESP` reply to stamped `snd` on EP9 (call/response discipline).
- Least privilege: shell/VFS name frames only through `Untyped`/`PT_ALLOC`
  invoke; vault cannot touch other qubes' memory; cryptblk cannot touch
  MMIO.

No bump set (vault thread/EP/qube/frames unchanged). WCET note unchanged.

## 4. Components

### 4.1 virtio-rng bind (vault client of existing transport)

ECAM-equivalent is virtio-mmio fixed transports (probed with magic
check, never assumed present): scan transports first (QEMU attaches
backends last-first; net/blk precedent scans all, takes first ID-4
match), match device-ID 4 for rng, negotiate features (none required),
single request queue (one descriptor per 32B read, bounded). Fail-closed:
no match / bad magic / version mismatch ⇒ park marker-free.
Bound comments on every loop. Reusable pattern stated, not built.

### 4.2 Mixer + DRBG re-seed (`userspace/vault/v2_main.c`)

Freestanding, existing qube: transport scan → bind → `RNG: up` → RECV loop
on own EP8 serving two RPCs (existing + new):

```
RANDOM_REQ [id]  cryptblk -> vault (id = request nonce, immediates only)
  vault: read 32 HW bytes -> mix sha256(HW || rdtime || irq_delta || dice_seed)
         -> drbg_reseed(mixed) -> reply RANDOM_RESP[seed_chunk] with R_OK;
         else reply R_DENY, no state change.
  anything else -> R_DENY (INVALID), no state change.
```

Mixer KATs live in `tests/test_rng.c` (fixed vectors). 8K stack (qrexec
precedent). No prints in mix path except markers (grep-gate discipline).
Tag allocation reuses free tag space — reviewer checks against T_KEY 8 /
T_KEY_ACK 10 / FILL 6.

### 4.3 Key consumer: cryptblk drops TEST_KEYS (no new thread)

`userspace/cryptblk/v2_main.c`: delete `TEST_KEYS` vector + fixed
`CRYPTFMT1` seed path; at boot SEND `RANDOM_REQ` (expect 32B) + RECV EP9
(expect `[R_OK]`), derive KEK via existing `pbkdf2_hmac_sha256` with
vault seed + per-volume salt, marker-free park on any deviation — the
live-stage call/response discipline verbatim. Format uses fresh seed
(deterministic-image note retired; smoke formats once then reuses).
QX grants unchanged (holder-based, server allowlists `sqb`).

### 4.4 Allocator: shell/VFS drop demo pools (no new syscalls)

`userspace/sh/shell.c`: `write` mints via `V2_INV_PT_ALLOC` + `MAP`
(Untyped retype path already in `caps.h`) instead of demo pool; exhausted
pool message retired, `R_DENY` on invoke failure with same UX shape.
`userspace/vfs_server/server.c`: placeholder "sh" becomes real root entry
backed by invoked frame (same clamp/validate-then-write discipline).
No kernel change beyond existing invoke ops.

### 4.5 Boot wiring (mirrors S4a Task-3 shape)

`kernel/kboot.c`: rng U-leaf to tid8 + `RNGMMIO: tid=8 only` leaf assert
(same shape as `GUIMMIO`). `tools/mkinitrd.sh` unchanged (no new ELF).
`tools/run_qemu.sh` + `verify.sh`: single cmdline gains
`-device virtio-rng-device`.

## 5. Data flow (boot)

1. Kernel maps rng leaf to tid8; asserts print `RNGMMIO: tid=8 only`.
2. Vault runs: scan → bind → mix → `RNG: up` → RECV-waits EP8.
3. Cryptblk (post-unlock-leg position, unchanged order): `RANDOM_REQ` →
   vault re-seeds → `RANDOM_RESP` → cryptblk derives KEK → existing
   `CRYPT:*` markers → parks/waits as before.
4. Shell/VFS use invoked frames from first `write`/mount — no boot marker
   change.
5. Everything else identical (serial primary; all prior markers).

## 6. Error handling (fail closed)

| Case | Behavior |
|---|---|
| No virtio-rng / bad magic / version mismatch | Vault parks, no markers → gate FAILs |
| Short HW read / zero bytes | Mixer rejects, park marker-free → FAIL |
| Wrong resolution of transport (last-first attach) | Scan-all-takes-first-ID-4; none → park |
| DRBG re-seed fails | Park (mapping was wrong — leaf assert catches it first) |
| RANDOM_REQ from non-cryptblk sender | `R_DENY`, zero state change (sqb allowlist) |
| Unknown tag on EP8 | `R_DENY` (INVALID), no state change |
| Vault not yet waiting when cryptblk calls | Rendezvous queues + cryptblk blocks (single-flight; no race) |
| Untyped alloc fails (shell/VFS) | `R_DENY` with same UX shape, zero bytes written |

## 7. Testing

- Host unit (`tests/test_rng.c`, `verify.sh [1f]`): mixer vectors
  (fixed HW/jitter/DICE → expected sha256), zero-len reject, short-read
  reject, transport-offset math, device-ID match, BAR/magic edges — pure
  helpers + malloc'd shadow buffer.
- QEMU smoke (`[4/4]`, +2 lines): `RNG: up`, `RNGMMIO: tid=8 only`.
  Missing ⇒ FAIL. All prior markers unchanged.
- Production gates unchanged. No TEST_KEYS anywhere after this stage;
  honest remainder notes retired (DRBG test-grade note stays until
  audit, explicitly).
- Isabelle: no `V2_C` replay (no bump) + `rng_mmio_covers`-style lemma;
  mutants; 0 sorry; KAT-correspondence for mixer via host test.

## 8. Non-goals (binding minimal hardening)

New rng server thread, new qube/EP/cap bump, scheduler/exec changes,
per-qube key hierarchy, key rotation, sealed storage, remote attestation,
multi-transport_rng scan, virtio-rng feature negotiation beyond MUST,
console migration, fallback entropy devices.

## 9. Exit criteria

- [ ] virtio-rng bind + vault mixer + RANDOM service + QX allowlist,
      all fail-closed; `RNG: up`, `RNGMMIO: tid=8 only` green; TEST_KEYS
      and fixed seeds gone; shell/VFS use invoked frames.
- [ ] No bump set (11/11/9/40 unchanged) with asserts + proof replay green.
- [ ] Host mixer/scan tests green; `verify.sh` full-pass (new tests in
      `[1f]`, markers in `[4/4]`, single cmdline, no SKIP).
- [ ] Docs: `V2_DESIGN.md` §9 hardening BUILT + refinements; threat model
      notes TEST_KEYS removal; honest remainder updated (DRBG audit
      deferred explicitly).
