# FDE Re-integration Design (vault/cryptblk + approval flows back to boot)

**Date:** 2026-10-04
**Status:** spec (approved section-by-section in chat 2026-10-04; awaits file review)
**Scope:** Approach A — relocate qrexec/adminvm to tids 5/6, TEST-closed key
provisioning, UNWRAP→T_KEY live in smoke, slot format v2 (`kdf_type`),
entropy audit line, raised QEMU budget. REWRAP with AdminVM-originated keys
stays dormant (physically impossible headless — no GETC, no RNG).
**Non-goals:** firewall/net re-integration, AdminVM key origination, FIPS.

---

## 0. Background and prior decisions

- `userspace/crypt/kdf_production.h` (real Argon2id, production DRBG/PBKDF2-600K,
  `entropy_audit_encode`) exists, and vault/cryptblk were migrated to it —
  but both ELFs are dead code: absent from `userspace/Makefile all:`,
  `tools/mkinitrd.sh`, `kernel/kboot.c` spawn, and smoke markers (qube-demo
  retirement, currently uncommitted worktree state).
- Kernel side is re-integration-ready: U-stacks (`kernel/user.c:596-614`,
  incl. `_Static_assert` minima), MMIO leaves for rng (tid 8) and blk
  (tid 9), BLK IRQ→tid9, and the `user_a` demo driver (still present,
  `kernel/user.c:178-204`, currently parked waiting `ADMIN_LIVE_BIT 2`).
- AdminVM auto-approves (`ADMIN: approve? [y/n] y`, no GETC in UABI), so the
  ASK→DECIDE→DELIVER path runs headless.
- Prior approvals: Phase-2 migration (chat), PBKDF2 demo factor 600K (chat),
  full approval flows (chat 2026-10-04), text `AUD:` hex audit line (chat),
  Approach A (chat).
- Refinement vs the §2 chat sketch: provisioning uses a **dedicated TEST
  rpc**, not the REWRAP arm — the rewrap arm gates on `vmk_valid
  (vault/v2_main.c:836)`, which no in-tree flow can set, so first-provision
  through rewrap deadlocks. Direction unchanged (cryptblk-as-provisioner,
  TEST policy row, full chain live).

## 1. Boot wiring

- **mkinitrd (`tools/mkinitrd.sh`):** index 5 → `qrexec.elf` (tid5),
  6 → `adminvm.elf` (tid6), 8 → `vault.elf` (tid8), 9 → `cryptblk.elf`
  (tid9). Indices 2, 7 stay `UNUSED`; 0/1/3/4/10 untouched. Firewall/net
  stay out (vault/cryptblk flows need only qrexec+adminvm — verified: no
  FW/NET tag overlap in either ELF).
- **kboot spawns (`kernel/kboot.c`):** new spawn blocks for tids 5, 6, 8, 9
  mirroring the deleted ones (load + PTE sync + `u_sp` + RUNNABLE +
  `[spawn] … ELF ok`), recovered from `git diff HEAD` with tid substitution.
  Free tids today are exactly 5, 6, 8, 9 (`NTHREADS 11`, rest parked).
- **Grants + labels:** restore the old QX-grant hunk for {5,6,8,9} only
  (slot-9 root-holder pattern, from the HEAD diff; no firewall/net grants).
  Rule the restored set must satisfy: cryptblk (qube7) can SEND EP0 (qube0)
  and GRANT vault slots; qrexec can SEND delivers to EPs 8/9; exact lines
  recovered from the HEAD diff at implementation, verified by the
  provision→UNWRAP rendezvous succeeding in smoke.
  `qube_of[5]=2, [6]=3, [8]=6, [9]=7`, `qube_next=8` (under `V2_QUBES_MAX 9`).
  cryptblk's EP0-readiness SEND ( §2) is covered by the restored crypt grant
  subset; verify at implementation.
- **EP relocation:** qrexec `EP3→5`, adminvm `EP4→6` in both ELF sources +
  `svc_of_qube` table + `user_a` driver `usend(3→5)`. Vault/crypt EP
  constants (8/9) unchanged. Console/tty and all live IPC untouched.
- **Makefile `all:`:** re-add `qrexec.elf adminvm.elf vault.elf cryptblk.elf`
  (boot components must not bit-rot again; supersedes the explicit-gate line).

## 2. Approval-chain runtime

- **Existing legs (fixed by EP move):** keys.sign ASK→PENDING (rpc1) and
  clipboard DENY (rpc2) driven by `user_a` as today.
- **Provision leg (new, TEST-only):** after boot-demo unlock, cryptblk
  PT_ALLOCs a frame, WRITEs KEK_live||VMK_live (8 words), GRANTs it to vault
  slot 20 (reuses the `CRYPT_KEY_SLOT 20` contract — phases provably do not
  overlap: provision completes before any T_KEY; mappings never linger past
  the READ), and SENDs readiness to EP0. `user_a` RECVs readiness, then
  T_CALLs the new TEST provision rpc (`VAULT_PROVISION 6` — rpc 6 is
  currently invalid in qrexec's `rpc_svc` table, so no renumbering; table
  gains `[6]=6/vault`) through qrexec (TEST policy-table row pinning
  src==7 — production rows keep pinning src==3/AdminVM; mechanism
  identical). Demo policy (compiled-in table + auto-approve approver) is
  dev-only by construction; production swaps the table and the approver, no
  protocol change.
  Vault's provision handler MAPs slot 20, READs 8 words, stores
  `keks[slot]` + `vmk`, sets `valid`/`vmk_valid` (+ label), wipes, UNMAPs,
  replies OK. This is the ONLY writer of vault key validity in-tree.
- **UNWRAP leg (new):** `user_a` T_CALLs rpc7 → ASK → auto-approve →
  DELIVER → vault unwraps slot-0 under KEK_live → `key_release` T_KEY grant
  → cryptblk `key_consume` canary-verifies vs the live disk → ack →
  `AUD: release slot=`. Full chain, live material, real approval path.
- **Dormant (documented):** REWRAP with AdminVM-originated keys (needs key
  origination that cannot exist headless); VOL_FORMAT-via-qrexec (cryptblk
  self-formats); firewall/net flows.
- **Vault RANDOM service** runs independently (direct tag-11, qube7-only).

## 3. Slot format v2 + kdf_type plumbing

- `layout_slot_t` gains `uint32_t kdf_type` (0=PBKDF2, 1=Argon2id):
  64→68B/slot, header USED 568→600B, `CRYPT_VERSION` 1→2. Parse accepts
  both: 568B v1 (kdf defaults 0) and 600B v2.
- kdf_type joins label+iters in the slot AEAD AD (nonce stays
  `salt||label`); unwrap selects the 12B (v1) vs 16B (v2) AD shape from the
  parsed version — cross-type transplant fails auth by construction.
- `crypt_kek` branches on the slot's kdf_type (PBKDF2 as today; Argon2id via
  `argon2id_kdf_with_mem` with frame scratch). Demo volume stays
  `kdf_type=0` until the 16K-frame/64MiB spike (§5) reports; Argon2id at
  production params is proven by host KATs regardless.
- Vault UNWRAP reads kdf_type (rejects unknown values; unwraps under the
  stored KEK — no derivation there). Vault granted-record image 64→68B
  (9 word-reads, 4B tail pad ignored).
- `test_crypt` gains: v2 round-trip, cross-type transplant-fails,
  unknown-kdf guard, v1-image-defaults-to-PBKDF2. `test_qube_policy.c` gains
  the TEST-row case.

## 4. Audit line, markers, QEMU budget

- Vault RANDOM arm, after successful reseed: `entropy_audit_encode` → 80B →
  `AUD: rng t=<16hex> n=<16hex> e=<8hex> src=<8hex> s=<64hex>` via a new
  `u_puthex` helper (AdminVM `u_puthex64` precedent). `key_consume` stays
  print-free.
- Gates to restore (from the HEAD-diff gate list): `QREXEC: up`,
  `QREXEC: admin registered`, `QREXEC: ask`, `AUD: allow rpc=`,
  `QREXEC: deny`, `VAULT: up`, `VAULT: live ok`, `CRYPT:
  up|locked|unlock ok|rw ok|wrong-key denied|leak denied|no volume`,
  `CRYPT: formatted|CRYPT: volume ok` union, `RNG: up`, `VAULTQ: labels
  ok`, `CRYPTQ: labels ok`. New gates: `CRYPT: provision ready`,
  `VAULT: provision ok`, `AUD: rng `, `AUD: release slot=`,
  `ADMIN: ask idx=`, `ADMIN: decided idx=`.
- `timeout 10` cannot survive 2×600K KDFs under emulation: measure
  fresh-boot format+unlock cost first, set budget = measured × 3 (floor
  120s). Pathological (>5 min) → stop and re-scope (e.g. gate on the
  second-boot single-KDF `volume ok` path). No silent inflating.
- Dependency (outside this spec): the stale `SHELL: thread 1 starting`
  marker fix lands first as a one-line prerequisite; this design assumes a
  green baseline.

## 5. Proofs, docs, test plan, rollout

- **Proofs:** `Qubes_D.thy` mechanical updates (`fslot` literals,
  `slot_release`, `demo_slots`, mutants; reprove release/fail-closed lemmas
  iff the field is predicate-visible). New markers proof-free. Anti-vacuity
  gate stays green. `V2_A.thy` out of scope.
- **Docs:** `CRYPTO_HARDENING.md` (Phase 2→done, Phase 3 wiring status, lift
  the dead-code note), `ARCHITECTURE.md`/`V2_DESIGN.md` tid/qube tables for
  the 5/6 reassignment. No new TODOs in touched code.
- **Rollout:** (0) stale-marker prerequisite → green baseline; (1) spikes —
  16K-frame feasibility + KDF timing (gate Argon2id-on-target and the budget
  number); (2) slot format + host tests + proofs; (3) boot wiring;
  (4) runtime legs + audit + markers; (5) full suite green. TDD + mutation
  checks throughout.
- **Success criteria:** suite fully green incl. new gates; every current
  live-service marker unchanged; proofs + docs green.
- **Open risks:** KDF-under-emulation cost (measured in (1)); adminvm
  HELLO/NOTIFY rendezvous with relocated EPs (covered by existing reply
  discipline — verify in (3)); `user_a` S4 legs now unpark past the qrexec
  legs (ordering dependency: UNWRAP legs must complete before S4 GUI legs
  wedge on… — verify; park-safe fallbacks already marker-free by
  construction).
