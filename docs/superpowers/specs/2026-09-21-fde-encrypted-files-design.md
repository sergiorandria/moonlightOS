# Moonlight FDE: full-disk encryption with per-qube keyslots ("everything is an encrypted file")

**Status:** Design drafted 2026-09-21, awaiting user review before implementation plan
**Depends on:** Qubes S1/S2 BUILT (labels, raw gate, qrexec + AdminVM, `Qubes_B`), S3 BUILT (virtio bring-up pattern: exact-bounds MMIO leaf, PLIC→`NOTIFY`, frame-window DMA)
**Decides:** Approach B (full-disk encryption, dm-crypt style) with LUKS-like per-qube keyslots; ChaCha20-Poly1305 per-sector AEAD with 4 KiB sectors; Linux-like hierarchy over a minimal filesystem; raw `/dev/blk` = ciphertext view
**Constraints (binding):** microkernel intact (kernel: label-stamping + cap enforcement + MMIO mapping only; all crypto/namespace/policy in userspace); Qubes isolation intact (vault holds keys, labels travel on every IPC, default-deny cross-qube, no ambient authority)

---

## 1. Goal

Every byte on the virtio-blk disk is ciphertext. Every file a qube sees through the filesystem is plaintext it is authorized for. The two views are enforced by different mechanisms that compose: cryptography (sector AEAD under a volume key) × authorization (per-qube keyslots released by label).

**Theorems to discharge (new `Qubes_D.thy`):**
- Slot-release-only-to-label: a keyslot unwrap succeeds only for the qube whose label matches the slot (kernel-stamped labels, never client bytes).
- Ciphertext-view label-independence: raw sector reads return identical bytes regardless of reader label (no plaintext oracle anywhere on the raw path).
- No-ambient-decrypt: no transition derives file plaintext without a released slot for the caller's label.

**Demos (QEMU text markers, fail-closed like current smoke):**
- `VAULT: up` + `VAULTQ: labels ok` (vault booted, label asserted), `CRYPTQ: labels ok` + `BLKMMIO: tid=9 only` (cryptblk booted, label + MMIO isolation asserted), `CRYPT: up` (cryptblk booted, header parsed), `CRYPT: locked` (no VMK — FS ops fail closed), `CRYPT: unlock ok` (passphrase → vault → slot → VMK in memory), `CRYPT: rw ok` (sector round-trip through the AEAD layer), `CRYPT: wrong-key denied` (tampered tag / wrong slot fails closed), `CRYPT: leak denied` (cross-qube raw/FS access without slot denied), `CRYPT: no volume` (RAM-shadow corrupt-header reject).

---

## 2. Background / what exists

- S1/S2: per-thread VSpaces + frame window, capability ops (`PT_ALLOC/MINT/GRANT/MAP/UNMAP/REVOKE/READ/WRITE`), kernel-stamped `(sender, sender_qube)` on RECV, raw cross-qube SEND denied without QX, qrexec policy (first-match-wins, default-deny, bounded ask queue, append-only audit), `T_DECIDE` arg-carrying ask/decide.
- S3: virtio-net-device bring-up pattern to copy for blk (exact-bounds MMIO U-leaf for one TID, PLIC claim/complete → `NOTIFY` badge on `scause=9`, frame-window DMA, SLIRP-free deterministic smoke). QEMU already attaches a 256M virtio-blk disk (`run_qemu.sh` `DISK_ARGS`); no V2 driver consumes it yet.
- v1 `userspace/vfs_server/server.c` (681 lines, frozen-ABI, TCB-keyed FD tables, frame-cap file data) is the namespace *shape* reference only — the FDE filesystem is new V2-UABI code, not a port (port debt + stacking audit surface rejected in Approach C).
- Crypto in-tree is effectively zero (`crypt.c` = DES password hashing). The ChaCha20-Poly1305 port is greenfield freestanding C.
- RISC-V `virt` facts (standard): virtio-blk sits on a virtio-MMIO transport like the NIC (scan-then-bind, S3 precedent — never hardcode transport 0); PLIC + `scause=9` path already exists from S3.

---

## 3. Architecture

```
U-mode qubes:
  vault      KEKs + VMK in memory only; unwraps slots, never touches disk frames
  cryptblk   ONLY qube with blk MMIO + IRQ; sector AEAD; minimal FS; /dev/blk + /mnt views
  AdminVM    passphrase prompt at boot (console y/n pattern already exists from S2)
  AppVMs     files via cryptfs-style open/read/write to cryptblk (QX-gated, label-checked)
Kernel (S-mode): unchanged roles — label stamps, cap enforcement, MMIO map, PLIC→notify.
qrexec: slot-release RPCs (ask/approve) + audit; same broker, new rows.
```

Disk layout (256M virtio-blk, 4 KiB sectors):
`[0] LUKS-like header (magic, KDF params, ≤8 keyslot records: wrapped-VMK + salt + KDF work factor)` →
`[1..N] ciphertext sectors` →
`[tag region] 16B Poly1305 tag per data sector (1 tag sector per 256 data sectors)`.

Filesystem (minimal, new): superblock (in sector 1, itself encrypted like any sector), inode table (flat, ≤1024 inodes: type/dir/file/device, size, extent list, owner-label), directory entries (`name → inode`, `/`, `/dev`, `/etc`, `/home/<qube>` pre-created at format). No journaling: crash consistency = fail-closed remount + offline check tool (host-side, `tools/fsck.crypt` future work — listed, not this stage). extents are contiguous runs (allocator: first-fit, ≤64 extents/file; fragmentation beyond that fails closed with `NOSPC` until defrag exists).

---

## 4. Components

### 4.1 `cryptblk` server (new V2 UABI ELF, own qube)

- Block backend: V2 virtio-blk driver cloned from the S3 net-driver pattern (probe MMIO magic, negotiate, one virtqueue pair, DMA frames from the frame window, completion via IRQ badge + `rdtime`/`YIELD` poll with park-on-timeout — never spin). Sector size presented to upper layers: 4096B (blk 512B × 8 glue in the driver, single place).
- Sector layer: `sec_read(n)` / `sec_write(n, buf)` — translate to tag-region load/store + `aead(sector_nonce=n)`; tag mismatch on read ⇒ `EIO`, buffer zeroed, never partial plaintext (fail closed, no oracle beyond the error code all callers already get).
- FS layer: `open/stat/read/write/close/mkdir` over EP with the v1-VFS-validated discipline (per-client FD tables keyed on kernel-stamped sender, rights re-validated per op, wrap-safe arithmetic) but V2 IPC + qube labels: a qube opens only inodes whose `owner-label` matches its stamped label, except `/dev` and `/etc` per the mount table (§4.4).
- Two views, one mechanism: `/dev/blk` device node returns raw sectors (ciphertext — the label-independence property); the `/` tree returns decrypted bytes after slot unlock. Same sector layer, different authorization at the FS edge.

### 4.2 Vault + key lifecycle (S2 AdminVM pattern extended)

- Format (once, AdminVM-attended): vault generates VMK (256b, kernel RNG? — no; `rdtime`-seeded ChaCha-DRBG documented as test-grade, hardware-RNG wiring is future work with a `RAND: test-grade` boot print — honest, never silent), wraps VMK into slot records under per-qube KEKs, writes header.
- Boot unlock: AdminVM console passphrase → PBKDF2-HMAC-SHA256 (600k iterations, salt from header) → vault master → vault unwraps **only slots whose label matches the requester** (qrexec `vault.unwrap` rows: `ask`, default-deny). Handoff transport is ADDRESSED endpoints (§4.5): the approved `T_DELIVER` arrives at vault on EP6, vault `SEND`s the keyless `T_KEY` notice addressed to cryptblk on EP7 — never broadcast, never oldest-waiter. VMK is `GRANT`ed never — it is COPIED into cryptblk memory via a sealed one-time handoff: vault `PT_ALLOC`s a frame, `WRITE`s the 4 VMK words, `GRANT`s R-only to cryptblk slot 20, `SEND`s keyless `T_KEY` notice; cryptblk maps slot 20, `READ`s, verifies by unwrapping a canary slot record, then acks `[T_KEY_ACK, slot, 0, 0]` (zero prints on the ack path); vault waits tick-bounded (`rdtime` deadline + `YIELD`, park + `REVOKE` + wipe on expiry — never wedges) and only then `REVOKE`s. Consumed once, never logged, never audited with key material — audit records the *release event*, never bytes.
- Revocation: slot wipe in the header (one sector rewrite + tag). Data re-encryption is out of scope: revoked qubes lose *future* access; already-exfiltrated plaintext is outside the model (documented, same as LUKS).
- KEK rotation: per-qube re-wrap without touching data sectors (header-only op, AdminVM-attended).

### 4.3 qrexec policy rows (new)

```
appvm    vault     vault.unwrap  ask      "release my slot?"
AdminVM  vault     vault.rewrap  ask      "re-wrap a slot?"
AdminVM  cryptblk  vol.format    ask      "format the volume?"
```

No `blk.raw` row exists deliberately: raw sector reads are label-independent ciphertext served to any QX-holding qube with no policy decision to make (nothing to allow/ask/deny — the bytes are identical for all readers). Reachability is governed by boot-minted QX grants, exactly like the firewall/net pattern.

### 4.4 Mount/visibility table (Linux-like hierarchy, qube-scoped)

```
/dev          all qubes, R/O device nodes (blk0 = ciphertext sectors, null, zero)
/etc          all qubes, R/O (world-readable config; secrets never live here)
/home/<qube>  owner qube RW, all others invisible (lookup fails closed as NOTFOUND, not DENIED — no existence oracle)
/              traversal only (no direct file storage at root)
```

`/dev/blk0` reads return ciphertext to every label including qube-0 root — the label-independence theorem's executable pin. Plaintext appears only under `/home/<own-label>` after that qube's slot unlock.

---

## 5. Data flow (first unlock + first file)

1. Boot: cryptblk parses header (`CRYPT: up`), prints `CRYPT: locked` (no VMK — all FS ops fail closed).
2. AdminVM passphrase → vault KDF → `vault.unwrap(qube=cryptblk-op)`… precisely: cryptblk requests its *operating* unwrap (slot 0, the volume slot, released to the cryptblk label only) via qrexec ask → AdminVM approves → `T_KEY` handoff → `CRYPT: unlock ok`.
3. AppVM (label 6, say) opens `/home/appvm/note`: cryptblk checks stamped label == inode owner == slot holder → serves decrypted bytes. Wrong-label open → NOTFOUND/DENIED without touching the disk (no oracle, no wasted I/O).
4. Write path: plaintext → AEAD seal → ciphertext sector + tag writes (data sector first, tag second, crash between = tag mismatch = detected, never silent).
5. Stolen disk: header + ciphertext + tags + salt. No KEKs, no VMK, no plaintext. KDF cost is the only gate (stated work factor, adjustable at format).

---

## 6. Error handling (all fail closed unless noted)

| Case | Behavior |
|---|---|
| Wrong passphrase | KDF yields wrong master → slot unwrap fails auth → `locked`, retry counter + exponential console backoff (no counter persistence — reboot resets; brute force is the KDF's problem, work factor stated) |
| Tag mismatch (torn write, yanked disk, tamper) | `EIO`, buffer zeroed, sector never delivered; counter `CRYPT: tagfail N` (rate-limited log, no per-byte oracle) |
| Cross-label open/stat | NOTFOUND (files) / DENY (vault ops); no disk I/O, no timing delta beyond the constant-time label compare |
| Slot revoked mid-session | In-flight FDs keep working (VMK already in memory — documented LUKS-equivalent semantics); new opens fail; reboot re-locks |
| Header corrupt/magic mismatch | `CRYPT: no volume`, cryptblk parks; format is AdminVM-attended only |
| Pool/ring exhaustion (DMA frames, FD tables) | `OVERFLOW`/`NOSPC`, old state kept, no partial writes (single-sector atomicity is the unit — multi-sector writes are best-effort-ordered, crash leaves tag-mismatch = detected) |
| Rollback (old snapshot restored) | NOT DETECTED — no monotonic counter without TPM (documented non-goal, §8) |

---

## 7. Testing

- Host unit (`tests/test_aead.c`, `verify.sh [1f]`): RFC 8439 ChaCha20-Poly1305 vectors (encrypt + decrypt + tamper-fail), PBKDF2-HMAC-SHA256 test vector, sector round-trip through the layout math (tag-region indexing, 4K glue), slot wrap/unwrap/revoke model, header parse rejects (bad magic, overcount slots, truncated).
- QEMU smoke (fail-closed markers in `[4/4]`): `VAULT: up`, `VAULTQ: labels ok`, `CRYPTQ: labels ok`, `CRYPT: up`, `CRYPT: locked`, `CRYPT: unlock ok`, `CRYPT: rw ok`, `CRYPT: wrong-key denied`, `CRYPT: leak denied`, `CRYPT: no volume` (RAM-shadow corrupt-header leg — no second boot, no live-disk mutation), `BLKMMIO: tid=9 only`. Missing marker ==> FAIL. Passphrase in smoke: fixed test vector behind a `TEST_KEYS` build flag (never the release path; release passphrase entry is manual-only, documented).
- Production gates unchanged + one more: no key material in any log (grep gate over QEMU transcript for hex-dump patterns of the test VMK? — implementer's choice, documented; at minimum the `T_KEY` path has no printfs, asserted by code review + grep for `kputs` in the handoff function).
- Isabelle (`Qubes_D.thy`): slot-release-only-to-label, ciphertext-view label-independence, no-ambient-decrypt; refinement of slot/FS ops against the C model; mutants per invariant; 0 sorry; cipher strength explicitly assumed (documented assumption lemma `aead_correct` as axiom? NO — axioms capped at 3 per anti-vacuity rules and must be named/dated/stage-linked: one named axiom `AEAD_CORRECT` (correctness only, not security) linked to this stage, or executable model + KAT correspondence — implementer's choice with reviewer sign-off).

---

## 8. Non-goals (this spec)

Journaling/crash recovery beyond fail-closed remount, multi-disk/LVM/RAID, live re-keying with re-encryption, rollback/replay protection (no counter), network block / shared-disk clustering, hardware RNG (test-grade DRBG disclosed), memory-hard KDF (PBKDF2 now, Argon2 later with a `KDF:` version field reserved in the header), file sharing across qubes (deny by default; re-wrap design is the named follow-up), filename encryption (names visible in directory sectors — documented; full name-privacy is follow-up work).

---

## 9. Exit criteria

- [ ] ChaCha20-Poly1305 + PBKDF2 host-tested (KATs green), freestanding-clean, no libc/host headers in the port.
- [ ] V2 virtio-blk driver (probe/negotiate/queues/IRQ, deterministic smoke, no-spin discipline like S3 net).
- [ ] `cryptblk` + vault slot lifecycle + qrexec rows, boot unlock demo green (`CRYPT:` markers).
- [ ] Raw-ciphertext view + label-scoped FS views demonstrated (`leak denied`, wrong-key denied).
- [ ] `Qubes_D.thy` builds clean, anti-vacuity gate passes (≤1 named axiom, else KAT-correspondence).
- [ ] `tools/verify.sh` full-pass discipline kept (new tests in `[1f]`, new markers in `[4/4]`, single QEMU cmdline, no new SKIP).
- [ ] Docs: `V2_DESIGN.md` §9 / `QUBES_ISOLATION_PLAN.md` storage rows flipped `[TODO]`→`[HAVE]` with paths + refinements; threat model states KDF-only gate, no-rollback, test-grade RNG, unencrypted filenames.
