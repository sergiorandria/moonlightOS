# FDE Encrypted-Files Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build full-disk encryption with per-qube keyslots: ported AEAD + KDF, a V2 virtio-blk driver, the `cryptblk` + `vault` servers, boot unlock, proofs, and docs.

**Architecture:** Phase 1 (Tasks 1–2) is pure host-testable headers (crypto, layout, slots) with zero kernel contact. Phase 2 (Tasks 3–4) adds the two ELFs, capability-bound bumps, boot spawns, and the sector/FS/driver stack. Phase 3 (Tasks 5–6) proves and documents.

**Tech Stack:** C (freestanding rv64imac stock clang, `-Werror`; host gcc for unit tests), RISC-V S-mode traps/pagetables (existing handler + tables only), Isabelle/HOL (session V2), bash (verify.sh/mkinitrd.sh/run_qemu.sh).

**Spec:** `docs/superpowers/specs/2026-09-21-fde-encrypted-files-design.md`

## Global Constraints

- Freestanding only: `-ffreestanding -nostdlib -fno-builtin -mcmodel=medany -mno-relax -Wall -Wextra -Werror`, includes from clang resource dir + in-tree headers only.
- C subset: no `float`, no function-pointer dispatch (switch on op/tag), no recursion, every loop carries a `/* bound: N */` comment tied to a named constant.
- Constant-time discipline for crypto code: no secret-dependent branches, no secret-dependent table indices, no early exits on secrets (reviewer checks; document each unavoidable deviation inline).
- Copy discipline: every kernel↔user pointer via `copy_from_user`/`copy_to_user` validate-then-copy; raw user-pointer dereference is a defect.
- Fail closed: validation failure returns `V2_ERR_INVALID`/`V2_ERR_OVERFLOW` (kernel) or `INVALID`/`EIO`/`DENY` (servers) with no partial state; reserved Invoke args must be zero; missing QEMU markers flip the smoke gate to FAIL.
- W^X preserved; QX never reaches PTE flags.
- Bounds are `_Static_assert`ed; after this plan `NTHREADS == V2_CAP_THREADS == 10`, `V2_QUBES_MAX == 8` (qube_next ends at 8 — any further qube forces a `V2_QUBES_MAX` bump + proof replay).
- `tools/verify.sh` is the single entry: new host tests in `[1f]`, new markers in `[4/4]`, single QEMU cmdline, no new SKIP branches.
- Proofs: zero `sorry`/`axiomatization` (≤1 named axiom only with reviewer sign-off), no `True`-definitions, mutant witness per invariant, Allow+Deny outcomes pinned.
- Test vectors are NEVER reproduced from memory: RFC vectors below must be copied verbatim from the RFC text (fetch it); if unreachable, the task reports DONE_WITH_CONCERNS with vectors marked UNVERIFIED and the property tests carry the gate.

---

## File Map

| File | Responsibility |
|---|---|
| Create `userspace/crypt/sha256.h` | SHA-256 (portable, freestanding-safe). Pure C, host-testable. |
| Create `userspace/crypt/aead.h` | ChaCha20-Poly1305 AEAD (seal/open, uint8-only API). Pure C, host-testable. |
| Create `userspace/crypt/kdf.h` | PBKDF2-HMAC-SHA256 + ChaCha-DRBG (test-grade, disclosed). Pure C, host-testable. |
| Create `tests/test_aead.c` | RFC + property + tamper tests for the three headers. |
| Create `userspace/cryptblk/layout.h` | On-disk structs, header parse/validate, tag-region math, 4K glue. Pure C, host-testable. |
| Create `userspace/cryptblk/slot.h` | Slot wrap/unwrap/revoke over `aead.h`. Pure C, host-testable. |
| Create `tests/test_crypt.c` | Layout + slot tests. |
| Create `userspace/vault/v2_main.c` + `vault_start.S` | Vault ELF (`vault_main`): KEK store, unwrap/release, one-time `T_KEY`. |
| Modify `userspace/qrexec_server/v2_main.c` | 3 policy rows (`VAULT_UNWRAP 7`, `VAULT_REWRAP 8`, `VOL_FORMAT 9`), `T_DECIDE` unchanged. |
| Modify `kernel/caps.h` | `V2_CAP_THREADS` 8→10 (+ matrix growth comment). |
| Modify `kernel/qube.h` | Bounds comments only (no API change; `V2_QUBES_MAX` stays 8). |
| Modify `kernel/kboot.c` + `kernel/user.c` | `NTHREADS` 8→10, 2 stacks, spawns tids 8/9, labels 6/7, QX grants, `T_KEY` handoff, demo. |
| Modify `userspace/Makefile`, `tools/mkinitrd.sh` | `vault.elf` + `cryptblk.elf` rules; append after `cat.elf` (indexes 8, 9; existing indexes unshifted). |
| Create `userspace/cryptblk/v2_main.c` + `cryptblk_start.S` | Cryptblk ELF: blk driver, sector layer, FS, both views. |
| Modify `tools/run_qemu.sh`, `tools/verify.sh` | Unchanged cmdline (blk disk already attached); new `[4/4]` markers. |
| Create `kernel/isabelle/Qubes_D.thy` (+ `ROOT` line; update `Qubes_A/B/C` bounds IF the bump breaks them) | Slot-release, label-independence, no-ambient-decrypt + bound-ripple fixes. |
| Modify `docs/V2_DESIGN.md`, `docs/QUBES_ISOLATION_PLAN.md`, `docs/ARCHITECTURE.md`, `docs/BUILD.md` | FDE BUILT entries with artifact links + honest limits. |

**Scope note:** one plan, phased. Tasks 1–2 (host-only crypto + layout) ship independently of any boot work. Tasks 3–4 need each other only through the boot (vault handoff → cryptblk unlock); Task 3 ends with `CRYPT: locked` green, Task 4 with the full demo green.

---

### Task 1: Crypto port + KAT/property tests (host-only, no boot)

**Files:**
- Create: `userspace/crypt/sha256.h`, `userspace/crypt/aead.h`, `userspace/crypt/kdf.h`
- Create: `tests/test_aead.c`
- Modify: `tools/verify.sh` (`[1f]`, after the `test_netfw` line)
- Test: `tests/test_aead.c`

**Interfaces:**
- Consumes: nothing (greenfield; RFC 8439 + RFC 6070 as external oracles, fetched not memorized).
- Produces: `sha256(const uint8_t*,len,uint8_t[32])`, `aead_seal(key32,nonce12,ad/adlen,pt/ptlen,out_ct, out_tag16)`, `aead_open(...)` (0 ok / -1 auth-fail, ct buffer zeroed on fail), `pbkdf2_hmac_sha256(pw,pwlen,salt,saltlen,iter,dk,dklen)`, `drbg_next(out,len)` used by Task 2 (slot wrap) and Task 4 (VMK generation, TEST_KEYS vectors).

- [ ] **Step 1: Write `tests/test_aead.c` (fails: headers don't exist)**

```c
/* tests/test_aead.c - KAT + property + tamper tests for crypt/*.h. */
#include <stdio.h>
#include <string.h>
#include "../userspace/crypt/sha256.h"
#include "../userspace/crypt/aead.h"
#include "../userspace/crypt/kdf.h"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

static int hextob(const char *h, uint8_t *b, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) { /* bound: test vector len */
        unsigned hi, lo;
        if (sscanf(h + 2*i, "%2x", &hi) != 1) return -1;
        lo = hi & 0xF; hi >>= 4; /* keep -Werror -Wconversion-clean shapes simple */
        b[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

int main(void) {
    /* Filled verbatim from RFC 8439 section 2.8.2 + RFC 6070 by the implementer.
     * NEVER from memory. If the RFC text is unreachable, leave the byte
     * strings empty, mark KATs UNVERIFIED in the report, and rely on the
     * property/tamper sections below (which catch implementation bugs alone). */
    static const char *KAT_KEY = "<64 hex chars from RFC 8439 2.8.2>";
    static const char *KAT_NONCE = "<24 hex chars>";
    static const char *KAT_AAD = "<40 hex chars of 50515253...>";
    static const char *KAT_PT = "<ascii>";
    static const char *KAT_CT = "<ciphertext hex>";
    static const char *KAT_TAG = "<32 hex chars>";
    /* ... KAT check: seal -> memcmp ct+tag; open -> memcmp pt; (code omitted here,
     * written by implementer following the CHECK pattern above) ... */

    /* Property: round-trip over adversarial lengths incl. padding edges. */
    {
        static const unsigned lens[] = {0,1,15,16,17,31,32,33,55,56,63,64,65,119,120,135,136,200,256};
        uint8_t key[32], nonce[12], pt[256], ct[256], back[256], tag[16], ad[16];
        for (unsigned li = 0; li < sizeof(lens)/sizeof(lens[0]); li++) { /* bound: 19 */
            unsigned long n = lens[li];
            for (unsigned long i = 0; i < n; i++) pt[i] = (uint8_t)(i * 31 + 7);
            CHECK(aead_seal(key, nonce, ad, sizeof(ad), pt, n, ct, tag) == 0);
            if (n > 0) CHECK(memcmp(ct, pt, n) != 0); /* actually encrypted */
            CHECK(aead_open(key, nonce, ad, sizeof(ad), ct, n, tag, back) == 0);
            CHECK(memcmp(back, pt, n) == 0);
        }
    }
    /* Property: nonce separation (same pt, different nonce ==> different ct). */
    /* Tamper: flip every byte of one tag + one ct byte ==> open fails AND out zeroed. */
    /* PBKDF2: RFC 6070 vectors (fetch verbatim) + dklen edge (1, 32, 64) + iter>=1 guard. */
    /* SHA-256: "abc" vector ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
     * (this one MAY be hardcoded: it is the universal empty-avg sanity vector; still
     * prefer the fetched copy and cross-check both agree). */
    printf("PASS: test_aead\n");
    return 0;
}
```

(The implementer expands the marked sections following the same CHECK idiom — KAT hex, nonce-separation loop, tamper loop over all 16 tag bytes + first ct byte asserting `-1` return and zeroed output, PBKDF2 vectors + edges.)

- [ ] **Step 2: Run it, watch it fail (headers missing)**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_aead tests/test_aead.c 2>&1 | head -n 5`
Expected: FAIL — `crypt/sha256.h: No such file` (path is `../userspace/...` from `tests/`).

- [ ] **Step 3: Write the three headers** — portable C99, `stdint.h`/`stddef.h` only, `static inline` + `static const` tables, no `malloc`, no host calls, constant-time discipline (no secret branches/indices/early-outs; Poly1305 reduction branch-free; ChaCha quarter-round straight-line; compare with accumulated-diff idiom `diff |= a[i]^b[i]` + single return). Sizes: SHA-256 ~120 lines, AEAD ~260 lines, KDF ~90 lines. If any file grows past ~400 lines, split (chacha.h / poly1305.h) and report DONE_WITH_CONCERNS.

- [ ] **Step 4: Run green**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_aead tests/test_aead.c && /tmp/test_aead`
Expected: `PASS: test_aead` (KAT section green only if vectors were fetched verbatim; otherwise UNVERIFIED + property/tamper green — either is shippable per Global Constraints, report says which).
Run: `clang --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 -O2 -ffreestanding -nostdlib -fno-builtin -I$(clang --print-resource-dir)/include -fsyntax-only userspace/crypt/aead.h userspace/crypt/sha256.h userspace/crypt/kdf.h 2>&1`
Expected: clean (freestanding-safe for the later ELFs).

- [ ] **Step 5: Wire into `tools/verify.sh [1f]`** — after the `test_netfw` line insert:

```bash
gcc -Wall -Wextra -Werror -o /tmp/test_aead tests/test_aead.c 2>&1 && /tmp/test_aead || echo "FAIL: test_aead"
```

- [ ] **Step 6: Commit**

```bash
git add userspace/crypt tests/test_aead.c tools/verify.sh
git commit -m "fde: chacha20-poly1305 + sha256 + pbkdf2 port + KAT tests"
```

### Task 2: Layout + slot model (host-only, no boot)

**Files:**
- Create: `userspace/cryptblk/layout.h`, `userspace/cryptblk/slot.h`
- Create: `tests/test_crypt.c`
- Modify: `tools/verify.sh` (`[1f]`, after the `test_aead` line)
- Test: `tests/test_crypt.c`

**Interfaces:**
- Consumes: Task 1 (`aead_seal/open`, `pbkdf2_hmac_sha256`, `sha256`).
- Produces: `LAYOUT_*` constants, `vol_header_t` + `layout_parse`, `layout_tag_loc` math, `slot_wrap/unwrap/wipe`, `MAX_SLOTS 8`, consumed by Tasks 3–4 (vault + cryptblk ELFs) and Task 5 (model mirror).

Constants (exact, all three artifacts use these — reviewer cross-checks): `CRYPT_MAGIC 0x43525950544D4F4EUL` ("CRYPTMON" LE), `CRYPT_VERSION 1`, `SECTOR 4096`, `TAG 16`, `TAGS_PER_SECTOR 256`, `MAX_SLOTS 8`, `SLOT_WRAPPED 48` (32B wrapped-VMK + 16B Poly1305 tag), `HEADER_SECTORS 2` (magic+version+KDF params+PBKDF2 salt32+8×(48B wrapped+8B slot-salt+4B iters+4B label)= header fits 2×4K), `KDF_ITERS_DEFAULT 600000`, `MAX_INODES 1024`, `MAX_EXTENTS 64`, `VFS_NAME_MAX 27` (dirent: 27+1+4B inode = 32B, 128 dents/dir sector).

- [ ] **Step 1: Write `tests/test_crypt.c` first** covering: header parse accepts a well-formed header (built field-by-field in-test) and rejects bad magic / version!=1 / slot-count>8 / truncated buffer; `layout_tag_loc` spot values (data sector 0 → tag sector 0 slot 0; 255 → sector 0 slot 255; 256 → tag sector 1 slot 0; last sector of 256M disk: `(268435456/4096 - 1)` → tag sector 255 slot 255); 512B×8 glue offsets (sub-sector `k` → byte `k*512`); slot wrap→unwrap round-trip (KEK→VMK→KEK), unwrap with wrong KEK fails, unwrap with tampered wrapped bytes fails, wipe zeroes the slot record (memcmp 0) and unwrap-after-wipe fails; extent first-fit (alloc 3 runs, free middle, realloc fits) + over-64-extents fail; dirent name-length 27 ok / 28 rejected.
- [ ] **Step 2: Run, watch fail (headers missing).**
- [ ] **Step 3: Write `layout.h` + `slot.h`** — pure C, `stdint.h`/`string.h`(memcpy/memset only — freestanding-safe, same as existing ELFs which use them? Existing mem_server uses no libc; `string.h` freestanding provides memcpy/memset via compiler builtins with `-fno-builtin`? The S3 ELFs compiled with `-fno-builtin` and use loops instead — follow that: NO string.h, hand loops with bounds). All loops `/* bound: */`, all parse paths length-checked before dereference, LE encode/decode helpers explicit.
- [ ] **Step 4: Run green** (`gcc -Wall -Wextra -Werror ... && /tmp/test_crypt` → `PASS: test_crypt`) + freestanding syntax check (same clang line shape as Task 1 Step 4, both headers).
- [ ] **Step 5: verify.sh insert** (after `test_aead` line):

```bash
gcc -Wall -Wextra -Werror -o /tmp/test_crypt tests/test_crypt.c 2>&1 && /tmp/test_crypt || echo "FAIL: test_crypt"
```

- [ ] **Step 6: Commit**

```bash
git add userspace/cryptblk tests/test_crypt.c tools/verify.sh
git commit -m "fde: on-disk layout + slot model + host tests"
```

### Task 3: Vault ELF + bounds + boot spawns (ends `CRYPT: locked` green)

**Files:**
- Create: `userspace/vault/v2_main.c`, `userspace/vault/vault_start.S`
- Modify: `userspace/qrexec_server/v2_main.c` (3 rows: `{0,Q,VAULT_UNWRAP 7,ASK}`, `{3,Q,VAULT_REWRAP 8,ASK}`, `{3,Q,VOL_FORMAT 9,ASK}`; `nrules` 4→7; `AUD: boot nrules=7`)
- Modify: `kernel/caps.h` (`V2_CAP_THREADS` 8→10), `kernel/kboot.c` (`NTHREADS` 8→10, 2 stacks wiring, Task 3 spawns vault tid8 + label 6 + next=7, Task 4 spawns cryptblk tid9 + label 7 + next=8==MAX, QX grants, `VAULT: up`/`CRYPT: locked` path), `kernel/user.c` (`ustack_vault[4096]`, `ustack_crypt[8192]` — cryptblk holds FS + DMA-adjacent staging on-stack, qrexec 8K precedent — + tops + init)
- Modify: `userspace/Makefile` (vault.elf + cryptblk-stub rules? No — cryptblk ELF comes in Task 4; this task adds ONLY the vault rule + `all:`), `tools/mkinitrd.sh` (append `"vault.elf"` after `"cat.elf"` → index 8; cryptblk appended in Task 4 → index 9)
- Modify: `tools/verify.sh` (`[4/4]`, 2 markers)
- Test: `make -C userspace`, `tools/mkinitrd.sh`, `make -C kernel`, QEMU smoke

**Interfaces:**
- Consumes: Task 2 (`slot.h` wrap/unwrap/wipe; `layout.h` parse).
- Produces: vault TID 8 / qube 6, cryptblk TID 9 / qube 7 (consumed by Task 4); `T_KEY 8` one-time handoff shape; `VAULT: up` / `CRYPT: locked` markers.

New constants: `VAULT_UNWRAP 7`, `VAULT_REWRAP 8`, `VOL_FORMAT 9`, `T_KEY 8`, `VAULT_QUBE 6`, `CRYPT_QUBE 7`, `VAULT_TID 8`, `CRYPT_TID 9`.

- [ ] **Step 1: Vault ELF** — `userspace/vault/v2_main.c` (`void vault_main(void)`): stack-local KEK table (8 slots: label+key, zeroed at boot) + VMK slot (empty until format/unlock); print `VAULT: up`; loop: `T_CALL vault.unwrap (slot, 0, 0)` with kernel-stamped sender_qube: allow iff a qrexec `T_DELIVER[rpc==VAULT_UNWRAP]` arrived from sender_qube==2 naming that slot — direct `T_CALL` gets INVALID (same DENY-direct discipline as the S3 firewall; comment cites it); on approved deliver: `slot_unwrap` into a one-shot buffer, `SEND [T_KEY, 0,0,0]`?? Keys don't fit 4 words — `T_KEY` carries the VMK how? 256b = 4 words exactly: `SEND [T_KEY, w0, w1, w2]` + ... 4-word messages: `[T_KEY, k0, k1, k2]` misses 64 bits. Two-message handoff (`T_KEY0`, `T_KEY1`) doubles rendezvous races. DECISION (pinned here, reviewer checks): VMK moves by GRANT, not SEND — vault `PT_ALLOC`s a frame, `WRITE`s 4 words via 4× `V2_INV_WRITE`, `GRANT`s R-only cap to cryptblk tid, then `SEND [T_KEY, slot, 0, 0]` (no key bytes on the wire at all); cryptblk `READ`s 4 words + `kputs`-free path (no prints in handoff — grep-gate in Task 6), then vault `REVOKE`s the frame. Audit records release events only. `vault.rewrap` (sender_qube==3): re-wrap named slot under new KEK (KEK arrives identically via granted frame, never SEND words). `vol.format` is Task 4 (cryptblk writes the header; vault only supplies the fresh VMK through the same handoff).
- [ ] **Step 2: qrexec rows + bound bumps** — 3 rows as above (`nrules` 4→7 — wait, S3 ended at nrules=4? S3 boot table: keys.sign, clipboard, net.send, filter.reload = 4. Plus 3 = 7. `AUD: boot nrules=7`). `V2_CAP_THREADS` 8→10 (caps.h + growth comment), `NTHREADS` 8→10 (kboot.c + comment; `_Static_assert` holds 10<=10).
- [ ] **Step 3: Build + pack** — vault rule in `userspace/Makefile` (clone qrexec rule), `all:` extended, mkinitrd append (index 8).
  Run: `make -C userspace && tools/mkinitrd.sh`
  Expected: `build/vault.elf` listed; order mem 0 … cat 7, vault 8.
- [ ] **Step 4: Kernel boot (vault only; cryptblk spawns in Task 4)** — spawn initrd 8→tid 8 (`[spawn] vault ELF ok`, FAIL→parked); assign `qube_of[8]=6; qube_next=7;` + assert print `VAULTQ: labels ok` (fail closed: mismatch prints `[demo] FAIL` instead); mint exactly one QX grant (qrexec→vault — the `T_DELIVER` path needs it; vault takes no direct calls, and AdminVM rewrap/format calls also route via qrexec ask) via `v2_grant` on the boot tables, mirroring the S1/S2 boot-grant code shape, documented beside the assert. tid9 stays dead-parked (normal for an unspawned slot under `NTHREADS=10`).
- [ ] **Step 5: `make -C kernel` clean.**
- [ ] **Step 6: Smoke (locked, no unlock yet)** — vault prints `VAULT: up`; cryptblk doesn't exist → no `CRYPT:` lines yet except... kboot prints nothing crypt yet. Markers this task: `VAULT: up`, `VAULTQ: labels ok`. verify.sh `[4/4]` 2 lines after the last S3 line. Full smoke must stay green (all old markers + 2 new).
  Run: `tools/verify.sh 2>&1 | grep -E "v2 smoke:|FAIL|verify done"`
  Expected: zero FAIL.
- [ ] **Step 7: Commit** (all Task-3 files + regenerated `initrd_data.c`/`initrd.h`):

```bash
git add userspace/vault userspace/qrexec_server userspace/Makefile tools/mkinitrd.sh kernel/caps.h kernel/kboot.c kernel/user.c kernel/initrd_data.c kernel/initrd.h tools/verify.sh
git commit -m "fde: vault server + 10-thread boot + locked smoke"
```

### Task 4: Cryptblk ELF — driver + sector/FS + unlock demo (full `CRYPT:` green)

**Files:**
- Create: `userspace/cryptblk/v2_main.c`, `userspace/cryptblk/cryptblk_start.S`
- Modify: `kernel/caps.h` (`V2_FRAMES_MAX` 16→32 + loop-bound audit), `userspace/vault/v2_main.c` (tick-bounded ack-wait only, nothing else), `kernel/kboot.c` (spawn tid9 + `qube_of[9]=7` + `qube_next=8` + `CRYPTQ: labels ok` assert + QX set (qube0→cryptblk for direct AppVM FS calls, qrexec→cryptblk for approved `T_DELIVER`s — mirror the Task-3 grant shape); demo is LIVE here: the unlock + rw legs run through real ELFs at boot, choreographed single-flight like S2/S3 brokers; kboot only spawns + asserts), `userspace/Makefile`, `tools/mkinitrd.sh` (append `"cryptblk.elf"` → index 9), `tools/verify.sh` (`[4/4]`, 9 markers)
- Test: builds + QEMU smoke

**Interfaces:**
- Consumes: Tasks 1–3 (AEAD/KDF, layout/slots, vault + `T_KEY` shape + QX topology, TID/label constants).
- Produces: `CRYPT:` transcript consumed by Task 6 docs; `Qubes_D` model surface (slot/FS ops) consumed by Task 5.

- [ ] **Step 0: Frame budget + handshake ratification (do first — Task 4 cannot fit otherwise)** — frame budget table (verified Task-3 exit state): mem 1 + qrexec 2 + adminvm 2 + fw 2 + net 2 + vault 3 + net DMA 2 + CAP 1 = 15 of 15 usable (`V2_FRAMES_MAX 16` minus reserved frame 0). Cryptblk needs image ~5 + DMA 2 + demo 1 (transient) = +8 steady. Bump `V2_FRAMES_MAX` 16→32 in `kernel/caps.h` (+ `frame_bitmap`/`fdata` sizing follows automatically as static arrays; audit every `V2_FRAMES_MAX`-indexed loop for the new bound comment; `_Static_assert` the pool fits the `0x81000000` window: 32×4K=128K — trivially true, assert anyway). Task 5 assesses proof impact (V2_D `max_frames=8` divergence note extended — Task 4 only documents the bump, never touches proofs).
  Handshake ratification (Task-3 review findings, decided here): `T_KEY_ACK=10` + grant-dst slot 20 are RATIFIED (tag 10 is free in message-tag space — `V2_INV_FORK=10` lives in the separate invoke-op namespace, no collision; slot 20 < 32 avoids slot-8 data + slot-9 QX conventions). Task 4 MUST: grant key frames to dst slot 20, ack as `[T_KEY_ACK, slot, 0, 0]` with zero prints on the ack path, and give vault's ack-wait a tick bound — edit `userspace/vault/v2_main.c` ack-wait into `rdtime`-deadline + `V2_YIELD` polling with park + `REVOKE` + key-wipe on expiry (never wedge holding frame+grant; expiry prints NO marker — the missing `unlock ok` fails the gate). No new markers in this step.
- [ ] **Step 1: Block driver (inside the ELF, S3-net pattern)** — probe MMIO magic at the scanned transport (scan-then-bind, never hardcoded transport 0 — S3 Task-4 precedent; `NETMMIO`-style boot print is `BLKMMIO: tid=9 only` for the U-leaf gate), negotiate, one queue pair, 2 DMA frames (`PT_ALLOC`+`MAP`+`FRAME_PA`), completion via IRQ badge + `rdtime`/`YIELD` poll with park-on-timeout (never spin). 512B×8 glue to 4K sectors in exactly one function (`blk44k_read/write`), bounds-checked. MMIO U-leaf: same per-thread single-leaf pattern as S3 net (tid 9 only, boot scan asserts, W^X intact). Kernel part: extend the S3 MMIO/leaf code paths for tid 9 + `BLKMMIO` print (small, mirrors S3 — implementer reads the S3 hunks).
- [ ] **Step 2: Sector + FS + views** — `sec_read/sec_write` (tag-region load/store + AEAD with sector-nonce; mismatch ⇒ zero buffer + `EIO`); superblock/inode/dir/extent ops per `layout.h` (first-fit ≤64 extents, `NOSPC` past that); FD tables keyed on stamped sender (v1-VFS discipline, V2 IPC); `/dev/blk0` returns raw sectors (ciphertext, any label); tree serves plaintext post-unlock with owner-label checks (non-owner ⇒ NOTFOUND, no I/O).
- [ ] **Step 3: Boot unlock demo (live, single-flight)** — TEST_KEYS vector passphrase (build flag, smoke-only — release path is manual AdminVM entry, documented): vault KDF → unwrap slot for cryptblk label → `T_KEY` frame handoff → cryptblk loads VMK → `CRYPT: unlock ok`; provision leg (format header on the attached disk image? The QEMU disk persists across runs — demo must be idempotent: probe header magic first; valid ⇒ skip format (`CRYPT: volume ok`), invalid ⇒ AdminVM-attended format branch prints `CRYPT: needs format` and parks (smoke pre-formats the image once via a `tools/crypt_format.sh` helper? No — keep smoke hermetic: the demo formats ONLY if magic absent, using TEST_KEYS KEKs, prints `CRYPT: formatted`. First-ever run formats, later runs reuse. Deterministic either way? First run shows `formatted`, later runs `volume ok` — marker set differs run-to-run! FIX (pinned): smoke gate asserts the UNION-tolerant pair — gate on `CRYPT: unlock ok` + `CRYPT: rw ok` always, and accept either `formatted` or `volume ok` via `grep -qE "formatted|volume ok"`. Document in the gate line comment.); rw leg: write+readback probe file → `CRYPT: rw ok`; wrong-key leg: tamper one tag byte in a scratch sector → `EIO` → `CRYPT: wrong-key denied`; leak leg: stamped non-owner open → `CRYPT: leak denied`; no-volume leg: separate negative path — corrupt-header probe CANNOT run against the live disk; implement as a RAM-shadow header parse (parse garbage bytes, expect reject) printing `CRYPT: no volume`. All legs fail closed to marker-free `[demo] FAIL`-equivalents (ELF prints `CRYPT: FAIL <leg>`, gate asserts absence? Simpler, S2/S3 precedent: unexpected result prints NO marker, gate misses it. Keep that: no FAIL-marker design.)
- [ ] **Step 4: Smoke gate** — after the last S3 line, 9 lines: `CRYPTQ: labels ok`, `CRYPT: up`, `CRYPT: locked`, `CRYPT: unlock ok`, `CRYPT: rw ok`, `CRYPT: wrong-key denied`, `CRYPT: leak denied`, `CRYPT: no volume`, `BLKMMIO: tid=9 only`.
  Run: `tools/verify.sh 2>&1 | grep -E "v2 smoke:|FAIL|verify done"`
  Expected: all old + 7 new PASS, zero FAIL.
- [ ] **Step 5: Commit** (regenerated blob included):

```bash
git add userspace/cryptblk kernel/kboot.c userspace/Makefile tools/mkinitrd.sh kernel/initrd_data.c kernel/initrd.h tools/verify.sh
git commit -m "fde: cryptblk server + unlock demo + smoke"
```

### Task 5: `Qubes_D.thy` + bound ripple (proofs)

**Files:**
- Create: `kernel/isabelle/Qubes_D.thy`
- Modify: `kernel/isabelle/ROOT` (add `Qubes_D` after `Qubes_C`)
- Modify: `kernel/isabelle/Qubes_A.thy`, `Qubes_B.thy`, `Qubes_C.thy` ONLY IF the `V2_CAP_THREADS` 8→10 / `NTHREADS` 8→10 bump breaks them (bound-ripple fixes, minimal diffs, reported as such)
- Test: `isabelle build -D kernel/isabelle -v` + `[2b/2c]` grep gates

**Interfaces:**
- Consumes: Tasks 1–2 C semantics (arg-free: slot wrap/unwrap/wipe, layout guards), Task 3–4 behaviors (release events, label checks, views).
- Produces: theorem names consumed by Task 6 docs.

- [ ] **Step 1: Write the theory** — imports `Qubes_C`; model slots (wrapped VMK + label + wiped flag), release events, sector/ciphertext abstraction (ciphertext = opaque function of (key, sector, bytes) with ONE axiom exactly as spec'd OR KAT-correspondence — implementer chooses with reviewer sign-off, default KAT-correspondence to keep zero axioms); prove: (a) `slot_release_only_to_label`; (b) `ciphertext_view_independent` (raw reads equal across labels); (c) `no_ambient_decrypt` (plaintext transitions require released slot); (d) refinement of slot/FS ops; (e) preservation of all prior invariants over the new ops + bound lemmas for 10 threads / 8 qubes (`c_qubes_implies_spec` pattern extended). Mutants per invariant (wrong-label release, forged slot, wiped-slot use, oversize sector, spoofed T_KEY sender). Zero `sorry`, no `True`-definitions, `eval` pins (release/deny/leak/wrong-key/no-volume demos). Explicit C(≤10 threads, ≤8 qubes, 1-frame/4K-sector packets) ⇒ spec bounds.
- [ ] **Step 2: Build**

Run: `isabelle build -D kernel/isabelle -v 2>&1 | tail -n 5`
Expected: clean incl. `V2.Qubes_D` (absent-Isabelle handling per S1/S2 precedent: DONE_WITH_CONCERNS + grep evidence + CI coverage).

- [ ] **Step 3: Anti-vacuity gates**

Run: `grep -rn "sorry\\|axiomatization\\|quick_and_dirty\\|oops" kernel/isabelle/; grep -rn "equiv> True" kernel/isabelle/*.thy; echo "gate done"`
Expected: empty before `gate done` (plus the ≤1 named axiom iff chosen, disclosed).

- [ ] **Step 4: Commit**

```bash
git add kernel/isabelle/Qubes_D.thy kernel/isabelle/ROOT kernel/isabelle/Qubes_A.thy kernel/isabelle/Qubes_B.thy kernel/isabelle/Qubes_C.thy
git commit -m "fde: Qubes_D slot release + ciphertext proofs"
```

### Task 6: Docs + full verify (stage closure)

**Files:**
- Modify: `docs/V2_DESIGN.md` (§9 FDE → BUILT + refinements + S2-(c)-style closures), `docs/QUBES_ISOLATION_PLAN.md` (storage rows `[TODO]`→`[HAVE]` + H-ext stays `[TODO]`), `docs/ARCHITECTURE.md` (crypt/vault/cryptblk files + views + MMIO/IRQ), `docs/BUILD.md` (initrd 0–9, markers, TEST_KEYS honesty, KDF-only gate, no-rollback, test-grade RNG, plaintext filenames)
- Test: `tools/verify.sh` end-to-end

**Interfaces:**
- Consumes: Tasks 1–5 artifacts.

- [ ] **Step 1: Update docs** — every BUILT/`[HAVE]` names test/marker/lemma/path; refinements list (10-thread bound, single-flight, TEST_KEYS smoke-only, format-if-absent idempotence, `T_KEY`-by-grant not SEND, byte-sum-style honesty notes where due); threat-model limits stated (KDF-only gate, no rollback, test-grade RNG, plaintext names, no re-encryption on revoke, in-flight FDs survive revoke).
- [ ] **Step 2: Full verification**

Run: `tools/verify.sh 2>&1 | tail -n 12`
Expected: host PASS (incl. `test_aead`, `test_crypt`), gates PASS, kernel PASS, QEMU PASS with all FDE markers, Isabelle PASS or pre-existing SKIP only, zero FAIL.

- [ ] **Step 3: Commit**

```bash
git add docs/V2_DESIGN.md docs/QUBES_ISOLATION_PLAN.md docs/ARCHITECTURE.md docs/BUILD.md
git commit -m "fde: docs mark stage built with proof/test links"
```

---

## Self-Review

- **Spec coverage:** §3 layout/FS → Tasks 2+4 (header/tags/extents/inodes/dirs, 256M math, first-fit/NOSPC, no-journal); §4.1 server/views → Task 4 (driver, sector EIO discipline, FD tables, dual views); §4.2 vault lifecycle → Task 3 (KEKs, KDF, per-label unwrap, T_KEY-by-grant, rewrap, revoke semantics); §4.3 rows → Task 3 Step 1 (7/8/9, nrules=7); §4.4 hierarchy/visibility → Task 4 (NOTFOUND discipline, blk0 ciphertext); §5 flows → Task 4 Step 3 (locked→unlock→rw, idempotent format); §6 error table → Tasks 3–4 (each row owned: passphrase/revoke/header/pool/multi-sector intent); §7 tests+gates+proofs → Tasks 1,2,4,5 (KATs, smoke, T_KEY log gate, Qubes_D + axiom budget); §8 non-goals → none tasked (deliberate); §9 exit → Task 6. Thread/label/frame budgets: Task 3 bumps threads to 10 with vault label 6 + next=7; Task 4 adds cryptblk label 7 reaching qube_next=8==V2_QUBES_MAX (documented cap).
- **Placeholder scan:** no TBD/TODO/later/appropriate/edge-cases/similar-to; every code step ships concrete constants (`CRYPT_MAGIC`, `T_KEY 8`, RPC 7–9, tids 8/9, labels 6/7, slots, iters 600000, sector math), commands and expected outputs. The three spec-stage latitudes (negative-boot form, key-log gate form, axiom-vs-KAT) are pinned here to: RAM-shadow reject leg, no-printfs-in-handoff + grep, KAT-correspondence-default.
- **Type consistency:** `arg0/arg1` ULONG preserved; `T_KEY 8` extends tags 1–7; RPC 7–9 extend 1–6; `VAULT_TID 8/CRYPT_TID 9` match spawn indexes 8/9; labels 6/7 match `qube_of[8/9]`; `FW: up`-style marker verbs reused (`CRYPT: up/locked/unlock ok/rw ok/...`); `slot_unwrap` naming consistent Task 2→3; `BLKMMIO: tid=9 only` mirrors `NETMMIO: tid=6 only`.
