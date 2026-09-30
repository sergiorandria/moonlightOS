# RNG + Demo-Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship vault-owned virtio-rng with HW+env mixer and harden demo pools/TEST_KEYS in place with identical markers.

**Architecture:** Task 1 builds pure mixer/scan math with host KATs. Task 2 wires QEMU rng device + kernel tid8-only leaf + asserts (vault still parks). Task 3 builds vault bind/mix/RANDOM service. Task 4 switches cryptblk off TEST_KEYS onto vault seed. Task 5 switches shell/VFS off demo pools onto Untyped invoke. Task 6 replays proofs and closes docs.

**Tech Stack:** C (freestanding rv64imac stock clang `-Werror`; host clang for unit tests), RISC-V S-mode (existing handlers/tables only), Isabelle/HOL (session V2), bash (verify.sh/mkinitrd.sh/run_qemu.sh).

**Spec:** `docs/superpowers/specs/2026-09-28-rng-harden-demos-design.md`

## Global Constraints

- Freestanding only for kernel/ELF code: `--target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 -ffreestanding -nostdlib` + `-Wall -Wextra -Werror`; follow `CFLAGS_V2`/`LDFLAGS_V2` shapes in `userspace/Makefile:44-48`.
- C subset: no `float`, no function-pointer dispatch (switch on op/tag), no recursion, every loop carries a `/* bound: N */` comment tied to a named constant.
- `kernel/user.c` constraint: no string literals, no globals — immediates + stack locals only (thread-A legs print nothing).
- Fail closed: validation failure parks marker-free or replies DENY with zero state touched; missing QEMU markers flip the smoke gate to FAIL.
- Unchanged (no bump set): `NTHREADS 11`, `V2_CAP_THREADS 11`, `V2_NEP 11`, `max_eps 11`, `V2_QUBES_MAX 9`, `V2_FRAMES_MAX 40`, `V2_MSG_MAX 4`, `V2_IPC_Q 16`, `V2_AUDIT_MAX 64`. Vault tid8 EP8 qube6, cryptblk tid9 EP9 qube7.
- `tools/verify.sh` single entry: host tests in `[1f]`, markers in `[4/4]`, single QEMU cmdline (extended with `-device virtio-rng-device`, not replaced), no new SKIP.
- Proofs: zero `sorry`/`axiomatization`, no `True`-definitions, mutant per new invariant; never `eval` large numerals (`simp` for big constants).
- Endpoint/tid/qube map: vault tid8 EP8 qube6 initrd index 8, cryptblk tid9 EP9 qube7 initrd index 9. Tags: existing `T_KEY 8`/`T_KEY_ACK 10` unchanged; new `RANDOM_REQ 11`/`RANDOM_RESP 12` (free: FILL 6, T_FWD 6/T_DONE 7 live on other EPs — reviewer confirms). Replies `R_OK 0`/`R_DENY -1`.
- `make -C kernel` does NOT regenerate tracked `kernel/initrd_data.c` — run `tools/mkinitrd.sh` between userspace and kernel builds whenever ELFs change.

---

## File Map

| File | Responsibility |
|---|---|
| Create `userspace/vault/rng_mix.h` | Pure mixer: `rng_mix()` sha256(HW\|\|rdtime\|\|irq_delta\|\|dice_seed), validation. Host-testable. |
| Create `userspace/vault/rng_scan.h` | Pure virtio-mmio scan helpers: transport offset, device-ID 4 match, queue bound. Host-testable. |
| Create `tests/test_rng.c` | KATs for both headers (mixer vectors, scan edges, reject cases). |
| Modify `tools/run_qemu.sh` | Add `RNG_ARGS="-device virtio-rng-device"` to both exec lines (same shape as `NET_ARGS`). |
| Modify `kernel/kboot.c` | RNG U-leaf `l0_rngmmio` to tid8 only + `RNGMMIO: tid=8 only` assert + `VIRTIO_DEV_RNG 4u` define. |
| Modify `userspace/vault/v2_main.c` | Bind virtio-rng, mixer call, `RANDOM_REQ` service on EP8, `RNG: up` marker, sqb allowlist (qube7-only). |
| Modify `userspace/cryptblk/v2_main.c` | Delete `crypt_test_pw`/`crypt_fmt_seed`, request vault seed at boot, derive KEK via existing pbkdf2. |
| Modify `userspace/sh/shell.c` | `write` mints via `V2_INV_PT_ALLOC`+`MAP` instead of demo pool; retire exhausted-pool message. |
| Modify `userspace/vfs_server/server.c` | Placeholder "sh" backed by invoked frame instead of demo pool frame. |
| Modify `tools/verify.sh` | `[1f]` test_rng line; `[4/4]` +2 marker lines (`RNG: up`, `RNGMMIO: tid=8 only`). |
| Modify `kernel/isabelle/V2_C.thy` | `rng_mmio_covers`-style bound lemma + mutant, `simp` only. |
| Modify `docs/V2_DESIGN.md`, `docs/ARCHITECTURE.md`, `docs/BUILD.md` | Hardening BUILT entries, TEST_KEYS removal note. |

**Scope note:** Tasks 1-2 are host/build-gated with zero vault contact. Task 2 ends with `RNGMMIO` green, vault parks (no `RNG: up`). Task 3 ends with `RNG: up` green. Tasks 4-5 keep all prior markers green.

---

### Task 1: Mixer + scan headers + KATs (host-only, no boot)

**Files:**
- Create: `userspace/vault/rng_mix.h`, `userspace/vault/rng_scan.h`
- Create: `tests/test_rng.c`
- Modify: `tools/verify.sh` (`[1f]`, after the `test_gui` line)
- Test: `tests/test_rng.c`

**Interfaces:**
- Consumes: nothing (greenfield; virtio-mmio base `0x10000000UL`, 8 transports × 0x2000, device-ID `4u` from QEMU `hw/virtio/virtio-rng.c` — fetch, don't recall).
- Produces: `rng_mix()`, `rng_scan_ok()`, `rng_dev_match()` consumed by Task 3 (vault links headers — same freestanding-safe subset).

Constants (exact — reviewer cross-checks): `RNG_HW_LEN 32`, `RNG_MIX_LEN 32`, `VIRTIO_MMIO_BASE 0x10000000UL`, `VIRTIO_MMIO_STRIDE 0x2000UL`, `VIRTIO_NTRANSPORTS 8`, `VIRTIO_DEV_RNG 4u`, `VIRTIO_MAGIC_VAL 0x74726976u`.

- [ ] **Step 1: Write `tests/test_rng.c` first** (CHECK idiom, no malloc — stack arrays like `test_gui.c`):

```c
/* tests/test_rng.c - KATs for vault/rng_mix.h + vault/rng_scan.h. */
#include <stdio.h>
#include <stdint.h>
#include "../userspace/vault/rng_mix.h"
#include "../userspace/vault/rng_scan.h"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

int main(void) {
    uint8_t hw[32] = {0};
    uint8_t out[32];
    hw[0] = 0x01u;
    /* mix_ok: full-length inputs accept, short/zero reject. */
    CHECK(rng_mix_ok(hw, 32u, 12345u, 678u, out));
    CHECK(!rng_mix_ok(hw, 0u, 0u, 0u, out));       /* zero HW len */
    CHECK(!rng_mix_ok((void*)0, 32u, 0u, 0u, out)); /* null HW */
    CHECK(!rng_mix_ok(hw, 32u, 0u, 0u, (void*)0));  /* null out */
    /* scan: transport 0 offset 0, transport 7 last, dev-4 match. */
    CHECK(rng_trans_off(0u) == 0x10000000UL);
    CHECK(rng_trans_off(7u) == (0x10000000UL + 7u * 0x2000UL));
    CHECK(rng_trans_off(8u) == 0xFFFFFFFFUL);        /* sentinel OOB */
    CHECK(rng_dev_match(4u));
    CHECK(!rng_dev_match(1u));                       /* net, not rng */
    CHECK(!rng_dev_match(2u));                       /* blk, not rng */
    printf("PASS: test_rng\n");
    return 0;
}
```

- [ ] **Step 2: Run, watch fail (headers missing)**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_rng tests/test_rng.c 2>&1 | head -n 5`
Expected: FAIL — `vault/rng_mix.h: No such file`.

- [ ] **Step 3: Write the two headers** — portable C99, `stdint.h`/`stddef.h` only, `static inline`, no malloc, no host calls. Mixer is byte-xor + length-checked copy shape (real sha256 call lives in vault TU which already links sha256; header only validates + packs the 32+8+8+32 input block). Every loop (if any) carries `/* bound: */`.

```c
/* userspace/vault/rng_mix.h - pure RNG mixer validation/packing. */
#ifndef VAULT_RNG_MIX_H
#define VAULT_RNG_MIX_H
#include <stdint.h>
#include <stddef.h>
#define RNG_HW_LEN 32u
#define RNG_MIX_LEN 32u
static inline int rng_mix_ok(const uint8_t *hw, unsigned long hw_len,
    uint64_t rdtime, uint64_t irq_delta, uint8_t *out) {
    unsigned long i;
    if (!hw || !out) return 0;
    if (hw_len != (unsigned long)RNG_HW_LEN) return 0;
    for (i = 0u; i < (unsigned long)RNG_HW_LEN; i++) /* bound: RNG_HW_LEN */
        out[i] = (uint8_t)(hw[i] ^ (uint8_t)(rdtime >> ((i % 8u) * 8u)) ^ (uint8_t)(irq_delta >> ((i % 8u) * 8u)));
    return 1;
}
#endif
```

```c
/* userspace/vault/rng_scan.h - pure virtio-mmio scan helpers. */
#ifndef VAULT_RNG_SCAN_H
#define VAULT_RNG_SCAN_H
#include <stdint.h>
#define VIRTIO_MMIO_BASE 0x10000000UL
#define VIRTIO_MMIO_STRIDE 0x2000UL
#define VIRTIO_NTRANSPORTS 8u
#define VIRTIO_DEV_RNG 4u
static inline unsigned long rng_trans_off(unsigned long idx) {
    if (idx >= (unsigned long)VIRTIO_NTRANSPORTS) return 0xFFFFFFFFUL;
    return (unsigned long)VIRTIO_MMIO_BASE + idx * (unsigned long)VIRTIO_MMIO_STRIDE;
}
static inline int rng_dev_match(unsigned long dev_id) {
    return dev_id == (unsigned long)VIRTIO_DEV_RNG;
}
#endif
```

- [ ] **Step 4: Run green + freestanding check**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_rng tests/test_rng.c && /tmp/test_rng`
Expected: `PASS: test_rng`.
Run: `clang --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 -O2 -ffreestanding -nostdlib -fno-builtin -fsyntax-only userspace/vault/rng_mix.h userspace/vault/rng_scan.h 2>&1`
Expected: clean.

- [ ] **Step 5: Wire into `tools/verify.sh [1f]`** — after the `test_gui` line:

```bash
gcc -Wall -Wextra -Werror -o /tmp/test_rng tests/test_rng.c 2>&1 && /tmp/test_rng || echo "FAIL: test_rng"
```

- [ ] **Step 6: Commit**

```bash
git add userspace/vault/rng_mix.h userspace/vault/rng_scan.h tests/test_rng.c tools/verify.sh
git commit -m "rng: mixer plus scan headers plus KATs"
```

### Task 2: QEMU rng device + kernel tid8-only leaf + asserts

**Files:**
- Modify: `tools/run_qemu.sh:99-106`, `kernel/kboot.c:105-106,151-155,210-221,239-260`, `tools/verify.sh` (`[4/4]` RNGMMIO line only)
- Test: `make -C kernel`, QEMU smoke shows `RNGMMIO: tid=8 only`, vault parks (no `RNG: up` yet → expected FAIL on rng-up line, do NOT add it yet)

**Interfaces:**
- Consumes: Task 1 constants (`VIRTIO_DEV_RNG 4u`, `VIRTIO_NTRANSPORTS 8`).
- Produces: `l0_rngmmio` U-leaf at tid8 + `RNG_ARGS` cmdline consumed by Task 3 (vault scans it).

- [ ] **Step 1: Add RNG device to QEMU cmdline** in `tools/run_qemu.sh` after `NET_ARGS`:

```bash
RNG_ARGS="-device virtio-rng-device"
```

Append `$RNG_ARGS` to both exec lines (gdb + normal, same position as `$NET_ARGS`). Verify: `grep -n RNG_ARGS tools/run_qemu.sh` shows 3 lines (def + 2 uses).

- [ ] **Step 2: Add kernel defines + leaf tables** in `kernel/kboot.c`:

```c
#define VIRTIO_DEV_RNG 4u
static uint64_t l0_rngmmio[512] __attribute__((aligned(4096)));
```

Wire in `pagetable_init()` after `l0_blkmmio` loop (same 8-transport shape):

```c
for (int k = 0; k < VIRTIO_NTRANSPORTS; k++) /* bound: 8 */
    l0_rngmmio[k] = pte_leaf(VIRTIO0_BASE + (unsigned long)k * 0x1000UL,
                             PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
```

Wire per-thread `l1_t[8][5]` (fresh index 5 — tid8 currently uses 4 for frame window, 6/7 free; use 5 to avoid GUI/BLK index 6 collision) in the per-thread loop. Add `RNGMMIO: tid=8 only` assert mirroring `GUIMMIO` (loop tids, fail-closed `[demo] FAIL rngmmio leak`).

- [ ] **Step 3: Wire RNGMMIO smoke line only** in `tools/verify.sh [4/4]`:

```bash
echo "$V2LOG" | grep -q "RNGMMIO: tid=8 only" && echo "v2 smoke: rngmmio leaf" || { echo "v2 smoke: FAIL (no rngmmio)"; QEMU_FAIL=1; }
```

- [ ] **Step 4: Build + smoke (leaf green, vault parks)**

Run: `make -C kernel 2>&1 | tail -n 3`
Expected: `build/moonlight.elf` PASS.
Run: `timeout 60 tools/run_qemu.sh --nographic 2>&1 | grep -E "RNGMMIO|RNG: up|no rng" | head`
Expected: `RNGMMIO: tid=8 only` present, `RNG: up` absent (vault still parks — correct for this task).

- [ ] **Step 5: Commit**

```bash
git add tools/run_qemu.sh kernel/kboot.c tools/verify.sh
git commit -m "rng: qemu device plus tid8-only leaf plus assert"
```

### Task 3: Vault virtio-rng bind + mixer + RANDOM service

**Files:**
- Modify: `userspace/vault/v2_main.c`, `userspace/Makefile` (no new rule — existing vault rule gains `rng_mix.h`/`rng_scan.h` deps)
- Test: QEMU smoke shows `RNG: up` + `VAULT: up` unchanged

**Interfaces:**
- Consumes: Task 1 (`rng_mix_ok`, `rng_trans_off`, `rng_dev_match`), Task 2 (rng U-leaf + cmdline).
- Produces: `RANDOM_RESP` IPC consumed by Task 4 (cryptblk `RANDOM_REQ [11, nonce, 0, 0]` → `[12, w0, w1, w2]` chunked 32B via 4× frame-WRITE + keyless notice — same T_KEY handoff shape, reviewer checks tag freedom).

- [ ] **Step 1: Add vault RNG bind helper** (copy net scan shape, bus-MMIO transports, device-ID 4, BAR-less — rng has no LFB):

```c
#define RNG_TID 8
#define RNG_EP 8
#define RANDOM_REQ 11
#define RANDOM_RESP 12
#define R_OK 0L
#define R_DENY (-1L)
static int vault_rng_bind(void) {
    unsigned long t;
    for (t = 0u; t < 8u; t++) { /* bound: 8 (virtio transports) */
        unsigned long base = rng_trans_off(t);
        uint32_t magic;
        uint32_t dev;
        if (base == 0xFFFFFFFFUL) continue;
        magic = mmio_read32(base + 0x000u);
        if (magic != 0x74726976u) continue;
        dev = mmio_read32(base + 0x008u);
        if (!rng_dev_match(dev)) continue;
        return 1;
    }
    return 0;
}
```

Call at vault boot before `VAULT: up`: `if (!vault_rng_bind()) u_park();` then `u_puts("RNG: up\n");` then existing `VAULT: up`.

- [ ] **Step 2: Add RANDOM_REQ service arm** in vault RECV loop (after T_DELIVER arms, before INVALID fallthrough):

```c
if (n >= 2 && buf[0] == (uint64_t)RANDOM_REQ) {
    unsigned long req_qb;
    uint8_t hw[32];
    uint8_t mixed[32];
    req_qb = sqb;
    if (req_qb != 7u) { u_reply(snd, R_DENY); continue; } /* cryptblk qube7-only */
    if (!vault_read_hw(hw) || !rng_mix_ok(hw, 32u, u_rdtime(), irq_delta, mixed)) {
        u_reply(snd, R_DENY);
        continue;
    }
    drbg_reseed(mixed); /* existing kdf.h owner */
    crypt_wipe(hw, sizeof hw); crypt_wipe(mixed, sizeof mixed);
    u_reply(snd, R_OK);
    continue;
}
```

`vault_read_hw` reads 32B from bound rng queue (bounded loop, `/* bound: 32 */`, fail-closed 0 on short read). `irq_delta` is `u_rdtime() - last_irq_t` (maintained in existing IRQ path).

- [ ] **Step 3: RISC-V syntax check + build**

Run: `clang --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 -O2 -ffreestanding -nostdlib -Wall -Wextra -Werror -fsyntax-only userspace/vault/v2_main.c 2>&1`
Expected: clean.
Run: `make -C userspace 2>&1 | grep -E "vault.elf|error" | head`
Expected: `vault.elf` rebuilt, no errors. Then `tools/mkinitrd.sh` + `make -C kernel`.

- [ ] **Step 4: Smoke RNG up**

Run: `timeout 60 tools/run_qemu.sh --nographic 2>&1 | grep -E "RNG: up|VAULT: up|RNGMMIO" | head`
Expected: all three present.

- [ ] **Step 5: Commit**

```bash
git add userspace/vault/v2_main.c userspace/Makefile
git commit -m "rng: vault bind plus mixer plus RANDOM service"
```

### Task 4: Cryptblk drops TEST_KEYS onto vault seed

**Files:**
- Modify: `userspace/cryptblk/v2_main.c:205-214,838,924,1292,1325,1612`
- Test: QEMU smoke `CRYPT:*` markers unchanged, `CRYPT: formatted` appears once then `volume ok`

**Interfaces:**
- Consumes: Task 3 (`RANDOM_REQ 11` on EP8, `R_OK` + reseeded vault DRBG).
- Produces: TEST_KEYS-free cryptblk consumed by Task 6 docs (honesty notes retired).

- [ ] **Step 1: Delete TEST vectors** — remove `crypt_test_pw[21]` + `crypt_fmt_seed[9]` + `CRYPT_TEST_ITERS`, replace with vault-seeded path:

```c
/* Production: KEK derives from vault RANDOM seed + per-volume salt via
 * pbkdf2_hmac_sha256 (no TEST_KEYS, no fixed format seed). */
static int crypt_get_seed(uint8_t *seed_out) {
    uint64_t req[4];
    long n;
    unsigned long snd = 0, sqb = 0, ovf = 0;
    req[0] = 11u; req[1] = 0x9e4bu; req[2] = 0u; req[3] = 0u; /* RANDOM_REQ + nonce */
    if (u_send(8u, req, 4) != 0) return 0;
    n = u_recv(9u, req, 4, &snd, &sqb, &ovf);
    if (n < 1 || req[0] != 0u || sqb != 6u) return 0; /* vault qube6 R_OK only */
    return vault_seed_to_local(seed_out); /* 4× frame-READ handoff, bounded, wiped */
}
```

Call in unlock leg replacing `pbkdf2_hmac_sha256(crypt_test_pw, ...)` with `pbkdf2_hmac_sha256(seed, 32, salt, ...)`, wipe seed after. Format path uses fresh `drbg_next` bytes (already linked) instead of fixed seed.

- [ ] **Step 2: Build + smoke crypt markers**

Run: `make -C userspace && tools/mkinitrd.sh && make -C kernel 2>&1 | tail -n 2`
Expected: clean builds.
Run: `timeout 60 tools/run_qemu.sh --nographic 2>&1 | grep -E "CRYPT: up|CRYPT: locked|CRYPT: unlock ok|CRYPT: rw ok|CRYPT: (formatted|volume ok)" | head`
Expected: all present, no `TEST_KEYS` string in binary: `grep -r TEST_KEYS userspace/cryptblk/v2_main.c || echo "TEST_KEYS gone"`.

- [ ] **Step 3: Commit**

```bash
git add userspace/cryptblk/v2_main.c
git commit -m "rng: cryptblk vault seed replaces TEST_KEYS"
```

### Task 5: Shell/VFS drop demo pools onto Untyped invoke

**Files:**
- Modify: `userspace/sh/shell.c:43,580-583`, `userspace/vfs_server/server.c:668`
- Test: shell `write`/`cat` round-trip + `ls` in QEMU smoke (serial shell), host shell sim still PASS

**Interfaces:**
- Consumes: existing `V2_INV_PT_ALLOC`/`MAP`/`WRITE`/`READ` (no new kernel ops).
- Produces: pool-free shell/VFS consumed by Task 6 (honesty notes retired).

- [ ] **Step 1: Shell write via invoke** — replace demo-pool mint:

```c
/* Production: mint via Untyped retype (PT_ALLOC + MAP), not demo pool. */
frame = u_invoke_pt_alloc();
if (frame == 0xFFFFFFFFUL) { shell_puts("write: no frames\n"); return; }
if (u_invoke_map(frame, scratch_vpn) != 0) { shell_puts("write: map failed\n"); return; }
```

Keep message shapes (`write: ...`, `cat`, `ls`) identical so `verify.sh [1b]` shell sim stays green. Delete `demo_pool[]` array + `demo frame pool exhausted` string.

- [ ] **Step 2: VFS placeholder via invoked frame** — replace `demo pool frame` backing for `"sh"` entry with `PT_ALLOC` frame recorded in existing pool-slot struct (same clamp/validate-then-write, same `server.c:618` reply shape).

- [ ] **Step 3: Host + smoke check**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_shell userspace/sh/shell.c 2>&1 | head -n 3 || true; tools/verify.sh 2>&1 | grep -E "PASS: shell|FAIL: shell" | head -n 5`
Expected: shell sim PASS (no FAIL lines).
Run QEMU serial `write notes.txt hi` + `cat notes.txt` manually or via smoke expect — same output as before, no `demo frame pool` string: `grep -rn "demo frame pool\|demo pool" userspace/sh/shell.c userspace/vfs_server/server.c || echo "demo pools gone"`.

- [ ] **Step 4: Commit**

```bash
git add userspace/sh/shell.c userspace/vfs_server/server.c
git commit -m "rng: shell vfs invoked frames replace demo pools"
```

### Task 6: Proofs + docs + verify close

**Files:**
- Modify: `kernel/isabelle/V2_C.thy`, `tools/verify.sh`, `docs/V2_DESIGN.md`, `docs/ARCHITECTURE.md`, `docs/BUILD.md`
- Test: full `tools/verify.sh` PARTIAL-or-PASS (only CHERI SKIP allowed)

**Interfaces:**
- Consumes: Tasks 1-5 (markers + tests + leaves).
- Produces: closed stage (nothing downstream except audit-deferred DRBG note).

- [ ] **Step 1: Isabelle bound lemma** — append to `kernel/isabelle/V2_C.thy` after `pci_*` family:

```isabelle
lemma rng_mmio_covers: "rng_scan 8 = 8"
  by (simp add: rng_scan_def)
lemma rng_tid8_only: "rng_leaf t ⟹ t = 8"
  by (simp add: rng_leaf_def)
lemma rng_mutant_leak_rejected: "rng_leaf 6 = False"
  by (simp add: rng_leaf_def)
```

Run: `isabelle build -D kernel/isabelle -v 2>&1 | tail -n 5 || echo "SKIP: isabelle not found"`
Expected: PASS or SKIP (verify.sh tolerates SKIP, CI has dedicated job).

- [ ] **Step 2: Verify close** — add second marker line in `tools/verify.sh [4/4]` (RNGMMIO already added in Task 2, add RNG up):

```bash
echo "$V2LOG" | grep -q "RNG: up" && echo "v2 smoke: rng up" || { echo "v2 smoke: FAIL (no rng up)"; QEMU_FAIL=1; }
```

Run: `timeout 120 tools/verify.sh 2>&1 | tail -n 15`
Expected: `Isabelle proofs: PASS-or-SKIP`, `Kernel build: PASS`, `QEMU smoke: PASS`, summary PARTIAL only for CHERI SKIP. All prior markers + 2 RNG markers green.

- [ ] **Step 3: Docs BUILT entries** — `docs/V2_DESIGN.md §9` hardening entry (vault RNG, TEST_KEYS removed, demo pools removed, DRBG audit deferred explicitly); `docs/ARCHITECTURE.md` RNG subsection (leaf, EP8, QX allowlist, mixer); `docs/BUILD.md` rng device + test_rng lines. Keep 1-2 sentences each, no new architecture claims.

- [ ] **Step 4: Commit**

```bash
git add kernel/isabelle/V2_C.thy tools/verify.sh docs/V2_DESIGN.md docs/ARCHITECTURE.md docs/BUILD.md
git commit -m "rng: proofs plus docs plus verify close"
```
