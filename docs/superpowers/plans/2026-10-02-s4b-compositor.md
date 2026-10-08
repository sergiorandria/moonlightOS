# S4b Compositor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add server-owned surfaces + COMPOSE to the gui server with no kernel bump.

**Architecture:** New pure header `surf.h` holds all math; `v2_main.c` owns `surf[][]` + owners + dirty bits and 3 new tags on EP10; `user.c` drives one pilot surface + COMPOSE; proofs/docs updated.

**Tech Stack:** Freestanding C99 rv64 (`clang --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 -ffreestanding -nostdlib`), host gcc for KATs, Isabelle V2_C.

**Spec:** `docs/superpowers/specs/2026-10-02-s4b-compositor-design.md`

## Global Constraints

- No `NTHREADS` / `V2_NEP` / `V2_CAP_THREADS` / `V2_FRAMES_MAX` / `V2_MSG_MAX` change (11/11/11/40/4 hold).
- `tid10 / EP10 / qube8` only; LFB `0x80C00000`, ECAM `0x80E00000`, `800x600x4` fixed.
- Chrome top 20px server-only; client `y<20` always DENY.
- `R_OK 0` / `R_DENY -1`; single reply per RECV; `ovf!=0` → DENY.
- `-Werror` everywhere; every loop carries `/* bound: */`.
- Markers kept: `GUI: up`, `GUI: fill ok`; new: `GUI: composed ok` once.

---

### Task 1: surf.h pure surface math

> R1 (2026-10-02): dims shrunk 200x150 → 64x48 (via 80x60; frame-pool fallback) to fit the 32-slot loader window (no-bump); values below updated. R2 (2026-10-02): dims shrunk 64x48 → 40x30 to free tid-10 cap slot 9 for the QX grant (no-bump); values below updated.

**Files:**
- Create: `userspace/gui/surf.h`
- Test: `tests/test_gui.c` (used in Task 2, not modified here)

**Interfaces:**
- Consumes: `userspace/gui/rect.h` (`rect_fill_ok`, `rect_off`, `GUI_W/H/BPP`)
- Produces: `SURF_N 4`, `SURF_W 40`, `SURF_H 30`, `SURF_MAX (SURF_W*SURF_H*4)`, `CHROME_H 20`, `int surf_wh_ok(uint32_t wh)`, `int surf_fill_ok(uint32_t sid, uint32_t x, uint32_t y, uint32_t w, uint32_t h)`, `uint32_t surf_px(uint32_t sid, uint32_t x, uint32_t y)` — later tasks use exact names.

- [ ] **Step 1: Create surf.h**

```c
/* userspace/gui/surf.h - S4b surface math. Portable C99, stdint.h only. */
#ifndef GUI_SURF_H
#define GUI_SURF_H
#include <stdint.h>
#include "rect.h"
#define SURF_N 4
#define SURF_W 40
#define SURF_H 30
#define SURF_MAX (SURF_W*SURF_H*4u)
#define CHROME_H 20
static inline int surf_wh_ok(uint32_t wh) {
    uint32_t w = (wh >> 16) & 0xFFFFu;
    uint32_t h = wh & 0xFFFFu;
    if (w == 0u || h == 0u) return 0;
    if (w > (uint32_t)SURF_W || h > (uint32_t)SURF_H) return 0;
    return 1;
}
static inline int surf_fill_ok(uint32_t sid, uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
    if (sid >= (uint32_t)SURF_N) return 0;
    if (w == 0u || h == 0u) return 0;
    if (x >= (uint32_t)SURF_W || y >= (uint32_t)SURF_H) return 0;
    { uint32_t xe = x + w; if (xe < x || xe > (uint32_t)SURF_W) return 0; }
    { uint32_t ye = y + h; if (ye < y || ye > (uint32_t)SURF_H) return 0; }
    return 1;
}
static inline uint32_t surf_px(uint32_t sid, uint32_t x, uint32_t y) {
    (void)sid; return y * (uint32_t)SURF_W + x;
}
#endif
```

- [ ] **Step 2: Syntax-check header freestanding**

Run: `clang --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 -ffreestanding -fsyntax-only -Werror -I userspace/gui userspace/gui/v2_main.c`
Expected: PASS (v2_main.c still compiles; surf.h unused yet, no warnings).

- [ ] **Step 3: Commit**

```bash
git add userspace/gui/surf.h
git commit -m "s4b: add surf.h surface math"
```

### Task 2: test_gui KATs for surf.h

**Files:**
- Modify: `tests/test_gui.c`
- Test: `tests/test_gui.c`

**Interfaces:**
- Consumes: `userspace/gui/surf.h` (`surf_wh_ok`, `surf_fill_ok`, `surf_px`, `SURF_N/W/H`, `CHROME_H`)
- Produces: Extended `PASS: test_gui` gate used by `verify.sh [1f]`.

- [ ] **Step 1: Append surf KATs after pci checks, before PASS line**

```c
    /* surf: wh validation. */
    CHECK(surf_wh_ok((200u<<16)|150u));
    CHECK(!surf_wh_ok((201u<<16)|150u));
    CHECK(!surf_wh_ok((0u<<16)|10u));
    /* surf_fill_ok: sid bounds, surface-local bounds, wrap. */
    CHECK(surf_fill_ok(0, 0, 0, 1, 1));
    CHECK(!surf_fill_ok(4, 0, 0, 1, 1));
    CHECK(!surf_fill_ok(0, 199, 149, 2, 2));
    CHECK(!surf_fill_ok(0, 0xFFFFFF00u, 0, 0x200u, 1));
    CHECK(surf_px(1, 3, 2) == (2u*200u+3u));
```

Insert by editing `tests/test_gui.c:29` (after `pci_bar_ok` CHECKs, before `printf("PASS...")`), add `#include "../userspace/gui/surf.h"` to line 5 imports.

- [ ] **Step 2: Run host KATs, expect fail-then-pass cycle**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_gui tests/test_gui.c && /tmp/test_gui`
Expected: `PASS: test_gui`. If FAIL, line number points to bad case — fix `surf.h`, not the test.

- [ ] **Step 3: Commit**

```bash
git add tests/test_gui.c userspace/gui/surf.h
git commit -m "s4b: surf.h KATs"
```

### Task 3: gui server surfaces + RPCs on EP10

> R1 (2026-10-02): dims shrunk 200x150 → 64x48 (via 80x60; frame-pool fallback) to fit the 32-slot loader window (no-bump); values below updated. R2 (2026-10-02): dims shrunk 64x48 → 40x30 to free tid-10 cap slot 9 for the QX grant (no-bump); values below updated. Companion fix (same dispatch): `surf_owner` is zero-init + runtime `0xFF` fill — a nonzero initializer emits a 4-byte `.data` that pushes `.bss` off page alignment, which the loader rejects (`elf.c:147`).

**Files:**
- Modify: `userspace/gui/v2_main.c:1-251`
- Test: `tests/test_gui.c` (host, Task 2) + QEMU markers in Task 4

**Interfaces:**
- Consumes: `surf.h` (`SURF_N/W/H`, `surf_wh_ok`, `surf_fill_ok`), `rect.h` (`rect_fill_ok`, `rect_off`), existing `u_recv/u_send/u_reply/u_puts`, tags `FILL 6`, new `SURF_CREATE 7`, `SURF_DESTROY 8`, `COMPOSE 9`.
- Produces: Surface-owned FILL path + `GUI: composed ok` marker consumed by Task 4 QEMU gate.

- [ ] **Step 1: Add includes + store after gui_announced flag**

```c
#include "surf.h"
#define SURF_CREATE 7
#define SURF_DESTROY 8
#define COMPOSE 9
static uint32_t surf[SURF_N][SURF_W*SURF_H];
static uint8_t surf_owner[SURF_N] = {0xFF,0xFF,0xFF,0xFF};
static uint8_t surf_dirty[SURF_N] = {0,0,0,0};
static uint8_t surf_has[11] = {0}; /* indexed by snd tid; 1 = owns a surface */
static uint8_t surf_id_of[11] = {0};
static int gui_composed = 0;
```

Place after `static int gui_announced = 0;` (`v2_main.c:180`). `surf_has` sized 11 = NTHREADS, tid-stamped `snd` always `<11`.

- [ ] **Step 2: Insert RPC arms before legacy FILL path**

In `gui_main` service loop after `if (n < 1) continue;` (`v2_main.c:215`), first replace `(void)ovf;` with `if (ovf != 0) { u_reply(snd, R_DENY); continue; }`, then insert:

```c
if (n >= 2 && buf[0] == (uint64_t)SURF_CREATE) { /* [7, sid, wh, flags] */
    uint32_t sid = (uint32_t)buf[1]; uint32_t wh = (n >= 3) ? (uint32_t)buf[2] : 0u;
    if (n != 4 || sid >= (uint32_t)SURF_N || !surf_wh_ok(wh) || surf_owner[sid] != 0xFF || surf_has[snd]) { u_reply(snd, R_DENY); continue; }
    surf_owner[sid] = (uint8_t)snd; surf_has[snd] = 1; surf_id_of[snd] = (uint8_t)sid; surf_dirty[sid] = 0;
    u_reply(snd, R_OK); continue;
}
if (n == 2 && buf[0] == (uint64_t)SURF_DESTROY) {
    uint32_t sid = (uint32_t)buf[1];
    if (sid >= (uint32_t)SURF_N || surf_owner[sid] != (uint8_t)snd) { u_reply(snd, R_DENY); continue; }
    surf_owner[sid] = 0xFF; surf_has[snd] = 0; surf_dirty[sid] = 0;
    u_reply(snd, R_OK); continue;
}
if (n == 1 && buf[0] == (uint64_t)COMPOSE) {
    /* bound: SURF_N * SURF_H * SURF_W */
    for (uint32_t s = 0; s < (uint32_t)SURF_N; s++) { /* bound: SURF_N */
        if (!surf_dirty[s]) continue;
        /* full-surface blit at fixed slot origin (s*40 % 800, 20 + s*30 % 430) */
        uint32_t ox = (s * 40u) % 800u; uint32_t oy = 20u + (s * 30u) % 430u;
        for (uint32_t r = 0; r < (uint32_t)SURF_H; r++) /* bound: SURF_H */
            for (uint32_t c = 0; c < (uint32_t)SURF_W; c++) { /* bound: SURF_W */
                uint32_t idx = rect_off(ox + c, oy + r);
                if (idx == 0xFFFFFFFFu) continue;
                *(volatile uint32_t *)(GUI_LFB_UVA + (unsigned long)(idx * 4u)) = surf[s][r * SURF_W + c];
            }
        surf_dirty[s] = 0;
    }
    /* chrome strip: top 20px solid qube color */
    for (uint32_t y = 0; y < 20u; y++) /* bound: 20 */
        for (uint32_t x = 0; x < 800u; x++) { /* bound: 800 */
            uint32_t idx = rect_off(x, y);
            *(volatile uint32_t *)(GUI_LFB_UVA + (unsigned long)(idx * 4u)) = 0x00112233u;
        }
    if (!gui_composed) { u_puts("GUI: composed ok\n"); gui_composed = 1; }
    u_reply(snd, R_OK); continue;
}
```

Then modify legacy FILL arm: after `if (n < 4 || buf[0] != FILL)` check, insert surface redirect before LFB write:

```c
if (surf_has[snd]) {
    uint32_t sid = surf_id_of[snd];
    if (surf_owner[sid] != (uint8_t)snd || !surf_fill_ok(sid, x, y, w, h)) { u_reply(snd, R_DENY); continue; }
    for (row = 0; row < h; row++) /* bound: SURF_H */
        for (col = 0; col < w; col++) /* bound: SURF_W */
            surf[sid][(y+row)*SURF_W + (x+col)] = color;
    surf_dirty[sid] = 1;
    u_reply(snd, R_OK); continue;
}
```

Chrome guard for direct path: after `rect_fill_ok` check add `if (y < 20u) { u_reply(snd, R_DENY); continue; }`.

- [ ] **Step 3: Build gui ELF freestanding**

Run: `make -C userspace build/gui.elf 2>&1 | tail -n 3`
Expected: builds with `-Werror`, no warnings. If `surf` `.bss` too large, linker errors — reduce `SURF_W/H`, do not add frames.

- [ ] **Step 4: Commit**

```bash
git add userspace/gui/v2_main.c
git commit -m "s4b: server surfaces + compose on EP10"
```

### Task 4: pilot client legs + QEMU gate + docs

> R1 (2026-10-02): dims shrunk 200x150 → 64x48 (via 80x60; frame-pool fallback) to fit the 32-slot loader window (no-bump); values below updated. R2 (2026-10-02): dims shrunk 64x48 → 40x30 to free tid-10 cap slot 9 for the QX grant, legs resized to `20x10 at (5,5)` (no-bump); values below updated.
> R3 (2026-10-02): S4a clear moved below chrome to `(0,20)+800x580` (no-bump, user.c-only); fullscreen clear would touch server chrome and is correctly DENYed.

**Files:**
- Modify: `kernel/user.c` (thread-A legs), `tools/verify.sh` (smoke expects), `docs/BUILD.md`, `docs/ARCHITECTURE.md`
- Test: QEMU smoke + `tests/test_gui.c`

**Interfaces:**
- Consumes: Task 3 RPCs (`SURF_CREATE 7`, `FILL 6`, `COMPOSE 9`, `R_OK 0`).
- Produces: `GUI: composed ok` marker + updated smoke table.

- [ ] **Step 1: Add S4b legs in user_a_main after 4 FILL legs**

Find S4a 4-leg pattern in `kernel/user.c` (clear + red/green/blue bars, ends before `W1` NOTIFY leg). Append:

```c
/* S4b pilot: create surface 0 40x30, fill 20x10 at (5,5) white, compose. */
{ uint64_t m[4]; m[0]=7; m[1]=0; m[2]=(40u<<16)|30u; m[3]=0; u_send(10, m, 4); u_recv(0, m, 4, &s, &q, &o); }
{ uint64_t m[4]; m[0]=6; m[1]=(5u<<16)|5u; m[2]=(20u<<16)|10u; m[3]=0xFFFFFFFFu; u_send(10, m, 4); u_recv(0, m, 4, &s, &q, &o); }
{ uint64_t m[1]; m[0]=9; u_send(10, m, 1); u_recv(0, m, 4, &s, &q, &o); }
```

Uses existing `u_send/u_recv` locals (`s,q,o` sender/qube/ovf). No string literals (U=0 rule), no globals.

- [ ] **Step 2: Rebuild kernel + userspace, run QEMU smoke locally**

Run: `make -C userspace && make -C kernel && timeout 10 tools/run_qemu.sh 2>&1 | grep -E "GUI:|composed|parking"`
Expected: `GUI: up`, `GUI: fill ok`, `GUI: composed ok`, `no runnable left; parking cpu`.

- [ ] **Step 3: Update docs smoke table**

In `docs/BUILD.md` smoke list after `GUI: fill ok` add `GUI: composed ok # S4b: first COMPOSE`. In `docs/ARCHITECTURE.md` S4b entry flip `[TODO]` → `BUILT (no-bump)`, note `NSURF=4 40x30`, tags `7/8/9`.

- [ ] **Step 4: Commit**

```bash
git add kernel/user.c docs/BUILD.md docs/ARCHITECTURE.md
git commit -m "s4b: pilot surface legs + docs"
```

### Task 5: V2_C proof delta + verify gate

**Files:**
- Modify: `kernel/isabelle/V2_C.thy`, `tools/verify.sh`, `docs/QUBES_ISOLATION_PLAN.md`
- Test: `isabelle build -D kernel/isabelle` (if installed) + `tools/verify.sh`

**Interfaces:**
- Consumes: Tasks 1-4 RPC set.
- Produces: `max_eps=11` unchanged proofs + `AUD`/smoke green.

- [ ] **Step 1: Extend V2_C tag set, no max_eps change**

In `V2_C.thy` find `FILL` tag definition (S4a `max_eps = 11` block). Add `SURF_CREATE=7`, `SURF_DESTROY=8`, `COMPOSE=9` to the message datatype; extend `deliveries⊆sends` + `no_cross_deliver` cases by cloning the FILL case (same EP-separation argument). Do not touch `max_eps`, `pci_scan_covers`, `V2_D`.

- [ ] **Step 2: Run anti-vacuity + build if Isabelle present**

Run: `isabelle build -D kernel/isabelle -v 2>&1 | tail -n 5`
Expected: PASS, no `sorry|axiomatization`. If Isabelle missing, `tools/verify.sh` reports `SKIP (NOT CHECKED)` — acceptable, do not fake proofs.

- [ ] **Step 3: Wire composed marker into verify.sh smoke**

Find QEMU grep block in `tools/verify.sh [4/4]` listing `GUI: fill ok`; append `GUI: composed ok` to the expected list (same `|| echo FAIL` pattern as neighbors — do not change fail-open behavior here; that is a separate fix).

- [ ] **Step 4: Commit**

```bash
git add kernel/isabelle/V2_C.thy tools/verify.sh docs/QUBES_ISOLATION_PLAN.md
git commit -m "s4b: V2_C tags + verify gate"
```
