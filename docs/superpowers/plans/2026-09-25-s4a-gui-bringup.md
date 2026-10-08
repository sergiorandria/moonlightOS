# S4a GUI bring-up Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a layered display stack — gui server binding bochs-display through a minimal PCI scan, thread-A painting the test pattern over IPC — with the full 10→11 cap-bump set replayed and proven.

**Architecture:** Task 1 builds pure pixel/config math headers with host KATs. Task 2 builds the complete gui ELF (scan/bind/map/FILL loop) against the existing 10-thread kernel (unspawned, build-gated only). Task 3 wires boot (spawn, leaves, labels, grants) plus the all-or-nothing bump set. Task 4 replays the proofs. Task 5 drives the 4 client FILLs and gates the markers. Task 6 closes docs.

**Tech Stack:** C (freestanding rv64imac stock clang `-Werror`; host clang for unit tests), RISC-V S-mode (existing handlers/tables only), Isabelle/HOL (session V2), bash (verify.sh/mkinitrd.sh/run_qemu.sh).

**Spec:** `docs/superpowers/specs/2026-09-25-s4a-gui-bringup-design.md` (rev 2, layered)

## Global Constraints

- Freestanding only for kernel/ELF code: `--target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 -ffreestanding -nostdlib` + `-Wall -Wextra -Werror`; follow `CFLAGS_V2`/`LDFLAGS_V2` shapes in `userspace/Makefile:44-48`.
- C subset: no `float`, no function-pointer dispatch (switch on op/tag), no recursion, every loop carries a `/* bound: N */` comment tied to a named constant.
- `kernel/user.c` constraint: no string literals, no globals — immediates + stack locals only (thread-A legs print nothing).
- Fail closed: validation failure parks marker-free or replies DENY with zero pixels touched; missing QEMU markers flip the smoke gate to FAIL.
- Unchanged except the bump set: `V2_MSG_MAX 4` (FILL packs into 4 words), `V2_IPC_Q 16`, `V2_AUDIT_MAX 64`. Bump set (all-or-nothing): `V2_CAP_THREADS`/`NTHREADS` 10→11, `V2_NEP`/`max_eps` 10→11, `V2_QUBES_MAX` 8→9, `V2_FRAMES_MAX` 32→40.
- `tools/verify.sh` single entry: host tests in `[1f]`, markers in `[4/4]`, single QEMU cmdline (extended with `-device bochs-display`, not replaced), no new SKIP.
- Proofs: zero `sorry`/`axiomatization`, no `True`-definitions, mutant per new invariant; never `eval` large numerals (FDE lesson — `simp` for big constants).
- Endpoint/tid/qube map: gui tid 10, EP 10, qube 8, initrd index 10. Tag `FILL 6` (free: T_KEY 8, T_KEY_ACK 10 live elsewhere — reviewer confirms). Replies `R_OK 0`/`R_DENY -1` (live-stage call/response discipline).
- `make -C kernel` does NOT regenerate tracked `kernel/initrd_data.c` — run `tools/mkinitrd.sh` between userspace and kernel builds whenever ELFs change.

---

## File Map

| File | Responsibility |
|---|---|
| Create `userspace/gui/rect.h` | Pure pixel math: offset, FILL validation, bar geometry. Host-testable. |
| Create `userspace/gui/pci.h` | Pure PCI helpers: config-address math, BAR validation. Host-testable. |
| Create `tests/test_gui.c` | KATs for both headers. |
| Create `userspace/gui/v2_main.c` | Server: ECAM scan, bochs bind, LFB map, FILL loop, markers. |
| Create `userspace/gui/gui_start.S` | Entry: set gp, call `gui_main`, park (clone `vault/vault_start.S`, symbol renamed). |
| Modify `userspace/Makefile` | `build/gui.elf` rule (clone vault rule) + `all:`. |
| Modify `kernel/caps.h` | `V2_CAP_THREADS` 10→11, `V2_FRAMES_MAX` 32→40 (+ matrix growth comment). |
| Modify `kernel/qube.h` | Bounds comments (`V2_QUBES_MAX` 8→9). No API change pattern (follow prior bumps). |
| Modify `kernel/kboot.c` | `NTHREADS` 10→11, `ustack_gui` wiring, spawn idx10→tid10, `qube_of[10]=8`, `qube_next=9`, `GUIQ: labels ok`, `GUIMMIO: tid=10 only` leaf + ECAM window map, qube0→gui QX grant + assert. |
| Modify `kernel/user.c` | `ustack_gui[8192]` + top + init; `user_a_main` 4 FILL legs post-clipboard. |
| Modify `tools/mkinitrd.sh` | Append `"gui.elf"` → index 10. |
| Modify `tools/run_qemu.sh`, `tools/verify.sh` | Cmdline + `-device bochs-display`; `[1f]` test line; `[4/4]` +3 marker lines. |
| Modify `kernel/isabelle/V2_C.thy` | `max_eps` 10→11 replay. |
| Modify `kernel/isabelle/Qubes_*.thy` | Bound-lemma replay ONLY if the build breaks (bound-ripple rule). |
| Modify `docs/V2_DESIGN.md`, `docs/QUBES_ISOLATION_PLAN.md`, `docs/ARCHITECTURE.md`, `docs/BUILD.md` | S4a BUILT entries. |

**Scope note:** Tasks 1–2 are host/build-gated with zero boot contact. Task 3 ends with `GUI: up` + leaf markers green (server RECV-waits, no client yet). Task 5 adds the pattern + `fill ok`.

---

### Task 1: Pixel + PCI math headers + KATs (host-only, no boot)

**Files:**
- Create: `userspace/gui/rect.h`, `userspace/gui/pci.h`
- Create: `tests/test_gui.c`
- Modify: `tools/verify.sh` (`[1f]`, after the `test_crypt` line)
- Test: `tests/test_gui.c`

**Interfaces:**
- Consumes: nothing (greenfield; 800×600×32 geometry + virt-machine ECAM base from the spec).
- Produces: `rect_off()`, `rect_fill_ok()`, `pci_cfg_off()`, `pci_bar_ok()` consumed by Task 2 (server links the headers — same freestanding-safe subset).

Constants (exact — reviewer cross-checks both files): `GUI_W 800`, `GUI_H 600`, `GUI_BPP 4`, `GUI_STRIDE (800*4)`, `GUI_FB_MAX (800*600*4)`, `PCI_ECAM_BASE 0x30000000UL`, `PCI_BUS0_ONLY 1`, `BOCHS_VEN/DEV` read from QEMU source by the implementer (spec forbids reproducing from memory — fetch, don't recall; if unreachable, report DONE_WITH_CONCERNS with IDs marked UNVERIFIED and the smoke gate carries).

- [ ] **Step 1: Write `tests/test_gui.c` first** (CHECK idiom, freestanding-safe asserts only — no malloc: use stack arrays like `test_aead.c` does):

```c
/* tests/test_gui.c - KATs for gui/rect.h + gui/pci.h. */
#include <stdio.h>
#include <string.h>
#include "../userspace/gui/rect.h"
#include "../userspace/gui/pci.h"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } while (0) }

int main(void) {
    /* rect_off: origin, last pixel, stride. */
    CHECK(rect_off(0, 0) == 0);
    CHECK(rect_off(799, 599) == (599u * 800u + 799u));
    /* fill_ok: in-bounds, edge-exact, zero-size reject, oob reject,
     * wrap-around reject (x+w < x), stride-overflow reject. */
    CHECK(rect_fill_ok(0, 0, 800, 600));
    CHECK(rect_fill_ok(0, 0, 1, 1));
    CHECK(!rect_fill_ok(0, 0, 0, 1));       /* zero width */
    CHECK(!rect_fill_ok(800, 0, 1, 1));     /* x edge */
    CHECK(!rect_fill_ok(0, 600, 1, 1));     /* y edge */
    CHECK(!rect_fill_ok(799, 599, 2, 2));   /* corner overhang */
    CHECK(!rect_fill_ok(0xFFFFFF00u, 0, 0x200u, 1)); /* wrap */
    /* pci_cfg_off: bus0/dev31/fn7 exact offset. */
    CHECK(pci_cfg_off(0, 31, 7) == (31u * 2048u + 7u * 256u));
    CHECK(pci_cfg_off(1, 0, 0) == (1u * 1048576u));
    /* pci_bar_ok: 16M LFB ok, 0 reject, >64M reject, unaligned reject. */
    CHECK(pci_bar_ok(0x40000000u, 0x1000000u));
    CHECK(!pci_bar_ok(0x40000000u, 0));
    CHECK(!pci_bar_ok(0x40000000u, 0x8000000u));
    CHECK(!pci_bar_ok(0x40000001u, 0x1000u));
    printf("PASS: test_gui\n");
    return 0;
}
```

(If any CHECK above misstates the file's real helper names after you write the headers, fix the TEST to match the headers — headers are authority, but keep every listed case.)

- [ ] **Step 2: Run, watch fail (headers missing)**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_gui tests/test_gui.c 2>&1 | head -n 5`
Expected: FAIL — `gui/rect.h: No such file`.

- [ ] **Step 3: Write the two headers** — portable C99, `stdint.h`/`stddef.h` only, `static inline`, no `malloc`, no host calls. All arithmetic wrap-safe (check `x + w < x` style BEFORE compare). Sizes ~60 lines each; every loop (if any — prefer straight-line) carries `/* bound: */`.
- [ ] **Step 4: Run green + freestanding check**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_gui tests/test_gui.c && /tmp/test_gui`
Expected: `PASS: test_gui`.
Run: `clang --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 -O2 -ffreestanding -nostdlib -fno-builtin -I$(clang --print-resource-dir)/include -fsyntax-only userspace/gui/rect.h userspace/gui/pci.h 2>&1`
Expected: clean.

- [ ] **Step 5: Wire into `tools/verify.sh [1f]`** — after the `test_crypt` line:

```bash
gcc -Wall -Wextra -Werror -o /tmp/test_gui tests/test_gui.c 2>&1 && /tmp/test_gui || echo "FAIL: test_gui"
```

- [ ] **Step 6: Commit**

```bash
git add userspace/gui tests/test_gui.c tools/verify.sh
git commit -m "s4a: gui pixel plus pci math plus KAT tests"
```

### Task 2: gui ELF — scan, bind, map, FILL loop (build-gated, unspawned)

**Files:**
- Create: `userspace/gui/v2_main.c`, `userspace/gui/gui_start.S`
- Modify: `userspace/Makefile` (rule + `all:`)
- Test: `make -C userspace` (ELF builds; NOT spawned — no boot contact)

**Interfaces:**
- Consumes: Task 1 (`rect.h`, `pci.h`).
- Produces: `build/gui.elf` with `gui_main` (Task 3 spawns it); FILL tag 6 + R_OK/R_DENY contract (Task 5 client).

- [ ] **Step 1: `gui_start.S`** — clone `userspace/vault/vault_start.S` verbatim with `vault_main` → `gui_main` (read it first; keep the gp setup + park loop shape).

- [ ] **Step 2: `v2_main.c`** — freestanding, `-fno-builtin` (no `string.h`: hand loops with bounds, S3-ELF precedent). Structure with exact constants:

```c
/* userspace/gui/v2_main.c - L1 display server (qube 8, tid 10).
 * Owns the ONLY display path: ECAM scan, bochs bind, LFB leaf use,
 * FILL service on EP10. Paints NOTHING itself: every pixel arrives
 * through a validated FILL (layered: L2 client drives the pattern).
 * Fill tag FILL=6 (T_KEY 8 / T_KEY_ACK 10 live elsewhere); replies
 * R_OK 0 / R_DENY -1 (call/response discipline). */
#define GUI_TID 10
#define GUI_QUBE 8
#define GUI_EP 10
#define FILL 6
#define R_OK 0L
#define R_DENY (-1L)
```

Loop: `u_recv(GUI_EP, ...)` with stamped sender (ignore sender — any qube WITH a QX grant passes the kernel gate; without QX the SEND never arrives); `buf[0]==FILL && n>=4` → unpack `xy=buf[1]` (`x=xy>>16, y=xy&0xFFFF`), `wh=buf[2]` (`w,h` same), `color=buf[3]` → `rect_fill_ok` → fill via `rect_off` walk (bound: rect area ≤ 800*600, loop `/* bound: GUI_W*GUI_H */`) → first-valid prints `u_puts("GUI: fill ok\n")` once (static flag — ELF servers may use .bss/data: vault keeps KEK tables; confirm v2_user.ld provides data sections, do not guess) → `u_reply(snd, R_OK)`; else `u_reply(snd, R_DENY)` (INVALID shape: silent-drop only if `n<1`, mirroring vault's `not ours` arm — read vault's shape first).
Boot prologue: ECAM scan bus 0 (bound 32 dev × 8 fn, magic-checked, bochs IDs from QEMU source — fetched, with source location in a comment) → BAR0/BAR1 read + `pci_bar_ok` → MAP LFB at scratch vpn via `V2_INV_MAP` on a boot-minted frame? NO — the LFB is an MMIO-leaf range the KERNEL maps (Task 3); the ELF uses the pre-mapped VA (fixed `GUI_LFB_UVA`, value from Task 3's leaf wiring — coordinate: Task 2 defines the WANT (`0x80C00000` proposed, tid-10 table leaf index documented), Task 3 implements it; if Task 3 must differ, Task 2's VA follows Task 3, recorded in the report). → `u_puts("GUI: up\n")` → RECV loop. ECAM window likewise pre-mapped by kernel (`GUI_ECAM_UVA` proposed). Fail-closed everywhere: no match / bad BAR → park marker-free (no `GUI: up`).

- [ ] **Step 3: Makefile rule** — after the cryptblk rule (read exact shape), add:

```make
build/gui.elf: gui/v2_main.c gui/gui_start.S v2_user.ld gui/rect.h gui/pci.h
	$(CC) $(CFLAGS_V2) $(LDFLAGS_V2) -Wl,--no-undefined -o $@ gui/v2_main.c gui/gui_start.S
```

and append `build/gui.elf` to `all:`.

- [ ] **Step 4: Build**

Run: `make -C userspace 2>&1 | tail -n 3`
Expected: `build/gui.elf` listed, zero warnings. (Do NOT pack/boot — unspawned tid 10 would fault the spawn assert. Task 3 wires it.)

- [ ] **Step 5: Commit**

```bash
git add userspace/gui userspace/Makefile
git commit -m "s4a: gui server ELF plus FILL service"
```

### Task 3: Boot wiring + full bump set (ends `GUI: up` green)

**Files:**
- Modify: `kernel/caps.h` (`V2_CAP_THREADS` 10→11, `V2_FRAMES_MAX` 32→40 + matrix comment), `kernel/qube.h` (bounds comments, `V2_QUBES_MAX` 8→9)
- Modify: `kernel/kboot.c` (`NTHREADS`, `ustack_gui` wiring, spawn idx10→tid10, `qube_of[10]=8`, `qube_next=9`, `GUIQ: labels ok`, `GUIMMIO: tid=10 only` + ECAM window map, qube0→gui QX grant + assert)
- Modify: `kernel/user.c` (`ustack_gui[8192]` + top + init — NO thread-A changes yet)
- Modify: `tools/mkinitrd.sh` (append `"gui.elf"` → 10), `tools/run_qemu.sh` (single cmdline + `-device bochs-display`)
- Test: kernel build + QEMU (`GUI: up`, leaf markers; server RECV-waits, no client)

**Interfaces:**
- Consumes: Task 2 (`build/gui.elf`, `GUI_LFB_UVA`/`GUI_ECAM_UVA` wants).
- Produces: spawned server at tid 10/qube 8/EP 10; bump set live (Task 4 replays proofs against it).

- [ ] **Step 1: Display device on the QEMU cmdline** — read the cmdline assembly in `tools/run_qemu.sh` first (VGA_ARGS exists for windowed runs; the SMOKE path is what matters — find which variable the verify smoke uses). Add `-device bochs-display` to the SMOKE cmdline (same line as the virtio-net/blk devices, not a second cmdline). If the smoke runs `--nographic`, confirm devices still instantiate (they do — `-display none` keeps hardware; the markers prove it). STOP-and-ask if the runner refuses display devices headless.
- [ ] **Step 2: Bounds** — `V2_CAP_THREADS` 10→11, `V2_FRAMES_MAX` 32→40 (comment: image ~5 + headroom; LFB is leaf range), `V2_QUBES_MAX` 8→9 (comment only, no API change — follow the prior bump shape), `NTHREADS` 10→11 + `_Static_assert` holds (11<=11; next growth forces WCET re-analysis — comment it).
- [ ] **Step 3: Wiring** — `ustack_gui[8192]` + top + init (user.c, mirrors `ustack_crypt`); spawn initrd 10→tid 8... NO: spawn initrd index 10 → tid 10 (`[spawn] gui ELF ok`, FAIL→parked); `qube_of[10]=8; qube_next=9;` + `GUIQ: labels ok` assert (fail-closed `[demo] FAIL`); ECAM window map + LFB U-leaf ONLY in tid 10's tables at the Task-2 VAs + `GUIMMIO: tid=10 only` assert (mirror the BLKMMIO hunk shape); grant `v2_grant(&caps, 0, 9, 10, 9)` + `qube_has_qx(10)`?? — the grant direction: qube0→gui gives tid 10 a QX cap (covers the SERVER's replies). Thread A holds QX via the qube0 slot-9 root augment (S3 shape — A IS tid 0, slot 9 augmented in place, no delegation needed for A itself). Assert both holders + `[demo] FAIL` on failure.
- [ ] **Step 4: Pack + build**

Run: `make -C userspace 2>&1 | tail -n 1 && tools/mkinitrd.sh 2>&1 | tail -n 2 && make -C kernel 2>&1 | tail -n 2`
Expected: `build/gui.elf`, initrd order `... cat 7, vault 8, cryptblk 9, gui 10`, clean kernel build. (mkinitrd between builds is MANDATORY.)
- [ ] **Step 5: Smoke (server up, no client yet)**

Run: `tools/verify.sh 2>&1 | grep -E "GUI:|GUIMMIO|FAIL|verify done"`
Expected: `GUI: up`, `GUIMMIO: tid=10 only`, zero FAIL. (`GUI: fill ok` absent — no client yet. Task 5.)

- [ ] **Step 6: Commit** (regenerated blob included per tracked-blob convention):

```bash
git add kernel/caps.h kernel/qube.h kernel/kboot.c kernel/user.c kernel/initrd_data.c kernel/initrd.h tools/mkinitrd.sh tools/run_qemu.sh userspace/Makefile
git commit -m "s4a: 11-thread boot plus gui spawn plus leaf asserts"
```

(Drop `initrd.h` if ignored/unmodified — check `git status`.)

### Task 4: Proof replay — max_eps 11 + bound lemmas + PCI scan bounds

**Files:**
- Modify: `kernel/isabelle/V2_C.thy` (`max_eps` 10→11 + replay)
- Modify: `kernel/isabelle/Qubes_*.thy` ONLY IF the 11/9 bump breaks them (bound-ripple rule, minimal diffs)
- Test: `isabelle build -D kernel/isabelle -v` + anti-vacuity greps

**Interfaces:**
- Consumes: Task 3 (11-thread/9-qube build the model must match).
- Produces: replayed session (Task 6 docs cite lemma names).

- [ ] **Step 1: Replay** — `max_eps = 11`; re-run every `V2_C` proof (same scripts + `max_eps_def`; the 10→11 change is a constant swap — if any proof hardcodes 10, generalize it). Qubes bound lemmas pinning 10 threads / 8 qubes (`c_qubes_implies_spec`-family, Qubes_D `c_fde_*_bound`) → 11 / 9 with the same proof shapes. Add PCI-scan bound lemmas in `V2_C` or a new tiny section mirroring `mmio_scan_covers`/`mmio_reach_exact`: bus0-only scan covers the bochs slot; config-offset exactness; BAR-size gate. Mutants per new invariant (scan-miss, oversize BAR, bus-1 device invisible by construction).
- [ ] **Step 2: Build**

Run: `isabelle build -D kernel/isabelle -v 2>&1 | tail -n 3`
Expected: `Finished V2`, all theories 100%. (Absent-Isabelle handling per FDE precedent: DONE_WITH_CONCERNS + grep evidence + CI coverage. Never `eval` large numerals.)
- [ ] **Step 3: Anti-vacuity gates**

Run: `grep -rn "sorry\|axiomatization\|quick_and_dirty\|oops" kernel/isabelle/; grep -rn "equiv> True" kernel/isabelle/*.thy; echo "gate done"`
Expected: empty before `gate done`.
- [ ] **Step 4: Commit**

```bash
git add kernel/isabelle/V2_C.thy kernel/isabelle/Qubes_A.thy kernel/isabelle/Qubes_B.thy kernel/isabelle/Qubes_C.thy kernel/isabelle/Qubes_D.thy
git commit -m "s4a: 11-thread 9-qube proof replay plus pci bounds"
```

(Stage files unchanged by the replay — still list them so reviewers see the ripple was assessed; name any file that DID need a fix in the message.)

### Task 5: L2 client legs + markers (the pattern)

**Files:**
- Modify: `kernel/user.c` (`user_a_main` 4 FILL legs after the clipboard leg)
- Modify: `tools/verify.sh` (`[4/4]`, +3 lines)
- Test: QEMU smoke with the pattern + markers

**Interfaces:**
- Consumes: Tasks 2–3 (server waiting on EP10, QX grant live).
- Produces: screen pattern + `GUI: fill ok` (Task 6 docs).

- [ ] **Step 1: Thread-A FILL legs** — in `user_a_main` after the clipboard leg, before the final park (immediates only, no literals, no prints — marker-free park on deviation; live-stage call/response: SEND expect 0, RECV EP0 expect `[R_OK]`):

```c
    /* S4a display legs: border + 3 bars through the gui server.
     * Words pack lanes (xy = x<<16|y, wh = w<<16|h); 800x600 needs
     * <=10/11 bits per lane. Each leg: SEND (expect 0) + RECV EP0
     * (expect [R_OK]); any deviation parks marker-free. */
    {
        uint64_t fill[4];
        uint64_t rep[4];
        unsigned long s = 0, q = 0, o = 0;
        /* [x, y, w, h, color] legs: border, red, green, blue. */
        static const unsigned long xs[4] = {0, 0, 0, 0};
        ...
    }
```

(NO `static const` — user.c forbids globals/literals pools; write the four legs as straight-line immediates: `fill[0]=6; fill[1]=(x<<16)|y; ...` with literal numbers in code (immediates are fine — the ban is on string literals and pooled data). Rects: border (0,0,800,600 — hmm, border as a filled rect is fullscreen; instead: 4 thin rects? MINIMAL says border + 3 bars. Border = 4 edge rects (top/bottom/left/right, 4px) + 3 horizontal bars (full-width 100px at y=100/250/400, colors red/green/blue). That's 7 legs — or ONE leg per bar + border-as-background? Simplest honest pattern: clear (fullscreen black? needs a fill of 800x600 — legal) + 3 bars = 4 legs. Border detail dropped (minimal!). Legs: [6, 0, (800<<16)|600, black], [6, (0<<16)|100, (800<<16)|100, red], [6, (0<<16)|250, ..., green], [6, (0<<16)|400, ..., blue]. Colors: black 0x00000000, red 0x00FF0000, green 0x0000FF00, blue 0x000000FF (32-bit XRGB — confirm server interprets low 32 bits, document the packing in BOTH files). Each leg: `if (usend(10, fill, 4) != 0) upark(); n = urecv(0, rep, 4, &s, &q, &o); if (n < 1 || rep[0] != 0) upark();`)

- [ ] **Step 2: Smoke gate** — after the `GUIMMIO` line:

```bash
    echo "$V2LOG" | grep -q "GUI: up" && echo "v2 smoke: gui up" || { echo "v2 smoke: FAIL (no gui up)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "GUIMMIO: tid=10 only" && echo "v2 smoke: guimmio leaf" || { echo "v2 smoke: FAIL (no guimmio)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "GUI: fill ok" && echo "v2 smoke: gui fill" || { echo "v2 smoke: FAIL (no gui fill)"; QEMU_FAIL=1; }
```

(Task 3 already gated the first two — Task 5 ADDS the third; if Task 3 gated all three lines, extend, don't duplicate. Read the file first.)

- [ ] **Step 3: Smoke**

Run: `tools/verify.sh 2>&1 | grep -E "v2 smoke: gui|v2 smoke: guimmio|FAIL|verify done"`
Expected: all three new PASS, zero FAIL.

- [ ] **Step 4: Commit**

```bash
git add kernel/user.c tools/verify.sh
git commit -m "s4a: thread-A display legs plus markers"
```

### Task 6: Docs + full verify (stage closure)

**Files:**
- Modify: `docs/V2_DESIGN.md` (§9 S4a → BUILT + refinements + S4b/c TODO), `docs/QUBES_ISOLATION_PLAN.md` (S4 partial: S4a `[HAVE]`, S4b/c `[TODO]`), `docs/ARCHITECTURE.md` (layers table + FILL protocol + verification list), `docs/BUILD.md` (initrd 0–10, transcript, bochs cmdline)
- Test: `tools/verify.sh` end-to-end

**Interfaces:**
- Consumes: Tasks 1–5 artifacts.

- [ ] **Step 1: Update docs** — every BUILT names test/marker/lemma/path; refinements (bochs+PCI choice, layer split, server-paints-nothing, V2_NEP bump mechanics, U-leaf range sizing, `eval`-free proofs); honest remainder (S4b/c, input gap, fallback devices, multi-bus PCI); closed holes named (vga.c fiction stays frozen — untouched).
- [ ] **Step 2: Full verification**

Run: `tools/verify.sh 2>&1 | tail -n 12`
Expected: host PASS (incl. `test_gui`), gates PASS, kernel PASS, QEMU PASS with all GUI markers, Isabelle PASS or pre-existing SKIP only, zero FAIL, no new SKIP.

- [ ] **Step 3: Commit**

```bash
git add docs/V2_DESIGN.md docs/QUBES_ISOLATION_PLAN.md docs/ARCHITECTURE.md docs/BUILD.md kernel/initrd_data.c kernel/initrd.h
git commit -m "s4a: docs mark stage built with proof-test links"
```

---

## Self-Review

- **Spec coverage:** §1 theorems/markers → Tasks 4–5; §2 env/fiction/kbd notes → Task 3 cmdline + Task 6 honest remainder; §3 layers/invariants/bumps → Tasks 2–3 (each invariant: single leaf asserted Task 3, no kernel display code by construction, addressed IPC Task 2–3, least-privilege review Task 5); §4.1 scan → Tasks 1–2 (math + ELF); §4.2 server/FILL → Task 2 (loop, validation, tag-6 check, markers); §4.3 client → Task 5 (4 legs, QX via Task 3 grant); §4.4 wiring → Task 3; §5 flow → Tasks 3+5 order; §6 table → Tasks 2–3 (each row: absent→park, MAP-fail→park, resolution→park, fault→park/assert, cross-touch→impossible); §7 host/smoke/gates/proofs → Tasks 1/4/5; §8 non-goals → none tasked; §9 exit → Tasks 1–6 gates.
- **Placeholder scan:** no TBD/TODO/later/appropriate/edge-cases/similar-to; every code step ships concrete constants (EP/tid/qube/index 10/10/8/10, tag 6, V2_NEP 11, FRAMES 40, geometry 800×600×4, ECAM base, slot 9, reply codes, marker strings), commands and expected outputs. Open reads owned explicitly (bochs IDs from QEMU source, VGA_ARGS/SMOKE cmdline shape, v2_user.ld data sections, `initrd.h` tracked-or-not, net.send-style DST precedents — none new).
- **Type consistency:** `GUI_TID/GUI_EP 10`, `GUI_QUBE 8`, initrd 10, `FILL 6`, `R_OK 0`/`R_DENY -1`, `V2_NEP`/`max_eps` 11, `V2_QUBES_MAX` 9, `V2_FRAMES_MAX` 40, `GUI_W/H/BPP` + stride math identical in test and header, `ADMIN_LIVE_BIT`-style defines pattern followed (new defines commented), marker strings identical across ELF/gate/docs.
