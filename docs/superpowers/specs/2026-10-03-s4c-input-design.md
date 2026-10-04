# S4c Input Takeover — Design (rev 1)

**Status:** Sections 1-4 approved in chat 2026-10-03. Takeover of in-tree WIP
(userspace VirtIO input + console; kernel edits pending).
**Depends on:** S4b BUILT (40x30 surfaces, slot-9 grant, `composed ok` green).
**Non-goals:** Focus/qube-separated keystrokes, clipboard RPC, ANSI/VT100,
mouse-button actions, any kernel constant bump.
**As-built:** §5 landed 2026-10-04 (Task 5); §§1-4 verbatim as approved.

## 1. Userspace audit scope

Files: `v2_main.c` S4c additions (~230 lines), `virtio_input.h`, `input.h`,
`console.h`, `font_8x16.h` (data). S4b code is frozen reference — fixes must
keep SURF_CREATE/FILL/COMPOSE, the chrome guard, and BSS ≤ ~8 pages so the
slot-9 QX grant survives (see S4b R1/R2).

Lenses: volatile MMIO discipline, 16-slot ring bounds + `desc_id`
validation, keycode-table bounds, 100x37 grid clipping, `/* bound: */`
comments, `-Werror` clean. Console is single-qube for now (recorded below).

## 2. Kernel edits (S4b-adapted, 2 commits)

(i) Definitions + leaves: `VIRTIO_DEV_INPUT`, kbd/mouse IRQ bits/vars,
`l0_kbdmmio`/`l0_mousemmio`, init loops, `l1_t[10][9]`/`[10]` wiring (both
free: tid10 uses 6,7,8 today). (ii) IRQ handler + discovery/PLIC + QEMU
cmdline devices. Extend the `mmio_ok` boot asserts (`kboot.c:2132,2164`) to
the new leaves. No slot/constant changes; if userspace wants more (e.g. a
statusq ring), it shrinks instead.

## 3. Gates + proofs + QEMU acceptance

Host: `test_gui` green; new KATs only for new pure helpers. Proofs: `V2_C`
notify/wait integrity over the new IRQ source + `pci_scan_covers` extension;
`max_eps`/slots untouched. QEMU must show `INPUT: kbd found`, `INPUT: mouse
found`, all S4b markers, live typing + 37-row scroll, park line, zero
FAIL/EXHAUSTED. `verify.sh [4/4]` gains the `INPUT:` greps fail-closed.

## 4. Retro-spec + landing

After green: update this doc to as-built, flip `V2_DESIGN.md` §9 S4c entry
with honest remainder (focus, clipboard, ANSI), update Qubes input-routing
checkbox. Userspace commit, then kernel commit, then spec commit. Root-level
S4C_*.md / add_input_support.py moved under `docs/` or removed at landing.

## Open S4c-remainder (not this track)

Per-qube focus + keystroke routing, trusted input indicator, clipboard RPC,
ANSI colors, dirty-region console redraw.

## 5. As-built deltas (Task 5 landing record)

Shipped (commits `238e290..f104b1a`, Tasks 1-4 + Task 5 micro-items):

- Userspace (`userspace/gui/v2_main.c`): `input_armed` armed at runtime
  (`=1` assignment — an initializer would move the flag to `.data`, and
  `v2_user.ld` lays `.data` immediately before `.bss` with no ALIGN
  between, so the linker splits the RW segment into a file-backed
  `.data` LOAD plus its own BSS LOAD at data-end (measured
  `0x80803008` for a 4-byte `.data`); `v2_elf_plan` (`kernel/elf.h`)
  rejects any PT_LOAD with `(p_vaddr & PAGE_MASK) != 0` → `[spawn] gui
  ELF FAIL`, both shapes measured with `readelf`). Phase-split loop:
  phase 1 serves the one-shot FILL/COMPOSE stream with the S4b path
  pristine (no WAIT inside — a WAIT-before-RECV would park at boot and
  wedge the S4b SEND stream, which never NOTIFies); on COMPOSE break to
  phase 2 = WAIT-driven input, poll-only-when-notified, console
  takeover (`INPUT: console live`) + serial echo per placed char.
  Dev-18 discovery scan over all 8 slots (reads only): first dev-18 in
  scan order is the mouse, second the keyboard (QEMU attaches backends
  last-first — measured: keypresses claim the second slot's IRQ; a
  `config.subsel` read would remove the order assumption). Queue PAs
  via `V2_INV_FRAME_PA` + `fence iorw,iorw` (the WIP's
  guest-physical = user-virtual was wrong: U VAs alias PAs through the
  frame window). Console 100x37 (`CONSOLE_COLS`/`CONSOLE_ROWS`);
  `font_8x16.h` trimmed 256→128 glyphs (upper half blank/unreachable)
  so `gui.elf` stays 9 mapped pages (max vpn 8 — the slot-9 QX grant);
  render indexes masked `ch & 0x7F` (Task 5, defense-in-depth).
- Kernel (`kernel/kboot.c`): `l1_t[10][9]` kbd / `l1_t[10][10]` mouse
  U-leaves (boot-asserted `GUIMMIO: tid=10 only`);
  `KBD_IRQ_BIT 0x4UL` / `MOUSE_IRQ_BIT 0x8UL` → tid-10 notify (+
  wake-delivery `regs[10]=pending`, `enter_thread` scheduling from the
  handler); post-halt IRQ wake (SIE re-enable at halt, `halt_ctx` save
  area, `sscratch` at the trap stack); discovery mouse-first with
  `INPUT: kbd found` / `INPUT: mouse found` markers. No slot/constant
  changes (`max_eps = 11` untouched).
- Proofs (`kernel/isabelle/V2_C.thy`, 0 sorry, 0 axioms): kbd/mouse
  notify integrity / accumulates / wakes-gui / keeps-rendezvous /
  take-clears (incl. `by eval` pins on raw 4/8) + `input_scan` /
  `input_leaf` transport family (`input_mmio_covers`,
  `input_tid10_only`, tid-9 mutant pin, `input_invariants_nontrivial`
  falsifiability lemma).
- Gates: `tests/test_input.c` KATs (`PASS: test_input` — keycode,
  Shift/Ctrl incl. table-derived Ctrl evidence, mouse clamp, 40-line
  scroll → `cursor_y==36`); `verify.sh [1f]` runs `test_input`,
  `[4/4]` gains both virtio input devices on the QEMU cmdline + three
  fail-closed `INPUT:` greps (`kbd found`, `mouse found`, `kbd and
  mouse ready` — the third proves arming); `run_qemu.sh` attaches the
  devices conditionally.
- Acceptance: armed canary (`-nographic` + input devices) prints
  `INPUT: kbd found`, `INPUT: mouse found`, `GUI: up`, `INPUT: kbd and
  mouse ready`, `GUI: fill ok`, `GUI: composed ok`,
  `INPUT: console live`, parks clean — zero FAIL/EXHAUSTED. Live VNC
  acceptance (KeyEvent client): lowercase a–z + Enter, `Shift+A`→`A`,
  `abc`+Backspace, 40× `scroll-NN` lines — all echoed in order, two
  full-green runs, S4b markers intact.

### Wake-path model-gap scope-out (reviewer-ordered)

The `V2_C.thy` input pins cover notify/wait integrity and transport
ownership over raw nat signals. They do NOT model the kboot post-halt
wake path: the `halt_ctx` save area, the SIE re-enable at halt, the
wake-delivery `regs[10]` pre-delivery, and the
`enter_thread`-from-handler scheduling. That path is verified by the
armed canary + live VNC runs only. Scoped out of the model
deliberately — it needs its own halt-machine spec, not a lemma
bolt-on. Recorded here so the landing does not overclaim proof
coverage of the wake path.

### KNOWN ISSUE — burst-typing race (PARKED, top remainder)

Symptoms: under sustained rapid typing the guest can take a store
page fault (`cause=0xf`) whose printed epc is the trap-entry `sd`
with a U-stack `tval`; the fault handler then parks the GUI (input
dead from there, fault loop) — always WITHOUT any FAIL/EXHAUSTED
marker corruption and WITHOUT affecting gates (canary/verify/KATs
deterministic green). Rate: ~1 in 3 burst runs; singles/paced typing
100% clean across ~1500 input IRQs (two full-green live runs + paced
green). Prime suspect (UNPROVEN): return-path + still-asserted-level
re-trap nesting vs `sscratch`/SUM discipline under burst overlap.
Proposed follow-up: reproduce with QEMU `-d int`, then a trap-aware
debug session (RISC-V GDB absent in this environment) or a `trap.S`
save-area audit. Until then: pace acceptance typing (no rate is
required) and treat burst-hardening as open — it needs its own
GDB-level spec, not a fix-round scramble.

### Honest S4c remainder (next track)

Per-qube focus + keystroke routing, trusted input indicator,
clipboard RPC, ANSI colors/attributes, dirty-region console redraw, F1
surface/console toggle, mouse-button actions, key-repeat (value 2
ignored by design), CP437 upper half, VNC-visible mode-setting (pixels
VOID in this setup: unprogrammed bochs mode shows 640×480 black;
render path verified by audit + KATs + serial echo), `config.subsel`
discovery (remove the last-first order assumption), burst-race
hardening above.
