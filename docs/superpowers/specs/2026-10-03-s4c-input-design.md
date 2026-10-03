# S4c Input Takeover — Design (rev 1)

**Status:** Sections 1-4 approved in chat 2026-10-03. Takeover of in-tree WIP
(userspace VirtIO input + console; kernel edits pending).
**Depends on:** S4b BUILT (40x30 surfaces, slot-9 grant, `composed ok` green).
**Non-goals:** Focus/qube-separated keystrokes, clipboard RPC, ANSI/VT100,
mouse-button actions, any kernel constant bump.

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
