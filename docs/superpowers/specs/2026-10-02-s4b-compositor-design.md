# S4b Compositor + Surfaces — Design (rev 1)

**Status:** Approved sections 1-5 in chat 2026-10-02. No-bump slice: stays in `tid10/EP10/qube8`.
**Depends on:** S4a BUILT (bochs bind + FILL service + 4-leg pattern, bump set 11/11/9/40).
**Non-goals:** Input/focus, clipboard RPC, alpha/resize, new threads/EPs (all S4c).

## 1. Architecture (no-bump)

Stays in `tid10 / EP10 / qube8`. No `NTHREADS`, `V2_NEP`, `V2_CAP_THREADS`, `V2_FRAMES_MAX` changes. New RPC tags ride the existing `u_recv(GUI_EP, buf, 4)` loop in `userspace/gui/v2_main.c:205`.

Server owns up to `NSURF=4` offscreens, each `40x30x4` max (fixed at compile time, gui-private `.bss` already mapped to tid10 — no new leaves, no ECAM change). R2 correction: `64x48` (49,152 B BSS, 13 pages, gui 14 frames) occupied tid-10 cap slots 0..13, colliding with the slot-9 QX grant (`kboot.c:2106`, `caps.h:235-236`) → `[demo] FAIL gui qx grant`; shipped `40x30` (`4*40*30*4 = 19,200 B` BSS, ~5 pages, gui ~6-7 pages, slots 0..6, slot 9 FREE for the grant, pool ~29/39). R1 history: rev 1 shipped `200x150` (480KB, ~118 pages — rejected by the 32-slot loader window, `V2_ERR_OVERFLOW`); `80x60` (76.8KB, 19 pages) passed the loader but exhausted the 39-frame pool at spawn (22 frames already taken by the 7 earlier ELFs, gui needed 20). LFB at `0x80C00000` stays the only display path; clients never name pixels outside their surface.

Layers: L0 kernel (EP routing + `GUIMMIO: tid=10 only` unchanged) → L1 gui server (surface store + compositor + chrome) → L2 clients (qube0 + one pilot qube, e.g. vault status) via `SEND EP10`.

## 2. RPCs + data flow (fits V2_MSG_MAX=4)

- `SURF_CREATE=7 [7, surf_id, wh, flags]` — `surf_id 0..3`, `wh = w<<16|h` (validated `w*h*4 <= SURF_MAX`, `w,h !=0`), `flags=0` reserved. One surface per creator (kernel-stamped `snd` owns it); create auto-binds that surface as the sender's paint target. No multi-surface-per-sender in S4b.
- `FILL=6 [6, xy, wh, color]` — unchanged shape. New rule: if sender has a bound surface, paint to offscreen via existing `rect_fill_ok` shifted to surface origin; else legacy direct-to-LFB (kept for S4a 4-leg pattern + `GUI: fill ok` marker).
- `SURF_DESTROY=8 [8, surf_id]` — owner-only free, else `R_DENY`.
- `COMPOSE=9 [9]` — any surface owner may call; composites all dirty surfaces in fixed `surf_id` order to LFB, then chrome strip. Single `GUI: composed ok` marker. Any other word count → `R_DENY`.

Flow: client `SEND EP10` → server `RECV` (validates `sqb` owner, `ovf` deny) → surface store → `u_reply(snd, R_OK/R_DENY)`. Server paints nothing except chrome; every client pixel arrives via validated `FILL`.

Back-compat: S4a thread-A 4 FILL legs still pass (no bound surface → direct), `verify.sh` smoke markers unbroken.

## 3. Surfaces + composite + chrome

Store: `static uint32_t surf[NSURF][SURF_W*SURF_H]` in gui `.bss` (no malloc; total `4*40*30*4 = 19,200 B (~5 pages BSS, gui ~6-7 pages, slots 0..6, slot 9 free for the QX grant)`). R2 correction: was `4*64*48*4 = 49,152 B` (~13 pages BSS, gui 14 pages, slots 0..13 — occupied slot 9, grant failed); before that `4*200*150*4 = 480KB` (~118 pages, overflowed the loader); `80x60` intermediate exhausted the frame pool. Companion fix: `surf_owner` is zero-init (BSS) + runtime `0xFF` fill — a nonzero initializer would emit a 4-byte `.data` that pushes `.bss` off page alignment, which the loader rejects (`elf.c:147`). `static uint8_t surf_owner[NSURF]` (`0xFF` = free) + dirty bits. All loops carry `/* bound: NSURF / SURF_H / SURF_W */`.

Composite: fixed `surf_id` ascending, last-wins, clipped to `800x600` via `rect_off`. No alpha/scaling — blit dirty rects only. Chrome: top 20px reserved server-only — client `FILL` with `y<20` denied, server fills owner color + qube id after each `COMPOSE`.

Isolation: cross-surface reads impossible (index by `snd`-owned id only), LFB writes only in `COMPOSE`, ECAM untouched after `gui_bind_lfb`.

## 4. Error handling (fail-closed)

Bad `surf_id`, zero/oversize, unowned, chrome touch, `ovf!=0`, wrong `n` → `R_DENY`, zero pixels touched, single reply. Double-create → `DENY` (must destroy first). Destroy non-owned/missing → `DENY`. `COMPOSE` with clean surfaces → `R_OK`, no LFB touch (idempotent). Kernel `sqb` check + per-surface owner check — either denies alone.

## 5. Tests + proofs + markers

- Host KATs: new `surf.h` pure logic (origin/last-pixel, chrome reject, wrap-safe `xe<x`, owner isolation, dirty idempotence) in `tests/test_gui.c`, `verify.sh [1f]`, `-Werror`.
- Proofs: `V2_C` delta only — new tags in `deliveries⊆sends`, `ep_separation` unchanged (`max_eps=11`), `pci_scan_covers` untouched. No `V2_D` change. Anti-vacuity gate unchanged.
- QEMU: keep `GUI: up` / `GUI: fill ok`, add `GUI: composed ok` once. Update `BUILD.md` smoke table, `ARCHITECTURE.md` S4b → BUILT, `QUBES_ISOLATION_PLAN.md` checkbox.

## Open S4c (not this spec)

Per-qube dynamic sizes, focus gesture, keyboard/pointer routing (`kbd.c`), clipboard RPC, trusted label rendering beyond color strip.
