# S4a GUI bring-up: framebuffer + server skeleton + cap bump

**Status:** Design approved 2026-09-25 (minimal GUI binding), awaiting
implementation plan
**Depends on:** S3 BUILT (virtio scan-then-bind pattern, exact-bounds
MMIO U-leaf, `Qubes_C`), live-qrexec BUILT (addressed EPs, broker
table, `V2_C` indexed), FDE BUILT (10-thread boot at cap)
**Decides:** bochs-display via a minimal PCI scan; per-thread EP11 for
the gui server; full cap-bump set with replay; test-pattern-only demo
**Constraints (binding):** MINIMAL GUI — pattern + two markers, nothing
else (no text, no input, no surfaces, no console migration, no
fallback device); microkernel intact; serial console stays primary;
`verify.sh` single entry (markers in `[4/4]`, single cmdline extended
with the display device, no new SKIP); C subset; fail closed

---

## 1. Goal

A `gui` server owns the display and proves it with pixels. Everything
else (surfaces, chrome, input) builds on the server, the endpoint,
and the bumped caps shipped here.

**Theorems:** no new ones. Replay `V2_C` (`max_eps` 10→11) and the
Qubes bound lemmas pinning 10 threads / 8 qubes; add PCI-scan bound
lemmas (`pci_scan_covers`, config-space exactness) in the style of
`mmio_scan_covers`. Mutants per new invariant; 0 sorry.

**Demos (QEMU text markers, fail-closed):** `GUI: up` (server mapped
the LFB and painted), `GUIMMIO: tid=10 only` (U-leaf exclusivity
asserted at boot like `NETMMIO`/`BLKMMIO`).

---

## 2. Background / what exists

- QEMU offers bochs-display (PCI bus), ramfb (System bus, fw_cfg
  configured), virtio-gpu (virtio bus); `run_qemu.sh` prefers bochs
  first and already wires `-display` + virtio-keyboard for windowed
  runs. The smoke runs with a display (not `--nographic`) for this
  stage — one cmdline, extended, not replaced.
- `userspace/drivers/vga.c` is frozen v1 host-sim fiction (fixed
  `0x40000000` framebuffer, never mapped by the v2 kernel) — shape
  reference for pixel math only, NOT ported.
- `run_qemu.sh` references `kbd.c` (virtio-keyboard merge) — that
  file does not exist in-tree. Honest gap, owned by S4c, not this
  stage.
- NTHREADS == V2_CAP_THREADS == 10 (at cap), V2_NEP == max_eps == 10,
  V2_QUBES_MAX == 8, V2_FRAMES_MAX == 32. No free tid: the gui
  server forces the full bump set (§3).

---

## 3. Architecture

```
QEMU bochs-display (PCI) <--ECAM scan-- gui ELF (tid 10, qube 8)
                                          |-- LFB U-leaf (tid-10-only,
                                          |   W never X, BAR-sized)
                                          |-- paints 3 bars + border
                                          |-- parks (no IPC in S4a)
Kernel (S-mode): unchanged roles — ECAM window map (like MMIO
leaves), cap enforcement, label stamps, spawn. No new syscalls.
```

Cap bump set (all-or-nothing, each with its assert/proof):
`V2_CAP_THREADS`/`NTHREADS` 10→11, `V2_NEP`/`max_eps` 10→11,
`V2_QUBES_MAX` 8→9 (`qube_next` ends at 9), `V2_FRAMES_MAX` 32→40
(image ~5 + headroom; the 448-page LFB is MMIO-leaf range, never
pool frames). WCET re-analysis note ships with the bump (any growth
forces it — same rule as FDE). Initrd index 10, EP 10 owned by tid
10. No QX grants (no cross-qube IPC yet).

---

## 4. Components

### 4.1 Minimal PCI scan (new, kernel or U-mode? KERNEL maps, ELF scans)

ECAM base is virt-machine fixed (`0x30000000`, 256 buses — probed
with magic check, never assumed present): scan bus 0 only first
(QEMU places bochs on bus 0; full 256-bus scan is YAGNI until USB),
match vendor/device for bochs (exact IDs read from the QEMU source
by the implementer — spec does not reproduce them from memory),
read BAR0 (LFB, prefetchable mem) + BAR1 (registers). Fail-closed:
no match / bad magic / BAR size absurd (>64M) ⇒ park marker-free.
Bound comments on every loop. Reusable by USB-xHCI later (stated,
not built).

### 4.2 gui server (`userspace/gui/v2_main.c` + `gui_start.S`)

Freestanding ELF, own qube: ECAM scan → bind → `PT_ALLOC`+`MAP` the
LFB range at a scratch vpn (single mapping, UNMAP after paint? NO —
keep mapped; S4b composites into it. UNMAP discipline returns in
S4b) → paint: border + 3 horizontal bars (red/green/blue, exact
pixel values in code, derivable: `0x00FF0000` etc.) → `GUI: up` →
park. No RECV loop (no IPC yet — a parked server holds no waiter,
so EP10 stays empty and cannot misdeliver). 8K stack (qrexec
precedent: driver + staging). No prints in the map/paint path
except the two markers (grep-gate discipline like `T_KEY`).

### 4.3 Boot wiring (mirrors FDE/vault Task-3 shape)

`kernel/user.c`: `ustack_gui[8192]` + top + init. `kernel/kboot.c`:
spawn initrd 10→tid 10, `qube_of[10]=8`, `qube_next=9`,
`GUIQ: labels ok` assert (fail-closed `[demo] FAIL`), `GUIMMIO:
tid=10 only` leaf assert (same shape as `NETMMIO`/`BLKMMIO`).
`userspace/Makefile` + `tools/mkinitrd.sh` (append `gui.elf` → 10).
`tools/run_qemu.sh` + `verify.sh`: single cmdline gains
`-device bochs-display`.

---

## 5. Data flow (boot)

1. Kernel spawns 0–10; in-kernel demos run (unchanged).
2. Gui ELF runs: scan → bind → map → paint → `GUI: up` → park.
3. Boot asserts print `GUIQ: labels ok`, `GUIMMIO: tid=10 only`.
4. Everything else identical (serial primary; all prior markers).

---

## 6. Error handling (fail closed)

| Case | Behavior |
|---|---|
| No bochs on bus 0 / bad magic | Park, no markers → gate FAILs |
| BAR size absurd / MAP fails | Park marker-free → FAIL |
| Wrong resolution (not 800×600×32?) | Server programs VBE for 800×600×32 explicitly; mismatch → park (no scaling code — minimal) |
| LFB write fault | Park (mapping was wrong — the leaf assert catches it first) |
| Any other thread touches LFB | Impossible by construction (single leaf, tid-10-only, asserted) |

---

## 7. Testing

- Host unit (`tests/test_gui.c`, `verify.sh [1f]`): bar/rect math
  (offsets, stride 800, bounds reject, border geometry) over a
  malloc'd shadow buffer; PCI config-address math (bus/dev/fn →
  offset); BAR size validation edges.
- QEMU smoke (`[4/4]`, +2 lines): `GUI: up`, `GUIMMIO: tid=10 only`.
  Missing ⇒ FAIL. All prior markers unchanged.
- Production gates unchanged. No key material anywhere near this
  stage; no log-content gate needed.
- Isabelle: `V2_C` replay (`max_eps` 11) + Qubes bound-lemma replay
  (10→11 threads, 8→9 qubes) + `pci_scan_covers`-style lemmas;
  mutants; 0 sorry; KAT-correspondence n/a (no crypto).

---

## 8. Non-goals (binding minimal GUI)

Text rendering, input/keyboard (`kbd.c` gap stays open for S4c),
per-qube surfaces, compositor, trusted chrome, focus, clipboard,
console migration (serial stays primary), fallback display devices,
multi-bus PCI scan, resolution negotiation, cursor, power management.

---

## 9. Exit criteria

- [ ] PCI scan + bochs bind + LFB leaf + pattern + park, all
      fail-closed; `GUI: up`, `GUIQ: labels ok`,
      `GUIMMIO: tid=10 only` green.
- [ ] Full bump set with asserts + WCET note + proof replay green.
- [ ] Host pattern/config tests green; `verify.sh` full-pass (new
      tests in `[1f]`, markers in `[4/4]`, single cmdline, no SKIP).
- [ ] Docs: `V2_DESIGN.md` §9 S4a BUILT + refinements; `QUBES` §11 S4
      partial (S4b/c stay TODO); threat model unchanged (display is
      output-only this stage — input attacks arrive in S4c).
