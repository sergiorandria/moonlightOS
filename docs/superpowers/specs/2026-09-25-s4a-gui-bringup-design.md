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

**Demos (QEMU text markers, fail-closed):** `GUI: up` (server bound
the display and serves), `GUIMMIO: tid=10 only` (U-leaf exclusivity
asserted at boot like `NETMMIO`/`BLKMMIO`), `GUI: fill ok` (first
client `FILL` served — proves the L2 path; the test pattern itself
is 4 client FILLs, nothing server-painted).

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

## 3. Architecture — layered, microkernel-faithful

```
Layer                    Owner          Hardware touch   IPC
L0 address mechanics     kernel         maps leaves only  none (existing gates)
L1 display server        gui ELF t10/q8 Binds PCI, owns   serves FILL on EP10,
                                        LFB leaf         replies R_OK/R_DENY
L2 paint client          thread A       NONE — pixels    SENDs FILL to EP10,
                        (qube 0)        only via server  RECVs reply on EP0
L3+ (S4b/c, not built)  future ELFs    via server RPCs  new RPCs, own bumps
```

Microkernel invariants (binding — this stage must not break them):
- Exactly one hardware path: LFB + ECAM windows map ONLY into tid
  10's tables (boot-asserted `GUIMMIO: tid=10 only`, same shape as
  `NETMMIO`/`BLKMMIO`); kernel holds no display code (no PCI
  structs, no pixel math — mechanics only); no ambient caps (the
  server's reach comes from boot-minted mappings, reviewable at the
  wiring site).
- All cross-layer traffic is addressed IPC with kernel-stamped
  senders: client→server `FILL` on EP10 (raw-gated qube0→qube8 via
  one QX grant, S3/FDE shape), server→client `R_OK`/`R_DENY` reply
  to stamped `snd` on EP0 (live-stage call/response discipline).
- Least privilege per layer: the client cannot name a pixel except
  through validated `FILL` rects; the server cannot touch any other
  qube's memory; S4b/c add RPCs — never mappings.

Cap bump set (all-or-nothing, each with its assert/proof):
`V2_CAP_THREADS`/`NTHREADS` 10→11, `V2_NEP`/`max_eps` 10→11,
`V2_QUBES_MAX` 8→9 (`qube_next` ends at 9), `V2_FRAMES_MAX` 32→40
(image ~5 + headroom; the 448-page LFB is MMIO-leaf range, never
pool frames). WCET re-analysis note ships with the bump (any growth
forces it — same rule as FDE). Initrd index 10, EP 10 owned by tid
10. One QX grant: qube0→gui (tid 10 slot 9 — covers A's FILLs;
holder-based, so the server's replies ride the same grant).

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

Freestanding ELF, own qube: ECAM scan → bind → map LFB at a scratch
vpn (stays mapped; S4b composites into it) → `GUI: up` → RECV loop
on own EP10 serving one RPC. The server paints NOTHING itself —
every pixel on screen arrives through a validated `FILL` (maximally
layered: even the test pattern is client-driven):

```
FILL [6, xy, wh, color]  client -> server (xy = x<<16|y, wh = w<<16|h;
                         800×600 needs ≤10/11 bits per lane)
  server: validate 0<=x, x+w<=800, 0<=y, y+h<=600 (wrap-safe) → fill
          → reply R_OK; else reply R_DENY, no pixels touched.
  anything else → R_DENY (INVALID), no state change.
```

First valid FILL additionally prints `GUI: fill ok` (proves the
client path ran; the boot paint is server-local). 8K stack (qrexec
precedent). No prints in the map/paint path except the markers
(grep-gate discipline like `T_KEY`). Tag 6 is free in message-tag
space (T_KEY 8, T_KEY_ACK 10 live elsewhere — reviewer checks).

### 4.3 L2 client: thread A drives the pattern (no new thread)

After the clipboard leg parks... no — A extends its live-legs tail:
post-`W1` WAIT (admin handshake, unchanged), keys.sign leg, clipboard
leg, then 4 FILL legs to EP10 (border + 3 bars, immediates-only
rects baked as words, no literals per the `user.c` constraint),
each SEND (expect 0) + RECV EP0 (expect `[R_OK]`), marker-free park
on any deviation — the live-stage call/response discipline verbatim.
QX grant qube0→gui covers the cross-qube SENDs (§3).

### 4.4 Boot wiring (mirrors FDE/vault Task-3 shape)

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
2. Gui ELF runs: scan → bind → map → `GUI: up` → RECV-waits EP10.
3. Boot asserts print `GUIQ: labels ok`, `GUIMMIO: tid=10 only`.
4. Thread A (post-handshake, post-qrexec-legs): 4 FILL legs → first
   valid one prints `GUI: fill ok` on the server → A parks.
5. Everything else identical (serial primary; all prior markers).

---

## 6. Error handling (fail closed)

| Case | Behavior |
|---|---|
| No bochs on bus 0 / bad magic | Park, no markers → gate FAILs |
| BAR size absurd / MAP fails | Park marker-free → FAIL |
| Wrong resolution (not 800×600×32?) | Resolution ASSUMED 800×600×32 from QEMU bochs-display default, unchecked — explicit VBE programming deferred to S4b; mismatch paints with wrong stride (smoke is marker-only, no pixel check) |
| LFB write fault | Park (mapping was wrong — the leaf assert catches it first) |
| FILL rect out-of-bounds / wrap-around | `R_DENY`, zero pixels touched (validate-then-paint; wrap-safe arithmetic) |
| Unknown tag on EP10 | `R_DENY` (INVALID), no state change |
| FILL from non-qube-0 sender | Kernel raw gate is holder-based (any QX holder passes) — server enforces qube0-only (`sqb != 0` → `R_DENY`, zero pixels touched) |
| Server not yet waiting when A calls | Rendezvous queues + A blocks (single-flight; no race) |

---

## 7. Testing

- Host unit (`tests/test_gui.c`, `verify.sh [1f]`): FILL validation
  matrix (in-bounds accept, edge-exact accept, x+w overflow reject,
  zero-size, wrap-around via `x+w < x` reject), pixel-offset math
  (stride 800, `y*stride+x` bounds), PCI config-address math
  (bus/dev/fn → offset), BAR size validation edges — over a
  malloc'd shadow buffer + pure helpers.
- QEMU smoke (`[4/4]`, +3 lines): `GUI: up`, `GUIMMIO: tid=10 only`,
  `GUI: fill ok`. Missing ⇒ FAIL. All prior markers unchanged.
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

- [ ] PCI scan + bochs bind + LFB leaf + FILL service + QX grant,
      all fail-closed; `GUI: up`, `GUIQ: labels ok`,
      `GUIMMIO: tid=10 only`, `GUI: fill ok` green; thread-A 4-FILL
      pattern (border + 3 bars) is the only screen content.
- [ ] Full bump set with asserts + WCET note + proof replay green.
- [ ] Host pattern/config tests green; `verify.sh` full-pass (new
      tests in `[1f]`, markers in `[4/4]`, single cmdline, no SKIP).
- [ ] Docs: `V2_DESIGN.md` §9 S4a BUILT + refinements; `QUBES` §11 S4
      partial (S4b/c stay TODO); threat model unchanged (display is
      output-only this stage — input attacks arrive in S4c).
