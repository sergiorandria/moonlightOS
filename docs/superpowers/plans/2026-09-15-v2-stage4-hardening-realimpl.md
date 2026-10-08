# v2 Stage 4: Hardening + Real implementation (caps <-> Sv39 MMU)

Date: 2026-09-15
Branch: `fix-isabelle-2025`
Base: `285c89f` (Stage 3 complete: per-thread `vspace_root_ppn`, frame pool,
V2_INVOKE, mem_server as thread 2, test_cap_thread, whole-branch review fixes)

## 1. Objective

Close the gap between the abstract capability model (`caps.h` / Isabelle `V2_D`)
and the real Sv39 hardware, then harden the trap/SYSCALL surface. User decision:
**"Both, in order"** — Phase 1 hardware-couples the capability model to the MMU,
Phase 2 is a security-hardening pass.

## 2. User directives / non-negotiables (carried from Stage 1-3)

- **Do not break the microkernel architecture. Kernel minimal.** The kernel
  provides enforcement primitives only; policy lives in the userspace mem_server.
- Every loop must carry a `/* bound: N */` comment tied to a compile-time constant.
- `caps.h` and `kernel/isabelle/V2_*.thy` stay **pure model** (host-testable,
  Isabelle-checked). All physicalization goes in `kernel/kboot.c` (or a new
  `kernel/phys.h` included by it — host tests can include it if it stays asm-free).
- Fail closed: any guard that fails returns `V2_ERR_INVALID` / `V2_ERR_OVERFLOW`;
  no partial updates. `fdata` in caps.h remains the abstract shadow of frame data
  (kept coherent so the model, host tests and Isabelle stay valid); the REAL frame
  memory is what read/write execute against.
- QEMU smoke assertions already parsing `satp Sv39 on`, `entering U-mode`, `B00pn`,
  `A10pg`, `W1`, `MEM`/`CAP`, `[invoke] rc=0`, `OK`, `no runnable left; parking cpu`
  must keep passing; new phase markers are additive.

## 3. Design decisions (physicalization refinement)

**Frame memory.** Real 8 frames (matches `V2_FRAMES_MAX`) at PA `0x81000000 +
f*4096` (within QEMU `-m 256M` RAM, `0x80000000..0x90000000`; free — image ends
< `0x80800000`). Kernel gets an S-only identity mapping for the region via a new
`l0_frames` table so it can zero/reclaim frames. Frame 0 stays reserved (kernel),
reworded comment.

**Per-thread VSpaces — REAL.** Replace the single shared `root_pt`/`l1_k` with
per-thread tables for user frame mappings, keeping kernel/UART/text/data shared:

| table (static, aligned 4096, indexed by `V2_CAP_THREADS=8`) | role |
|---|---|
| `root_pt_t[t][512]` | t's root: `[0]->l1_m` (UART), `[2]->l1_t[t]` |
| `l1_t[t][512]` | `[1]->l0_k` (kernel 0x80200000, shared), `[2]->leaf 0x80400000 RXU`, `[3]->leaf 0x80600000 RWU` (data+stacks, shared, keeps IPC recv buffers valid), `[4]->l0_u_t[t]` (frame window), `[8]->l0_frames` (S-only) |
| `l0_u_t[t][512]` | user frame window `0x80800000 + vpn*4096` -> leaf PTE per VPN |

Each thread's `vspace_root_ppn` is built from its own `root_pt_t[t]`. `enter_thread`
already switches `satp` + `sfence.vma` per entry (Stage 3) — no scheduler change.

**VPN -> VA binding.** Hardware ground truth: `vpn` is an index into `l0_u_t`,
VA = `0x80800000 + vpn*4096`. The kernel **enforces `vpn < V2_VPN_SLOTS (32)`**
on MAP (else `V2_ERR_INVALID`). This is a safe refinement: the model's `vm[]` is a
32-slot table keyed by arbitrary `vpn`; hardware makes that concrete. Existing
`test_cap_thread` uses `vpn 0x200` (=512, out of window) -> must change to `vpn 0`.

**Physical layer lives in kboot.c.** The `V2_INVOKE` handler runs the model op
first (permission check), and on `V2_OK` performs the real PTE / frame work:
- `V2_INV_PT_ALLOC` success -> zero real frame page at `0x81000000 + f*4096`.
- `V2_INV_MAP` success -> install leaf PTE in `l0_u_t[cur][vpn]`:
  `pte_leaf(frame_pa, (R?PTE_R:0)|(W?PTE_W:0)|PTE_U|PTE_A|(W?PTE_D:0))`; `sfence.vma`.
- `V2_INV_UNMAP` success -> clear PTE + `sfence.vma`.
- `V2_INV_REVOKE` success -> capture affected `(u,vpn)` pairs from `vm[]` first,
  call model, then clear those PTEs + one `sfence.vma`.
- `V2_INV_WRITE` success -> also store `val` to real frame PA (kernel S map);
  `V2_INV_READ` success -> load real frame PA first, then validated copy-out.

**Stage-3 findings this phase fixes.** (g) V2_INV_READ RX-text hole,
(f) TODO _u_invoke drops a3_, (h) park timer spam, (j) orphaned v1 tests.

**Non-goals this phase (rationale):**
- **ELF loading** (`V2_INV_ELF_MAP`): no consumer exists; the frame model forbids
  `X` in mappings (W^X), so executable ELF pages can't be represented anyway.
  Validation-only `V2_INV_ELF_CHECK` stays. Deferred.
- **mem_server owning the frame pool**: moving free-set state to userspace would
  grow the invoke surface and churn caps.h/Isabelle. Current split (kernel
  enforces bitmap, mem_server orchestrates via invoke) stays; noted as follow-up.

## 4. Work breakdown

### Phase 1 — Hardware-couple the capability model (real implementation)

## Task 1 — Real frame backing + kernel S-map

Add `l0_frames` + `l1` S-only identity mapping (`0x81000000..0x811FFFFF`),
`V2_FRAME_PHYS_BASE` macro; update `frame_pool_init` comment (frame 0 still
reserved); `frame_alloc_slot` zeroes the real page on alloc. Verify: kernel
builds, QEMU boots, frames region readable.

## Task 2 — Per-thread VSpaces

Add `root_pt_t`/`l1_t`/`l0_u_t` (size `V2_CAP_THREADS`), per-thread wiring per
the §3 table, build satp per thread in `kboot()`, initial satp uses
`root_pt_t[0]`. Verify: each thread's `vspace_root_ppn` distinct; smoke
unchanged.

## Task 3 — MAP/UNMAP/REVOKE create/invalidate real PTEs

Enforce `vpn < V2_VPN_SLOTS`; install/clear leaf PTEs + `sfence.vma` per the
physical-layer spec; REVOKE uses captured pairs. Verify: host model unchanged;
direct user read of a mapped VPN works (Task 4).

## Task 4 — Real WRITE/READ

WRITE stores to real frame PA; READ loads real PA then validated copy-out;
`fdata` kept as shadow. Verify: `test_cap_thread` maps frame, WRITE via
invoke, then **directly reads VA `0x80800000`** (no syscall) — proof the
mapping is real in the MMU (new marker).

### Phase 2 — Security hardening

## Task 5 — V2_INV_READ hardening

Replace raw bounds+SUM deref with the standard validated copy-out path:
`v2_recv_range_ok(ptr, 1)` (data-region only `0x80600000..0x80800000`,
8-byte aligned, overflow-safe) + `u_copy_out`. Kills the write-to-RX-text
hole and the alignment hole. Grep for any other direct `sum_on()` outside
`u_copy_in/out` and eliminate.

## Task 6 — Park timer hygiene

In `halt_no_runnable()`: `csrc sie` (STIE) + push `stimecmp` far / stop timer
before the WFI loop so a pending timer can't fire once all threads park (kills
tick print spam after "no runnable left").

## Task 7 — Wire the 4-arg invoke ABI

`u_invoke` currently `(void)a3` (drops a3 — MINT/GRANT/ELF_CHECK dst args
lost). Make `u_invoke` forward `a3` via `u_ecall4`; remove
`__attribute__((unused))`; delete the now-redundant `u_invoke4`/`u_ecall4`
duplicates or keep exactly one used path.

## Task 8 — Negative syscall/cap tests

Host: extend `tests/test_v2caps.c` (+ new phys-layer checks, host-include kboot
phys helpers if asm-free) with fail-closed cases: bad tid, slot OOB,
rights-with-X, vpn OOB, unmap-not-mapped, read/write with missing cap/mapping
right. Kernel/QEMU: extend `test_cap_thread` — MAP on bad slot rc<0, READ to a
pointer inside `0x80400000..0x80600000` must FAIL (hardening proof), UNMAP then
READ fails, plus the direct-read-of-mapped-VA proof (Task 4).

## Task 9 — Orphaned v1 test cleanup

Identify the ~24 v1-era test files not referenced by `tools/verify.sh` / build
scripts and not including live headers; grep each before deleting. Keep every
test verify.sh references (test_abi, test_sched_server, test_vfs, test_shell,
test_uart/plic/timer/rtc/power, test_libc, test_newlibc, test_batch4/5/6,
test_v2ipc, test_v2caps).

## Task 10 — Full verification + smoke markers

Update `tools/verify.sh`[4/4] with new markers (e.g. `DU` real-map direct read,
negative-test PASS markers); run full `tools/verify.sh` (host tests, kernel +
userspace builds, Isabelle V2 with anti-vacuity gate, QEMU smoke). Isabelle
session must remain untouched & PASS.

Each task: implement -> review diff in SDD -> commit with a precise message
(peer-review task where it changes security semantics: T3, T5, T8).

## 5. Verification

- Per-task: build + host test for that unit; QEMU smoke for kernel tasks.
- End: `tools/verify.sh` full run — expect Isabelle PASS, kernel build PASS
  (CHERI or stock clang), QEMU smoke PASS with old + new markers.
- Anti-vacuity / bound-comment / no-.rodata-in-user.c gates must keep passing.

## 6. Risks

- Per-thread tables grow BSS by 3 slabs * 8 threads * 4KB = 96KB (trivial at 256M).
- Changing `test_cap_thread` vpn 0x200 -> 0 changes an old smoke marker's arg only
  (grep target strings unchanged).
- Isabelle V2_D does NOT model leaf PTEs; physicalization is below the model by
  design — no proof churn, but documented as a refinement, not a contradiction.