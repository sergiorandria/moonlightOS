# Moonlight v2 Stage 3: Capabilities + Memory

**Status:** Design approved, ready for implementation
**Depends on:** Stage 2 (IPC + U-mode threads) — complete
**Isabelle spec:** `kernel/isabelle/V2_D.thy` (green)

---

## Goal

Wire the capability model (`caps.h`) into the kernel as minimal enforcement
primitives. All allocation policy lives in userspace (`mem_server`). The
kernel owns no heap.

**Theorems to discharge (from V2_D):**
- Authority confinement: write/grant/map affects only objects reachable from caller's caps
- W^X: no mapping carries execute rights
- Revoke destroys all non-root caps + mappings to an object

---

## Kernel Changes (minimal)

### 1. New UABI: `V2_INVOKE` (syscall 7)

```
a7 = V2_INVOKE (7)
a0 = op code
a1..a5 = arguments (cap slots, frame IDs, VPNs, rights)
return: a0 = V2_OK / V2_ERR_INVALID / V2_ERR_OVERFLOW
```

| Op | a0 | a1 | a2 | a3 | a4 | a5 |
|----|----|----|----|----|----|----|
| MINT | V2_INV_MINT | src_slot | rights | dst_slot | — | — |
| GRANT | V2_INV_GRANT | from_tid | src_slot | to_tid | dst_slot | — |
| MAP | V2_INV_MAP | cap_slot | vpn | — | — | — |
| UNMAP | V2_INV_UNMAP | vpn | — | — | — | — |
| REVOKE | V2_INV_REVOKE | cap_slot | — | — | — | — |
| PT_ALLOC | V2_INV_PT_ALLOC | dst_slot | — | — | — | — |
| ELF_CHECK | V2_INV_ELF_CHECK | magic_ok | phdr_ptr | n_phdrs | — | — |
| WRITE | V2_INV_WRITE | vpn | value | — | — | — |
| READ | V2_INV_READ | vpn | out_ptr | — | — | — |

All validation mirrors `caps.h` (bounds checks, rights subset, root-bit
rules, W^X). Fail-closed on any check.

### 2. Per-thread VSpace

- `uctx_t` gains `uint64_t vspace_root_ppn` (PPN of thread's root PT)
- `enter_thread()` emits:
  ```
  csrw satp, (8<<60) | vspace_root_ppn
  sfence.vma
  ```
- `V2_INV_PT_ALLOC` returns a zeroed frame cap (kernel takes a free
  frame, zeroes it, mints a cap into caller's table). Frame pool size
  `V2_FRAMES_MAX=8`; kernel tracks free frames internally (simple bitmap).

### 3. Boot-time frame pool handoff

`kboot()`:
1. `v2_caps_init(&caps, nthreads)` — thread 0 gets root caps to all frames
2. Start thread 0 as `mem_server` (separate `uctx_t` entry)
3. Kernel keeps no frame references except the PT allocation bitmap

### 4. `V2_INV_ELF_CHECK` + `V2_INV_ELF_MAP`

- `ELF_CHECK`: userspace passes ELF phdrs; kernel runs `v2_elf_ok` (magic,
  1–4 segments, 1–512 pages each, never W+X). Returns `V2_OK`/`V2_ERR_INVALID`.
- `ELF_MAP` (optional helper): kernel iterates validated phdrs, calls
  `v2_elf_map` → `V2_INV_MAP` for each page. Pure convenience; mem_server
  could do the loop itself.

---

## Userspace

### mem_server (thread 0)
- Owns root caps to all frames at boot
- Implements:
  - `alloc_frame(caller_tid) -> cap_slot` (GRANTs a frame cap)
  - `map_frame(caller_tid, cap_slot, vpn, rights) -> V2_OK/ERR`
  - `unmap(caller_tid, vpn)`
  - `revoke(caller_tid, cap_slot)`
- IPC protocol: `SEND`/`RECV` on a dedicated endpoint (or `NOTIFY`/`WAIT`
  for async replies)

### ELF loader (in mem_server or separate)
- Reads ELF from a file cap (VFS)
- `ELF_CHECK` → validates
- For each PT_LOAD: `ELF_MAP` or loop `MAP`
- Jumps to entry point

---

## Testing / Demo

1. **mem_server smoke**: boot → mem_server receives root caps → thread 1
   asks for frame → gets cap → `MAP` at VPN 0x1000 → `WRITE` 0xdeadbeef
   → `READ` returns 0xdeadbeef.
2. **Authority confinement**: thread 2 without caps tries `MAP`/`WRITE` →
   `V2_ERR_INVALID`.
3. **Revoke**: thread 1 grants frame to thread 2; thread 1 `REVOKE` →
   thread 2's cap + mapping destroyed; thread 2 `READ` faults.
4. **W^X**: `ELF_CHECK` rejects W+X segment; `MAP` with X rights rejected.

---

## Implementation Order

1. `caps.h` → `kboot.c` integration: add `v2_caps_t caps` global, init in `kboot()`
2. `V2_INVOKE` handler in `s_trap_handler` (new syscall case)
3. Per-thread `vspace_root_ppn` + `satp` switch in `enter_thread()`
4. `V2_INV_PT_ALLOC` (frame pool bitmap in `caps` or separate)
5. Boot: start mem_server as thread 0 with root caps
6. Userspace: `mem_server/server.c` + test thread
7. Verify: `tools/verify.sh` extends with capability tests

---

## Open Questions (deferred)

- AutoCorres refinement for `Invoke` handler (Stage 3→4 boundary)
- Timer tick rate vs WCET budget (measured in Stage 1, freeze in Stage 3)
- Whether `Seal` stays a syscall or becomes `V2_INV_SEAL` (spec churn only)