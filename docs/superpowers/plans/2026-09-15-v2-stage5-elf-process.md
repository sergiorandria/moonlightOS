# v2 Stage 5: ELF loading + process management

## Context
Stage 4 completed: real frame backing, per-thread VSpaces, real PTEs, WRITE/READ, park-timer hygiene, 4-arg ABI, negative tests. The kernel invoke handler has `V2_INV_ELF_CHECK` (validation) but `V2_INV_ELF_MAP` (load + map) is missing — deferred because the frame model forbids `X` in mappings (W^X).

Stage 5 adds execute permission to the model (careful W^X), implements the ELF loader, and provides process spawn/fork/exec.

## 1. Model changes (caps.h + Isabelle)

### Execute right
- Add `V2_RIGHT_X` to rights bitfield (already used in mint rejection)
- `v2_map` / `v2_mint`: allow `X` iff `W` is NOT set (W^X enforcement)
- `v2_vm_install`: PTE_X set iff rights has `V2_RIGHT_X` and not `V2_RIGHT_W`

### New caps.h helpers
- `v2_elf_map`: load ELF64 from frame pool (read-only initrd image), map segments with R/X or R/W (no RWX)
- `v2_spawn`: allocate new thread, map its VSpace, load ELF, set entry point
- `v2_fork`: copy parent's VSpace (COW), new thread with identical caps
- `v2_exec`: replace current thread's image (unmap old, load new)

### Memory layout
- Per-thread VSpace already exists (T2)
- User stack already allocated (ustack_*)
- Add: initial brk (heap) region per thread
- ELF segments mapped at their virtual addresses (low addresses < 0x80000000)

## 2. Kernel implementation (kboot.c)

### ELF loader (new elf.c/h)
- Parse ELF64 header from initrd/frame pool
- Validate: magic, 64-bit, little-endian, PIE or fixed base
- For each PT_LOAD: `v2_elf_map` → allocate frames, copy data, map with R/W or R/X
- Zero BSS (p_memsz > p_filesz)
- Set entry point, stack pointer, brk

### New invoke ops
- `V2_INV_ELF_MAP` (8?): `a1=frame_src`, `a2=phdrs_ptr`, `a3=phdr_count` → load ELF into current VSpace, returns entry point in a0
- `V2_INV_SPAWN` (9?): `a1=frame_src`, `a2=phdrs_ptr`, `a3=phdr_count` → new thread, returns child tid
- `V2_INV_FORK` (10?): no args → child tid in parent, 0 in child
- `V2_INV_EXEC` (11?): `a1=frame_src`, `a2=phdrs_ptr`, `a3=phdr_count` → replace current image

### Invoke handler updates
- Extend `s_trap_handler` with new cases
- All fail-closed (V2_ERR_INVALID on any validation failure)
- Real frame operations only after model success

## 3. Userspace integration

### mem_server
- Serve ELF frame requests (read initrd frames)
- Handle `SPAWN` / `EXEC` requests from shell

### shell (sh)
- `exec` builtin: load ELF from VFS, invoke SPAWN/EXEC
- Path resolution, argument/env passing

### initrd
- Embed userspace binaries (sh, ls, cat, etc.) as read-only frames

## 4. Isabelle proofs
- Extend V2_C.thy with execute right, W^X invariant
- Prove `v2_elf_ok` → `v2_elf_map` preserves W^X
- Prove spawn/fork/exec preserve capability confinement

## 5. Verification
- Host tests: test_v2elf.c (ELF parsing, mapping, W^X)
- QEMU smoke: shell can `exec /bin/ls`, `cat /etc/passwd`
- verify.sh updated with SPAWN/FORK/EXEC markers

## 6. Risks
- W^X: must never have R+W+X in same mapping
- ELF loader in kernel vs userspace tradeoff (kernel keeps TCB small)
- COW for fork: needs page-fault handler + copy-on-write PTEs
- initrd format: need a simple archive format (cpio? tar?)

## 7. Work breakdown

### Phase 1: Model + kernel
- Task 1: Add `V2_RIGHT_X` to model, W^X in `v2_map`/`v2_vm_install`
- Task 2: ELF loader (elf.c/h) + `V2_INV_ELF_MAP`
- Task 3: `V2_INV_SPAWN` (new thread + load)
- Task 4: `V2_INV_FORK` (COW VSpace copy)
- Task 5: `V2_INV_EXEC` (replace current image)

### Phase 2: Userspace
- Task 6: mem_server ELF frame service
- Task 7: shell `exec` builtin + path resolution
- Task 8: initrd builder + embed binaries

### Phase 3: Verification
- Task 9: Host tests + QEMU integration
- Task 10: Isabelle proofs + full verify.sh

---

## Approval
This plan must be reviewed and approved before any implementation begins.