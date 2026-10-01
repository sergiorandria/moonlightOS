# Shell live harness: spawn moonsh with in-process VFS

**Status:** Design approved 2026-10-01 (sections 1-5 approved in chat), awaiting
implementation plan
**Depends on:** RNG hardening BUILT (Untyped invoke path, fail-closed markers),
S4a BUILT (bump-set discipline, GUIMMIO gate shape), Stage 5 BUILT
(V2_INV_SPAWN/EXEC, ELF loader, per-thread VSpace)
**Decides:** moonsh spawned as tid11 with in-process VFS; VA-passing data path;
scripted-serial QEMU harness; 11→12 bump set
**Constraints (binding):** Harden + keep behavior — same markers green plus 3
new ones; microkernel intact (shell owns no MMIO, no ambient caps beyond
existing console); serial console stays primary; `verify.sh` single entry
(markers in `[4/4]`, single cmdline extended with stdin script, no new SKIP);
C subset; fail closed

---

## 1. Goal

Give MoonlightOS a live shell: `moonsh.elf` (initrd idx5, built but never
spawned) boots as tid11, serves `write`/`cat` over an in-process VFS backed
by invoked frames, and proves it with a scripted serial transcript. No new
server, no new qube.

**Theorems:** no new ones. Replay `V2_C` (`max_eps` 11→12) and the Qubes
bound lemmas pinning 11 threads; add no new invariants. Mutants per touched
invariant; 0 sorry.

**Demos (QEMU text markers, fail-closed):** `SH: up` (shell entered main),
`SHMMIO: none` (boot-asserted absence of MMIO leaves in tid11 tables),
`SH: file ok` (scripted `write`+`cat` round-trip byte-exact). All prior
markers unchanged.

## 2. Background / what exists

- `userspace/sh/shell.c` (moonsh.elf, initrd idx5) implements
  `write`/`cat`/`ls`/`rm` against weak-null VFS hooks (`vfs_open == 0` →
  `needs the VFS (TODO)`); `vfs_server/server.c` is never linked into
  moonsh and no VFS server thread/EP exists.
- Task 5 (RNG series) switched `write` to `PT_ALLOC`+`MAP` but passed the
  cap **slot int** where `server.c` `memcpy`s a **pointer** (`cap = 1`
  precedent) — live `write` would fault; hidden because moonsh never runs
  (host stub returns -1 → `write: no frames`).
- `kernel/kboot.c:83` `NTHREADS 11 == V2_CAP_THREADS 11` — table full;
  thread comments name tids 0,1,2,6,7,8,9,10 (7 = CAP test stub).
- Shell I/O is serial polling (`SYS_DEBUG_GETC` + `YIELD`, see
  `run_qemu.sh` logging note); `-serial mon:stdio` accepts piped stdin.

## 3. Architecture — in-process VFS, one new thread

```
Layer                  Owner              Hardware touch   IPC
L0 address mechanics   kernel             maps NO leaves   none (asserts
                                          to tid11         absence)
L1 shell + VFS         moonsh tid11/q0    NONE — frames    none (direct
                       (linked server.c)  via Invoke only  calls, same TU)
L2 exec clients        ls/cat ELFs        via shell exec   spawned by shell
                       (later, not built) (V2_INV_SPAWN)   (not this stage)
```

Microkernel invariants (binding):
- Exactly one file path: shell's frames come from `PT_ALLOC`+`MAP`
  (Untyped retype); `SHMMIO: none` asserts tid11 holds no MMIO leaves
  (same gate shape as `GUIMMIO`, inverted predicate).
- Shell runs as qube0 (same as thread A): no new qube, `qube_next`
  unchanged, no new QX grants (shell SENDs nothing cross-qube this stage;
  console `V2_PUTC` stays ambient SBI-forward as today).
- Least privilege: shell names bytes only through validated VFS rects
  (name ≤31, len clamped); server touches no other qube's memory.

Bump set (all-or-nothing): `V2_CAP_THREADS`/`NTHREADS` 11→12,
`V2_NEP`/`max_eps` 11→12 (EP11 owned by tid11). `V2_QUBES_MAX` stays 9,
`V2_FRAMES_MAX` stays 40. WCET note ships with the bump (same rule as S4a).

## 4. Components

### 4.1 moonsh link change (`userspace/Makefile`)

`moonsh.elf` rule gains `vfs_server/server.c` (same `CFLAGS_V2`,
`user.ld`, 8K stack). Strong defs replace weak-null hooks; host-sim keeps
weak stubs (never linked with server.c there — host tests construct the
pairing explicitly).

### 4.2 VA-passing data path (`shell.c` + `server.c`)

`write` (fd<0 path): `PT_ALLOC` → `MAP` at `SHELL_SCRATCH_VPN` →
`vfs_create(client, name, va, 4096, 0, VFS_R)` where `va` is the mapped
scratch VA (unsigned, page-aligned). `server.c` stores VA+len, `memcpy`s
within it (same clamp/validate-then-copy; slot bookkeeping replaced by
VA+len pair). `vfs_create` doc comment updated: `cap` param is a mapped VA
in this build (no API rename — weak/strong link shape preserved).
Failure tears down the mapping (`UNMAP`; no leak).

### 4.3 Boot wiring (`kernel/kboot.c`, `ipc.h`, `caps.h`)

Spawn initrd 5→tid11, `qube_of[11]=0`, `SH: up` printed by ELF,
`SHMMIO: none` leaf-absence assert (loop tids, fail-closed `[demo] FAIL`
marker-free). `V2_THREADS_MAX` doc-bump comment (same as S4a minor).

### 4.4 Scripted harness (`tools/run_qemu.sh`, `tools/verify.sh`)

New `tools/sh_script.txt` (`write notes.txt hi`, `cat notes.txt`, empty
line to park). `verify.sh [4/4]` runs one extra QEMU invocation with
`< tools/sh_script.txt` on `-serial mon:stdio`, greps transcript for
`wrote 2 bytes to notes.txt` + standalone `hi` + `SH: file ok`. Single
cmdline otherwise unchanged; windowed/display flags untouched.

## 5. Data flow (boot)

1. Kernel spawns 0–11; shell prints `SH: up`, polls serial (yield between
   polls, never spins).
2. Script `write notes.txt hi` → mint+map+create+write → `wrote 2 bytes
   to notes.txt`; `cat notes.txt` → open/read → `hi`; shell prints
   `SH: file ok`, parks on EOF.
3. Everything else identical (all prior markers byte-identical; shell
   never SENDs FILL or touches framebuffer).

## 6. Error handling (fail closed)

| Case | Behavior |
|---|---|
| `PT_ALLOC` fails | `write: no frames`, zero bytes, nothing registered |
| `MAP` fails | `write: map failed`, frame released via `UNMAP` |
| `vfs_create` denied | `write: create denied`, mapping torn down |
| `cat` missing file | `cat: cannot open`, no marker |
| moonsh.elf missing | spawn skipped, no `SH: up` → gate FAILs |
| Script bytes mismatch | marker-free park, transcript grep → FAIL |

## 7. Testing

- Host unit (`tests/test_shell_vfs.c`, `verify.sh [1f]`): VA-backed
  create/write/read round-trip over malloc'd shadow (in-bounds accept,
  oversize/clash deny, wrap-safe len), CHECK idiom.
- QEMU scripted (`[4/4]`, +3 lines): `SH: up`, `SHMMIO: none`,
  `SH: file ok`. Missing ⇒ FAIL. Prior markers unchanged.
- Production gates unchanged. No key material in this stage.
- Isabelle: `V2_C` replay (`max_eps` 12) + Qubes bound-lemma replay
  (11→12 threads); mutants; 0 sorry; KAT-correspondence n/a.

## 8. Non-goals (binding minimal harness)

`ls`/`rm` live legs, `exec` of ls/cat ELFs, VFS server thread/EP,
per-qube shell surfaces, shell job control, history persistence,
console migration (serial stays primary), multi-script harness,
resolution/input devices.

## 9. Exit criteria

- [ ] moonsh spawn + in-process VFS + VA data path + qube0 wiring, all
      fail-closed; `SH: up`, `SHMMIO: none`, `SH: file ok` green.
- [ ] Full bump set (11→12 threads/EPs) with asserts + WCET note + proof
      replay green; frames/qubes unchanged.
- [ ] Host create/write/read tests green; `verify.sh` full-pass (new tests
      in `[1f]`, markers in `[4/4]`, single cmdline, no SKIP).
- [ ] Docs: `V2_DESIGN.md` §9 shell BUILT + refinements; threat model notes
      shell as qube0 (no new privilege) — S4b owns separation.
