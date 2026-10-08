# Shell live harness: spawn moonsh with in-process VFS

**Status:** Design approved 2026-10-01 (sections 1-5 approved in chat, input
path revised to IPC after no-GETC finding), awaiting implementation plan
**Depends on:** RNG hardening BUILT (Untyped invoke path, fail-closed markers),
S4a BUILT (bump-set discipline, GUIMMIO gate shape, thread-A immediates-only
legs), Stage 5 BUILT (V2_INV_SPAWN/EXEC, ELF loader, per-thread VSpace)
**Decides:** moonsh spawned as tid11 with in-process VFS; VA-passing data path;
IPC keystroke harness driven by thread A; 11→12 bump set
**Constraints (binding):** Harden + keep behavior — same markers green plus 3
new ones; microkernel intact (shell owns no MMIO, no ambient caps beyond
existing console); serial console stays primary; `verify.sh` single entry
(markers in `[4/4]`, single QEMU boot transcript grep, no new SKIP);
C subset; fail closed

---

## 1. Goal

Give MoonlightOS a live shell: `moonsh.elf` (initrd idx5, built but never
spawned) boots as tid11, serves `write`/`cat` over an in-process VFS backed
by invoked frames, and proves it with an in-boot keystroke harness. No new
server, no new qube, no new syscall.

**Theorems:** no new ones. Replay `V2_C` (`max_eps` 11→12) and the Qubes
bound lemmas pinning 11 threads; add no new invariants. Mutants per touched
invariant; 0 sorry.

**Demos (QEMU text markers, fail-closed):** `SH: up` (shell entered main),
`SHMMIO: none` (boot-asserted absence of MMIO leaves in tid11 tables),
`SH: file ok` (harness `write`+`cat` round-trip byte-exact). All prior
markers unchanged.

## 2. Background / what exists

- `userspace/sh/shell.c` (moonsh.elf, initrd idx5) implements
  `write`/`cat`/`ls`/`rm` against weak-null VFS hooks (`vfs_open == 0` →
  `needs the VFS (TODO)`); `vfs_server/server.c` is never linked into
  moonsh and no VFS server thread/EP exists. `vfs_server_init()` already
  anticipates in-process linking (weak symbol, called from `shell_main`).
- Task 5 (RNG series) switched `write` to `PT_ALLOC`+`MAP` but passed the
  cap **slot int** where `server.c` `memcpy`s a **pointer** (`cap = 1`
  precedent; `vfs_server_init` has the same bug) — live `write` would
  fault; hidden because moonsh never runs (host stub returns -1).
- `kernel/kboot.c:83` `NTHREADS 11 == V2_CAP_THREADS 11` — table full;
  thread comments name tids 0,1,2,6,7,8,9,10 (7 = CAP test stub).
- **No GETC in the V2 UABI** (`kernel/kboot.c` S2-demo honesty note):
  `moonlight_getc()` issues ecall 7 (`V2_INVOKE`), so QEMU stdin can never
  reach the shell. Keystrokes must arrive as IPC (the shape a future
  console server would use — S4c owns real input). `V2_PUTC` works
  (SBI-forward), so transcript markers are greppable.

## 3. Architecture — in-process VFS, one new thread, IPC keystrokes

```
Layer                  Owner              Hardware touch   IPC
L0 address mechanics   kernel             maps NO leaves   none (asserts
                                          to tid11         absence)
L1 shell + VFS         moonsh tid11/q0    NONE — frames    RECV KEY chunks
                       (linked server.c)  via Invoke only  on own EP11
L2 harness             thread A qube0     NONE — baked     SENDs KEY chunks
                                          immediates       to EP11, RECVs ack
```

Microkernel invariants (binding):
- Exactly one file path: shell's frames come from `PT_ALLOC`+`MAP`
  (Untyped retype); `SHMMIO: none` asserts tid11 holds no MMIO leaves
  (same gate shape as `GUIMMIO`, inverted predicate).
- Input is addressed IPC with kernel-stamped senders: harness→shell `KEY`
  chunks `[TAG_KEY, n, w0, w1]` (16 payload bytes/msg, multi-chunk lines
  reassembled by pure `sh_feed`); shell→harness per-chunk `R_OK`/`R_DENY`
  replies to stamped `snd` on EP0 (call/response discipline). Both qube0:
  same-qube gate always passes, **no QX grant**; server additionally
  enforces `sqb==0` (GUI precedent — any QX holder could otherwise SEND).
- Least privilege: shell names bytes only through validated VFS rects
  (name ≤31, len clamped); shell SENDs nothing except chunk acks.

Bump set (all-or-nothing): `V2_CAP_THREADS`/`NTHREADS` 11→12,
`V2_NEP`/`max_eps` 11→12 (EP11 owned by tid11). `V2_QUBES_MAX` stays 9,
`V2_FRAMES_MAX` stays 40, `V2_MSG_MAX` stays 4, `V2_IPC_Q` stays 16.
WCET note ships with the bump (same rule as S4a).

## 4. Components

### 4.1 moonsh link change (`userspace/Makefile`)

`moonsh.elf` rule gains `vfs_server/server.c` (same `CFLAGS_V2`,
`user.ld`, 8K stack). Strong defs replace weak-null hooks; host-sim keeps
weak stubs (host tests construct the pairing explicitly).

### 4.2 VA-passing data path (`shell.c` + `server.c`)

`write` (fd<0 path): `PT_ALLOC` → `MAP` at `SHELL_SCRATCH_VPN` →
`vfs_create(client, name, va, 4096, 0, VFS_R)` where `va` is the mapped
scratch VA (unsigned, page-aligned). `server.c` stores VA+len, `memcpy`s
within it (same clamp/validate-then-copy; slot bookkeeping replaced by
VA+len pair). Same fix in `vfs_server_init` (`"sh"` seed entry).
`vfs_create` doc comment updated: `cap` param is a mapped VA in this build
(no API rename — weak/strong link shape preserved for host-sim).
Failure tears down the mapping (`UNMAP`; no leak).

### 4.3 Input rework (`shell.c`: pure `sh_feed` + RECV loop)

New pure helper `sh_feed(const char *chunk, unsigned n)` owns the line
buffer (128B) and dispatches complete lines to the existing exec path;
returns 0 ok, -1 line-too-long (buffer reset, `SH: line too long`).
`shell_main` RECV-loops EP11 feeding it (getc poll kept for host-sim
only). Overflow and `n > 16` chunks are dropped fail-closed
(validate-then-append, wrap-safe).

### 4.4 Harness legs (`kernel/user.c` thread A)

Thread-A tail (post-FILL, immediates-only baked words): SENDs
`write notes.txt hi\n` as 2 chunks + `cat notes.txt\n` as 1 chunk,
RECVs EP0 ack per chunk (expect `[R_OK]`), marker-free park on any
deviation — the live-stage call/response discipline verbatim.

### 4.5 Boot wiring (`kernel/kboot.c`, `ipc.h`, `caps.h`)

Spawn initrd 5→tid11, `qube_of[11]=0`, `SH: up` printed by ELF,
`SHMMIO: none` leaf-absence assert (loop tids, fail-closed `[demo] FAIL`
marker-free). `V2_THREADS_MAX` doc-bump comment (same as S4a minor).

## 5. Data flow (boot)

1. Kernel spawns 0–11; shell prints `SH: up`, RECV-waits EP11.
2. Thread A (post-FILL): 3 chunk SENDs → shell reassembles 2 lines →
   `write` mints+maps+creates+writes (`wrote 2 bytes to notes.txt`),
   `cat` opens+reads (`hi`) → shell prints `SH: file ok` → A parks.
3. Rendezvous queuing absorbs chunk bursts (≤4 msgs < `V2_IPC_Q` 16, FIFO).
4. Everything else identical (all prior markers byte-identical).

## 6. Error handling (fail closed)

| Case | Behavior |
|---|---|
| `PT_ALLOC` fails | `write: no frames`, zero bytes, nothing registered |
| `MAP` fails | `write: map failed`, frame released via `UNMAP` |
| `vfs_create` denied | `write: create denied`, mapping torn down |
| `cat` missing file | `cat: cannot open`, no marker |
| Chunk `n > 16` / wrap | Drop + `R_DENY`, zero state touched |
| Line >127 / unknown tag / non-qube0 sender | Drop + `R_DENY` (`SH: line too long` for overflow) |
| moonsh.elf missing | spawn skipped, no `SH: up` → gate FAILs |
| Harness deviation | marker-free park, transcript grep → FAIL |

## 7. Testing

- Host unit (`tests/test_shell_vfs.c`, `verify.sh [1f]`): `sh_feed` fed the
  exact 3-chunk harness sequence (byte-identical reassembly proof) + VA
  round-trip over malloc'd shadow (in-bounds accept, oversize/clash deny,
  wrap-safe len), CHECK idiom.
- QEMU (`[4/4]`, +3 lines on the single boot transcript): `SH: up`,
  `SHMMIO: none`, `SH: file ok` (+ `wrote 2 bytes` / standalone `hi`
  content greps). Missing ⇒ FAIL. Prior markers unchanged.
- Production gates unchanged. No key material in this stage.
- Isabelle: `V2_C` replay (`max_eps` 12) + Qubes bound-lemma replay
  (11→12 threads); own-EP + same-qube covered by existing
  `ep_separation`/`no_cross_deliver`; mutants; 0 sorry.

## 8. Non-goals (binding minimal harness)

`ls`/`rm` live legs, `exec` of ls/cat ELFs, `V2_GETC` syscall, console
server, VFS server thread/EP, per-qube shell surfaces, job control,
history persistence, console migration (serial stays primary — S4c owns
input), fallback input devices.

## 9. Exit criteria

- [ ] moonsh spawn + in-process VFS + VA data path + qube0 wiring +
      KEY-chunk input, all fail-closed; `SH: up`, `SHMMIO: none`,
      `SH: file ok` green.
- [ ] Full bump set (11→12 threads/EPs) with asserts + WCET note + proof
      replay green; frames/qubes unchanged.
- [ ] Host feed-sequence + create/write/read tests green; `verify.sh`
      full-pass (new tests in `[1f]`, markers in `[4/4]`, single boot,
      no SKIP).
- [ ] Docs: `V2_DESIGN.md` §9 shell BUILT + refinements (incl. no-GETC
      record + IPC-input rationale); threat model notes shell as qube0
      (no new privilege) — S4b owns separation.
