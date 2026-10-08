# Shell Live Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Boot moonsh as tid11 with in-process VFS and prove write/cat over IPC keystrokes from thread A.

**Architecture:** Task 1 builds pure `sh_feed` line reassembly with host KATs. Task 2 fixes the VA data path (slot int → mapped VA) with host round-trip tests. Task 3 links server.c into moonsh.elf. Task 4 adds thread-A KEY legs plus the shell RECV loop and file-ok check. Task 5 wires boot (spawn, qube0, SHMMIO absence assert) plus the 11→12 bump set. Task 6 replays proofs and closes docs.

**Tech Stack:** C (freestanding rv64imac stock clang `-Werror` for ELFs/kernel; host clang for unit tests), RISC-V S-mode (existing handlers/tables only), Isabelle/HOL (session V2), bash (verify.sh/mkinitrd.sh/run_qemu.sh).

**Spec:** `docs/superpowers/specs/2026-10-01-shell-harness-design.md`

## Global Constraints

- Freestanding only for kernel/ELF code: `--target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 -ffreestanding -nostdlib` + `-Wall -Wextra -Werror`; follow `CFLAGS_V2` (kernel/servers) / `CFLAGS_U` (shell, `userspace/Makefile:97-99`) shapes.
- C subset: no `float`, no function-pointer dispatch (switch on op/tag; the existing weak-hook null checks `if (!vfs_open)` stay as-is), no recursion, every loop carries a `/* bound: N */` comment tied to a named constant.
- `kernel/user.c` constraint: no string literals, no globals — immediates + stack locals only (KEY legs bake words, same as FILL legs).
- Fail closed: invoke failure parks marker-free or replies DENY with zero bytes stored; missing QEMU markers flip the smoke gate to FAIL.
- Unchanged except the bump set: `V2_MSG_MAX 4`, `V2_IPC_Q 16`, `V2_AUDIT_MAX 64`, `V2_QUBES_MAX 9`, `V2_FRAMES_MAX 32→40` (stays 40). Bump set (all-or-nothing): `V2_CAP_THREADS`/`NTHREADS` 11→12, `V2_NEP`/`max_eps` 11→12.
- Endpoint/tid/qube map: shell tid11, EP11 owned by tid11, qube0 (`qube_of[11]=0`, `qube_next` stays 9), initrd index 5 (already in `tools/mkinitrd.sh:29`, no change). Tag `TAG_KEY 9` (top-level tag 9 is free — `VOL_FORMAT 9`/`RPC_VOL_FORMAT 9`/`CRYPT_TID 9` are rpc-id/tid namespaces, not message tags — reviewer confirms). Replies `R_OK 0`/`R_DENY -1`.
- `tools/verify.sh` single entry: host tests in `[1f]`, markers in `[4/4]`, single QEMU boot transcript grep, no new SKIP.
- Proofs: zero `sorry`/`axiomatization`, no `True`-definitions, mutant per new invariant; never `eval` large numerals (`simp` for big constants).
- `make -C kernel` does NOT regenerate tracked `kernel/initrd_data.c` — run `tools/mkinitrd.sh` between userspace and kernel builds whenever ELFs change.

---

## File Map

| File | Responsibility |
|---|---|
| Modify `userspace/sh/shell.c` | Pure `sh_feed` (T1); VA write path + `sh_file_ok` check + RECV loop + `SH: up` (T2/T4); weak `vfs_map_frame` decl |
| Modify `userspace/vfs_server/server.c` | `vfs_map_frame` helper + `vfs_server_init` VA fix (T2) |
| Create `tests/test_shell_vfs.c` | KATs for `sh_feed` (T1) + VA round-trip + fail-closed (T2) |
| Modify `userspace/Makefile` | `moonsh.elf` rule gains `vfs_server/server.c` (T3) |
| Modify `kernel/user.c` | Thread-A KEY legs post-FILL (T4) |
| Modify `kernel/kboot.c` | `NTHREADS` 11→12, spawn idx5→tid11, `qube_of[11]=0`, `SHMMIO: none` assert (T5) |
| Modify `kernel/caps.h`, `kernel/ipc.h` | `V2_CAP_THREADS` 11→12, `V2_NEP` 11→12, `V2_THREADS_MAX` doc line (T5) |
| Modify `kernel/isabelle/V2_C.thy` | `max_eps` 11→12 replay (T6) |
| Modify `tools/verify.sh` | `[1f]` test line; `[4/4]` +3 marker lines (T6) |
| Modify `docs/V2_DESIGN.md`, `docs/ARCHITECTURE.md`, `docs/BUILD.md` | Shell BUILT entries (T6) |

**Scope note:** Tasks 1–2 are host-gated with zero boot contact. Task 3 ends with moonsh.elf link green (unspawned). Task 4 ends with riscv syntax + host green (unspawned). Task 5 ends with `SH: up` + `SHMMIO: none` green. Task 6 ends with `SH: file ok` green.

---

### Task 1: `sh_feed` pure helper + KATs (host-only, no boot)

**Files:**
- Modify: `userspace/sh/shell.c` (append helper near `shell_exec_line:313`)
- Create: `tests/test_shell_vfs.c`
- Modify: `tools/verify.sh` (`[1f]`, after the `test_rng` line)
- Test: `tests/test_shell_vfs.c`

**Interfaces:**
- Consumes: `shell_exec_line(const char *line)` (`userspace/sh/shell.c:313`), `SHELL_LINE_MAX 128` (`shell.c:26`).
- Produces: `int sh_feed(const char *chunk, unsigned n)` consumed by Task 4 (RECV loop) and host tests here.

Contract (exact): appends `n` bytes to a 128B line buffer; each completed `\n`-terminated line dispatches via `shell_exec_line`; returns lines dispatched (0, 1+); `n > 16` or buffer overflow (>127 without `\n`) drops + resets and returns -1 (`SH: line too long` printed on overflow only). Empty chunks (`n == 0`) return 0.

- [ ] **Step 1: Write `tests/test_shell_vfs.c` first** (CHECK idiom, same compile line shape as `verify.sh:14` plus server.c omitted — VFS-free commands only):

```c
/* tests/test_shell_vfs.c - KATs for sh_feed + VA-backed VFS pairing. */
#include <stdio.h>
#include <string.h>
#include "../userspace/sh/shell.c"
#include "../userspace/lib/moonlight.c"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0) }

int main(void) {
    /* feed: VFS-free lines dispatch, chunk splits reassemble. */
    CHECK(sh_feed("help\n", 5) == 1);
    CHECK(sh_feed("ec", 2) == 0);
    CHECK(sh_feed("ho hi\n", 6) == 1);   /* "echo hi" across a split */
    CHECK(sh_feed("", 0) == 0);          /* empty chunk */
    CHECK(sh_feed("0123456789ABCDEFx", 17) == -1); /* n > 16 reject */
    printf("PASS: test_shell_vfs\n");
    return 0;
}
```

- [ ] **Step 2: Run, watch fail (no `sh_feed`)**

Run: `gcc -Wall -Wextra -o /tmp/test_shell_vfs tests/test_shell_vfs.c userspace/sh/shell.c userspace/lib/moonlight.c 2>&1 | head -n 5`
Expected: FAIL — `undefined reference to 'sh_feed'` (mirror the intent; exact linker text may vary).

- [ ] **Step 3: Implement `sh_feed` in `userspace/sh/shell.c`** after `shell_exec_line` — pure C, no ecalls, no globals beyond one 128B static buffer + index:

```c
/* sh_feed: append chunk bytes to the line buffer, dispatch complete lines.
 * Pure (no ecalls): the RECV loop and host tests share it. Lines cap at
 * SHELL_LINE_MAX-1 (128); overflow drops the line fail-closed. */
static char sh_feed_buf[SHELL_LINE_MAX];
static unsigned sh_feed_len = 0;
int sh_feed(const char *chunk, unsigned n) {
    unsigned i;
    int dispatched = 0;
    if (!chunk || n > 16u) return -1;
    for (i = 0u; i < n; i++) { /* bound: 16 (chunk cap above) */
        if (sh_feed_len >= (unsigned)SHELL_LINE_MAX - 1u) {
            sh_feed_len = 0;
            sh_feed_buf[0] = '\0';
            shell_puts("SH: line too long\n");
            return -1;
        }
        sh_feed_buf[sh_feed_len++] = chunk[i];
        if (chunk[i] == '\n') {
            sh_feed_buf[sh_feed_len - 1u] = '\0';
            shell_exec_line(sh_feed_buf);
            sh_feed_buf[0] = '\0';
            sh_feed_len = 0;
            dispatched++;
        }
    }
    return dispatched;
}
```

- [ ] **Step 4: Run green**

Run: `gcc -Wall -Wextra -o /tmp/test_shell_vfs tests/test_shell_vfs.c 2>&1 && /tmp/test_shell_vfs`
Expected: `PASS: test_shell_vfs` (shell builtin output like `help` text may print — only the final PASS line matters; no FAIL line).
Run existing sim (no regression): `gcc -Wall -Wextra -o /tmp/test_shell tests/test_shell.c userspace/sh/shell.c userspace/lib/moonlight.c && /tmp/test_shell 2>&1 | grep -c FAIL`
Expected: `0`.

- [ ] **Step 5: Wire into `tools/verify.sh [1f]`** — after the `test_rng` line:

```bash
gcc -Wall -Wextra -o /tmp/test_shell_vfs tests/test_shell_vfs.c 2>&1 && /tmp/test_shell_vfs || echo "FAIL: test_shell_vfs"
```

- [ ] **Step 6: Commit**

```bash
git add userspace/sh/shell.c tests/test_shell_vfs.c tools/verify.sh
git commit -m "shell: sh_feed helper plus KATs"
```

### Task 2: VA data path + host round-trip (host-gated, no boot)

**Files:**
- Modify: `userspace/vfs_server/server.c` (add `vfs_map_frame`, fix `vfs_server_init`)
- Modify: `userspace/sh/shell.c` (weak decl, write-path rewire, remove dead `u_invoke_map`/`SHELL_SCRATCH_VPN`, add `sh_last_*` statics — check set here, comparison in Task 4)
- Modify: `tests/test_shell_vfs.c` (link server.c, VA round-trip + fail-closed checks)
- Test: `tests/test_shell_vfs.c`

**Interfaces:**
- Consumes: `vfs_invoke(VFS_INV_PT_ALLOC)` (`server.c:683-691`, host returns -1), `vfs_create` (`server.c:165`), `shell_exec_line` + `sh_feed` (Task 1).
- Produces: `unsigned long vfs_map_frame(unsigned long frame)` (0 = fail) consumed by shell write path here and `vfs_server_init` here.

VA rule (exact): `VA = 0x80800000UL + vpn * 4096UL`, VPNs bump-allocated `32..63` (`VFS_MAP_VPN_BASE 32UL`, `VFS_MAP_VPN_MAX 64UL`, 32 files max — never freed, files live to reboot; base 32 clears the ELF image + net scratch precedent at vpn<8 with wide headroom). 32-bit truncation is safe (all VAs < 4GB).

- [ ] **Step 1: Extend the test first** — change compile to link server.c and append checks to `main` (before the PASS print):

```c
#include <stdlib.h>
/* ... inside main(), after the feed checks: */
/* VA round-trip over a malloc'd shadow (stands in for a mapped frame). */
{
    char *shadow;
    int fd;
    char back[8];
    int r;
    shadow = (char *)malloc(4096);
    CHECK(shadow != (char *)0);
    memset(shadow, 0, 4096);
    CHECK(vfs_create(128u, "f", (unsigned)(uintptr_t)shadow, 4096, 0, 1u) == 0);
    CHECK(vfs_open(128u, "f", 1u) >= 0);
    fd = vfs_open(128u, "f", 3u);
    CHECK(fd >= 0);
    CHECK(vfs_write(128u, fd, "hi", 2) == 2);
    vfs_close(128u, fd);
    fd = vfs_open(128u, "f", 1u);
    CHECK(fd >= 0);
    r = vfs_read(128u, fd, back, 2);
    CHECK(r == 2 && back[0] == 'h' && back[1] == 'i');
    vfs_close(128u, fd);
    /* fail-closed without invoke (host vfs_invoke returns -1): */
    CHECK(sh_feed("write g hi\n", 11) == 1);
    CHECK(vfs_open(128u, "g", 1u) < 0); /* no frames on host: nothing registered */
}
```

Compile for this task: `gcc -Wall -Wextra -o /tmp/test_shell_vfs tests/test_shell_vfs.c userspace/sh/shell.c userspace/lib/moonlight.c userspace/vfs_server/server.c`

- [ ] **Step 2: Run, watch fail**

Run the compile above.
Expected: FAIL — `undefined reference to 'vfs_map_frame'` (write path calls it) or test assertion failure on the VA round-trip (slot bug). Either failure proves the gap.

- [ ] **Step 3: Add `vfs_map_frame` + fix init in `server.c`** (after the `vfs_invoke` defin
...[truncated 8903 chars]