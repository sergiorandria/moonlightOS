# Sprint 4 Proxy Seam Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a generic IPC proxy seam in `lib/` and migrate all lib-linked clients to it, with host mocks behind the same seam.

**Architecture:** Header-only `svc_proxy.h` over the existing `ipc_send_sync/async` primitives; proxies carry `{ep, svc}` so validation and transport stay together; host KAT stubs `moonlight_*` and drives proxies against a mock dispatch table. No kernel, proof, or capacity changes.

**Tech Stack:** Freestanding rv64 C (header), host C99 KAT, `tools/verify.sh` gates.

**Spec:** `docs/superpowers/specs/2026-10-14-sprint4-proxy-seam-design.md`

## Global Constraints

- No kernel changes, no Isabelle theory changes, no capacity bumps (NTHREADS=11, V2_NEP=11, V2_QUBES_MAX=9).
- Header-only: no new translation units, no Makefile changes (`svc_proxy.h` ships with `lib/` like the constructors).
- Freestanding-safe: `svc_proxy.h` includes `moonlight.h`, `ipc_protocol.h`, `ipc_tags.h` (registry consumer) only; no libc.
- `msg_valid` stays the sole validator; proxy never re-implements shape checks.
- Fail-closed: validation failure returns `-1` before any transport; transport errors propagate negative unchanged.
- Wire bytes never change: proxy calls `ipc_send_sync/async` with identical arguments the direct sites use today.
- Path-scoped commits; `-Werror`-clean; bound comments on new loops.

## Review Focus

- Proxy validating a different `(svc,tag)` than the struct actually carries (label comes from the struct's `msg_type`, validation from the proxy's `svc` + passed `tag` — a mismatch admits/rejects wrongly): pinned by KAT vectors pairing mismatched tag args with rejection (Task 1).
- `msg_size`→words conversion over-admitting (e.g. 33 bytes → 5 words must reject): pinned by boundary KAT vectors (Task 1).
- Mock dispatch diverging from real server tag logic (mocks answer what no server would): pinned by driving mock replies from the same registry rows + constructors (Task 1).
- Migrated call site changing wire behavior (different EP, size, or sync/async flavor): pinned by per-site argument preservation checks + QEMU byte-identical transcript (Tasks 2–3).
- Unmigrated stragglers (a direct `ipc_send_*` site left behind): pinned by a grep gate in Task 3 (zero direct call sites outside `lib/` + proxy internals).

---

### Task 1: Proxy header + mock-backed KAT

**Files:**
- Create: `userspace/include/services/svc_proxy.h`
- Create: `tests/test_svc_proxy.c`
- Modify: `tools/verify.sh` (`[1f]` KAT block)
- Test: `tests/test_svc_proxy.c`

**Interfaces:**
- Consumes: `ipc_send_sync(uint32_t self, uint32_t ep, const void*, uint32_t, void*, uint32_t)`, `ipc_send_async(uint32_t ep, const void*, uint32_t)` (both in `lib/`, unchanged); `msg_valid(const char*, unsigned, unsigned)` (unchanged)
- Produces: `svc_proxy_t { unsigned ep; const char *svc; }`, `svc_proxy(unsigned ep, const char *svc)`, `int svc_call(uint32_t self, svc_proxy_t px, unsigned tag, const void *msg, uint32_t msg_size, void *resp, uint32_t resp_size)`, `int svc_cast(svc_proxy_t px, unsigned tag, const void *msg, uint32_t msg_size)` — later tasks use these exact names/signatures

- [ ] **Step 1: Write the failing KAT**
  Create `tests/test_svc_proxy.c`: host stubs for `moonlight_send/recv/asend` (pattern from `test_msg_registry.c:25-42`) + mock dispatch keyed by message label with canned replies; assert `svc_call` returns the canned reply bytes, `svc_cast` returns 0, mismatched-tag and oversize (`33`-byte) calls return `-1` without touching the transport (stub records call count, asserts zero), transport-error stub (`-5`) propagates as `-5`.

- [ ] **Step 2: Run it to verify it fails**
  Run: `gcc -Wall -Wextra -Werror -Ikernel -I. -Iuserspace/include -o /tmp/test_svc_proxy tests/test_svc_proxy.c`
  Expected: FAIL with `svc_proxy.h: No such file`.

- [ ] **Step 3: Implement `svc_proxy.h` in `userspace/include/services/`**
  Struct + constructor + `svc_call` (`nw = (msg_size + 7) >> 3; if (!msg_valid(px.svc, tag, nw)) return -1; return ipc_send_sync(self, px.ep, msg, msg_size, resp, resp_size);`) + `svc_cast` (same gate, then `ipc_send_async(px.ep, msg, msg_size)`). Declaration order: struct, constructor, call, cast.

- [ ] **Step 4: Run KAT to verify pass**
  Run: same command as Step 2
  Expected: `PASS: test_svc_proxy` (exact string the test prints).

- [ ] **Step 5: Wire into `tools/verify.sh`**
  Add the Step-4 compile+run with the `|| echo "FAIL: test_svc_proxy"` idiom in `[1f]` beside the registry KAT line.
  Run: `bash -n tools/verify.sh`
  Expected: syntax OK.

- [ ] **Step 6: Commit**
  ```bash
  git add userspace/include/services/svc_proxy.h tests/test_svc_proxy.c tools/verify.sh
  git commit -m "feat(ipc): svc_proxy seam + mock-backed KAT"
  ```

### Task 2: Migrate console/tty/shell direct sites

**Files:**
- Modify: `userspace/console/console.c` (1 site), `userspace/tty/tty.c` (2 sites), `userspace/sh/shell_tty.c` (direct sites)
- Test: `tests/test_svc_proxy.c` (unchanged) + QEMU smoke markers

**Interfaces:**
- Consumes: Task 1's `svc_call`/`svc_cast`/`svc_proxy`
- Produces: zero direct `ipc_send_*` call sites outside `lib/` and the proxy header

- [ ] **Step 1: Migrate console's site**
  `console.c:198` `ipc_send_async(SERVICE_TTY, &input, sizeof(input))` becomes `svc_proxy_t px = svc_proxy(SERVICE_TTY, "console"); return svc_cast(px, MSG_CONSOLE_INPUT, &input, sizeof(input));` — proxy `svc` is the sender namespace. Same EP, same bytes, same async flavor.

- [ ] **Step 2: Migrate tty's two sites + shell's sites**
  Same pattern with sender namespace `"tty"` (tags `MSG_TTY_WRITE`) and `"shell"` (tags `MSG_APP_*`; shell's `ipc_send_sync` becomes `svc_call` preserving self EP, reply buffers, sizes).

- [ ] **Step 3: Grep gate + builds + KAT**
  Run: `grep -rn "ipc_send_sync\|ipc_send_async" userspace/console/ userspace/tty/ userspace/sh/ userspace/gui/ | grep -v Binary`
  Expected: zero hits outside `svc_proxy.h` internals. Then `make -C userspace` build of affected ELFs `-Werror` clean + KAT still `PASS: test_svc_proxy`.

- [ ] **Step 4: Commit**
  ```bash
  git add userspace/console/console.c userspace/tty/tty.c userspace/sh/shell_tty.c
  git commit -m "feat(ipc): migrate console/tty/shell sites to svc_proxy"
  ```

### Task 3: Migrate shared constructors onto the proxy

**Files:**
- Modify: `userspace/include/services/ipc_helpers.h` (constructor bodies only)
- Test: `tests/test_svc_proxy.c` (unchanged) + affected ELF builds

**Interfaces:**
- Consumes: Task 1's `svc_cast` (constructors are all fire-and-forget `ipc_send_async` today — verify each body before converting; any sync constructor keeps `ipc_send_sync` and is recorded)

**Steps:** same TDD rhythm as Task 2 (convert one constructor family, rebuild its consumers, KAT):
- [ ] gui constructors → `svc_cast` with sender `"gui"`
- [ ] console constructors → `svc_cast` with sender `"console"`
- [ ] shell `tty_write`/`tty_read` → `svc_cast`/`svc_call` with sender `"shell"` (preserve sync/async flavor and pacing yields exactly)
- [ ] `kernel_send_boot_log` stays direct (documented ungated; kernel-originated)
- [ ] Rebuild all consumers `-Werror` clean, KAT PASS, commit `feat(ipc): migrate shared constructors onto svc_proxy`

### Task 4: Full verification + review + merge-prep

**Files:**
- Test: `tools/verify.sh` (full run)

**Interfaces:**
- Consumes: Tasks 1–3
- Produces: green baseline ready for merge

- [ ] **Step 1: Run full verification**
  Run: `tools/verify.sh`
  Expected: exit 0 modulo the known pre-existing shell-build reds (untracked `shell_expr.h`; document any other FAIL as new); `PASS: test_svc_proxy`; QEMU byte-identical otherwise; Isabelle PASS.

- [ ] **Step 2: Request code review**
  Dispatch the reviewer per `superpowers:requesting-code-review` over the task range before merging. Fix Critical/Important findings first.

- [ ] **Step 3: Merge-prep (no merge without explicit approval)**
  Confirm worktree clean except untracked generated headers; report branch ready. Do not merge or push.
