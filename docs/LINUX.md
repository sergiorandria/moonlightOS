# MoonlightOS — Linux personality (rv64 syscall compat)

Run ordinary Linux-targeted C programs on the capability microkernel
without porting them: the kernel translates a subset of rv64 Linux
syscalls onto Moonlight primitives (console, `vfs_server`, static
arenas), and `userspace/libc/` is a freestanding C library over exactly
that subset. Numbers are the asm-generic table (verified against musl
`arch/riscv64/bits/syscall.h.in`); the single source of truth is
`kernel/include/linux_abi.h`, which both the kernel and libc include.

Status: running. `userspace/example/linux_demo.c` exercises
identity/time/heap/mmap/files/stdio on target (QEMU smoke asserts
`[LINUX-DEMO] ALL PASS`); host suites `tests/test_linux.c` (personality)
and `tests/test_libc.c` (libc) run in `tools/verify.sh [1b]`.

## 1. Dispatch rule (`kernel/src/syscall.c`)

`a7 <= SYS_MAX` (7) runs the native Moonlight capability path; `a7 > 7`
runs the Linux personality (`linux_syscall_frame`). Linux numbers 0..7
therefore stay `-ENOSYS`: no collision, no ambiguity. Results use the
Linux convention (`a0` = value or `-errno`); unknown numbers return
`-ENOSYS` (including `execve`, `kill`, `clone` — see §7).

## 2. Processes, users, time

- One thread = one "process": `getpid`/`gettid` return the caller TCB id
  (shell slot reports 0). No `fork`/`clone`/`exec`: new processes are
  kernel threads spawned at boot (`boot.c`: `linux_demo_main`).
- Single user: `getuid`/`geteuid`/`getgid`/`getegid` = 0, `getppid` = 0.
- `uname` reports `MoonlightOS / moonlight / 0.1-linux-compat / riscv64`.
- `set_tid_address` records nothing and returns the caller id.
- Time is the CLINT MTIME at 10 MHz (100 ns/tick):
  `clock_gettime` (`REALTIME`/`MONOTONIC`/`PROCESS_CPUTIME_ID`),
  `clock_getres` (100 ns), `gettimeofday` (tz arg must be NULL).
  `sleep`/`usleep` are yield spins, not timer sleeps.
- `sched_yield` parks the caller cooperatively via `sched_coop_switch`
  (same mechanism as native `SYS_YIELD`); `exit`/`exit_group` park the
  thread permanently and record the masked exit code
  (`linux_last_exit_code`, `linux_exit_count`).

## 3. fds and the flat file model (`kernel/src/linux.c` + `vfs_server`)

- fds 0/1/2 are the console (see §5); fds >= 3 are that caller's VFS fds
  (`linux_fd - 3`), isolated per caller exactly like the shell's tables.
- One flat namespace, single root: absolute paths land on the basename
  (`/tmp/abs.txt` → `abs.txt`), trailing slashes stripped, `/` itself is
  not openable. `getcwd` always returns `/`; `chdir` accepts only `/`
  and `.`; there are no directories (`O_DIRECTORY`/`AT_REMOVEDIR` fail,
  `mkdir` is `ENOSYS` in libc).
- Names: 1..31 chars of `[A-Za-z0-9._-]` not starting with `-`; anything
  else is `ENOENT`. Paths are copied from user space bounded (256 B cap,
  per-page `vspace_resolve` validation) and always NUL-terminate.
- `openat` (only `AT_FDCWD`): `O_CREAT` backs the file with a 32 KB frame
  from a static 8-file pool; `O_EXCL`, `O_TRUNC` (shrink to 0 at open),
  `O_APPEND` (every write snaps to EOF) honored; `O_CLOEXEC`/`O_NONBLOCK`
  accepted and ignored (single-hart, no exec). Mode bits are ignored
  (owner model). Anything beyond 8 files is `ENOSPC`.
- `read`/`write` stage through a bounded 4 KB kernel buffer (never on
  user memory directly); per-call sizes are capped (512 MB hard,
  `readv`/`writev` additionally: 16 vecs, 64 KB total).
- `lseek` on any open fd over `[0, capacity]` (holes read as zero: the
  extending write zero-fills the gap); console fds are not seekable.
  `pread64`/`pwrite64` are seek+IO+restore, **not atomic** (single hart).
- `ftruncate` shrinks only (grow-by-truncate is `EINVAL`; extend via
  writes). `unlink` is owner-only and refused while open.
  `faccessat`: existence + `R_OK`/`W_OK` granted, `X_OK` denied.
- `stat`/`fstat`/`newfstatat`: 128-byte rv64 layout shared byte-for-byte
  with libc (`lx_stat_t`); regular files mode `0644`, console fds report
  a char device. No symlinks (`lstat` == `stat`); unknown flags `EINVAL`.
- The VFS operations used here (`seek`, `truncate_fd`, `set_append`,
  zero-filling extending write) are covered by the same model as the
  shell path: `kernel/isabelle/FS_Verification.thy` (`seek_other_fds`,
  `seek_bounded`, `wf_seek`, append/ownership theorems), no axioms.

## 4. Memory: `brk` / `mmap` (`lx_heap` static arena)

- One 192 KB static arena (16-byte aligned, BSS-zeroed): `brk` grows up
  from its base, `mmap` (`ANONYMOUS` only) takes page-rounded slices from
  the same bump. Linux semantics kept: `brk(0)` queries, failure returns
  the *current* break (not an error); `mmap` length 0 is `EINVAL`,
  `MAP_FIXED` inside the arena is honored, outside is `ENOMEM`.
- `munmap`/`madvise` validate the range and accept (no reclaim — bump
  only); `mprotect` accepts inside the arena (single RW domain on M-mode;
  no per-page XN yet). File-backed `mmap` is `ENOSYS`.
- `malloc`/`calloc`/`realloc`/`free` (K&R free list over `sbrk`) plus
  `qsort`, `rand`/`srand`, `strtol`/`atoi`, `strdup` live in libc
  (`userspace/libc/src/stdlib.c`).

## 5. Console fds

- Writes to 1/2 go to `console_putc` (UART+VGA routing, same as native
  `SYS_DEBUG_PUTC`); reads from 0 are nonblocking (`-EAGAIN` when the
  keyboard ring is empty — libc's `__ml_call6` yields and retries, up to
  8x) with newline-terminated line discipline. fd order is checked before
  pointers (Linux validates the fd first); `read(1)`/`write(0)` are
  `EBADF`, `close(0..2)` is `EBADF`.

## 6. The EAGAIN contract (read this before touching either side)

`-EAGAIN` always means **"not executed, safe to retry"**:

- Kernel (`syscall.c`): the WCET gate on the Linux path is an *admission*
  check, taken before the personality runs. A post-execution clobber
  would be a lie — VFS/heap side effects already committed — and libc's
  retry would execute them twice (this exact bug once produced doubled
  file bytes and leaked fds blocking `unlink` as QEMU flakes).
- libc (`bits/ml_sys.h`, `errno.c`): every raw ecall goes through
  `__ml_call6`, which retries `-EAGAIN` with a yield between tries.
  Legitimate `-EAGAIN` sources (empty stdin, exhausted tick budget at
  entry) all precede side effects by construction.
- WCET is therefore **advisory** for the personality: an overrunning
  Linux op is delivered with its real result. The 5 µs kernel budget is
  still hard-enforced on the native capability path.

## 7. Explicit non-goals (v1)

No `fork`/`clone`/`exec`/signals/pipes/sockets/epoll/shared-memory/file
`mmap`/symlinks/directories/permissions beyond the owner model/`ioctl`/
`fcntl`/` poll`/`futex`. Purecap builds additionally refuse file *create*
(`-EIO`: backing needs an `Untyped`-retyped `Frame` cap — future work);
all other ops work. User pointers are validated page-by-page against the
kernel vspace (M-mode identity map today) with a 16 MB per-range cap;
violations are `-EFAULT`, never a kernel fault.

## 8. Build, test, demo

```
make -C userspace          # ELFs incl. build/linux_demo.elf (_start -> main)
make -C userspace drivers  # freestanding rv64 -Werror compartment gate
tools/build_qemu.sh        # target image, DICE self-provisioned (includes linux_demo thread)
tools/verify.sh            # [1b] test_linux + test_libc, [1c] ELFs, [4/4] LINUX-DEMO smoke
```

- `tests/test_linux.c`: numbers sanity, `ENOSYS` set, fd/console
  semantics, full file roundtrip (incl. `O_EXCL`, append, sparse,
  `ftruncate`-shrink refusal-to-grow, `pread`/`pwrite`), `brk`/`mmap`
  bounds, stat layout, per-client isolation. Links the real
  `kernel/src/linux.c` + `vfs_server`; needs `-no-pie` (the VFS cap is
  u32, the pool must sit below 4 GB) and skips otherwise.
- `tests/test_libc.c`: `vsnprintf` formats, `malloc`/`calloc`/`realloc`/
  `strdup`, `qsort`, `strtol` bases, `FILE` over a ramfile stub.
- `userspace/example/linux_demo.c`: the same `main()` builds both as a
  standalone ELF and as the in-kernel `linux_demo_main` thread spawned
  by `boot.c` (partition 0, budget 2000/5000 — headroom first, since a
  starved budget surfaces as `-EAGAIN` and libc only retries 8x).
  Prints `[LINUX-DEMO] ...` markers, ends `ALL PASS`, parks via `exit`.
