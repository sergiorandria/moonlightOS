# BusyBox File-Utils Compat — Phase 1 Design (2026-10-06)

## 1. Intent (agreed)
- Bring moonsh file applets closer to real BusyBox behavior without leaving the microkernel builtin model.
- Phased work; Phase 1 = file utils only.
- Ground truth = BusyBox (flags, exit codes, error text), not GNU coreutils, not POSIX-minimal.
- Keep things modular: stop growing monolithic `userspace/sh/shell_core.h` (2173 lines).

What was said vs assumed:
- Said: improve all busybox-like commands, mimic real implementation, keep modular.
- Agreed: phased groups, BusyBox truth, file-utils first, approach A (compat in builtins) + C (ELF ABI as interface-only roadmap).
- Assumed (locked in Sec 2-4): flag matrix below, error/exit rules, test extensions. Correct me if wrong.

Success = `tests/test_moonsh_busybox.c` extended with BusyBox-compat cases passes, existing cases stay green, kernel build untouched.

## 2. Architecture — modular split (Sec 1, approved)
- Engine stays in `userspace/sh/shell_core.h`: tokenize, `;` chaining, pipes, `>`/`>>`, vars (`$?`, `$USER`, …), quotes/escapes, history, alias, `shell_exec_single_cmd`, single `shell_builtins[]` table.
- New: `userspace/sh/applets/shell_file.h` owns file applets only:
  `ls, cat, touch, write, rm, cp, mv, mkdir, rmdir, head, tail, wc, stat, find, tee` (+ existing `hex/hd/hexdump/xxd` stays where it is unless trivial to move).
- Shared helpers live with applets or in engine, not duplicated:
  `sh_puts/sh_putc/sh_print_*`, `vfs_resolve_path/vfs_find/vfs_read_file` (from `shell_vfs.h`), plus new small `sh_file_error(prog, path, msg)` for uniform `prog: path: msg` text.
- Inclusion rule: `shell_core.h` includes `applets/shell_file.h`; nothing else includes it directly. No duplicate symbols (all `static inline` as today).
- No IPC change in Phase 1. Phase 2 ELF ABI is interface-only here:
  `argv + stdin/stdout byte streams + int exit_code over IPC`, shell dispatches, applet links against same VFS client. No server code in this phase.

Out of scope: permission/ownership/time semantics beyond display strings, `chmod/chown/chgrp`, `ln`, `df/du`, VFS-server split.

## 3. Flag matrix — file utils (Sec 2, approved)
- `ls`: `-l/-a/-A/-h/-R/-d/-1/-F/-p`, multi-path args, file-vs-dir handling, `-A` = dotfiles minus `.`/`..` (ramfs has no `.`/`..` entries; document as no-op filter).
- `cat`: `-n/-b/-s/-E`, multi-file concat, stdin when no file or `-` (pipe data via existing `sh_stdin_data`), `cat: X: No such file or directory` continued across files.
- `head/tail`: `-n N`, `-c N`, `tail +n` (from-N), `-q` implied with multi-file headers only when BusyBox prints them; keep current `-n` compat.
- `wc`: `-l/-w/-c/-L`, multi-file with `total` line, stdin path.
- `touch/cp/mv/rm/mkdir/rmdir`: `touch -c` (no-create), `cp -f/-i/-r/-R`, `mv -f/-i`, `rm -f/-i/-r/-R`, `mkdir -p`, `rmdir -p` (best-effort on ramfs).
- `stat/find/tee`: `stat -c FORMAT` (minimal `%n %s %F`), `find PATH -name PAT -type f/d -maxdepth N`, `tee -a`.
- Unknown flags: BusyBox-style `prog: invalid option -- 'x'` + usage line, return 2 (locked in Sec 3).

## 4. Errors / exit codes / data flow (Sec 3, approved)
- Text (single `sh_puts` sink, no stderr split yet):
  `ls: cannot access 'X': No such file or directory`
  `cat: X: No such file or directory`
  `cp: cannot stat 'X': No such file or directory`
  `mv: can't rename 'X': No such file or directory`
  `rm: cannot remove 'X': No such file or directory`
  `mkdir: can't create directory 'X': File exists`
- Codes: `0` success, `1` runtime/partial failure (one of many files missing still prints others, returns 1), `2` usage error. `$?` reflects it (existing `test`/`[` plumbing).
- Flow unchanged: `parse -> vfs_resolve_path -> vfs_find/read -> sh_puts`. Masked sections untouched (no `sie` work here).

## 5. Tests (Sec 4, approved)
- Extend `tests/test_moonsh_busybox.c`: multi-path `ls`, `cat -b/-s/-E`, `head -c`, `tail +n`, `wc` totals, `cp -i`/`mv -i` non-interactive path (treat as prompt-declined or overwrite per flag; document choice in test), `rm -r`, `mkdir -p`, error-text substring checks + `$?` checks (`echo $?`).
- Keep all existing cases green; no kernel changes; host-only `gcc` run.
- Compile gate: `shell_file.h` compiles only via `shell_core.h` (include-guard + no standalone TU).

## 6. Phase 2 sketch (not built now)
- ELF applet ABI draft: `main(argc, argv)` over spawn, stdin/stdout as IPC byte streams, exit code returned via IPC reply, VFS client syscalls (`SEND/RECV` on VFS ep). Shell keeps builtin fallback until server lands.

## 7. Risks
- BusyBox version drift in flag details — pin to BusyBox 1.36 applet help text, note deviations in code comments.
- ramfs limits (`VFS_FILE_MAX`, `VFS_MAX_NODES`) cap `-R`/large-file fidelity — tests use small trees.
- `cp -i`/`rm -i` interactivity has no tty prompt plumbing yet — define as “decline without tty, override with `-f`” and test that.
