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
- BusyBox version drift in flag details — pin to BusyBox 1_36_stable applet help text, note deviations in code comments.
- ramfs limits (`VFS_FILE_MAX`, `VFS_MAX_NODES`) cap `-R`/large-file fidelity — tests use small trees.
- `cp -i`/`rm -i` interactivity has no tty prompt plumbing yet — define as “decline without tty, override with `-f`” and test that.

## 8. Real-implementation grounding (BusyBox 1_36_stable, mandatory per applet)
- Source of truth per applet (mirror/busybox @1_36_stable):
  `coreutils/ls.c`, `coreutils/cat.c`, `coreutils/head.c`, `coreutils/tail.c`,
  `coreutils/wc.c`, `coreutils/cp.c`, `coreutils/mv.c`, `coreutils/rm.c`,
  `coreutils/mkdir.c`, `coreutils/touch.c`, `coreutils/stat.c`,
  `findutils/find.c`, `coreutils/tee.c`, plus `libbb/` helpers
  (`getopt32long`, `bb_cat`, `print_numbered_lines`, `open_or_warn_stdin`,
  `bb_simple_perror_msg`, `make_human_readable_str`).
- Checked 2026-10-06 (ls, cat — rest must be checked the same way during plan):
  `ls.c` usage `[-1AaCxdLH R Fp lins h rSXv ctu]` with option-bitmask +
  precedence rules (`:t-S:S-t`, `:C-xl:x-Cl:l-xC`, `:C-1:1-C`, `:c-u:u-c`,
  `-d` cancels `-R`, `-n`/`-g` imply `-l`); `cat.c` usage `[-nbvteA]`
  with `-A == -vet`, default stdin when no FILE (`*--argv = "-"`),
  `open_or_warn_stdin` + continue-on-error with `retval` accumulation.
- Architectural lessons to mimic (adapted to ramfs/builtins, not copied verbatim):
  - Option parsing as bitmask + explicit precedence resolution, not independent bools
    (current `cmd_ls` bool flags miss `-d` vs `-R`, `-C/-x/-l/-1` precedence).
  - Separate scan vs display (`scan_one_dir` / `splitdnarray` / `sort_and_display_files`
    vs `display_single`); `dnode`-style stat-once struct instead of re-`vfs_find` per print.
  - Continue-on-error with accumulated exit code (`G.exit_code` pattern):
    multi-file `cat`/`ls`/`cp` print others and return 1 — current `cmd_cat`
    already continues, `cmd_ls` must do the same for multi-path.
  - Numbering via shared helper (`print_numbered_lines` + `number_state`
    with `width/start/inc/sep/all/nonempty`) instead of per-applet loops;
    `-b` overrides `-n` for empty lines, `-s` squeezes blanks.
  - Stdin default (`-` or no args reads pipe/`sh_stdin_data`), `bb_cat` streaming
    instead of whole-file `VFS_FILE_MAX` buffering where possible.
- Plan gate: each applet diff must cite the BusyBox function/behavior it mimics
  (e.g. “`ls` sort precedence per `ls.c: sortcmp`”, “`cat -b` per `catv()` numbering”)
  and note deliberate deviations (no `lstat`/symlinks, no uid/gid, ramfs-only).
