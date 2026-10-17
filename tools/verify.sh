#!/bin/bash
set -euo pipefail
echo "=== Moonlight verification (v2 single codebase) ==="
echo "[1/4] Host unit tests"
ABI="-I userspace/abi"
LIBCINC="-I userspace/libc/include -I userspace/abi"
# Shared include set for the seven shipping kernel/userspace suites added to
# §1f (test_elf, test_frames, test_tcp, test_ipc_integration,
# test_qube_destroy_auth, test_blk_hal, test_console_gui_layout). The two shell
# suites keep their own per-suite flags: test_shell_readline takes
# -I userspace/include because its included userspace/sh/shell_tty.c pulls in
# services/ipc_helpers.h (without it the TU does not compile), and
# test_moonsh_busybox takes no -I dirs.
SHIPINC="-I userspace/include -I kernel -I userspace/abi -I userspace/libc/include -I userspace/net"

# --- Fail aggregation for host tests ----------------------------------------
# A bare `cmd || echo "FAIL: cmd"` exits 0 under `set -e`, so a broken test
# still produced a green gate. run_test records every failure in FAILED and the
# script exits non-zero before the summary if any occurred.
# run_test always returns 0: one failure must not abort the run (otherwise the
# rest of the gate would never execute and stay hidden); the FAILED check below
# is the single kill switch.
FAILED=0
run_test() {
  local label="$1"; shift
  if "$@"; then
    return 0
  fi
  echo "FAIL: $label"
  FAILED=$((FAILED + 1))
  return 0
}

# run_optional <label> <cmd...>
# Environment-optional stage. The only such stages are the clang-gated
# userspace/kernel builds: with no clang they cannot run at all, so they print
# SKIP and do not fail the gate. If clang IS present a genuine build failure is
# fatal and is aggregated like any other.
run_optional() {
  local label="$1"; shift
  if "$@"; then
    return 0
  fi
  if command -v clang &>/dev/null; then
    echo "FAIL: $label"
    FAILED=$((FAILED + 1))
  else
    echo "SKIP: $label (clang not found)"
  fi
  return 0
}

echo "[1a] ABI regression: uintptr_t must be 8 bytes (PLAN 3)"
run_test abi-uintptr bash -c "gcc $ABI -o /tmp/test_abi tests/test_abi.c && /tmp/test_abi"
run_test abi-static-assert bash -c 'echo "#include <stdint.h>
_Static_assert(sizeof(uintptr_t)==8, \"uintptr_t is not 8 bytes\");" | clang --target=riscv64-unknown-elf -mabi=lp64 -I$(clang --print-resource-dir)/include -ffreestanding -fsyntax-only -xc - && echo "PASS: cross static_assert 8 bytes (freestanding, no -I/usr/include)"'
echo "[1b] userspace servers (host sim)"
run_test test_sched_server bash -c "gcc $ABI -o /tmp/test_sched_server tests/test_sched_server.c userspace/sched_server/server.c && /tmp/test_sched_server"
run_test test_vfs bash -c "gcc $ABI -o /tmp/test_vfs tests/test_vfs.c userspace/vfs_server/server.c 2>&1 && /tmp/test_vfs"
echo "[1c] userspace drivers host-sim (frozen v1 ABI headers in userspace/abi)"
run_test test_uart bash -c "gcc -Wall -Wextra -Werror $ABI -o /tmp/test_uart tests/test_uart.c && /tmp/test_uart"
run_test test_plic bash -c "gcc -Wall -Wextra -Werror $ABI -o /tmp/test_plic tests/test_plic.c && /tmp/test_plic"
run_test test_timer bash -c "gcc -Wall -Wextra -Werror $ABI -o /tmp/test_timer tests/test_timer.c && /tmp/test_timer"
run_test test_rtc bash -c "gcc -Wall -Wextra -Werror $ABI -o /tmp/test_rtc tests/test_rtc.c && /tmp/test_rtc"
run_test test_power bash -c "gcc -Wall -Wextra -Werror $ABI -o /tmp/test_power tests/test_power.c && /tmp/test_power"
echo "[1d] freestanding libc host-sim"
run_test test_libc bash -c "gcc $LIBCINC -o /tmp/test_libc tests/test_libc.c userspace/libc/src/string.c userspace/libc/src/stdlib.c userspace/libc/src/stdio.c userspace/libc/src/ctype.c userspace/libc/src/time.c userspace/libc/src/errno.c userspace/libc/src/math.c userspace/libc/src/wchar.c userspace/libc/src/wctype.c userspace/libc/src/signal.c userspace/libc/src/fenv.c userspace/libc/src/locale.c userspace/libc/src/scanf.c userspace/libc/src/getopt.c userspace/libc/src/env.c userspace/libc/src/strings.c userspace/libc/src/spawn.c userspace/libc/src/proc.c 2>&1 && /tmp/test_libc"
run_test test_newlibc bash -c "gcc $LIBCINC -o /tmp/test_newlibc tests/test_newlibc.c userspace/libc/src/complex.c userspace/libc/src/monetary.c userspace/libc/src/langinfo.c userspace/libc/src/iconv.c userspace/libc/src/locale.c userspace/libc/src/math.c userspace/libc/src/nltypes.c userspace/libc/src/threads.c userspace/libc/src/stdlib.c userspace/libc/src/string.c userspace/libc/src/errno.c -lm 2>&1 && /tmp/test_newlibc"
run_test test_batch4 bash -c "gcc $LIBCINC -o /tmp/test_batch4 tests/test_batch4.c userspace/libc/src/string.c userspace/libc/src/stdlib.c userspace/libc/src/stdio.c userspace/libc/src/errno.c userspace/libc/src/time.c userspace/libc/src/file.c userspace/libc/src/unistd.c userspace/libc/src/proc.c userspace/libc/src/fcntl.c userspace/libc/src/signal.c userspace/libc/src/math.c userspace/libc/src/wchar.c userspace/libc/src/wctype.c userspace/libc/src/locale.c -lm 2>&1 && /tmp/test_batch4"
run_test test_batch5 bash -c "gcc $LIBCINC -o /tmp/test_batch5 tests/test_batch5.c userspace/libc/src/syscall.c userspace/libc/src/crypt.c userspace/libc/src/ether.c userspace/libc/src/execinfo.c userspace/libc/src/fmtmsg.c userspace/libc/src/libgen.c userspace/libc/src/ndbm.c userspace/libc/src/search.c userspace/libc/src/sendfile.c userspace/libc/src/shadow.c userspace/libc/src/sysevent.c userspace/libc/src/sysvipc.c userspace/libc/src/utmpx.c userspace/libc/src/ptimer.c userspace/libc/src/aio.c userspace/libc/src/string.c userspace/libc/src/stdlib.c userspace/libc/src/stdio.c userspace/libc/src/errno.c userspace/libc/src/time.c userspace/libc/src/file.c userspace/libc/src/dir.c userspace/libc/src/unistd.c userspace/libc/src/fcntl.c userspace/libc/src/signal.c userspace/libc/src/pthread.c userspace/libc/src/math.c userspace/libc/src/wchar.c userspace/libc/src/wctype.c userspace/libc/src/locale.c -lm -lpthread 2>&1 && timeout 60 /tmp/test_batch5"
run_test test_batch6 bash -c "gcc $LIBCINC -o /tmp/test_batch6 tests/test_batch6.c userspace/libc/src/sysstat.c userspace/libc/src/netif.c userspace/libc/src/stropts.c userspace/libc/src/string.c userspace/libc/src/stdlib.c userspace/libc/src/stdio.c userspace/libc/src/errno.c userspace/libc/src/time.c userspace/libc/src/file.c userspace/libc/src/statvfs.c userspace/libc/src/dir.c userspace/libc/src/unistd.c userspace/libc/src/fcntl.c userspace/libc/src/signal.c userspace/libc/src/math.c -lm 2>&1 && /tmp/test_batch6"
echo "[1e] userspace ELFs + driver compile gates (freestanding rv64 -Werror)"
run_optional userspace-ELFs bash -c 'set -o pipefail; make -C userspace 2>&1 | tail -n 2'
run_optional userspace-drivers bash -c 'set -o pipefail; make -C userspace drivers 2>&1 | tail -n 3'
run_optional userspace-stubs bash -c 'set -o pipefail; make -C userspace stubs 2>&1 | tail -n 3'
run_optional vault-cryptblk-ELFs bash -c 'set -o pipefail; make -C userspace build/vault.elf build/cryptblk.elf 2>&1 | tail -n 3'
# §1e2 — initrd blob freshness (R0.6). The check regenerates the blob from
# userspace/build/*.elf and requires the committed kernel/initrd_data.c +
# kernel/initrd.h to be byte-identical. mkinitrd.sh contributes determinism (no
# timestamps, host paths or randomness), but byte-identity ALSO requires the
# ELF-producing toolchain (clang + lld) to be reproducible on this host: an ELF
# whose bytes differ for the same source (e.g. a different toolchain build)
# makes this check fail on an otherwise up-to-date tree. Cross-host ELF
# bit-reproducibility is tracked as R5.4 (plan Phase 5); this stage assumes a
# deterministic local toolchain. A blob that no longer matches the ELFs §1e
# built is exactly the silent drift this stage catches.
#
# Two phases, because regeneration REPAIRS the file in place:
#   (a) BEFORE: a working copy that is already dirty is only visible here — the
#       rewrite below would silently heal it and leave the post-diff empty, so a
#       lone post-regeneration diff can never fail on a hand-edited blob.
#   (b) AFTER:  a blob committed stale only shows up once the rewrite replaces
#       it and the new bytes diverge from the index.
# The pre-check therefore (correctly, if conservatively) also flags a blob that
# was regenerated but never `git add`ed: that blob would not be committed.
echo "[1e2] initrd freshness (regenerate from userspace ELFs; committed blob must match)"
INITRD_FILES=(kernel/initrd_data.c kernel/initrd.h)
if [ ! -f userspace/build/mem_server.elf ]; then
  # Same environment-optional carve-out as §1e: with no ELFs there is nothing to
  # regenerate from, and kernel/Makefile deliberately falls back to the committed
  # blob so a standalone `make -C kernel` still builds (PARTIAL, not red).
  echo "SKIP: initrd freshness (userspace/build/mem_server.elf absent; nothing to regenerate from)"
else
  initrd_stale=0
  if ! git diff --quiet -- "${INITRD_FILES[@]}"; then
    echo "FAIL: initrd blob dirty before regeneration (hand-edited, or regenerated but not staged)"
    git diff --stat -- "${INITRD_FILES[@]}"
    initrd_stale=1
  fi
  if ! tools/mkinitrd.sh > /tmp/mkinitrd_gate.log 2>&1; then
    echo "FAIL: tools/mkinitrd.sh failed"
    sed 's/^/  /' /tmp/mkinitrd_gate.log
    initrd_stale=1
  fi
  if ! git diff --quiet -- "${INITRD_FILES[@]}"; then
    echo "FAIL: initrd blob stale: regeneration from userspace/build/*.elf differs from the committed blob"
    git diff --stat -- "${INITRD_FILES[@]}"
    initrd_stale=1
  fi
  if [ "$initrd_stale" -eq 0 ]; then
    echo "PASS: initrd blob matches userspace/build/*.elf"
  else
    FAILED=$((FAILED + 1))
  fi
fi
echo "[1f] v2 kernel build + Stage-2/3 host tests"
run_test test_v2ipc bash -c "clang -Wall -Wextra -Werror -o /tmp/test_v2ipc tests/test_v2ipc.c 2>&1 && /tmp/test_v2ipc"
run_test test_v2caps bash -c "clang -Wall -Wextra -Werror -o /tmp/test_v2caps tests/test_v2caps.c 2>&1 && /tmp/test_v2caps"
run_test test_qlabels bash -c "clang -Wall -Wextra -Werror -o /tmp/test_qlabels tests/test_qlabels.c 2>&1 && /tmp/test_qlabels"
run_test test_qube_policy bash -c "clang -Wall -Wextra -Werror -o /tmp/test_qube_policy tests/test_qube_policy.c 2>&1 && /tmp/test_qube_policy"
run_test test_qargs bash -c "clang -Wall -Wextra -Werror -o /tmp/test_qargs tests/test_qargs.c 2>&1 && /tmp/test_qargs"
run_test test_netfw bash -c "gcc -Wall -Wextra -Werror -o /tmp/test_netfw tests/test_netfw.c 2>&1 && /tmp/test_netfw"
run_test test_aead bash -c "gcc -Wall -Wextra -Werror -o /tmp/test_aead tests/test_aead.c 2>&1 && /tmp/test_aead"
run_test test_crypt bash -c "gcc -Wall -Wextra -Werror -o /tmp/test_crypt tests/test_crypt.c 2>&1 && /tmp/test_crypt"
run_test test_argon2id bash -c "gcc -Wall -Wextra -Werror -o /tmp/test_argon2id tests/test_argon2id.c 2>&1 && /tmp/test_argon2id"
run_test test_gui bash -c "gcc -Wall -Wextra -Werror -o /tmp/test_gui tests/test_gui.c 2>&1 && /tmp/test_gui"
run_test test_irq bash -c "gcc -Wall -Wextra -Werror -o /tmp/test_irq tests/test_irq.c 2>&1 && /tmp/test_irq"
run_test test_dev_leaves bash -c "gcc -Wall -Wextra -Werror -o /tmp/test_dev_leaves tests/test_dev_leaves.c 2>&1 && /tmp/test_dev_leaves"
run_test test_net_stack bash -c "gcc -Wall -Wextra -Werror -o /tmp/test_net_stack tests/test_net_stack.c 2>&1 && /tmp/test_net_stack"
run_test test_stub_drivers bash -c "gcc -Wall -Wextra -Werror -o /tmp/test_stub_drivers tests/test_stub_drivers.c 2>&1 && /tmp/test_stub_drivers"
run_test test_input bash -c "gcc -Wall -Wextra -Werror -o /tmp/test_input tests/test_input.c 2>&1 && /tmp/test_input"
run_test test_virtio_input bash -c "gcc -Wall -Wextra -Werror -o /tmp/test_virtio_input tests/test_virtio_input.c 2>&1 && /tmp/test_virtio_input"
run_test test_driver_bounds bash -c "gcc -Wall -Wextra -Werror -I userspace/abi -o /tmp/test_driver_bounds tests/test_driver_bounds.c 2>&1 && /tmp/test_driver_bounds"
run_test test_rng bash -c "gcc -Wall -Wextra -Werror -o /tmp/test_rng tests/test_rng.c 2>&1 && /tmp/test_rng"
run_test test_abi_sync bash -c "gcc -Wall -Wextra -Werror -o /tmp/test_abi_sync tests/test_abi_sync.c 2>&1 && /tmp/test_abi_sync"
run_test test_shell_programs bash -c "gcc -Wall -Wextra -Werror -o /tmp/test_shell_programs tests/test_shell_programs.c 2>&1 && /tmp/test_shell_programs"
# --- Shipping-suite coverage (Task 0.4) -------------------------------------
# Nine real suites that were never gated. The two shell suites cover the
# shipping engine: test_moonsh_busybox #includes userspace/sh/shell_core.h and
# test_shell_readline #includes userspace/sh/shell_tty.c (which pulls
# shell_core.h -> shell_vfs.h), replacing the retired dead-engine tests
# test_shell/test_shell_vfs. The other seven cover kernel/user memory, ELF
# loading, TCP, IPC and device paths.
run_test test_shell_readline bash -c "gcc -O2 -I userspace/include -o /tmp/test_shell_readline tests/test_shell_readline.c 2>&1 && /tmp/test_shell_readline"
run_test test_moonsh_busybox bash -c "gcc -O2 -no-pie -o /tmp/test_moonsh tests/test_moonsh_busybox.c 2>&1 && /tmp/test_moonsh"
run_test test_elf bash -c "gcc -O2 $SHIPINC -o /tmp/test_elf tests/test_elf.c 2>&1 && /tmp/test_elf"
run_test test_frames bash -c "gcc -O2 $SHIPINC -o /tmp/test_frames tests/test_frames.c 2>&1 && /tmp/test_frames"
run_test test_tcp bash -c "gcc -O2 $SHIPINC -o /tmp/test_tcp tests/test_tcp.c 2>&1 && /tmp/test_tcp"
run_test test_ipc_integration bash -c "gcc -O2 $SHIPINC -o /tmp/test_ipc_integration tests/test_ipc_integration.c 2>&1 && /tmp/test_ipc_integration"
run_test test_qube_destroy_auth bash -c "gcc -O2 $SHIPINC -o /tmp/test_qube_destroy_auth tests/test_qube_destroy_auth.c 2>&1 && /tmp/test_qube_destroy_auth"
run_test test_blk_hal bash -c "gcc -O2 $SHIPINC -o /tmp/test_blk_hal tests/test_blk_hal.c 2>&1 && /tmp/test_blk_hal"
run_test test_console_gui_layout bash -c "gcc -O2 $SHIPINC -o /tmp/test_console_gui_layout tests/test_console_gui_layout.c 2>&1 && /tmp/test_console_gui_layout"
# Delete the kernel artifact before building so a failed `make -C kernel` cannot
# be masked by a stale ELF from an earlier successful run: with no ELF, §1g's
# linker/rodata gates SKIP and §4 (QEMU) refuses to boot a binary this run never
# produced. (§3 rebuilds from `make clean` afterwards, so this also fixes the
# §1g window between the two builds.)
rm -f kernel/build/moonlight.elf
run_optional kernel-build bash -c 'set -o pipefail; make -C kernel 2>&1 | tail -n 1'
# SOLID module budget (production-ready): every S-mode kernel TU <= 500
# lines, kboot (orchestration only) <= 200. seL4-style file-per-concern.
# Caps are named constants so each bound is reviewable in one place.
KERNEL_TU_MAX=500  # default cap: every S-mode kernel TU
KBOOT_C_MAX=200    # kboot.c: boot orchestration only
USER_C_MAX=700     # user.c: hand-written U-mode payload TU. Byte-at-a-time
                   # `uputc` emission with no literal pool keeps it larger than
                   # the 500-line kernel-TU budget, but it is a hard bound
                   # (647 lines today, ~50 lines of headroom).
#
# The TU list is DERIVED, not hand-maintained (Task 0.7). It used to be a
# hard-coded list, so a TU added to kernel/Makefile's SRC_C was silently
# unchecked. `make -p -n` prints make's variable database WITHOUT running
# recipes and joins `\`-continued assignments onto one line; a sed filter
# then pulls the SRC_C / SRC_S values.
#
# Fail closed, SRC_C and SRC_S INDEPENDENTLY: either extraction being empty is
# a failure. Testing only the union is not enough -- SRC_S always yields the
# .S files, so a failed SRC_C extraction would leave a non-empty union and
# print PASS while silently dropping every `.c` TU from the cap.
#
# Scope stays the kernel proper: the one SRC_C entry that is not a kernel
# module is initrd_data.c, a machine-generated byte blob (tools/mkinitrd.sh,
# ~15.6k lines), excluded by name from the derived list. user.c IS checked --
# it is a hand-written TU that kernel/Makefile compiles with kernel flags (and
# §1g gates its object), so it carries its own bound (USER_C_MAX) rather than
# escaping the budget. Every other name in SRC_C/SRC_S is checked, so a newly
# added TU is covered automatically.
kernel_line_budget() {
  local mkdb src_c src_s tus over kboot_n bad=0
  # Capture make's variable database once; a `make` failure degrades to the
  # fail-closed guard rather than a bare `set -e` abort (pipefail).
  mkdb=$(make -C kernel --no-print-directory -p -n 2>/dev/null) || mkdb=""
  src_c=$(printf '%s\n' "$mkdb" \
    | sed -n 's/^SRC_C[[:space:]]*[:?+]*=[[:space:]]*//p' \
    | tr ' ' '\n' | sed '/^$/d; s|^|kernel/|') || src_c=""
  src_s=$(printf '%s\n' "$mkdb" \
    | sed -n 's/^SRC_S[[:space:]]*[:?+]*=[[:space:]]*//p' \
    | tr ' ' '\n' | sed '/^$/d; s|^|kernel/|') || src_s=""
  if [ -z "$src_c" ]; then
    echo "FAIL: kernel module budget: SRC_C not derived from kernel/Makefile (fail closed)"
    return 1
  fi
  if [ -z "$src_s" ]; then
    echo "FAIL: kernel module budget: SRC_S not derived from kernel/Makefile (fail closed)"
    return 1
  fi
  # Fixed-string, whole-line exclusion of the generated blob; user.c is KEPT
  # (it is a bounded kernel TU, not a generated artifact).
  tus=$(printf '%s\n%s\n' "$src_c" "$src_s" | grep -vxF 'kernel/initrd_data.c') || true
  if [ -z "$tus" ]; then
    echo "FAIL: kernel module budget: no TUs derived from kernel/Makefile SRC_C/SRC_S (fail closed)"
    return 1
  fi
  # Per-TU size gate. A non-file token (wc fails) must fail RED with a clear
  # message, not abort the script with no FAIL line under `set -e`.
  if ! over=$(printf '%s\n' "$tus" | xargs wc -l 2>/dev/null | awk \
        -v umax="$USER_C_MAX" -v kmax="$KERNEL_TU_MAX" '
          $2 == "total" { next }
          { lim = ($2 == "kernel/user.c") ? umax : kmax
            if ($1 + 0 > lim) printf "%s (%s > %s)\n", $2, $1, lim }'); then
    echo "FAIL: kernel module budget: derivation produced an unreadable entry (wc failed)"
    return 1
  fi
  if [ -n "$over" ]; then
    echo "FAIL: kernel module budget: $over"
    bad=1
  else
    echo "PASS: kernel module budget ($(printf '%s\n' "$tus" | wc -l) kernel TUs derived from SRC_C/SRC_S, all within caps)"
  fi
  kboot_n=$(wc -l < kernel/kboot.c)
  if [ "$kboot_n" -gt "$KBOOT_C_MAX" ]; then
    echo "FAIL: kboot budget ($kboot_n > $KBOOT_C_MAX)"
    bad=1
  else
    echo "PASS: kboot budget ($kboot_n <= $KBOOT_C_MAX)"
  fi
  return "$bad"
}
run_test kernel-module-budget kernel_line_budget
echo "[1g] v2 production gates (linker layout + user rodata ban)"
if [ -f kernel/build/moonlight.elf ]; then
  if python3 <<'PYEOF'
import re, subprocess, sys
secs = subprocess.run(['llvm-readelf', '-S', 'kernel/build/moonlight.elf'],
                      capture_output=True, text=True).stdout
syms = subprocess.run(['llvm-readelf', '-s', 'kernel/build/moonlight.elf'],
                      capture_output=True, text=True).stdout
def sym(name):
    m = re.search(r'([0-9a-f]+)\s+\d+ \w+ +\w+ +\w+ +\w+ +' + name + r'\b', syms)
    return int(m.group(1), 16)
bss, bend = sym('_bss'), sym('_bss_end')
bad = []
for line in secs.splitlines():
    # [Nr] Name Type Addr Off Size ES Flg ...
    m = re.match(r'\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)\s+\S+\s+(\S+)', line)
    if not m:
        continue
    name, typ, addr, size, flags = m.group(1), m.group(2), int(m.group(3), 16), int(m.group(4), 16), m.group(5)
    if typ != 'PROGBITS' or 'A' not in flags or addr == 0 or size == 0:
        continue
    if addr < bend and addr + size > bss:
        bad.append(name)
if bad:
    print('FAIL: PROGBITS inside [_bss,_bss_end):', bad)
    sys.exit(1)
print('linker gate: no PROGBITS in BSS-clear range (_bss=%x _bss_end=%x)' % (bss, bend))
PYEOF
  then
    : # gate passed (prints its own success line)
  else
    echo "FAIL: kernel linker gate"
    FAILED=$((FAILED + 1))
  fi
  clang --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 -O2 -ffreestanding \
    -nostdlib -fno-builtin -mcmodel=medany -mno-relax -Wall \
    -I$(clang --print-resource-dir)/include -c kernel/user.c -o /tmp/user_check.o 2>/dev/null
  if llvm-readelf -S /tmp/user_check.o | grep -q "rodata"; then
    echo "FAIL: user.c emits .rodata (U-mode would fault reading U=0 literals)"
    FAILED=$((FAILED + 1))
  else
    echo "kernel gate: user.c has no .rodata (immediates-only holds)"
  fi
else
  echo "SKIP: gates (kernel/build/moonlight.elf not built)"
fi
ISABELLE_STATUS="SKIP"
CHERI_STATUS="SKIP"
echo "[2/4] Isabelle/HOL proofs (requires Isabelle2025-2 + l4v)"
if command -v isabelle &>/dev/null; then
  if isabelle build -D kernel/isabelle -v; then
    ISABELLE_STATUS="PASS"
  else
    ISABELLE_STATUS="FAIL"
    echo "FAIL: isabelle build failed"
  fi
  echo "[2b/4] v2 anti-vacuity gate (no True-defined invariants, no sorry)"
  if grep -rn "sorry\|axiomatization\|quick_and_dirty\|oops" kernel/isabelle/; then
    ISABELLE_STATUS="FAIL"
    echo "FAIL: v2 spec contains sorry/axioms"
  elif grep -rn "equiv> True" kernel/isabelle/*.thy; then
    ISABELLE_STATUS="FAIL"
    echo "FAIL: v2 spec contains True-defined invariant (vacuous)"
  else
    echo "v2 anti-vacuity: PASS"
  fi
else
  echo "SKIP — isabelle not installed, proofs NOT checked (install Isabelle2025-2 to verify)"
  ISABELLE_STATUS="SKIP (NOT CHECKED)"
fi
echo "[3/4] CHERI build"
if command -v riscv64-unknown-elf-clang &>/dev/null; then
  if make -C kernel clean && CC=riscv64-unknown-elf-clang make -C kernel -j; then
    CHERI_STATUS="PASS (CHERI toolchain)"
  else
    CHERI_STATUS="FAIL"
  fi
else
  echo "SKIP — CHERI toolchain not found (riscv64-unknown-elf-clang missing), stock clang build covers this instead"
  if make -C kernel clean && make -C kernel -j; then
    echo "stock kernel build: PASS"
    CHERI_STATUS="PASS (STOCK)"
  else
    echo "FAIL: stock kernel build failed"
    CHERI_STATUS="FAIL"
  fi
fi
echo "[4/4] QEMU smoke (v2 S-mode kernel under OpenSBI)"
QEMU_STATUS="SKIP"
if [ -f kernel/build/moonlight.elf ]; then
  QEMU=$(command -v qemu-system-riscv64 || command -v /tmp/qb2/qemu-system-riscv64 || echo "")
  if [ -n "$QEMU" ] && [ -x "$QEMU" ]; then
    # FDE block disk (Task 4): 256M raw image owned by the cryptblk ELF
    # (mirrors tools/run_qemu.sh DISK_ARGS). Created once, persists
    # across runs: first-ever boot formats it, later boots reuse it.
    DISK="kernel/build/moonlight-disk.img"
    if [ ! -f "$DISK" ]; then
      if command -v qemu-img >/dev/null 2>&1; then
        qemu-img create -f raw "$DISK" 256M
      else
        truncate -s 256M "$DISK"
      fi
    fi
    # S4c input devices: virtio-keyboard/mouse over MMIO. Attached even
    # headless (-nographic feeds them no keys, but the dev-18 transports
    # enumerate so kernel discovery + the userspace probe run; live
    # typing instead needs a windowed/VNC display, see run_qemu.sh).
    $QEMU -M virt -m 256M -nographic -bios default -kernel kernel/build/moonlight.elf \
      -device virtio-net-device,netdev=n0 -netdev user,id=n0 -device virtio-rng-device \
      -global virtio-mmio.force-legacy=off -drive file=$DISK,format=raw,if=none,id=hd0 \
      -device virtio-blk-device,drive=hd0 -device bochs-display -device virtio-keyboard-device \
      -device virtio-mouse-device > /tmp/v2_qemu.log 2>&1 &
    QPID=$!
    # Wait for the terminal liveness marker or a bounded ceiling. Polling
    # (rather than a fixed sleep) exits as soon as boot reaches steady
    # state, so the common path stays fast while a loaded host gets real
    # headroom instead of flaking on an arbitrary 4s line.
    for _ in $(seq 1 40); do
      if grep -qF "[ipc] send tcb=1 -> 4" /tmp/v2_qemu.log 2>/dev/null; then break; fi
      if ! kill -0 $QPID 2>/dev/null; then break; fi
      sleep 0.5
    done
    kill -9 $QPID 2>/dev/null || true
    wait $QPID 2>/dev/null || true
    # Strip NULs and CR: the SBI/QEMU serial path emits CRLF, so an exact
    # whole-line (-x) assertion would otherwise fail on the trailing \r
    # rather than on the kernel's real line content. Normalising here keeps
    # -x honest: it matches the line as the kernel printed it.
    V2LOG=$(cat /tmp/v2_qemu.log 2>/dev/null | tr -d '\0\r')
    # Fail closed: every missing marker flips the gate to FAIL (a smoke
    # that only prints FAIL lines but reports PASS proves nothing).
    QEMU_FAIL=0
    # Production microkernel gates (all services in qube 0; the retired
    # qube-demo set — B00pn/A10pg, QREXEC/FW/NET/VAULT/CRYPT, MMIO-leaf
    # asserts, FILL/COMPOSE — no longer exists, so gating it would fail
    # on phantom markers).
    # Anchored markers: -F is a fixed-string match (no regex-metacharacter or
    # substring surprise). -x is added ONLY where the marker is verified to be
    # a COMPLETE line as emitted. Four markers are legitimately a fragment of
    # a longer line and stay substring-anchored on purpose:
    #   "satp Sv39 on"         <- "v2: satp Sv39 on, U-bit split ..."
    #   "entering U-mode"      <- "v2: entering U-mode"
    #   "DU: vpn0 mirrored"    <- "DU: vpn0 mirrored 2/2"
    #   "GUI: Bochs VGA found" <- "GUI: Bochs VGA found (dev=...)"
    # Every other marker below is a whole line (verified against the kernel
    # kputs/u_puts emitters), so -x is exact and cannot match a substring.
    echo "$V2LOG" | grep -qF "satp Sv39 on" && echo "v2 smoke: satp on" || { echo "v2 smoke: FAIL (no satp)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qF "entering U-mode" && echo "v2 smoke: U-mode entry" || { echo "v2 smoke: FAIL (no U entry)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "INPUT: kbd found" && echo "v2 smoke: input kbd" || { echo "v2 smoke: FAIL (no input kbd)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "INPUT: mouse found" && echo "v2 smoke: input mouse" || { echo "v2 smoke: FAIL (no input mouse)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "GUI: bochs 800x600x32" && echo "v2 smoke: bochs mode" || { echo "v2 smoke: FAIL (no bochs mode)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "[spawn] mem_server ELF ok" && echo "v2 smoke: mem spawn" || { echo "v2 smoke: FAIL (no mem spawn)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "[spawn] shell ELF ok" && echo "v2 smoke: shell spawn" || { echo "v2 smoke: FAIL (no shell spawn)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "[spawn] console ELF ok" && echo "v2 smoke: console spawn" || { echo "v2 smoke: FAIL (no console spawn)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "[spawn] tty ELF ok" && echo "v2 smoke: tty spawn" || { echo "v2 smoke: FAIL (no tty spawn)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "[spawn] vault ELF ok" && echo "v2 smoke: vault spawn" || { echo "v2 smoke: FAIL (no vault spawn)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "[spawn] cryptblk ELF ok" && echo "v2 smoke: cryptblk spawn" || { echo "v2 smoke: FAIL (no cryptblk spawn)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "[spawn] gui ELF ok" && echo "v2 smoke: gui spawn" || { echo "v2 smoke: FAIL (no gui spawn)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "Services: mem+console+tty+vault+cryptblk+gui up" && echo "v2 smoke: services up" || { echo "v2 smoke: FAIL (no services up)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "MEM-SRV" && echo "v2 smoke: MEM-SRV userspace" || { echo "v2 smoke: FAIL (no MEM-SRV)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qF "DU: vpn0 mirrored" && echo "v2 smoke: DU real-frame proof" || { echo "v2 smoke: FAIL (no DU)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "NP" && echo "v2 smoke: NP negative-passed" || { echo "v2 smoke: FAIL (no NP)"; QEMU_FAIL=1; }
    # Retired: "[sched] exited 7" can no longer print (klog is silenced at
    # boot-complete and no production path exits thread 7). Gating it
    # would fail forever; the liveness gate below covers scheduler health.
    echo "$V2LOG" | grep -qF "GUI: Bochs VGA found" && echo "v2 smoke: vga bind" || { echo "v2 smoke: FAIL (no vga bind)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "GUI: framebuffer initialised" && echo "v2 smoke: fb init" || { echo "v2 smoke: FAIL (no fb init)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "GUI: keyboard ready" && echo "v2 smoke: kbd ready" || { echo "v2 smoke: FAIL (no kbd ready)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "GUI: mouse ready" && echo "v2 smoke: mouse ready" || { echo "v2 smoke: FAIL (no mouse ready)"; QEMU_FAIL=1; }
    # Retired: "SHELL: thread 1 starting" was a phantom gate (721f9c7) - repo-wide
    # history shows no C source ever printed it, so gating it failed forever.
    # Shell liveness is covered by "[spawn] shell ELF ok" + the live-IPC gate
    # below (tcb=1 proves thread 1 runs and sends within the window).
    # Liveness (not clean-park: the production system stays up serving
    # IPC — shell/tty traffic at the timeout proves the scheduler + IPC
    # plane are alive instead of wedged).
    # Per-service IPC liveness (R0.5): each IPC-serving service answered a
    # boot MSG_PING with MSG_PONG (the shell prober prints one whole line
    # per answer). This proves the service RUNS and SERVES IPC; the
    # "[spawn] ... ELF ok" markers above only prove it LOADED.
    #   Covered positively: mem_server (2), console (3), tty (4), vault (8).
    #   cryptblk (9) is PINGED but pinned ABSENT below: it parks in its
    #   boot-time vault-seed handoff before reaching its service loop, so it
    #   cannot answer a ping (pre-existing defect; the handoff expects vault
    #   qube 6 / cryptblk qube 7 while the shipped boot puts every service in
    #   qube 0; tracked finding S10 in docs/PRODUCTION_READINESS.md). The pin
    #   exists so a change to cryptblk's liveness fails this gate instead of
    #   silently passing (bounded by the one-boot lag noted below). Its LOAD is
    #   still asserted via "[spawn] cryptblk ELF ok" above. gui (tid 10) has
    #   no receive loop and stays covered by its GUI: readiness markers.
    #
    #   Known limitation: V2 has no timer-armed receive, so the prober drains
    #   only the four expected replies. If cryptblk were fixed, its PONG
    #   might arrive after that drain completes, in which case this pin lags
    #   by one boot rather than tripping immediately.
    echo "$V2LOG" | grep -qxF "LIVE: tid=2 ok" && echo "v2 smoke: live mem_server" || { echo "v2 smoke: FAIL (mem_server not live)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "LIVE: tid=3 ok" && echo "v2 smoke: live console" || { echo "v2 smoke: FAIL (console not live)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "LIVE: tid=4 ok" && echo "v2 smoke: live tty" || { echo "v2 smoke: FAIL (tty not live)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -qxF "LIVE: tid=8 ok" && echo "v2 smoke: live vault" || { echo "v2 smoke: FAIL (vault not live)"; QEMU_FAIL=1; }
    # Fail-closed inverse pin: cryptblk (9) is known-dead at boot (parks in
    # crypt_get_seed; the vault->cryptblk seed handoff expects qube 6/7 but
    # the shipped boot puts every service in qube 0 — tracked finding S10 in
    # docs/PRODUCTION_READINESS.md). The prober pings 9 too and prints
    # "LIVE: tid=9 ok" for any PONG it receives, so this pin fails closed the
    # moment cryptblk answers within the drain window. It is NOT instant: V2
    # has no timer-armed receive, so a PONG that arrives after the drain
    # completes is not observed and the pin lags by one boot (see the
    # limitation note above). When cryptblk answers, promote this to a
    # positive assertion (Phase 1 task 1.9).
    if echo "$V2LOG" | grep -qxF "LIVE: tid=9 ok"; then
      echo "v2 smoke: FAIL (cryptblk unexpectedly live — promote this to a positive LIVE assertion)"
      QEMU_FAIL=1
    else
      echo "v2 smoke: cryptblk known-dead (pinned absent — see docs/PRODUCTION_READINESS.md S10)"
    fi
    echo "$V2LOG" | grep -qxF "[ipc] send tcb=1 -> 4" && echo "v2 smoke: shell->tty live IPC" || { echo "v2 smoke: FAIL (no live IPC)"; QEMU_FAIL=1; }
    if [ "$QEMU_FAIL" = "0" ]; then
      QEMU_STATUS="PASS"
    else
      QEMU_STATUS="FAIL"
      echo "FAIL: QEMU smoke missing markers (see above)"
    fi
  else
    echo "SKIP: QEMU not found"
    QEMU_STATUS="SKIP"
  fi
else
  # REACHED with no ELF after both build stages ran. clang is present for the
  # §1f build and §3 rebuilds from clean, so absence means the kernel build was
  # attempted and failed — the QEMU smoke could not run and must be a hard
  # failure, NOT a benign "SKIP" (a silent SKIP is what let an earlier
  # stale-ELF boot slip through). Only a genuinely clang-less host (build
  # skipped, PARTIAL) may SKIP here.
  if command -v clang &>/dev/null; then
    echo "FAIL: kernel/build/moonlight.elf not found after build (QEMU smoke could not run)"
    QEMU_STATUS="FAIL"
  else
    echo "SKIP: kernel/build/moonlight.elf not found (clang absent; kernel build skipped)"
    QEMU_STATUS="SKIP"
  fi
fi
if [ "$FAILED" -ne 0 ]; then
  echo "FAILED=$FAILED"
  echo "=== verify done: FAIL ($FAILED failing check(s)) ==="
  exit 1
fi
# A failed proof session or kernel build is a failure, not a partial run.
# Missing toolchains leave the *_STATUS as "SKIP"/"PASS (STOCK)" (PARTIAL,
# exit 0); only an actual "FAIL" turns the gate red.
if [ "$ISABELLE_STATUS" = "FAIL" ] || [ "$CHERI_STATUS" = "FAIL" ]; then
  echo "=== verify done: FAIL (Isabelle proofs or kernel build failed) ==="
  exit 1
fi
echo "=== verify summary ==="
echo "Isabelle proofs: $ISABELLE_STATUS"
echo "Kernel build: $CHERI_STATUS"
echo "QEMU smoke: $QEMU_STATUS"
if [ "$QEMU_STATUS" = "FAIL" ]; then
  echo "=== verify done: FAIL (QEMU smoke missing markers) ==="
  exit 1
fi
if [ "$ISABELLE_STATUS" = "PASS" ] && [ "$CHERI_STATUS" = "PASS (CHERI toolchain)" ]; then
  echo "=== verify done: FULL PASS (proofs and CHERI checked) ==="
  exit 0
else
  echo "=== verify done: PARTIAL (some checks were SKIPPED - see above, NOT a full PASS) ==="
  if [ "$ISABELLE_STATUS" != "PASS" ]; then
    echo "NOTE: isabelle proofs were NOT checked - run with Isabelle2025-2 installed for full verification"
  fi
  if [ "$CHERI_STATUS" != "PASS (CHERI toolchain)" ]; then
    echo "NOTE: CHERI toolchain was NOT found (stock clang used) - install riscv64-unknown-elf-clang for full verification"
  fi
  exit 0
fi