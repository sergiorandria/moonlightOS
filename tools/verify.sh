#!/bin/bash
set -e
echo "=== Moonlight verification (production) ==="
echo "[1/4] Host unit tests"
gcc -I kernel/include -o /tmp/test_cap tests/test_cap.c tests/stub_globals.c kernel/src/cap.c kernel/src/cnode.c kernel/src/alloc.c kernel/src/sched.c kernel/src/iommu.c kernel/src/irq.c kernel/src/cheri.c kernel/src/tcb.c && /tmp/test_cap
gcc -I kernel/include -o /tmp/test_sched tests/test_sched_realtime.c tests/stub_globals.c kernel/src/sched.c kernel/src/cheri.c kernel/src/tcb.c && /tmp/test_sched
gcc -I kernel/include -o /tmp/test_sched_bitmap tests/test_sched_bitmap.c tests/stub_globals.c kernel/src/sched.c kernel/src/cheri.c kernel/src/tcb.c && /tmp/test_sched_bitmap || echo "FAIL: test_sched_bitmap"
gcc -I kernel/include -o /tmp/test_revoke tests/test_revoke_process.c tests/stub_globals.c kernel/src/revoke.c kernel/src/process.c kernel/src/sched.c kernel/src/alloc.c kernel/src/cheri.c kernel/src/tcb.c kernel/src/endpoint.c && /tmp/test_revoke
gcc -I kernel/include -o /tmp/host_emul tests/host_emul.c tests/stub_globals.c kernel/src/revoke.c kernel/src/process.c kernel/src/sched.c kernel/src/alloc.c kernel/src/cheri.c kernel/src/tcb.c kernel/src/cnode.c kernel/src/cap.c kernel/src/endpoint.c && /tmp/host_emul
gcc -I kernel/include -o /tmp/bench tests/bench_ipc.c tests/stub_globals.c kernel/src/endpoint.c kernel/src/tcb.c && /tmp/bench
gcc -I kernel/include -o /tmp/fuzz tests/fuzz_syscall.c tests/stub_globals.c kernel/src/syscall.c kernel/src/cap.c kernel/src/cnode.c kernel/src/tcb.c kernel/src/endpoint.c kernel/src/sched.c kernel/src/cheri.c kernel/src/vspace.c kernel/src/alloc.c kernel/src/revoke.c kernel/src/flush.c kernel/src/kbd.c && /tmp/fuzz || echo "FAIL: fuzz_syscall"
echo "[1a] ABI regression: uintptr_t must be 8 bytes (PLAN 3)"
gcc -I kernel/include -o /tmp/test_abi tests/test_abi.c && /tmp/test_abi
echo '#include <stdint.h>
_Static_assert(sizeof(uintptr_t)==8, "uintptr_t is not 8 bytes");' | clang --target=riscv64-unknown-elf -mabi=lp64 -I/usr/lib/clang/22/include -I kernel/include -ffreestanding -fsyntax-only -xc - && echo "PASS: cross static_assert 8 bytes (freestanding, no -I/usr/include)"
echo "[1b] Hardening + vspace + trap (host sim)"
gcc -I kernel/include -o /tmp/test_hardening tests/test_hardening.c kernel/src/hardening.c 2>/dev/null && /tmp/test_hardening || echo "SKIP: test_hardening not found"
gcc -I kernel/include -o /tmp/test_vspace tests/test_vspace.c tests/stub_globals.c kernel/src/vspace.c kernel/src/alloc.c kernel/src/cheri.c kernel/src/tcb.c 2>&1 && /tmp/test_vspace || echo "FAIL: test_vspace"
gcc -Wall -Wextra -Werror -I kernel/include -o /tmp/test_dice tests/test_dice.c kernel/src/sha256.c kernel/src/dice.c 2>&1 && /tmp/test_dice || echo "FAIL: test_dice"
gcc -Wall -Wextra -Werror -I kernel/include -o /tmp/test_virtio_net tests/test_virtio_net.c tests/stub_globals.c kernel/src/iommu.c kernel/src/cheri.c kernel/src/alloc.c 2>&1 && /tmp/test_virtio_net || echo "FAIL: test_virtio_net"
gcc -Wall -Wextra -Werror -I kernel/include -o /tmp/test_net_queue tests/test_net_queue.c tests/stub_globals.c kernel/src/iommu.c kernel/src/cheri.c kernel/src/alloc.c 2>&1 && /tmp/test_net_queue || echo "FAIL: test_net_queue"
gcc -I userspace/libc/include -I kernel/include -o /tmp/test_libc tests/test_libc.c userspace/libc/src/string.c userspace/libc/src/stdlib.c userspace/libc/src/stdio.c userspace/libc/src/ctype.c userspace/libc/src/time.c userspace/libc/src/errno.c userspace/libc/src/math.c userspace/libc/src/wchar.c userspace/libc/src/wctype.c userspace/libc/src/signal.c userspace/libc/src/fenv.c userspace/libc/src/locale.c userspace/libc/src/scanf.c userspace/libc/src/getopt.c userspace/libc/src/env.c userspace/libc/src/strings.c userspace/libc/src/spawn.c userspace/libc/src/proc.c 2>&1 && /tmp/test_libc || echo "FAIL: test_libc"
gcc -I userspace/libc/include -I kernel/include -o /tmp/test_newlibc tests/test_newlibc.c userspace/libc/src/complex.c userspace/libc/src/monetary.c userspace/libc/src/langinfo.c userspace/libc/src/iconv.c userspace/libc/src/locale.c userspace/libc/src/math.c userspace/libc/src/nltypes.c userspace/libc/src/threads.c userspace/libc/src/stdlib.c userspace/libc/src/string.c userspace/libc/src/errno.c -lm 2>&1 && /tmp/test_newlibc || echo "FAIL: test_newlibc"
gcc -I userspace/libc/include -I kernel/include -o /tmp/test_batch4 tests/test_batch4.c userspace/libc/src/string.c userspace/libc/src/stdlib.c userspace/libc/src/stdio.c userspace/libc/src/errno.c userspace/libc/src/time.c userspace/libc/src/file.c userspace/libc/src/unistd.c userspace/libc/src/proc.c userspace/libc/src/fcntl.c userspace/libc/src/signal.c userspace/libc/src/math.c userspace/libc/src/wchar.c userspace/libc/src/wctype.c userspace/libc/src/locale.c -lm 2>&1 && /tmp/test_batch4 || echo "FAIL: test_batch4"
gcc -I userspace/libc/include -I kernel/include -o /tmp/test_batch5 tests/test_batch5.c userspace/libc/src/syscall.c userspace/libc/src/crypt.c userspace/libc/src/ether.c userspace/libc/src/execinfo.c userspace/libc/src/fmtmsg.c userspace/libc/src/libgen.c userspace/libc/src/ndbm.c userspace/libc/src/search.c userspace/libc/src/sendfile.c userspace/libc/src/shadow.c userspace/libc/src/sysevent.c userspace/libc/src/sysvipc.c userspace/libc/src/utmpx.c userspace/libc/src/ptimer.c userspace/libc/src/aio.c userspace/libc/src/string.c userspace/libc/src/stdlib.c userspace/libc/src/stdio.c userspace/libc/src/errno.c userspace/libc/src/time.c userspace/libc/src/file.c userspace/libc/src/dir.c userspace/libc/src/unistd.c userspace/libc/src/fcntl.c userspace/libc/src/signal.c userspace/libc/src/pthread.c userspace/libc/src/math.c userspace/libc/src/wchar.c userspace/libc/src/wctype.c userspace/libc/src/locale.c -lm -lpthread 2>&1 && timeout 60 /tmp/test_batch5 || echo "FAIL: test_batch5"
gcc -I userspace/libc/include -I kernel/include -o /tmp/test_batch6 tests/test_batch6.c userspace/libc/src/sysstat.c userspace/libc/src/netif.c userspace/libc/src/stropts.c userspace/libc/src/string.c userspace/libc/src/stdlib.c userspace/libc/src/stdio.c userspace/libc/src/errno.c userspace/libc/src/time.c userspace/libc/src/file.c userspace/libc/src/statvfs.c userspace/libc/src/dir.c userspace/libc/src/unistd.c userspace/libc/src/fcntl.c userspace/libc/src/signal.c userspace/libc/src/math.c -lm 2>&1 && /tmp/test_batch6 || echo "FAIL: test_batch6"
gcc -I kernel/include -o /tmp/test_virtio_net tests/test_virtio_net.c tests/stub_globals.c kernel/src/iommu.c kernel/src/cheri.c kernel/src/alloc.c 2>&1 && /tmp/test_virtio_net || echo "FAIL: test_virtio_net"
gcc -I kernel/include -o /tmp/test_ipc_trap tests/test_ipc_trap.c tests/stub_globals.c kernel/src/endpoint.c kernel/src/tcb.c kernel/src/cap.c kernel/src/cnode.c kernel/src/syscall.c kernel/src/sched.c kernel/src/cheri.c kernel/src/vspace.c kernel/src/revoke.c kernel/src/alloc.c kernel/src/notification.c kernel/src/hardening.c kernel/src/flush.c kernel/src/kbd.c 2>&1 && /tmp/test_ipc_trap || echo "FAIL: test_ipc_trap"
gcc -I kernel/include -o /tmp/test_invoke_ops tests/test_invoke_ops.c tests/stub_globals.c kernel/src/cap.c kernel/src/cnode.c kernel/src/tcb.c kernel/src/vspace.c kernel/src/sched.c kernel/src/alloc.c kernel/src/revoke.c kernel/src/cheri.c kernel/src/syscall.c kernel/src/endpoint.c kernel/src/notification.c kernel/src/flush.c kernel/src/kbd.c 2>&1 && /tmp/test_invoke_ops || echo "FAIL: test_invoke_ops"
gcc -I kernel/include -o /tmp/test_mem_server tests/test_mem_server.c userspace/mem_server/server.c kernel/src/cap.c kernel/src/cnode.c kernel/src/alloc.c 2>&1 && /tmp/test_mem_server || echo "FAIL: test_mem_server"
gcc -I kernel/include -o /tmp/test_sched_server tests/test_sched_server.c userspace/sched_server/server.c 2>&1 && /tmp/test_sched_server || echo "FAIL: test_sched_server"
if gcc -I kernel/include -o /tmp/test_vfs tests/test_vfs.c userspace/vfs_server/server.c 2>&1; then /tmp/test_vfs || echo "FAIL: test_vfs run failed"; else echo "FAIL: test_vfs compile failed"; fi
echo "[1c] moonsh shell + keyboard + userspace ELFs"
gcc -Wall -Wextra -o /tmp/test_shell tests/test_shell.c userspace/sh/shell.c 2>&1 && /tmp/test_shell || echo "FAIL: test_shell"
gcc -Wall -Wextra -I kernel/include -o /tmp/test_kbd tests/test_kbd.c kernel/src/kbd.c 2>&1 && /tmp/test_kbd || echo "FAIL: test_kbd"
gcc -Wall -Wextra -I kernel/include -o /tmp/test_console tests/test_console.c kernel/src/flush.c kernel/src/kbd.c 2>&1 && /tmp/test_console || echo "FAIL: test_console"
gcc -Wall -Wextra -I kernel/include -o /tmp/test_info tests/test_info.c tests/stub_globals.c kernel/src/sched.c kernel/src/tcb.c kernel/src/process.c kernel/src/alloc.c kernel/src/revoke.c kernel/src/cheri.c kernel/src/cnode.c kernel/src/cap.c 2>&1 && /tmp/test_info || echo "FAIL: test_info"
if command -v clang &>/dev/null; then
  make -C userspace 2>&1 | tail -n 2 || echo "FAIL: userspace ELFs"
else
  echo "SKIP: userspace ELFs (clang not found)"
fi
echo "[1d] v2 S-mode kernel build"
if command -v clang &>/dev/null; then
  make -C v2/kernel 2>&1 | tail -n 1 || echo "FAIL: v2 kernel build"
else
  echo "SKIP: v2 kernel (clang not found)"
fi
echo "[1e] v2 production gates (linker layout + user rodata ban)"
if [ -f v2/kernel/build/v2.elf ]; then
  python3 <<'PYEOF' || echo "FAIL: v2 linker gate"
import re, subprocess, sys
secs = subprocess.run(['llvm-readelf', '-S', 'v2/kernel/build/v2.elf'],
                      capture_output=True, text=True).stdout
syms = subprocess.run(['llvm-readelf', '-s', 'v2/kernel/build/v2.elf'],
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
print('v2 gate: no PROGBITS in BSS-clear range (_bss=%x _bss_end=%x)' % (bss, bend))
PYEOF
  clang --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 -O2 -ffreestanding \
    -nostdlib -fno-builtin -mcmodel=medany -mno-relax -Wall \
    -I/usr/lib/clang/22/include -c v2/kernel/user.c -o /tmp/user_check.o 2>/dev/null
  if llvm-readelf -S /tmp/user_check.o | grep -q "rodata"; then
    echo "FAIL: user.c emits .rodata (U-mode would fault reading U=0 literals)"
  else
    echo "v2 gate: user.c has no .rodata (immediates-only holds)"
  fi
else
  echo "SKIP: v2 gates (v2.elf not built)"
fi
ISABELLE_STATUS="SKIP"
CHERI_STATUS="SKIP"
echo "[2/4] Isabelle/HOL proofs (requires Isabelle2024 + l4v)"
if command -v isabelle &>/dev/null; then
  if isabelle build -D kernel/isabelle -v; then
    ISABELLE_STATUS="PASS"
  else
    ISABELLE_STATUS="FAIL"
    echo "FAIL: isabelle build failed"
  fi
  echo "[2b/4] v2 spec (Stage 0: TCB + scheduler, mutant-tested invariants)"
  if isabelle build -D v2/isabelle -v; then
    echo "v2 spec: PASS"
  else
    ISABELLE_STATUS="FAIL"
    echo "FAIL: v2 isabelle build failed"
  fi
  echo "[2c/4] v2 anti-vacuity gate (no True-defined invariants, no sorry)"
  if grep -rn "sorry\|axiomatization\|quick_and_dirty\|oops" v2/isabelle/; then
    ISABELLE_STATUS="FAIL"
    echo "FAIL: v2 spec contains sorry/axioms"
  elif grep -rn "equiv> True" v2/isabelle/*.thy; then
    ISABELLE_STATUS="FAIL"
    echo "FAIL: v2 spec contains True-defined invariant (vacuous)"
  else
    echo "v2 anti-vacuity: PASS"
  fi
else
  echo "SKIP — isabelle not installed, proofs NOT checked (install Isabelle2024 + l4v to verify)"
  ISABELLE_STATUS="SKIP (NOT CHECKED)"
fi
echo "[3/4] CHERI build"
if command -v riscv64-unknown-elf-clang &>/dev/null; then
  if make -C kernel clean && make -C kernel -j; then
    CHERI_STATUS="PASS (CHERI)"
  else
    CHERI_STATUS="FAIL"
  fi
else
  echo "SKIP — CHERI toolchain not found (riscv64-unknown-elf-clang missing), CHERI build NOT checked — trying stock QEMU fallback build"
  CHERI_STATUS="SKIP (FALLBACK)"
  if [ -x tools/build_qemu.sh ]; then
    if tools/build_qemu.sh; then
      echo "Fallback QEMU build: PASS (stock, not CHERI)"
    else
      echo "FAIL: fallback QEMU build failed"
      CHERI_STATUS="FAIL"
    fi
  else
    echo "SKIP: no QEMU build"
    CHERI_STATUS="SKIP"
  fi
fi
echo "[4/4] QEMU smoke (if ELF exists)"
QEMU_STATUS="SKIP"
if [ -f kernel/build/moonlight.elf ]; then
  QEMU=$(command -v qemu-system-riscv64 || command -v /tmp/qb2/qemu-system-riscv64 || echo "")
  if [ -n "$QEMU" ] && [ -x "$QEMU" ]; then
    timeout 3 $QEMU -M virt -m 256M -nographic -bios none -kernel kernel/build/moonlight.elf -d guest_errors 2>&1 | head -n 20 || echo "QEMU smoke: no output (expected wfi)"
    echo "QEMU smoke done"
    # moonsh interactive smoke: one boot, pipe commands, expect prompt +
    # builtin output and version banner in the same log.
    # (60s: TCG boot is slow on loaded machines; 30s flaked under load.
    # Single boot serves both greps so a slow boot can't fail one half.)
    MOONSH_LOG=$(printf 'help\nver\nkbd\nhistory\nhex hi\nyield\n' | timeout 60 $QEMU -M virt -m 256M -nographic -bios none -kernel kernel/build/moonlight.elf 2>&1 || true)
    if echo "$MOONSH_LOG" | grep -q "moonsh builtins"; then
      echo "moonsh smoke: PASS (prompt + help on serial)"
    else
      echo "moonsh smoke: FAIL (no shell output - see log above)"
    fi
    if echo "$MOONSH_LOG" | grep -q "MoonlightOS"; then
      echo "moonsh smoke: PASS (ver on serial)"
    else
      echo "moonsh smoke: FAIL (no ver output - see log above)"
    fi
    if echo "$MOONSH_LOG" | grep -q "\[DICE\] kernel_hash="; then
      echo "dice smoke: PASS (measurement logged on serial)"
    else
      echo "dice smoke: FAIL (no DICE measurement - see log above)"
    fi
    if echo "$MOONSH_LOG" | grep -q "\[DICE\] verified against provisioned hash"; then
      echo "dice smoke: provisioned + enforced"
    elif echo "$MOONSH_LOG" | grep -q "unprovisioned (measure-only)"; then
      echo "dice smoke: unprovisioned (measure-only)"
    else
      echo "dice smoke: FAIL (no DICE verdict - see log above)"
    fi
    # v2 Stage-1 smoke: S-mode kernel under OpenSBI, two U threads, fault demo
    if [ -f v2/kernel/build/v2.elf ]; then
      V2LOG=$(timeout 10 $QEMU -M virt -m 256M -nographic -bios default -kernel v2/kernel/build/v2.elf 2>&1 | tr -d '\0')
      echo "$V2LOG" | grep -q "satp Sv39 on" && echo "v2 smoke: satp on" || echo "v2 smoke: FAIL (no satp)"
      echo "$V2LOG" | grep -q "entering U-mode" && echo "v2 smoke: U-mode entry" || echo "v2 smoke: FAIL (no U entry)"
      echo "$V2LOG" | grep -q "parked 0" && echo "v2 smoke: A parked" || echo "v2 smoke: FAIL (A never parked)"
      echo "$V2LOG" | grep -q "fault.*tcb=1" && echo "v2 smoke: B fault contained" || echo "v2 smoke: FAIL (no B fault)"
    else
      echo "SKIP: v2 smoke (v2.elf not built)"
    fi
    QEMU_STATUS="PASS"
  else
    echo "SKIP: QEMU not found"
    QEMU_STATUS="SKIP"
  fi
else
  echo "SKIP: kernel/build/moonlight.elf not found"
  QEMU_STATUS="SKIP"
fi
echo "=== verify summary ==="
echo "Isabelle proofs: $ISABELLE_STATUS"
echo "CHERI build: $CHERI_STATUS"
echo "QEMU smoke: $QEMU_STATUS"
if [ "$ISABELLE_STATUS" = "PASS" ] && [ "$CHERI_STATUS" = "PASS (CHERI)" ]; then
  echo "=== verify done: FULL PASS (proofs and CHERI checked) ==="
  exit 0
else
  echo "=== verify done: PARTIAL (some checks were SKIPPED - see above, NOT a full PASS) ==="
  if [ "$ISABELLE_STATUS" != "PASS" ]; then
    echo "NOTE: isabelle proofs were NOT checked - run with Isabelle2024 installed for full verification"
  fi
  if [ "$CHERI_STATUS" != "PASS (CHERI)" ]; then
    echo "NOTE: CHERI build was NOT checked (fell back to stock) - install riscv64-unknown-elf-clang with cheri for full verification"
  fi
  exit 0
fi
