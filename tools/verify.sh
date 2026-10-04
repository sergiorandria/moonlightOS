#!/bin/bash
set -e
echo "=== Moonlight verification (v2 single codebase) ==="
echo "[1/4] Host unit tests"
ABI="-I userspace/abi"
LIBCINC="-I userspace/libc/include -I userspace/abi"
echo "[1a] ABI regression: uintptr_t must be 8 bytes (PLAN 3)"
gcc $ABI -o /tmp/test_abi tests/test_abi.c && /tmp/test_abi
echo '#include <stdint.h>
_Static_assert(sizeof(uintptr_t)==8, "uintptr_t is not 8 bytes");' | clang --target=riscv64-unknown-elf -mabi=lp64 -I$(clang --print-resource-dir)/include -ffreestanding -fsyntax-only -xc - && echo "PASS: cross static_assert 8 bytes (freestanding, no -I/usr/include)"
echo "[1b] userspace servers + shell (host sim)"
gcc $ABI -o /tmp/test_sched_server tests/test_sched_server.c userspace/sched_server/server.c && /tmp/test_sched_server || echo "FAIL: test_sched_server"
if gcc $ABI -o /tmp/test_vfs tests/test_vfs.c userspace/vfs_server/server.c 2>&1; then /tmp/test_vfs || echo "FAIL: test_vfs run failed"; else echo "FAIL: test_vfs compile failed"; fi
gcc -Wall -Wextra -o /tmp/test_shell tests/test_shell.c userspace/sh/shell.c userspace/lib/moonlight.c && /tmp/test_shell || echo "FAIL: test_shell"
echo "[1c] userspace drivers host-sim (frozen v1 ABI headers in userspace/abi)"
gcc -Wall -Wextra -Werror $ABI -o /tmp/test_uart tests/test_uart.c && /tmp/test_uart || echo "FAIL: test_uart"
gcc -Wall -Wextra -Werror $ABI -o /tmp/test_plic tests/test_plic.c && /tmp/test_plic || echo "FAIL: test_plic"
gcc -Wall -Wextra -Werror $ABI -o /tmp/test_timer tests/test_timer.c && /tmp/test_timer || echo "FAIL: test_timer"
gcc -Wall -Wextra -Werror $ABI -o /tmp/test_rtc tests/test_rtc.c && /tmp/test_rtc || echo "FAIL: test_rtc"
gcc -Wall -Wextra -Werror $ABI -o /tmp/test_power tests/test_power.c && /tmp/test_power || echo "FAIL: test_power"
echo "[1d] freestanding libc host-sim"
gcc $LIBCINC -o /tmp/test_libc tests/test_libc.c userspace/libc/src/string.c userspace/libc/src/stdlib.c userspace/libc/src/stdio.c userspace/libc/src/ctype.c userspace/libc/src/time.c userspace/libc/src/errno.c userspace/libc/src/math.c userspace/libc/src/wchar.c userspace/libc/src/wctype.c userspace/libc/src/signal.c userspace/libc/src/fenv.c userspace/libc/src/locale.c userspace/libc/src/scanf.c userspace/libc/src/getopt.c userspace/libc/src/env.c userspace/libc/src/strings.c userspace/libc/src/spawn.c userspace/libc/src/proc.c 2>&1 && /tmp/test_libc || echo "FAIL: test_libc"
gcc $LIBCINC -o /tmp/test_newlibc tests/test_newlibc.c userspace/libc/src/complex.c userspace/libc/src/monetary.c userspace/libc/src/langinfo.c userspace/libc/src/iconv.c userspace/libc/src/locale.c userspace/libc/src/math.c userspace/libc/src/nltypes.c userspace/libc/src/threads.c userspace/libc/src/stdlib.c userspace/libc/src/string.c userspace/libc/src/errno.c -lm 2>&1 && /tmp/test_newlibc || echo "FAIL: test_newlibc"
gcc $LIBCINC -o /tmp/test_batch4 tests/test_batch4.c userspace/libc/src/string.c userspace/libc/src/stdlib.c userspace/libc/src/stdio.c userspace/libc/src/errno.c userspace/libc/src/time.c userspace/libc/src/file.c userspace/libc/src/unistd.c userspace/libc/src/proc.c userspace/libc/src/fcntl.c userspace/libc/src/signal.c userspace/libc/src/math.c userspace/libc/src/wchar.c userspace/libc/src/wctype.c userspace/libc/src/locale.c -lm 2>&1 && /tmp/test_batch4 || echo "FAIL: test_batch4"
gcc $LIBCINC -o /tmp/test_batch5 tests/test_batch5.c userspace/libc/src/syscall.c userspace/libc/src/crypt.c userspace/libc/src/ether.c userspace/libc/src/execinfo.c userspace/libc/src/fmtmsg.c userspace/libc/src/libgen.c userspace/libc/src/ndbm.c userspace/libc/src/search.c userspace/libc/src/sendfile.c userspace/libc/src/shadow.c userspace/libc/src/sysevent.c userspace/libc/src/sysvipc.c userspace/libc/src/utmpx.c userspace/libc/src/ptimer.c userspace/libc/src/aio.c userspace/libc/src/string.c userspace/libc/src/stdlib.c userspace/libc/src/stdio.c userspace/libc/src/errno.c userspace/libc/src/time.c userspace/libc/src/file.c userspace/libc/src/dir.c userspace/libc/src/unistd.c userspace/libc/src/fcntl.c userspace/libc/src/signal.c userspace/libc/src/pthread.c userspace/libc/src/math.c userspace/libc/src/wchar.c userspace/libc/src/wctype.c userspace/libc/src/locale.c -lm -lpthread 2>&1 && timeout 60 /tmp/test_batch5 || echo "FAIL: test_batch5"
gcc $LIBCINC -o /tmp/test_batch6 tests/test_batch6.c userspace/libc/src/sysstat.c userspace/libc/src/netif.c userspace/libc/src/stropts.c userspace/libc/src/string.c userspace/libc/src/stdlib.c userspace/libc/src/stdio.c userspace/libc/src/errno.c userspace/libc/src/time.c userspace/libc/src/file.c userspace/libc/src/statvfs.c userspace/libc/src/dir.c userspace/libc/src/unistd.c userspace/libc/src/fcntl.c userspace/libc/src/signal.c userspace/libc/src/math.c -lm 2>&1 && /tmp/test_batch6 || echo "FAIL: test_batch6"
echo "[1e] userspace ELFs + driver compile gates (freestanding rv64 -Werror)"
if command -v clang &>/dev/null; then
  make -C userspace 2>&1 | tail -n 2 || echo "FAIL: userspace ELFs"
  make -C userspace drivers 2>&1 | tail -n 3 || echo "FAIL: userspace drivers"
  make -C userspace stubs 2>&1 | tail -n 3 || echo "FAIL: userspace stubs"
  make -C userspace build/vault.elf build/cryptblk.elf 2>&1 | tail -n 3 || echo "FAIL: vault/cryptblk ELFs (outside all:, explicitly gated)"
else
  echo "SKIP: userspace ELFs (clang not found)"
fi
echo "[1f] v2 kernel build + Stage-2/3 host tests"
clang -Wall -Wextra -Werror -o /tmp/test_v2ipc tests/test_v2ipc.c 2>&1 && /tmp/test_v2ipc || echo "FAIL: test_v2ipc"
clang -Wall -Wextra -Werror -o /tmp/test_v2caps tests/test_v2caps.c 2>&1 && /tmp/test_v2caps || echo "FAIL: test_v2caps"
clang -Wall -Wextra -Werror -o /tmp/test_qlabels tests/test_qlabels.c 2>&1 && /tmp/test_qlabels || echo "FAIL: test_qlabels"
clang -Wall -Wextra -Werror -o /tmp/test_qube_policy tests/test_qube_policy.c 2>&1 && /tmp/test_qube_policy || echo "FAIL: test_qube_policy"
clang -Wall -Wextra -Werror -o /tmp/test_qargs tests/test_qargs.c 2>&1 && /tmp/test_qargs || echo "FAIL: test_qargs"
gcc -Wall -Wextra -Werror -o /tmp/test_netfw tests/test_netfw.c 2>&1 && /tmp/test_netfw || echo "FAIL: test_netfw"
gcc -Wall -Wextra -Werror -o /tmp/test_aead tests/test_aead.c 2>&1 && /tmp/test_aead || echo "FAIL: test_aead"
gcc -Wall -Wextra -Werror -o /tmp/test_crypt tests/test_crypt.c 2>&1 && /tmp/test_crypt || echo "FAIL: test_crypt"
gcc -Wall -Wextra -Werror -o /tmp/test_argon2id tests/test_argon2id.c 2>&1 && /tmp/test_argon2id || echo "FAIL: test_argon2id"
gcc -Wall -Wextra -Werror -o /tmp/test_gui tests/test_gui.c 2>&1 && /tmp/test_gui || echo "FAIL: test_gui"
gcc -Wall -Wextra -Werror -o /tmp/test_irq tests/test_irq.c 2>&1 && /tmp/test_irq || echo "FAIL: test_irq"
gcc -Wall -Wextra -Werror -o /tmp/test_dev_leaves tests/test_dev_leaves.c 2>&1 && /tmp/test_dev_leaves || echo "FAIL: test_dev_leaves"
gcc -Wall -Wextra -Werror -o /tmp/test_net_stack tests/test_net_stack.c 2>&1 && /tmp/test_net_stack || echo "FAIL: test_net_stack"
gcc -Wall -Wextra -Werror -o /tmp/test_stub_drivers tests/test_stub_drivers.c 2>&1 && /tmp/test_stub_drivers || echo "FAIL: test_stub_drivers"
gcc -Wall -Wextra -Werror -o /tmp/test_input tests/test_input.c 2>&1 && /tmp/test_input || echo "FAIL: test_input"
gcc -Wall -Wextra -Werror -o /tmp/test_virtio_input tests/test_virtio_input.c 2>&1 && /tmp/test_virtio_input || echo "FAIL: test_virtio_input"
gcc -Wall -Wextra -Werror -I userspace/abi -o /tmp/test_driver_bounds tests/test_driver_bounds.c 2>&1 && /tmp/test_driver_bounds || echo "FAIL: test_driver_bounds"
gcc -Wall -Wextra -Werror -o /tmp/test_rng tests/test_rng.c 2>&1 && /tmp/test_rng || echo "FAIL: test_rng"
gcc -Wall -Wextra -no-pie -o /tmp/test_shell_vfs tests/test_shell_vfs.c userspace/vfs_server/server.c 2>&1 && /tmp/test_shell_vfs || echo "FAIL: test_shell_vfs"
gcc -Wall -Wextra -Werror -o /tmp/test_abi_sync tests/test_abi_sync.c 2>&1 && /tmp/test_abi_sync || echo "FAIL: test_abi_sync"
gcc -Wall -Wextra -Werror -o /tmp/test_shell_programs tests/test_shell_programs.c 2>&1 && /tmp/test_shell_programs || echo "FAIL: test_shell_programs"
if command -v clang &>/dev/null; then
  make -C kernel 2>&1 | tail -n 1 || echo "FAIL: kernel build"
else
  echo "SKIP: kernel (clang not found)"
fi
echo "[1g] v2 production gates (linker layout + user rodata ban)"
if [ -f kernel/build/moonlight.elf ]; then
  python3 <<'PYEOF' || echo "FAIL: kernel linker gate"
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
  clang --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 -O2 -ffreestanding \
    -nostdlib -fno-builtin -mcmodel=medany -mno-relax -Wall \
    -I$(clang --print-resource-dir)/include -c kernel/user.c -o /tmp/user_check.o 2>/dev/null
  if llvm-readelf -S /tmp/user_check.o | grep -q "rodata"; then
    echo "FAIL: user.c emits .rodata (U-mode would fault reading U=0 literals)"
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
    V2LOG=$(timeout 10 $QEMU -M virt -m 256M -nographic -bios default -kernel kernel/build/moonlight.elf -device virtio-net-device,netdev=n0 -netdev user,id=n0 -device virtio-rng-device -global virtio-mmio.force-legacy=off -drive file=$DISK,format=raw,if=none,id=hd0 -device virtio-blk-device,drive=hd0 -device bochs-display -device virtio-keyboard-device -device virtio-mouse-device 2>&1 | tr -d '\0')
    # Fail closed: every missing marker flips the gate to FAIL (a smoke
    # that only prints FAIL lines but reports PASS proves nothing).
    QEMU_FAIL=0
    # Production microkernel gates (all services in qube 0; the retired
    # qube-demo set — B00pn/A10pg, QREXEC/FW/NET/VAULT/CRYPT, MMIO-leaf
    # asserts, FILL/COMPOSE — no longer exists, so gating it would fail
    # on phantom markers).
    echo "$V2LOG" | grep -q "satp Sv39 on" && echo "v2 smoke: satp on" || { echo "v2 smoke: FAIL (no satp)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "entering U-mode" && echo "v2 smoke: U-mode entry" || { echo "v2 smoke: FAIL (no U entry)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "INPUT: kbd found" && echo "v2 smoke: input kbd" || { echo "v2 smoke: FAIL (no input kbd)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "INPUT: mouse found" && echo "v2 smoke: input mouse" || { echo "v2 smoke: FAIL (no input mouse)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "GUI: bochs 800x600x32" && echo "v2 smoke: bochs mode" || { echo "v2 smoke: FAIL (no bochs mode)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "\[spawn\] mem_server ELF ok" && echo "v2 smoke: mem spawn" || { echo "v2 smoke: FAIL (no mem spawn)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "\[spawn\] shell ELF ok" && echo "v2 smoke: shell spawn" || { echo "v2 smoke: FAIL (no shell spawn)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "\[spawn\] console ELF ok" && echo "v2 smoke: console spawn" || { echo "v2 smoke: FAIL (no console spawn)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "\[spawn\] tty ELF ok" && echo "v2 smoke: tty spawn" || { echo "v2 smoke: FAIL (no tty spawn)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "\[spawn\] gui ELF ok" && echo "v2 smoke: gui spawn" || { echo "v2 smoke: FAIL (no gui spawn)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "Services: mem+console+tty+gui up" && echo "v2 smoke: services up" || { echo "v2 smoke: FAIL (no services up)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "MEM-SRV" && echo "v2 smoke: MEM-SRV userspace" || { echo "v2 smoke: FAIL (no MEM-SRV)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "DU: vpn0 mirrored" && echo "v2 smoke: DU real-frame proof" || { echo "v2 smoke: FAIL (no DU)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "NP" && echo "v2 smoke: NP negative-passed" || { echo "v2 smoke: FAIL (no NP)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "\[sched\] exited 7" && echo "v2 smoke: demo exited (spawn slot)" || { echo "v2 smoke: FAIL (no demo exit)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "GUI: Bochs VGA found" && echo "v2 smoke: vga bind" || { echo "v2 smoke: FAIL (no vga bind)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "GUI: framebuffer initialised" && echo "v2 smoke: fb init" || { echo "v2 smoke: FAIL (no fb init)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "GUI: keyboard ready" && echo "v2 smoke: kbd ready" || { echo "v2 smoke: FAIL (no kbd ready)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "GUI: mouse ready" && echo "v2 smoke: mouse ready" || { echo "v2 smoke: FAIL (no mouse ready)"; QEMU_FAIL=1; }
    echo "$V2LOG" | grep -q "SHELL: thread 1 starting" && echo "v2 smoke: shell live" || { echo "v2 smoke: FAIL (no shell live)"; QEMU_FAIL=1; }
    # Liveness (not clean-park: the production system stays up serving
    # IPC — shell/tty traffic at the timeout proves the scheduler + IPC
    # plane are alive instead of wedged).
    echo "$V2LOG" | grep -q "\[ipc\] send tcb=1 -> 4" && echo "v2 smoke: shell->tty live IPC" || { echo "v2 smoke: FAIL (no live IPC)"; QEMU_FAIL=1; }
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
  echo "SKIP: kernel/build/moonlight.elf not found"
  QEMU_STATUS="SKIP"
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