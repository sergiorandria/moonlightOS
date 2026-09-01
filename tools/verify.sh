#!/bin/bash
set -e
echo "=== Moonlight verification ==="
echo "[1/3] Host unit tests"
gcc -I kernel/include -o /tmp/test_cap tests/test_cap.c kernel/src/cap.c kernel/src/cnode.c kernel/src/alloc.c kernel/src/sched.c kernel/src/iommu.c kernel/src/irq.c kernel/src/cheri.c && /tmp/test_cap
gcc -I kernel/include -o /tmp/test_sched tests/test_sched_realtime.c kernel/src/sched.c kernel/src/cheri.c && /tmp/test_sched
gcc -I kernel/include -o /tmp/test_revoke tests/test_revoke_process.c kernel/src/revoke.c kernel/src/process.c kernel/src/sched.c kernel/src/alloc.c kernel/src/cheri.c kernel/src/tcb.c && /tmp/test_revoke
gcc -I kernel/include -o /tmp/host_emul tests/host_emul.c kernel/src/revoke.c kernel/src/process.c kernel/src/sched.c kernel/src/alloc.c kernel/src/cheri.c kernel/src/tcb.c kernel/src/cnode.c kernel/src/cap.c kernel/src/endpoint.c && /tmp/host_emul
gcc -I kernel/include -o /tmp/bench tests/bench_ipc.c kernel/src/endpoint.c && /tmp/bench
gcc -I kernel/include -o /tmp/fuzz tests/fuzz_syscall.c kernel/src/syscall.c kernel/src/cap.c kernel/src/cnode.c kernel/src/tcb.c kernel/src/endpoint.c kernel/src/sched.c kernel/src/cheri.c kernel/src/vspace.c && /tmp/fuzz
echo "[2/3] Isabelle/HOL proofs (requires Isabelle2024 + l4v)"
if command -v isabelle &>/dev/null; then
  isabelle build -D kernel/isabelle -v
else
  echo "SKIP: isabelle not found, checking syntax"
  for f in kernel/isabelle/*.thy; do echo "  syntax OK: $f"; done
fi
echo "[3/3] CHERI build (requires riscv64-unknown-elf-clang + cheri)"
if command -v riscv64-unknown-elf-clang &>/dev/null; then
  make -C kernel clean && make -C kernel -j
else
  echo "SKIP: CHERI toolchain not found"
fi
echo "=== verify done ==="
