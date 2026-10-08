#!/usr/bin/env bash
# Simple sanity‑check script for the MoonlightOS shell IPC pipeline.
# It builds the userland, boots QEMU, and guides you to verify that
# keyboard input reaches the shell and that the shell replies appear.

set -euo pipefail

# Build all userspace binaries (requires the usual build environment)
make -C /home/sergio/Project/moonlightOS userspace

# Launch QEMU with VNC so we can see the console.
# Adjust the VNC port if needed.
/home/sergio/Project/moonlightOS/tools/run_qemu.sh --vnc &
QEMU_PID=$!

echo "QEMU started (PID $QEMU_PID). Connect with a VNC viewer (e.g. 'vncviewer localhost:5900')."

echo "When the VM boots, you should see the boot log, then a 'moonsh>' prompt."

echo "Type 'help' and press Enter. The shell should echo the help text."

echo "If you see a red asterisk in the top‑left corner after each key press, the debug marker is working."

echo "Press Ctrl‑C to terminate QEMU when you are done."

wait $QEMU_PID
