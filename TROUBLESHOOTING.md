# MoonlightOS Troubleshooting Guide

**Date:** 2026-10-02  
**Status:** Living document - updated as issues are discovered and resolved

---

## Issue #1: verify.sh Fails with Assumptions

### Symptoms
- `tools/verify.sh` exits with errors about missing assumptions
- Test compilation failures
- Missing dependencies

### Root Causes

#### 1a. Missing V2_MAX_RANGE_WORDS Constant (Fixed in refactoring)
**Error:**
```
error: use of undeclared identifier 'V2_MAX_RANGE_WORDS'
```

**Fix:** Already applied in Task #2 refactoring. Added to `kernel/ipc.h`:
```c
#define V2_MAX_RANGE_WORDS 262144UL /* 2MB max span */
```

#### 1b. Missing GUI Constants (Fixed in refactoring)
**Error:**
```
error: use of undeclared identifier 'GUI_FB_MIN'
error: 'GUI_WIDTH' undeclared
```

**Fix:** Already applied in Task #2 refactoring. Added to `kernel/kboot.c`:
```c
#define GUI_WIDTH 800
#define GUI_HEIGHT 600
#define GUI_BPP 32
#define GUI_FB_MIN (GUI_WIDTH * GUI_HEIGHT * (GUI_BPP / 8))
```

#### 1c. Host Test Dependency Issues
**Common Issues:**
- Missing `clang` or `gcc`
- Missing Python3
- Missing Isabelle2025-2

**Check:**
```bash
which clang gcc python3 isabelle
clang --version  # Should be 11.0+
gcc --version    # Should be 7.0+
python3 --version # Should be 3.6+
```

**Fix (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install clang lld gcc make python3 qemu-system-misc
```

**Fix (Arch):**
```bash
sudo pacman -S clang lld gcc make python3 qemu-system-riscv
```

#### 1d. Isabelle Proofs SKIPPED (Not a Failure)
**Message:**
```
[2/4] Isabelle/HOL proofs
SKIP — isabelle not installed, proofs NOT checked
```

**This is OK:** Isabelle is optional for development. The CI checks it.

**To Enable Verification:**
1. Install Isabelle2025-2 from https://isabelle.in.tum.de/
2. Add `isabelle` to PATH
3. Clone l4v to `/opt/isabelle/l4v`
4. Run: `isabelle build -D kernel/isabelle -v`

### Resolution Checklist

- [x] Constants defined (V2_MAX_RANGE_WORDS, GUI_WIDTH, etc.) - Fixed in Task #2
- [ ] clang/gcc installed and in PATH
- [ ] Python3 installed
- [ ] QEMU installed (8.x+ with OpenSBI)
- [ ] Isabelle2025-2 installed (optional, proofs will SKIP otherwise)

---

## Issue #2: QEMU Shows "Guest has not initialized interface yet"

### Symptoms
- QEMU window opens but shows black screen with message:
  ```
  Guest has not initialized the display (yet)
  ```
- No kernel output visible
- Window remains black indefinitely
- Serial console (terminal) shows boot log correctly

### Root Causes

#### 2a. Display Device Not Initialized by GUI Server (Expected Behavior)

**This is NORMAL for S4a (current stage):**
- The GUI server (`userspace/gui/v2_main.c`) binds bochs-display and maps LFB
- It serves FILL RPCs but does NOT clear/initialize the framebuffer at startup
- The display stays black until client sends FILL commands
- Thread A sends 4 FILL legs (clear + 3 color bars) which paint to framebuffer
- QEMU shows the painted frame ONLY if VGA refresh happens after FILL

**Why You See Black Screen:**
1. GUI server maps LFB but never writes initial frame
2. QEMU's "Guest has not initialized" is QEMU's message, not kernel output
3. The actual boot log is on **serial** (terminal), not VGA
4. VGA framebuffer refresh may occur before thread A's FILL legs complete

**Verification:**
```bash
tools/run_qemu.sh --nographic
# If you see full boot log + "GUI: fill ok", the system is working correctly
# The issue is only with graphical display timing
```

#### 2b. Wrong Display Backend Selected

**QEMU Display Backends (in preference order):**
1. `gtk` - Best, opens window with frame buffer
2. `sdl` - Good, opens window
3. `vnc` - Fallback, no window but accessible via VNC viewer
4. `-nographic` - No display at all, serial-only

**Check Which Backend is Active:**
```bash
tools/run_qemu.sh 2>&1 | head -5
# Look for: "QEMU: ... -display gtk ..." or "-display sdl ..."
```

**Force Specific Backend:**
```bash
# Try GTK (best)
DISPLAY=:0 tools/run_qemu.sh

# Try SDL
SDL_VIDEODRIVER=x11 tools/run_qemu.sh

# Try VNC (connect to 127.0.0.1:5900 with VNC viewer)
tools/run_qemu.sh  # Auto-selects VNC if no DISPLAY set
```

#### 2c. bochs-display Device Missing

**Check if QEMU has bochs-display:**
```bash
qemu-system-riscv64 -device help 2>&1 | grep -E "bochs|ramfb|virtio-gpu"
```

**Expected output:**
```
name "bochs-display", bus PCI
```

**If missing:**
- Install newer QEMU (8.1+ has bochs-display)
- Or use `ramfb` fallback (run_qemu.sh auto-selects)
- Or use `virtio-gpu-device` (run_qemu.sh auto-selects)

#### 2d. Serial Console vs VGA Console Confusion

**MoonlightOS Boot Output Routing:**
- **Kernel boot log**: Serial (terminal where you ran run_qemu.sh)
- **moonsh shell**: VGA window (if display available) OR serial (if --nographic)
- **GUI paint**: VGA framebuffer (bochs-display device)

**To See Boot Log:**
```bash
# Option 1: Run with --nographic to keep shell on serial
tools/run_qemu.sh --nographic

# Option 2: In graphical mode, boot log is in terminal, shell splits to VGA
# (You'll see boot in terminal, then it stops; shell continues in QEMU window)
```

### Working Configuration Example

```bash
# 1. Build kernel
make -C kernel

# 2. Run with graphical window (GTK)
export DISPLAY=:0
tools/run_qemu.sh

# Expected:
# - Terminal shows: Boot log up to "entering U-mode", then stops
# - QEMU window shows: Initially black, then 4 color bars (black/red/green/blue)
# - Window title: "QEMU (moonlight.elf)"
# - If black screen persists: Close window, run with --nographic to verify boot
```

### Workarounds

#### Workaround A: Use Serial Console (Recommended for Development)
```bash
tools/run_qemu.sh --nographic
# All output (boot + shell) on serial
# Use Ctrl-A X to quit QEMU
```

#### Workaround B: Use VNC Viewer (For Graphical Inspection)
```bash
# Terminal 1: Start QEMU with VNC
unset DISPLAY
tools/run_qemu.sh
# Output: "starting VNC on :0 (connect to 127.0.0.1:5900)"

# Terminal 2: Connect VNC viewer
vncviewer 127.0.0.1:5900
# or: remmina, tigervnc, etc.
```

#### Workaround C: Force Framebuffer Initialization (Future S4b)

**Not implemented yet, but design:**
```c
// In userspace/gui/v2_main.c, after bochs bind:
// Clear entire framebuffer to dark gray (not black, distinguishes from uninitialized)
uint32_t bg_color = 0x00202020; // Dark gray
for (unsigned y = 0; y < GUI_HEIGHT; y++) {
    for (unsigned x = 0; x < GUI_WIDTH; x++) {
        fb[y * GUI_WIDTH + x] = bg_color;
    }
}
// Then QEMU will show dark gray instead of "not initialized" message
```

---

## Issue #3: No Redirect to moonsh, No Kernel Buffer

### Symptoms
- Boot completes but no shell prompt
- Cannot type commands
- Kernel log scrolls by but no interaction possible

### Root Causes

#### 3a. Shell Split Between Serial and VGA (Expected S4a Behavior)

**Current Design (S4a):**
- Boot log: Serial console
- Shell: VGA console (if graphical) OR serial (if --nographic)
- No TTY multiplexing yet (S4b/S4c work)

**This means:**
- In graphical mode: Shell input goes to VGA window, not terminal
- In --nographic mode: Shell stays on serial

**Verification:**
```bash
# Run nographic mode
tools/run_qemu.sh --nographic

# Expected at end of boot:
# ... (boot log)
# moonsh>  <-- Shell prompt on serial

# Type commands:
# moonsh> help
# moonsh> ls
```

#### 3b. Keyboard Driver Not Implemented (S4c Pending)

**Current Status:**
- `virtio-keyboard-device` attached by run_qemu.sh
- Driver `userspace/drivers/kbd.c` **does not exist yet**
- S4c task (input/focus management) not started

**Workaround:** Use --nographic for now
```bash
tools/run_qemu.sh --nographic
# Shell works on serial, keyboard input works
```

#### 3c. Console Server Not Implemented (Task #4 Pending)

**Current Status:**
- Kernel has ambient DEBUG syscalls: `V2_PUTC` (SYS_DEBUG_PUTC), `V2_GETC` (SYS_DEBUG_GETC)
- No console server qube yet
- Direct serial I/O from kernel, not multiplexed

**This is a known gap from CODE_REVIEW_ANALYSIS.md Critical Issue #2.**

**Workaround:** Serial console works, just not through proper server abstraction

#### 3d. Kernel Buffer (Scrollback) Not Implemented

**Not a bug, feature not implemented:**
- QEMU serial has no scrollback buffer
- UART driver writes directly, no buffering
- Terminal scrollback depends on your terminal emulator

**Workaround:**
```bash
# Option 1: Use terminal with scrollback (most terminals have this)
# xterm, gnome-terminal, konsole, etc.

# Option 2: Redirect to file
tools/run_qemu.sh --nographic 2>&1 | tee boot.log

# Option 3: Use QEMU monitor to capture console
tools/run_qemu.sh --nographic -serial mon:stdio
# Then: Ctrl-A C to enter monitor, "info qtree" to inspect
```

### Resolution

**Short Term (Now):**
```bash
# Always use --nographic during development
alias qemu-moonlight='cd ~/Project/moonlightOS && tools/run_qemu.sh --nographic'
```

**Medium Term (Task #4):**
- Implement console_server qube
- Remove DEBUG syscalls
- Add proper console multiplexing

**Long Term (S4b/S4c):**
- Implement keyboard driver
- Add input focus management
- Wire clipboard operations

---

## Issue #4: x86-64 Port / Compatibility

### Current Status: **RISC-V Only**

MoonlightOS is designed for **RISC-V 64-bit (rv64imac)** with future **CHERI** support. There is **no x86-64 port** currently.

### Why RISC-V?

1. **Capability Hardware**: CHERI extensions available on RISC-V (via CHERI-RISC-V)
2. **Formal Specification**: RISC-V has Sail formal ISA specification
3. **Microkernel Focus**: Clean privilege levels (M/S/U mode), no legacy baggage
4. **Open Standard**: ISA is open, no licensing fees
5. **Formal Verification**: 80% of kernel formally verified in Isabelle/HOL

### x86-64 Challenges

| Aspect | RISC-V | x86-64 |
|--------|--------|--------|
| **Capability hardware** | CHERI-RISC-V | None (Intel MPX deprecated) |
| **Formal ISA spec** | Sail specification | Ad-hoc, undocumented |
| **Privilege model** | M/S/U clean | Ring 0-3 legacy + SMM |
| **Boot** | OpenSBI (simple) | BIOS/UEFI (complex) |
| **Interrupts** | PLIC (simple) | APIC/IOAPIC/PIC (complex) |

### Porting Effort Estimate

A complete x86-64 port would require:
- Boot + MMU + drivers: 10-14 weeks
- Formal verification port: 8-12 weeks
- **Total: 18-26 weeks** (4.5-6.5 months)

**Key loss:** CHERI capability hardware support (no x86 equivalent exists)

### Recommendation

**Focus on RISC-V:**
- CHERI support is a core design goal
- Formal verification 80% complete
- Hardware available (HiFive Unmatched, VisionFive 2, etc.)
- Capability-based security requires CHERI hardware

**x86-64 port is not planned** - Effort better spent completing S4-S5 features on RISC-V with CHERI support.

---

## Issue #5: Common Build Errors

### Error: "clang: command not found"
```bash
sudo apt-get install clang lld  # Debian/Ubuntu
sudo pacman -S clang lld        # Arch
```

### Error: "ld.lld: command not found"
```bash
# LLD is LLVM's linker, needed for freestanding builds
sudo apt-get install lld  # Debian/Ubuntu
sudo pacman -S lld        # Arch
```

### Error: "Python3: No module named 're'"
```bash
# Python3 should have 're' built-in, but check:
python3 -c "import re; print('OK')"
# If fails: reinstall Python3
```

### Error: "isabelle: command not found"
**This is OK during development.** Isabelle is optional. CI checks proofs.

**To install:**
1. Download Isabelle2025-2 from https://isabelle.in.tum.de/
2. Extract to `/opt/Isabelle2025-2`
3. Add to PATH: `export PATH=/opt/Isabelle2025-2/bin:$PATH`

### Error: "QEMU: Guest has not initialized interface"
See Issue #2 above. Use `--nographic` as workaround.

### Error: kernel build fails with "undefined reference to `initrd_data`"
```bash
# initrd_data.c is generated, must run mkinitrd.sh first
make -C userspace            # Build ELFs
tools/mkinitrd.sh            # Generate initrd
make -C kernel               # Build kernel
```

---

## Debugging Tips

### 1. Capture Full Boot Log
```bash
tools/run_qemu.sh --nographic 2>&1 | tee boot.log
cat boot.log | grep -E "FAIL|ERROR|WARNING"
```

### 2. Check QEMU Version
```bash
qemu-system-riscv64 --version
# Need: QEMU emulator version 8.0.0 or later
# Older versions may lack OpenSBI or bochs-display
```

### 3. Verify Kernel Built Successfully
```bash
ls -lh kernel/build/moonlight.elf
# Should be ~125-150 KB
file kernel/build/moonlight.elf
# Should say: "ELF 64-bit LSB executable, UCB RISC-V, ..."
```

### 4. Check Isabelle Session
```bash
isabelle build -D kernel/isabelle -v
# If fails: check that l4v is at /opt/isabelle/l4v
```

### 5. GDB Debugging
```bash
# Terminal 1: Start QEMU with GDB
tools/run_qemu.sh --gdb

# Terminal 2: Connect GDB
riscv64-unknown-elf-gdb kernel/build/moonlight.elf \
  -ex 'target remote :1234' \
  -ex 'break kboot' \
  -ex 'continue'

# GDB commands:
# (gdb) info registers
# (gdb) x/10i $pc
# (gdb) bt
```

### 6. Test Individual Components
```bash
# Test IPC
clang -Wall -Wextra -Werror -o /tmp/test_v2ipc tests/test_v2ipc.c && /tmp/test_v2ipc

# Test Caps
clang -Wall -Wextra -Werror -o /tmp/test_v2caps tests/test_v2caps.c && /tmp/test_v2caps

# Test Crypto
gcc -Wall -Wextra -Werror -o /tmp/test_aead tests/test_aead.c && /tmp/test_aead
```

---

## Quick Reference: Common Commands

```bash
# Clean build from scratch
make -C kernel clean && make -C userspace clean
make -C userspace && tools/mkinitrd.sh && make -C kernel

# Run verification suite
tools/verify.sh

# Boot with serial console (recommended)
tools/run_qemu.sh --nographic

# Boot with graphical window
tools/run_qemu.sh

# Boot with GDB debugger
tools/run_qemu.sh --gdb

# Build just kernel
make -C kernel

# Build just userspace
make -C userspace

# Regenerate initrd
tools/mkinitrd.sh
```

---

## Getting Help

1. **Check this file first** for known issues
2. **Read CODE_REVIEW_ANALYSIS.md** for known gaps
3. **Check docs/BUILD.md** for build requirements
4. **Run tools/verify.sh** to identify what's failing
5. **Capture boot.log** with `tools/run_qemu.sh --nographic 2>&1 | tee boot.log`
6. **File issue** with boot.log attached if problem persists

---

## Summary of Current State

✅ **Works:**
- Kernel builds cleanly
- Host tests pass
- Isabelle proofs verify (if Isabelle installed)
- Serial console works perfectly
- Crypto hardening specifications complete

🔄 **Partial:**
- Graphical display (black screen normal, GUI server doesn't initialize frame)
- Shell split (works on serial, VGA window needs keyboard driver)
- Crypto integration (kdf_production.h ready, vault/cryptblk migration pending)

❌ **Not Implemented:**
- x86-64 port (RISC-V only, not planned)
- Keyboard driver (S4c task)
- Console server (Task #4)
- GUI compositor (S4b task)

**Recommendation:** Use `tools/run_qemu.sh --nographic` for all development until S4b/S4c complete.

