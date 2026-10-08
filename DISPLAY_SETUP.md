# MoonlightOS Display Setup Guide

## Current Status

The kernel now includes:
- Bochs display device support (PCI BAR programming)
- GUI thread (tid 10) with input/keyboard/mouse drivers  
- S-mode kernel-to-framebuffer mapping for future console output

## Running the OS

### Option 1: GTK Window (Local Display)
If you have X11 or Wayland:
```bash
tools/run_qemu.sh
```
A QEMU window will appear with the bochs display.

### Option 2: VNC Remote Display (Recommended for testing)
```bash
tools/run_qemu.sh --vnc
```
Then connect with a VNC viewer:
```bash
vncviewer 127.0.0.1:5900
```
This works even over SSH and allows you to see kernel boot messages and GUI output.

### Option 3: Serial Only (Headless)
```bash
tools/run_qemu.sh --nographic
```
Shell and boot output on UART/serial only. No framebuffer display.

## Display Support Implementation

### Bochs Display (QEMU)
- Device: `bochs-display` (PCI vendor 0x1234, device 0x1111)
- Resolution: 800×600×32 XRGB8888
- Kernel BAR programming: at 0x40000000 (64MB window)
- User MMIO: tid 10 (GUI thread) maps LFB at 0x80C00000 (l0_guifb)

### Kernel Framebuffer Console (In Progress)
- File: `kernel/fbconsole.h` (kernel/fbconsole support layer)
- S-mode identity mapping: GUI_LFB_PHYS (0x40000000) accessible as VA 0x40000000
- Dual output: UART + framebuffer (when initialized)
- Status: Foundation laid, framebuffer write safety verification pending

### GUI Driver (Userspace)
- File: `userspace/gui/v2_main.c` (tid 10, qube 8)
- Features:
  - VirtIO keyboard input (tid 10 receives IRQs via KBD_IRQ_BIT notify)
  - VirtIO mouse input (MOUSE_IRQ_BIT notify)
  - Text console rendering (8×16 VGA font, 100×37 grid)
  - FILL service for pixel operations from other qubes
- Status: Fully implemented and integrated

## VNC Viewer Setup

### Linux
```bash
apt install vncviewer   # or: vinagre, remmina
vncviewer 127.0.0.1:5900
```

### macOS
```bash
brew install vnc-viewer
open vnc://127.0.0.1:5900
```

### Windows
Download: TightVNC, RealVNC, or UltraVNC
Connect to: 127.0.0.1:5900

## Troubleshooting

### Display appears black
- Kernel may still be booting. VNC viewer auto-reconnects when guest framebuffer initializes.
- Check serial output: `tools/run_qemu.sh --nographic` to see boot messages on UART.

### "Guest has not initialized the display (yet)"
- Normal message while OpenSBI is loading (pre-kernel).
- QEMU framebuffer becomes active once kernel assigns bochs BAR (around "GUI: bochs bound").
- If message persists, check that gui.elf is in the initrd (index 10).

### VNC connection refused
- Ensure QEMU is running: `ps aux | grep qemu`
- Check VNC is enabled: run without `--nographic`
- Try: `telnet 127.0.0.1 5900` to verify port is listening

## Next Steps

1. **GUI Console Output**: Implement kernel framebuffer rendering for boot messages
   - fbcon_putc() safety verification
   - Character rendering with 8×16 font
   - Dual output: UART (serial) + display (window)

2. **GUI Input Handling**: Map VirtIO input to GUI thread
   - Keyboard: routing keypresses to shell
   - Mouse: cursor rendering and click handling

3. **CHERI QEMU Migration** (Optional, S4c+):
   - Use `riscv64cheristd` build for full CHERI support
   - Better display isolation and hardware verification

## References

- `kernel/kboot.c`: GUI BAR programming (lines 1847-1893)
- `kernel/fbconsole.h`: Framebuffer console driver (new)
- `userspace/gui/v2_main.c`: GUI server implementation
- `tools/run_qemu.sh`: QEMU launch script with display mode selection
