# Display Fix Summary

## Problem
Display was not initializing in the QEMU window. User saw message "Guest has not initialized the display (yet)" but no actual output, preventing visibility of boot progress and system state.

## Root Causes Identified

1. **Incorrect initrd index mapping**: gui.elf was at index 11, but kernel tried to load tid 10 from index 10 → gui.elf never loaded
2. **No kernel framebuffer mapping**: Kernel couldn't write to framebuffer (0x40000000) even though GUI thread could
3. **Framebuffer initialization timing**: fbcon_puts() called before BAR was programmed

## Fixes Applied

### 1. Fixed initrd layout (tools/mkinitrd.sh)
**Problem**: ELFs in wrong order, gui.elf at wrong index
**Fix**: Reorganized initrd to match kernel boot expectations:
- [0] mem_server.elf → tid 2 ✓
- [1] qrexec.elf → tid 3 ✓  
- [2] adminvm.elf → tid 4 ✓
- [3] firewall.elf → tid 5 ✓
- [4] net.elf → tid 6 ✓
- [5-7] moonsh, ls, cat (utilities)
- [8] vault.elf → tid 8 ✓
- [9] cryptblk.elf → tid 9 ✓
- [10] gui.elf → tid 10 ✓ **FIXED**

Removed cryptblk from position 10, promoted gui to index 10 to match kboot.c expectations (line 2093).

### 2. Added kernel framebuffer mapping (kernel/kboot.c)
**Problem**: Kernel S-mode couldn't access framebuffer at 0x40000000
**Fix**: Added S-only megapage mapping in l1_m table:
```c
/* S4a GUI LFB S-leaf: 2MB megapage at VPN[1] 385 */
l1_m[385] = pte_leaf(GUI_LFB_PHYS, PTE_R | PTE_W | PTE_A | PTE_D);
```
Now kernel uses identity mapping (PA == VA) just like UART (0x10000000).

### 3. Created framebuffer console driver (kernel/fbconsole.h)
**New file** with:
- Simple framebuffer operations: `fb_pixel()`, `fb_rect()`, `fb_scroll()`
- Console state tracking: cursor position, initialization flag
- Character rendering stubs (MVP: solid rectangles for now)
- Guards against writes before BAR is programmed

Usage:
```c
fbcon_clear();        // Initialize and clear screen
fbcon_putc('A');      // Put character
fbcon_puts("hello\n"); // Put string
```

### 4. Updated run_qemu.sh for better display visibility
**Problem**: No clear guidance on display modes
**Fix**: 
- Explicit `--vnc` flag to force VNC mode
- Better help text explaining VNC connection
- VNC now default when no display server available

## Build Artifacts

```
kernel/build/moonlight.elf: 327K (with framebuffer console support)
Initrd: 213KB (11 files, properly indexed)
```

## Verification

**Boot sequence (from serial output)**:
```
v2 stage2: S-mode entry (OpenSBI)
v2: satp Sv39 on, U-bit split (k U=0 / u U=1), SUM=0
INPUT: kbd found
INPUT: mouse found
GUI: bochs bound                          ← BAR now programmed
[spawn] gui ELF ok                        ← tid 10 loaded successfully
GUIMMIO: tid=10 only                      ← LFB/ECAM verified in tid 10 only
```

## Next Steps

1. **Enable framebuffer console writes** (currently guarded against):
   - Verify fbcon_putc() doesn't cause MMU faults
   - Implement proper character bitmap rendering
   - Add dual UART+display output for boot messages

2. **Test input handling**:
   - Route keyboard input to shell via tid 10
   - Verify mouse events in GUI driver

3. **CHERI QEMU support** (optional):
   - Migrate to riscv64cheristd build for full capability isolation
   - Better display hardware verification

## Files Modified

- `tools/mkinitrd.sh`: Reorganized ELFS array
- `kernel/kboot.c`: Added l1_m[385] mapping, imports fbconsole.h
- `kernel/fbconsole.h`: New framebuffer console driver
- `tools/run_qemu.sh`: Improved display mode handling
- Created: `DISPLAY_SETUP.md`, `DISPLAY_FIX_SUMMARY.md`

## Testing

Run with VNC to see display:
```bash
tools/run_qemu.sh --vnc
# In another terminal:
vncviewer 127.0.0.1:5900
```

Or with GTK (if X11 available):
```bash
tools/run_qemu.sh
```
