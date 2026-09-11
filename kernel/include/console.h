#pragma once
/* console - serial/VGA routing for the debug console syscalls.
 *
 * Mirror (default): SYS_DEBUG_PUTC -> UART + VGA, SYS_DEBUG_GETC <- merged
 * virtio-keyboard + UART ring. Everything appears in both places.
 *
 * Split (window shell): PUTC -> VGA only, GETC <- virtio-keyboard only.
 * The launch terminal keeps whatever the kernel printed before the split
 * (boot log) and stays usable for the QEMU monitor; moonsh lives only in
 * the QEMU window. boot.c enables split when VGA + virtio-keyboard are
 * both present (run_qemu.sh only attaches those devices with a display;
 * --nographic stays mirrored on serial).
 *
 * Host-sim has no VGA: console_putc() is UART/putchar either way, but the
 * split flag itself still works (tests/test_console.c).
 */
void console_set_split(int on);
int console_is_split(void);
/* Routed putc for the SYS_DEBUG_PUTC path (NOT for early boot logs, which
 * stay on boot.c's own UART helper). */
void console_putc(char c);
