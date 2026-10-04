/* tests/test_abi_sync.c — KAT: userspace/lib/moonlight.h must emit the
 * kernel V2 UABI numbers (kernel/kernel.h). A drift here (e.g. V1 seL4-style
 * numbers) makes shell/example ELFs trap wrong: putc(6) hits V2_WAIT,
 * yield(3) hits V2_SEND, send(2) parks the thread.
 *
 * Compile gate: any mismatch is a _Static_assert failure (build breaks
 * loudly instead of shipping a silent ABI skew). Run: gcc -I. -o
 * /tmp/test_abi_sync tests/test_abi_sync.c && /tmp/test_abi_sync
 */
#include <stdio.h>

#include "../kernel/kernel.h"
#include "../userspace/lib/moonlight.h"
#include "../userspace/shell_exec.h"

/* Syscall numbers (a7): all 8, no gaps for drift to hide in. */
_Static_assert(MOONLIGHT_SYS_YIELD == V2_YIELD, "yield must be V2_YIELD (0)");
_Static_assert(MOONLIGHT_SYS_PUTC == V2_PUTC, "putc must be V2_PUTC (1)");
_Static_assert(MOONLIGHT_SYS_PARK == V2_PARK, "park must be V2_PARK (2)");
_Static_assert(MOONLIGHT_SYS_SEND == V2_SEND, "send must be V2_SEND (3)");
_Static_assert(MOONLIGHT_SYS_RECV == V2_RECV, "recv must be V2_RECV (4)");
_Static_assert(MOONLIGHT_SYS_NOTIFY == V2_NOTIFY, "notify must be V2_NOTIFY (5)");
_Static_assert(MOONLIGHT_SYS_WAIT == V2_WAIT, "wait must be V2_WAIT (6)");
_Static_assert(MOONLIGHT_SYS_INVOKE == V2_INVOKE, "invoke must be V2_INVOKE (7)");

/* INVOKE sub-ops (a0) exposed by the lib */
_Static_assert(MOONLIGHT_INV_MINT == V2_INV_MINT, "mint op must match");
_Static_assert(MOONLIGHT_INV_GRANT == V2_INV_GRANT, "grant op must match");
_Static_assert(MOONLIGHT_INV_MAP == V2_INV_MAP, "map op must match");
_Static_assert(MOONLIGHT_INV_UNMAP == V2_INV_UNMAP, "unmap op must match");
_Static_assert(MOONLIGHT_INV_REVOKE == V2_INV_REVOKE, "revoke op must match");
_Static_assert(MOONLIGHT_INV_PT_ALLOC == V2_INV_PT_ALLOC, "pt_alloc op must match");

/* IPC wire bound: the lib transfers MOONLIGHT_SEND_WORDS leading words;
 * longer spans fail INVALID in the kernel (v2_len_ok). */
_Static_assert(MOONLIGHT_SEND_WORDS == V2_MSG_MAX, "send cap must equal V2_MSG_MAX");

/* Second header, same numbers: shell_exec.h duplicates the INVOKE numbers
 * for the SPAWN/FORK/EXEC wrappers — drift here traps wrong the same way. */
_Static_assert(V2_INVOKE == 7, "shell_exec INVOKE must be 7");
_Static_assert(V2_INV_SPAWN == 9, "shell_exec SPAWN must be 9");
_Static_assert(V2_INV_FORK == 10, "shell_exec FORK must be 10");
_Static_assert(V2_INV_EXEC == 11, "shell_exec EXEC must be 11");

int main(void)
{
    printf("ABI sync ok: yield=%d putc=%d park=%d send=%d recv=%d notify=%d wait=%d invoke=%d sendwords=%d\n",
           MOONLIGHT_SYS_YIELD, MOONLIGHT_SYS_PUTC, MOONLIGHT_SYS_PARK, MOONLIGHT_SYS_SEND, MOONLIGHT_SYS_RECV,
           MOONLIGHT_SYS_NOTIFY, MOONLIGHT_SYS_WAIT, MOONLIGHT_SYS_INVOKE, MOONLIGHT_SEND_WORDS);
    return 0;
}
