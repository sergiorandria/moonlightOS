#pragma once
#include <stddef.h>
#include <stdint.h>

/* Userspace purecap ABI - all pointers are CHERI caps on HW, checked pointers on host */
#ifdef __CHERI_PURE_CAPABILITY__
#define PURECAP __capability
#else
#define PURECAP
#endif

/* IPC message layout mirrors kernel ipc_msg_t (userspace/abi/types.h).
 * SYS_CALL/SYS_SEND take a user pointer to this struct; the kernel copies
 * label/length/caps + words/cap_ptrs after validating bounds. */
#define MOONLIGHT_MSG_MAX 30
#define MOONLIGHT_CAPS_MAX 3

typedef struct
{
    uint32_t label;
    uint32_t length;
    uint32_t caps;
    /* Kernel-filled on receive (sender TCB id, 0xFFFFFFFF unknown). Clients
     * must ignore on send. Mirrors kernel ipc_msg_t: do not reorder. */
    uint32_t sender_tcb;
    uint32_t _rsv;
    uint64_t words[MOONLIGHT_MSG_MAX];
    uint32_t cap_ptrs[MOONLIGHT_CAPS_MAX];
} moonlight_msg_t;

/* Syscall numbers are the kernel V2 UABI (a7), single source of truth:
 * kernel/kernel.h (V2_YIELD..V2_INVOKE). Do NOT use userspace/abi/types.h
 * here: that header freezes the retired V1 seL4-style ABI (CALL 0..
 * DEBUG_GETC 7), whose numbers trap wrong on a V2 kernel (putc 6 hits
 * V2_WAIT, yield 3 hits V2_SEND, send 2 parks the thread). KAT:
 * tests/test_abi_sync.c static-asserts every number below against V2_*.
 * V2 has no console-input ecall: moonlight_getc() is a no-trap -1 stub
 * (RX-empty, never blocks) until an input server lands. */
#define MOONLIGHT_SYS_YIELD 0
#define MOONLIGHT_SYS_PUTC 1
#define MOONLIGHT_SYS_PARK 2
#define MOONLIGHT_SYS_SEND 3
#define MOONLIGHT_SYS_RECV 4
#define MOONLIGHT_SYS_NOTIFY 5
#define MOONLIGHT_SYS_WAIT 6
#define MOONLIGHT_SYS_INVOKE 7
/* V2 IPC transfers at most V2_MSG_MAX words (kernel/ipc.h, currently 4).
 * moonlight_send/recv move exactly MOONLIGHT_SEND_WORDS leading words of
 * msg->words (struct header fields label/length/caps/sender_tcb are NOT
 * transferred: V2 messages are raw words, no header). This is lossy by
 * design for the legacy struct API; servers needing full fidelity must
 * drive u_ecall directly. MOONLIGHT_SEND_WORDS must equal V2_MSG_MAX:
 * pinned by tests/test_abi_sync.c. */
#define MOONLIGHT_SEND_WORDS 4
/* INVOKE sub-ops (a0), mirroring kernel/kernel.h V2_INV_*. */
#define MOONLIGHT_INV_MINT 1
#define MOONLIGHT_INV_GRANT 2
#define MOONLIGHT_INV_MAP 3
#define MOONLIGHT_INV_UNMAP 4
#define MOONLIGHT_INV_REVOKE 5
#define MOONLIGHT_INV_PT_ALLOC 6

int moonlight_call(uint32_t ep_cptr, void *msg);
int moonlight_recv(uint32_t ep_cptr, void *msg);
int moonlight_send(uint32_t ep_cptr, void *msg);
int moonlight_yield(void);
int moonlight_retype(uint32_t untyped_cptr, uint32_t type, size_t size, uint32_t dest_cptr);
int moonlight_cnode_copy(uint32_t dst, uint32_t src, uint32_t rights);

/* Debug console (polled UART today, console server later).
 * moonlight_getc returns 0-255, or -1 when RX is empty (never blocks). */
int moonlight_putc(char c);
int moonlight_getc(void);
