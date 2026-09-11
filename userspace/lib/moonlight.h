#pragma once
#include <stdint.h>
#include <stddef.h>

/* Userspace purecap ABI - all pointers are CHERI caps on HW, checked pointers on host */
#ifdef __CHERI_PURE_CAPABILITY__
#define PURECAP __capability
#else
#define PURECAP
#endif

/* IPC message layout mirrors kernel ipc_msg_t (kernel/include/types.h).
 * SYS_CALL/SYS_SEND take a user pointer to this struct; the kernel copies
 * label/length/caps + words/cap_ptrs after validating bounds. */
#define MOONLIGHT_MSG_MAX 30
#define MOONLIGHT_CAPS_MAX 3

typedef struct {
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

/* Syscall numbers mirror kernel/include/types.h (do not drift). */
#define MOONLIGHT_SYS_CALL 0
#define MOONLIGHT_SYS_REPLY_RECV 1
#define MOONLIGHT_SYS_SEND 2
#define MOONLIGHT_SYS_YIELD 3
#define MOONLIGHT_SYS_SEAL 4
#define MOONLIGHT_SYS_INVOKE 5
#define MOONLIGHT_SYS_DEBUG_PUTC 6
#define MOONLIGHT_SYS_DEBUG_GETC 7

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
