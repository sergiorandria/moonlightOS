#pragma once
#include <stdint.h>
#include <stddef.h>

/* Freestanding rv64 lp64 must have 8-byte uintptr_t. Host glibc
 * bits/wordsize.h breaks this under --target=riscv64 if -I/usr/include
 * is pulled (see PLAN 3). Fail loudly instead of silently truncating
 * vspace.c/syscall.c/elf.c/boot.c address casts. */
_Static_assert(sizeof(uintptr_t) == 8, "uintptr_t must be 8 bytes for rv64 lp64");
_Static_assert(sizeof(void *) == 8, "void* must be 8 bytes for rv64 lp64");
_Static_assert(sizeof(uint64_t) == 8, "uint64_t must be 8 bytes");
_Static_assert(sizeof(size_t) == 8, "size_t must be 8 bytes for rv64 lp64");

#define PAGE_SIZE 4096
#define MAX_PARTITIONS 8
#define MAX_THREADS 256
#define MAX_CSPACE_DEPTH 4
#define IPC_MSG_MAX 30  /* 120 bytes */
#define IPC_CAPS_MAX 3

typedef uint64_t ticks_t;
typedef uint32_t asid_t;
typedef uint32_t cptr_t;  /* capability pointer = CNode index */

typedef enum {
    ERR_OK = 0,
    ERR_INVALID_CAP = 1,
    ERR_NO_RIGHTS = 2,
    ERR_INVALID_ARG = 3,
    ERR_NO_MEM = 4,
    ERR_REVOKE_NEEDED = 5,
    ERR_OVERFLOW = 6,
    ERR_PARTITION_DENIED = 7,
    ERR_WCET_EXCEEDED = 8,
} kerror_t;

typedef struct {
    uint32_t label;
    uint32_t length;
    uint32_t caps;
    uint64_t words[IPC_MSG_MAX];
    cptr_t cap_ptrs[IPC_CAPS_MAX];
} ipc_msg_t;

/* Syscall numbers - only 6 syscalls, minimal TCB */
typedef enum {
    SYS_CALL = 0,
    SYS_REPLY_RECV = 1,
    SYS_SEND = 2,
    SYS_YIELD = 3,
    SYS_SEAL = 4,
    SYS_INVOKE = 5, /* cap invocation: retype, mint, revoke, map, etc */
} syscall_t;

typedef enum {
    INV_UNTYPED_RETYPE = 0,
    INV_CNODE_COPY = 1,
    INV_CNODE_MINT = 2,
    INV_CNODE_MOVE = 3,
    INV_CNODE_DELETE = 4,
    INV_TCB_CONFIGURE = 5,
    INV_TCB_RESUME = 6,
    INV_TCB_SUSPEND = 7,
    INV_VSPACE_MAP = 8,
    INV_VSPACE_UNMAP = 9,
    INV_FRAME_MAP = 10,
    INV_SCHED_BIND = 11,
} invoke_op_t;
