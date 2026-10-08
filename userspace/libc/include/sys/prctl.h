/* Moonlight libc - sys/prctl (process-local controls).
 * Subset with process-local meaning is stored in libc (pdeathsig,
 * dumpable, keepcaps, name, timerslack, no_new_privs, thp_disable);
 * PR_GET_TID_ADDRESS reports the real tid; PR_SET_VMA needs file-backed
 * mappings (ENOSYS in the kernel) and anything else needing kernel
 * MMU/scheduler support fails EINVAL honestly (see src/sysstat.c). */
#pragma once

#define PR_SET_PDEATHSIG 1
#define PR_GET_PDEATHSIG 2
#define PR_GET_DUMPABLE 3
#define PR_SET_DUMPABLE 4
#define PR_GET_KEEPCAPS 7
#define PR_SET_KEEPCAPS 8
#define PR_GET_NAME 16
#define PR_SET_NAME 15
#define PR_GET_TIMERSLACK 30
#define PR_SET_TIMERSLACK 29
#define PR_GET_THP_DISABLE 42
#define PR_SET_THP_DISABLE 41
#define PR_GET_NO_NEW_PRIVS 39
#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_TID_ADDRESS 40
#define PR_SET_VMA 0x53564d41
#define PR_SET_VMA_ANON_NAME 0

int prctl(int op, ...);
