#pragma once
#include <stdint.h>
#include <stddef.h>

/* Userspace purecap ABI - all pointers are CHERI caps on HW, checked pointers on host */
#ifdef __CHERI_PURE_CAPABILITY__
#define PURECAP __capability
#else
#define PURECAP
#endif

int moonlight_call(uint32_t ep_cptr, void *msg);
int moonlight_recv(uint32_t ep_cptr, void *msg);
int moonlight_yield(void);
int moonlight_retype(uint32_t untyped_cptr, uint32_t type, size_t size, uint32_t dest_cptr);
int moonlight_cnode_copy(uint32_t dst, uint32_t src, uint32_t rights);
