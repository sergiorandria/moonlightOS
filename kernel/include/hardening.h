#pragma once
#include <stdint.h>
#include <stddef.h>

/* Hardening primitives - defense in depth even though CHERI catches most */

#define STACK_CANARY 0xDEADBEEFCAFEBABEULL
#define GUARD_PAGE_PATTERN 0x0

void hardening_init(void);
bool canary_check(uint64_t canary);
void guard_page_init(uintptr_t base, size_t len);
void ubsan_handler(const char *file, int line, const char *msg);

/* CBMC harness helpers - for bounded model checking */
#ifdef CBMC
void __CPROVER_assert(int cond, const char *msg);
void __CPROVER_assume(int cond);
#endif
