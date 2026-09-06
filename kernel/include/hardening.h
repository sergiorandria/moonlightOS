#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Hardening primitives - defense in depth even though CHERI catches most
 * Production: stack canary, guard pages via PMP, UBSAN fail-closed, CFI
 */

#define STACK_CANARY 0xDEADBEEFCAFEBABEULL
#define GUARD_PAGE_PATTERN 0xDEADC0DEDEADC0DEULL
#define CANARY_ALIGNMENT 16
#define GUARD_PAGE_SIZE 4096

void hardening_init(void);
bool canary_check(uint64_t canary) __attribute__((warn_unused_result));
void guard_page_init(uintptr_t base, size_t len);
void ubsan_handler(const char *file, int line, const char *msg) __attribute__((noreturn));
void panic(const char *msg) __attribute__((noreturn));
bool is_canonical_addr(uintptr_t addr) __attribute__((warn_unused_result));

/* Compile-time hardening checks */
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#error "ASAN not allowed in kernel"
#endif
#endif

/* CBMC harness helpers - for bounded model checking */
#ifdef CBMC
void __CPROVER_assert(int cond, const char *msg);
void __CPROVER_assume(int cond);
#define HARDENING_ASSERT(c) __CPROVER_assert((c), #c)
#else
#define HARDENING_ASSERT(c) do { if (!(c)) panic("assert: " #c); } while(0)
#endif
