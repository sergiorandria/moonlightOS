/* Moonlight libc - stdatomic (C11, header-only).
 *
 * Fully implemented over compiler __atomic built-ins: works on the
 * rv64 target (clang) and the host (gcc). Lock-free queries map to
 * __atomic_is_lock_free; fences map to __atomic_thread_fence /
 * __atomic_signal_fence. No stubs: every C11 operation is a real
 * atomic access with the requested ordering. */
#pragma once

#include <stdint.h>

typedef enum {
    memory_order_relaxed = __ATOMIC_RELAXED,
    memory_order_consume = __ATOMIC_CONSUME,
    memory_order_acquire = __ATOMIC_ACQUIRE,
    memory_order_release = __ATOMIC_RELEASE,
    memory_order_acq_rel = __ATOMIC_ACQ_REL,
    memory_order_seq_cst = __ATOMIC_SEQ_CST
} memory_order;

#define ATOMIC_VAR_INIT(v) (v)
#define ATOMIC_FLAG_INIT {0}

typedef _Atomic(_Bool) atomic_bool;
typedef _Atomic(char) atomic_char;
typedef _Atomic(signed char) atomic_schar;
typedef _Atomic(unsigned char) atomic_uchar;
typedef _Atomic(short) atomic_short;
typedef _Atomic(unsigned short) atomic_ushort;
typedef _Atomic(int) atomic_int;
typedef _Atomic(unsigned int) atomic_uint;
typedef _Atomic(long) atomic_long;
typedef _Atomic(unsigned long) atomic_ulong;
typedef _Atomic(long long) atomic_llong;
typedef _Atomic(unsigned long long) atomic_ullong;
typedef _Atomic(intptr_t) atomic_intptr_t;
typedef _Atomic(uintptr_t) atomic_uintptr_t;
typedef _Atomic(size_t) atomic_size_t;
typedef _Atomic(ptrdiff_t) atomic_ptrdiff_t;
typedef _Atomic(intmax_t) atomic_intmax_t;
typedef _Atomic(uintmax_t) atomic_uintmax_t;
typedef struct {
    _Atomic(_Bool) __ml_flag;
} atomic_flag;

#define atomic_init(obj, v) __atomic_store_n(obj, v, __ATOMIC_RELAXED)
#define atomic_store(obj, v) \
    __atomic_store_n(obj, v, __ATOMIC_SEQ_CST)
#define atomic_store_explicit(obj, v, mo) __atomic_store_n(obj, v, mo)
#define atomic_load(obj) __atomic_load_n(obj, __ATOMIC_SEQ_CST)
#define atomic_load_explicit(obj, mo) __atomic_load_n(obj, mo)
#define atomic_exchange(obj, v) \
    __atomic_exchange_n(obj, v, __ATOMIC_SEQ_CST)
#define atomic_exchange_explicit(obj, v, mo) __atomic_exchange_n(obj, v, mo)
#define atomic_compare_exchange_strong(obj, exp, des) \
    __atomic_compare_exchange_n(obj, exp, des, 0, __ATOMIC_SEQ_CST, \
                                __ATOMIC_SEQ_CST)
#define atomic_compare_exchange_strong_explicit(obj, exp, des, smo, fmo) \
    __atomic_compare_exchange_n(obj, exp, des, 0, smo, fmo)
#define atomic_compare_exchange_weak(obj, exp, des) \
    __atomic_compare_exchange_n(obj, exp, des, 1, __ATOMIC_SEQ_CST, \
                                __ATOMIC_SEQ_CST)
#define atomic_compare_exchange_weak_explicit(obj, exp, des, smo, fmo) \
    __atomic_compare_exchange_n(obj, exp, des, 1, smo, fmo)
#define atomic_fetch_add(obj, v) __atomic_fetch_add(obj, v, __ATOMIC_SEQ_CST)
#define atomic_fetch_add_explicit(obj, v, mo) __atomic_fetch_add(obj, v, mo)
#define atomic_fetch_sub(obj, v) __atomic_fetch_sub(obj, v, __ATOMIC_SEQ_CST)
#define atomic_fetch_sub_explicit(obj, v, mo) __atomic_fetch_sub(obj, v, mo)
#define atomic_fetch_or(obj, v) __atomic_fetch_or(obj, v, __ATOMIC_SEQ_CST)
#define atomic_fetch_or_explicit(obj, v, mo) __atomic_fetch_or(obj, v, mo)
#define atomic_fetch_xor(obj, v) __atomic_fetch_xor(obj, v, __ATOMIC_SEQ_CST)
#define atomic_fetch_xor_explicit(obj, v, mo) __atomic_fetch_xor(obj, v, mo)
#define atomic_fetch_and(obj, v) __atomic_fetch_and(obj, v, __ATOMIC_SEQ_CST)
#define atomic_fetch_and_explicit(obj, v, mo) __atomic_fetch_and(obj, v, mo)

#define atomic_flag_test_and_set(obj) \
    __atomic_test_and_set(&(obj)->__ml_flag, __ATOMIC_SEQ_CST)
#define atomic_flag_test_and_set_explicit(obj, mo) \
    __atomic_test_and_set(&(obj)->__ml_flag, mo)
#define atomic_flag_clear(obj) \
    __atomic_clear(&(obj)->__ml_flag, __ATOMIC_SEQ_CST)
#define atomic_flag_clear_explicit(obj, mo) \
    __atomic_clear(&(obj)->__ml_flag, mo)

#define atomic_is_lock_free(obj) __atomic_is_lock_free(sizeof(*(obj)), obj)
#define atomic_thread_fence(mo) __atomic_thread_fence(mo)
#define atomic_signal_fence(mo) __atomic_signal_fence(mo)

#define kill_dependency(y) (y)
