/* Moonlight libc - stdckdint.h (C23 checked arithmetic, real). */
#pragma once

#define ckd_add(res, a, b) __builtin_add_overflow((a), (b), (res))
#define ckd_sub(res, a, b) __builtin_sub_overflow((a), (b), (res))
#define ckd_mul(res, a, b) __builtin_mul_overflow((a), (b), (res))
