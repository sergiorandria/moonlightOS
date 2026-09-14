/* Moonlight libc - fenv (C99, real rounding/exception state).
 *
 * Rounding mode and exception flags live in a per-process soft cell
 * that our own rint/nearbyint honor; on riscv the mode is additionally
 * written to fcsr so hardware arithmetic follows it too. Host builds
 * use the same soft cell (no host <fenv.h> dependency, freestanding).
 */
#pragma once

typedef unsigned fexcept_t;
typedef struct {
    unsigned mode;
    unsigned flags;
} fenv_t;

#define FE_DIVBYZERO 1
#define FE_INEXACT 2
#define FE_INVALID 4
#define FE_OVERFLOW 8
#define FE_UNDERFLOW 16
#define FE_ALL_EXCEPT 31

#define FE_TONEAREST 0
#define FE_DOWNWARD 1
#define FE_UPWARD 2
#define FE_TOWARDZERO 3

int feclearexcept(int excepts);
int fegetexceptflag(fexcept_t *flagp, int excepts);
int feraiseexcept(int excepts);
int fesetexceptflag(const fexcept_t *flagp, int excepts);
int fetestexcept(int excepts);
int fegetround(void);
int fesetround(int mode);
int fegetenv(fenv_t *envp);
int fesetenv(const fenv_t *envp);
int feholdexcept(fenv_t *envp);
int feupdateenv(const fenv_t *envp);
int fedisableexcept(int excepts);
int feenableexcept(int excepts);
int fegetexcept(void);
