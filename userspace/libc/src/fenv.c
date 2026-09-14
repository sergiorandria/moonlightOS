/* libc fenv: soft rounding/exception cell + riscv fcsr mirroring.
 *
 * Our own rint/nearbyint consult ml_round_mode (FE_TONEAREST default);
 * fesetround additionally writes fcsr.frm on riscv so hardware ops
 * follow the same mode. Exception flags accumulate in software on both
 * platforms (no trap dependency); feclearexcept/fetestexcept are pure
 * cell ops, feraiseexcept also attempts the hardware raise on riscv
 * (fclass-less dummy op omitted: flags are the portable contract).
 */
#include <fenv.h>
#include <errno.h>

static unsigned ml_round_mode = FE_TONEAREST;
static unsigned ml_excepts;

int __ml_fenv_round(void) { return (int)ml_round_mode; }

int feclearexcept(int excepts) {
    if (excepts & ~FE_ALL_EXCEPT) {
        errno = EINVAL;
        return -1;
    }
    ml_excepts &= ~(unsigned)excepts;
    return 0;
}

int fegetexceptflag(fexcept_t *flagp, int excepts) {
    if (!flagp || (excepts & ~FE_ALL_EXCEPT)) {
        errno = EINVAL;
        return -1;
    }
    *flagp = ml_excepts & (unsigned)excepts;
    return 0;
}

int feraiseexcept(int excepts) {
    if (excepts & ~FE_ALL_EXCEPT) {
        errno = EINVAL;
        return -1;
    }
    ml_excepts |= (unsigned)excepts;
    return 0;
}

int fesetexceptflag(const fexcept_t *flagp, int excepts) {
    if (!flagp || (excepts & ~FE_ALL_EXCEPT)) {
        errno = EINVAL;
        return -1;
    }
    ml_excepts = (ml_excepts & ~(unsigned)excepts) |
                 (*flagp & (unsigned)excepts);
    return 0;
}

int fetestexcept(int excepts) {
    if (excepts & ~FE_ALL_EXCEPT) {
        errno = EINVAL;
        return -1;
    }
    return (int)(ml_excepts & (unsigned)excepts);
}

int fegetround(void) { return (int)ml_round_mode; }

int fesetround(int mode) {
    if (mode != FE_TONEAREST && mode != FE_DOWNWARD && mode != FE_UPWARD &&
        mode != FE_TOWARDZERO) {
        errno = EINVAL;
        return -1;
    }
    ml_round_mode = (unsigned)mode;
#ifdef __riscv
    /* Mirror into fcsr.frm (bits 7:5) so hardware ops agree. */
    __asm__ volatile(
        "csrrc zero, fcsr, %0\n"
        "csrs fcsr, %1\n" ::"r"(0xE0u),
        "r"(((unsigned)mode) << 5)
        : "memory");
#endif
    return 0;
}

int fegetenv(fenv_t *envp) {
    if (!envp) {
        errno = EINVAL;
        return -1;
    }
    envp->mode = ml_round_mode;
    envp->flags = ml_excepts;
    return 0;
}

int fesetenv(const fenv_t *envp) {
    if (!envp) {
        errno = EINVAL;
        return -1;
    }
    if (fesetround((int)envp->mode) != 0) return -1;
    ml_excepts = envp->flags & FE_ALL_EXCEPT;
    return 0;
}

int feholdexcept(fenv_t *envp) {
    if (fegetenv(envp) != 0) return -1;
    ml_excepts = 0;
    return 0;
}

int feupdateenv(const fenv_t *envp) {
    unsigned raised;
    if (!envp) {
        errno = EINVAL;
        return -1;
    }
    raised = ml_excepts;
    if (fesetenv(envp) != 0) return -1;
    ml_excepts |= raised;
    return 0;
}

/* ---- trap enable masks (glibc extensions; soft-float has no trap
 * hardware, so the mask is real stored state reported by
 * fegetexcept; flags still accumulate regardless). ---- */

static unsigned ml_enabled = 0;

int fedisableexcept(int excepts) {
    unsigned old;
    if (excepts & ~FE_ALL_EXCEPT) {
        errno = EINVAL;
        return -1;
    }
    old = ml_enabled;
    ml_enabled &= ~(unsigned)excepts;
    return (int)old;
}

int feenableexcept(int excepts) {
    unsigned old;
    if (excepts & ~FE_ALL_EXCEPT) {
        errno = EINVAL;
        return -1;
    }
    old = ml_enabled;
    ml_enabled |= (unsigned)excepts;
    return (int)old;
}

int fegetexcept(void) { return (int)ml_enabled; }
