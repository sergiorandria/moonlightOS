/* userspace/shell_programs.h - Shell command dispatcher with SPAWN/FORK/EXEC support.
 * Integrates initrd program discovery with execution via V2 syscalls.
 * Provides: program lookup, discovery, and invocation wrappers.
 *
 * Design:
 * - SPAWN: Create new thread and load program (suitable for background jobs, not shell built-ins)
 * - FORK: Duplicate shell, child replaces with program via EXEC (classic Unix fork/exec)
 * - Direct approach: Shell could call exec directly, but then can't return to accept next command
 *   (typical usage: shell spawns child to run command, waits for child to exit)
 *
 * This header maps program names to initrd indices and provides launch helpers.
 */

#ifndef SHELL_PROGRAMS_H
#define SHELL_PROGRAMS_H

#include "shell_exec.h"
#include <stddef.h>
#include <stdint.h>

/* Known programs: mapping from name to initrd index.
 * SINGLE SOURCE OF TRUTH: tools/mkinitrd.sh ELFS array. Any reorder/add
 * there MUST update this table + tests/test_shell_programs.c together:
 * a stale index executes the WRONG image (isolation violation).
 *
 * Current mkinitrd.sh layout (production microkernel):
 *   [0] mem_server.elf (-> tid 2, kernel requirement)
 *   [1] moonsh.elf     (-> tid 1, shell application)
 *   [2] UNUSED hole (sparse slot, lookup rejects)
 *   [3] console.elf    (-> tid 3, text rendering)
 *   [4] tty.elf        (-> tid 4, line discipline)
 *   [5..9] UNUSED holes (sparse slots, lookup rejects)
 *   [10] gui.elf       (-> tid 10, hardware driver)
 * qrexec/adminvm/firewall/net/vault/cryptblk/ls/cat/echo/hello are NOT
 * packed (no entry): lookup returns -1 so nothing executes a wrong image.
 * Holes keep indices pinned (mkinitrd emits size-0 sparse slots). */

/* Program table entry */
typedef struct
{
    const char *name;
    unsigned int initrd_idx;
    int is_builtin; /* 1 = handled by shell directly, 0 = external ELF */
} shell_program_t;

/* Hardcoded program table mirroring tools/mkinitrd.sh ELFS order.
 * In production, tools/mkinitrd.sh would generate this programmatically. */
static const shell_program_t shell_programs[] = {
    /* Boot services (kernel-spawned; indices mirror mkinitrd.sh) */
    {"mem_server", 0, 0},
    {"moonsh", 1, 0},
    {"console", 3, 0},
    {"tty", 4, 0},
    {"gui", 10, 0},

    /* End marker */
    {NULL, 0, 0},
};

/* Look up program by name. Returns initrd index (>= 0) on success, -1 on not found. */
static inline int shell_lookup_program(const char *name)
{
    if (!name || *name == '\0')
        return -1;

    for (int i = 0; shell_programs[i].name != NULL; i++)
    {
        const char *n = shell_programs[i].name;
        const char *cmd = name;
        while (*n && *cmd && *n == *cmd)
        {
            n++;
            cmd++;
        }
        if (*n == '\0' && *cmd == '\0')
        {
            return (int)shell_programs[i].initrd_idx;
        }
    }
    return -1; /* not found */
}

/* List all known programs. Useful for "help" or shell completion.
 * Calls callback(name, idx) for each program. */
typedef int (*shell_program_callback_t)(const char *name, unsigned int idx);

static inline void shell_list_programs(shell_program_callback_t callback)
{
    if (!callback)
        return;
    for (int i = 0; shell_programs[i].name != NULL; i++)
    {
        if (callback(shell_programs[i].name, shell_programs[i].initrd_idx) != 0)
            break; /* callback returned non-zero: stop iteration */
    }
}

/* SPAWN program: create new thread and load program (returns new tid on success).
 * Usage: spawn_program("hello") creates a new thread, loads hello.elf into it, returns tid.
 * Returns negative on error (program not found, allocation failure, etc.).
 * Parent continues running; child is scheduled independently. */
static inline int shell_spawn_program(const char *name)
{
    int idx = shell_lookup_program(name);
    if (idx < 0)
        return -1; /* not found */
    return shell_spawn((unsigned int)idx);
}

/* FORK + EXEC program: fork the shell, child replaces with program (classic Unix).
 * Usage:
 *   int child = fork_and_exec_program("hello");
 *   if (child > 0) {
 *       // Parent: wait for child or do other work
 *   } else if (child == 0) {
 *       // Should not reach here (child image replaced)
 *   } else {
 *       // Error
 *   }
 *
 * On success, child is replaced with the program image (never returns).
 * Parent gets child tid and can wait/monitor it. */
static inline int shell_fork_and_exec_program(const char *name)
{
    int child = shell_fork();
    if (child > 0)
    {
        /* Parent: return child tid */
        return child;
    }
    else if (child == 0)
    {
        /* Child: replace with program */
        int idx = shell_lookup_program(name);
        if (idx < 0)
        {
            /* Program not found: exit with error status */
            /* In real Unix, we'd exit(127); here we can only loop */
            while (1)
            { /* park forever */
            }
        }
        /* Exec: if successful, never returns */
        shell_exec((unsigned int)idx);
        /* If exec fails (error returned), we're still the child shell image */
        /* Could retry or exit, but for now just loop */
        while (1)
        { /* park forever */
        }
    }
    else
    {
        /* Error: fork failed */
        return child;
    }
}

/* Direct EXEC program: replace current shell with program.
 * CAUTION: Shell will not return; all state is lost except registers and stack.
 * This is useful for exec cmd1 && exec cmd2 chains, but not for shell-then-continue.
 *
 * Usage:
 *   shell_exec_program("hello");
 *   // Never reaches here
 *
 * Returns only on error (program not found, exec validation failure). */
static inline int shell_exec_program(const char *name)
{
    int idx = shell_lookup_program(name);
    if (idx < 0)
        return -1; /* not found */
    return shell_exec((unsigned int)idx);
}

/* Query program metadata (size, availability, etc.) */
static inline unsigned int shell_get_program_size(const char *name)
{
    int idx = shell_lookup_program(name);
    if (idx < 0)
        return 0;
    /* Would need to query initrd metadata; stub for now */
    return 0; /* unknown */
}

#endif /* SHELL_PROGRAMS_H */
