/* Moonlight libc - sys/wait (real children table: clone/fork register
 * parent/child, exit parks the status, wait4 reaps; see LINUX.md).
 * Macros are real (exit codes are parked by the kernel). */
#pragma once

#include <sys/types.h>
#include <signal.h>

struct rusage;

#define WIFEXITED(s) (((s) & 0x7F) == 0)
#define WEXITSTATUS(s) (((s) >> 8) & 0xFF)
#define WIFSIGNALED(s) (((s) & 0x7F) != 0 && ((s) & 0x7F) != 0x7F)
#define WTERMSIG(s) ((s) & 0x7F)
#define WIFSTOPPED(s) (((s) & 0xFF) == 0x7F)
#define WSTOPSIG(s) (((s) >> 8) & 0xFF)
#define WIFCONTINUED(s) ((s) == 0xFFFF)
#define WCOREDUMP(s) 0

#define WNOHANG 1
#define WUNTRACED 2
#define WCONTINUED 8
/* waitid options (Linux values). */
#define WEXITED 0x4
#define WSTOPPED 0x2
#define WNOWAIT 0x1000000

int wait(int *status);
int waitpid(int pid, int *status, int options);
int wait3(int *status, int options, struct rusage *rusage);
int wait4(int pid, int *status, int options, struct rusage *rusage);

typedef enum { P_ALL, P_PID, P_PGID, P_PIDFD } idtype_t;
int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
