/* libc popen: fork + exec sh -c with a pipe bound to the child's
 * stdin or stdout. pclose reaps the child and returns its status. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>

#define ML_POPEN_MAX 16
static struct {
    int used;
    FILE *f;
    int pid;
} ml_popen_tab[ML_POPEN_MAX];

FILE *popen(const char *cmd, const char *mode) {
    int pfd[2], i, slot = -1;
    pid_t pid;
    int reading;
    char *argv[4];
    if (!cmd || !mode || (mode[0] != 'r' && mode[0] != 'w')) {
        errno = EINVAL;
        return 0;
    }
    reading = mode[0] == 'r';
    for (i = 0; i < ML_POPEN_MAX; i++) {
        if (!ml_popen_tab[i].used) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        errno = ENOMEM;
        return 0;
    }
    if (pipe(pfd) != 0) return 0;
    pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return 0;
    }
    if (pid == 0) {
        /* Child: wire the pipe to stdio, then run the shell. */
        if (reading) {
            dup2(pfd[1], 1);
        } else {
            dup2(pfd[0], 0);
        }
        close(pfd[0]);
        close(pfd[1]);
        argv[0] = "sh";
        argv[1] = "-c";
        argv[2] = (char *)cmd;
        argv[3] = 0;
        execvp("sh", argv);
        _Exit(127);
    }
    /* Parent: the other end becomes a FILE. */
    {
        FILE *f;
        if (reading) {
            close(pfd[1]);
            f = fdopen(pfd[0], "r");
        } else {
            close(pfd[0]);
            f = fdopen(pfd[1], "w");
        }
        if (!f) {
            int e = errno;
            close(reading ? pfd[0] : pfd[1]);
            errno = e;
            return 0;
        }
        ml_popen_tab[slot].used = 1;
        ml_popen_tab[slot].f = f;
        ml_popen_tab[slot].pid = pid;
        return f;
    }
}

int pclose(FILE *f) {
    int i, status, pid;
    if (!f) {
        errno = EINVAL;
        return -1;
    }
    for (i = 0; i < ML_POPEN_MAX; i++) {
        if (ml_popen_tab[i].used && ml_popen_tab[i].f == f) break;
    }
    if (i >= ML_POPEN_MAX) {
        errno = EINVAL;
        return -1;
    }
    pid = ml_popen_tab[i].pid;
    ml_popen_tab[i].used = 0;
    fclose(f);
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return status;
}
