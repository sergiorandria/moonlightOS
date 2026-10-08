/* libc getopt (permuting, glibc-style default). Single-threaded globals.
 * optstring: leading '-' returns each non-option as code 1 (optarg set);
 * leading '+' (or POSIXLY_CORRECT in the environment) stops at the first
 * non-option. A leading ':' makes missing arguments return ':' instead of
 * '?'. Errors print to stderr unless opterr == 0. At end of options,
 * argv is permuted so argv[optind..argc) are the operands in order. */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *optarg = 0;
int optind = 1;
int opterr = 1;
int optopt = 0;

/* Pending skipped-non-option run [go_first, go_last), option char index
 * inside the current element, stop flag (after "--"), effective argc
 * (shrinks by one when "--" is excised). */
static int go_first = 1;
static int go_last = 1;
static int go_next = 1;
static int go_stop = 0;
static int go_end = -1;

/* Rotate: [first,last) are pending non-options, [last,optind) scanned
 * options; swap the blocks so the non-options move after the options.
 * Unscanned argv[optind..] never moves (option/argument adjacency kept). */
static void go_exchange(char **argv, int optind) {
    int npre = go_last - go_first; /* pending non-options */
    int npost = optind - go_last;  /* scanned options */
    int i;
    if (npre == 0 || npost == 0) return;
    /* Three-reversal rotation over [go_first, optind). */
    for (i = 0; i < npre / 2; i++) {
        char *t = argv[go_first + i];
        argv[go_first + i] = argv[go_first + npre - 1 - i];
        argv[go_first + npre - 1 - i] = t;
    }
    for (i = 0; i < npost / 2; i++) {
        char *t = argv[go_last + i];
        argv[go_last + i] = argv[go_last + npost - 1 - i];
        argv[go_last + npost - 1 - i] = t;
    }
    for (i = 0; i < (npre + npost) / 2; i++) {
        char *t = argv[go_first + i];
        argv[go_first + i] = argv[go_first + npre + npost - 1 - i];
        argv[go_first + npre + npost - 1 - i] = t;
    }
    go_first += npost;
    go_last = optind;
}

static int go_isopt(const char *a) {
    return a[0] == '-' && a[1] != '\0';
}

int getopt(int argc, char *const argv[], const char *optstring) {
    char **args = (char **)argv;
    const char *oli = optstring;
    int reorder = 0, colon = 0;
    char *arg;
    const char *o;
    if (!argv || !optstring || optind < 1) return -1;
    if (optind == 1) {
        /* Fresh parse (also the initial state): clear all statics. */
        go_first = go_last = 1;
        go_next = 1;
        go_stop = 0;
        go_end = -1;
    }
    if (go_end < 0) go_end = argc;
    if (oli[0] == '-' || oli[0] == '+') {
        reorder = oli[0];
        oli++;
    }
    if (oli[0] == ':') {
        colon = 1;
        oli++;
    }
    if (reorder == 0 && getenv("POSIXLY_CORRECT")) reorder = '+';
    for (;;) {
        if (go_stop || optind >= go_end) {
            /* End: park a pending run at the tail, in order, and point
             * optind at its start (first operand). */
            if (go_first != go_last && go_last != optind)
                go_exchange(args, optind);
            if (go_first != go_last) {
                optind = go_end - (go_last - go_first);
                go_first = optind;
                go_last = go_end;
            }
            return -1;
        }
        arg = args[optind];
        if (go_next == 1) {
            if (strcmp(arg, "--") == 0) {
                /* Excise "--": shift the tail left; skipped run plus
                 * operands are already contiguous and ordered, so the
                 * run dissolves (no exchange) and optind aims at the
                 * first operand. */
                int first = go_first, i;
                for (i = optind; i + 1 < go_end; i++)
                    args[i] = args[i + 1];
                go_end--;
                go_stop = 1;
                go_first = go_last = go_end;
                optind = first;
                return -1;
            }
            if (!go_isopt(arg)) {
                if (reorder == '-') {
                    optarg = arg;
                    optind++;
                    return 1;
                }
                if (reorder == '+') return -1;
                /* Permute: extend the pending run over this element. */
                if (go_first != go_last && go_last != optind)
                    go_exchange(args, optind);
                else if (go_first == go_last)
                    go_first = optind;
                go_last = optind + 1;
                optind++;
                continue;
            }
        }
        /* An option element, parsed in place (adjacency preserved). */
        optopt = arg[go_next];
        o = strchr(oli, optopt);
        if (!o || optopt == ':') {
            if (opterr) {
                fputs("invalid option -- ", stderr);
                fputc(optopt, stderr);
                fputc('\n', stderr);
            }
            if (arg[++go_next] == '\0') {
                optind++;
                go_next = 1;
            }
            return '?';
        }
        if (o[1] == ':') {
            if (arg[go_next + 1] != '\0') {
                optarg = &arg[go_next + 1];
            } else {
                optind++;
                if (optind >= go_end) {
                    if (opterr) {
                        fputs("option requires an argument -- ", stderr);
                        fputc(optopt, stderr);
                        fputc('\n', stderr);
                    }
                    go_next = 1;
                    return colon ? ':' : '?';
                }
                optarg = args[optind];
            }
            go_next = 1;
            optind++;
        } else {
            if (arg[++go_next] == '\0') {
                optind++;
                go_next = 1;
            }
        }
        return o[0];
    }
}

/* ---- long options (getopt_long / getopt_long_only) ---- */

#include <getopt.h>

static int ml_long_match(const char *arg, const char *name) {
    size_t n = 0;
    while (arg[n] && arg[n] != '=' && name[n] && arg[n] == name[n]) n++;
    if (arg[n] == '=' || arg[n] == '\0') {
        size_t m = strlen(name);
        if (n == m) return 2; /* exact */
        return 1;             /* prefix */
    }
    return 0;
}

static int ml_long_run(int argc, char *const argv[], const char *optstring,
                       const struct option *longopts, int *longindex,
                       int only) {
    char **args = (char **)argv;
    char *arg = args[optind];
    const struct option *best = 0, *o;
    int best_score = 0, ambiguous = 0, exact = 0;
    const char *eq;
    (void)optstring;
    (void)only;
    for (o = longopts; o && o->name; o++) {
        int m = ml_long_match(arg, o->name);
        if (m == 2) {
            best = o;
            exact = 1;
            break;
        }
        if (m == 1) {
            ambiguous++;
            best = o;
            best_score = 1;
        }
    }
    if (!best) return '?';
    if (ambiguous > 1 && !exact) {
        if (opterr) {
            fputs("option '--", stderr);
            fputs(arg, stderr);
            fputs("' is ambiguous\n", stderr);
        }
        optind++;
        return '?';
    }
    (void)best_score;
    eq = strchr(arg, '=');
    if (longindex) {
        int i = 0;
        for (o = longopts; o && o->name; o++, i++)
            if (o == best) {
                *longindex = i;
                break;
            }
    }
    if (best->has_arg == required_argument || best->has_arg == optional_argument) {
        if (eq) {
            optarg = (char *)eq + 1;
        } else if (best->has_arg == required_argument) {
            optind++;
            if (optind >= argc) {
                if (opterr) {
                    fputs("option '--", stderr);
                    fputs(arg, stderr);
                    fputs("' requires an argument\n", stderr);
                }
                optopt = best->val;
                return optstring && optstring[0] == ':' ? ':' : '?';
            }
            optarg = args[optind];
        } else {
            optarg = 0;
        }
    } else {
        if (eq) {
            if (opterr) {
                fputs("option '--", stderr);
                fputs(arg, stderr);
                fputs("' doesn't allow an argument\n", stderr);
            }
            optind++;
            return '?';
        }
        optarg = 0;
    }
    optind++;
    optopt = best->val;
    if (best->flag) {
        *best->flag = best->val;
        return 0;
    }
    return best->val;
}

int getopt_long(int argc, char *const argv[], const char *optstring,
                const struct option *longopts, int *longindex) {
    char **args = (char **)argv;
    if (!argv || !optstring || optind < 1 || !longopts) return -1;
    if (optind < argc && args[optind][0] == '-' && args[optind][1] == '-' &&
        args[optind][2] != '\0') {
        /* Long form: strip "--" in place for the matcher. */
        int idx = optind;
        char *saved = args[idx];
        int r;
        args[idx] = saved + 2;
        r = ml_long_run(argc, argv, optstring, longopts, longindex, 0);
        args[idx] = saved;
        return r;
    }
    return getopt(argc, argv, optstring);
}

int getopt_long_only(int argc, char *const argv[], const char *optstring,
                     const struct option *longopts, int *longindex) {
    char **args = (char **)argv;
    if (!argv || !optstring || optind < 1 || !longopts) return -1;
    if (optind < argc && args[optind][0] == '-' && args[optind][1] != '\0') {
        /* Try a long match first (single '-' counts too). */
        int idx = optind;
        const char *probe =
            args[idx][1] == '-' ? args[idx] + 2 : args[idx] + 1;
        int islong = 0;
        const struct option *o;
        for (o = longopts; o && o->name; o++) {
            if (ml_long_match(probe, o->name)) {
                islong = 1;
                break;
            }
        }
        if (islong) {
            char *saved = args[idx];
            int r;
            args[idx] = (char *)probe;
            r = ml_long_run(argc, argv, optstring, longopts, longindex, 1);
            args[idx] = saved;
            return r;
        }
    }
    return getopt(argc, argv, optstring);
}
