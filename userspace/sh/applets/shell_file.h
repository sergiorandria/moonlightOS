/*
 * shell_file.h - moonsh file-applet module (BusyBox style, Phase 1)
 *
 * Verbatim split of the file applets out of shell_core.h; no behavior change.
 * Ground truth for future flag/error work: BusyBox 1_36_stable applet help
 * text and per-applet sources (coreutils/ls.c, cat.c, head.c, tail.c, wc.c,
 * cp.c, mv.c, rm.c, mkdir.c, touch.c, stat.c, findutils/find.c, tee.c).
 *
 * Inclusion rule: included only by userspace/sh/shell_core.h, after the
 * engine primitives (sh_puts/sh_putc/sh_print_*, sh_stdin_data/len, sh_cwd)
 * and shell_expr.h are defined. Not a standalone translation unit.
 * All functions are static inline; the single shell_builtins[] table stays
 * in shell_core.h unchanged.
 */

#ifndef SHELL_FILE_H
#define SHELL_FILE_H

#include "../shell_vfs.h"

/*
 * Task 2 compat helpers (BusyBox 1_36_stable).
 *
 * Error pattern mimics libbb/bb_simple_perror_msg(): applet-prefixed
 * messages through the single sh_puts sink (no stderr split yet).
 * Exit codes: 0 success, 1 runtime/partial failure, 2 usage error;
 * $? reflects them via sh_last_status. Verbs below are the BusyBox
 * coreutils texts (spec Sec 4); ramfs has no errno, so the trailing
 * reason is a fixed string chosen by the caller.
 *
 * Prints: "<prog>: <verb> '<path>': <msg>" (cat-style applets with no
 * verb print "<prog>: <path>: <msg>").
 */
static inline void sh_file_error(const char *prog, const char *path, const char *msg)
{
    const char *verb = NULL;
    if (prog)
    {
        if (vfs_strcmp(prog, "ls") == 0)
            verb = "cannot access";
        else if (vfs_strcmp(prog, "cp") == 0)
            verb = "cannot stat";
        else if (vfs_strcmp(prog, "mv") == 0)
            verb = "can't rename";
        else if (vfs_strcmp(prog, "rm") == 0)
            verb = "cannot remove";
        else if (vfs_strcmp(prog, "mkdir") == 0)
            verb = "can't create directory";
        /* cat + unknown progs: no verb ("cat: <path>: <msg>"). */
    }
    sh_puts(prog ? prog : "?");
    sh_puts(": ");
    if (verb)
    {
        sh_puts(verb);
        sh_puts(" '");
        sh_puts(path ? path : "?");
        sh_puts("': ");
    }
    else
    {
        sh_puts(path ? path : "?");
        sh_puts(": ");
    }
    sh_puts(msg ? msg : "");
    sh_putc('\n');
}

/*
 * BusyBox getopt32-style unknown-option path: "<prog>: invalid option --
 * 'x'" + usage line, returning 2 (usage error). Usage strings match each
 * applet's own usage text.
 */
static inline int sh_unknown_opt(const char *prog, char opt)
{
    sh_puts(prog ? prog : "?");
    sh_puts(": invalid option -- '");
    sh_putc(opt);
    sh_puts("'\n");
    if (!prog)
    {
        sh_puts("usage: ? [ARGS]...\n");
    }
    else if (vfs_strcmp(prog, "ls") == 0)
    {
        sh_puts("usage: ls [-1AaCdFhlpRx] [FILE]...\n");
    }
    else if (vfs_strcmp(prog, "cat") == 0)
    {
        sh_puts("usage: cat [-bnEs] [FILE]...\n");
    }
    else if (vfs_strcmp(prog, "touch") == 0)
    {
        sh_puts("usage: touch [-c] FILE...\n");
    }
    else if (vfs_strcmp(prog, "write") == 0)
    {
        sh_puts("usage: write <file> <text...>\n");
    }
    else if (vfs_strcmp(prog, "rm") == 0)
    {
        sh_puts("usage: rm [-fiRr] FILE...\n");
    }
    else if (vfs_strcmp(prog, "cp") == 0)
    {
        sh_puts("usage: cp [-fiRr] SOURCE... DEST\n");
    }
    else if (vfs_strcmp(prog, "mv") == 0)
    {
        sh_puts("usage: mv [-fi] SOURCE... DEST\n");
    }
    else if (vfs_strcmp(prog, "mkdir") == 0)
    {
        sh_puts("usage: mkdir [-p] <dir...>\n");
    }
    else if (vfs_strcmp(prog, "rmdir") == 0)
    {
        sh_puts("usage: rmdir [-p] DIR...\n");
    }
    else if (vfs_strcmp(prog, "head") == 0)
    {
        sh_puts("usage: head [-n N] [-c N] [-qv] [FILE]...\n");
    }
    else if (vfs_strcmp(prog, "tail") == 0)
    {
        sh_puts("usage: tail [-n N] [-c N] [-qv] [FILE]...\n");
    }
    else if (vfs_strcmp(prog, "wc") == 0)
    {
        sh_puts("usage: wc [-lwcmL] [FILE]...\n");
    }
    else if (vfs_strcmp(prog, "stat") == 0)
    {
        sh_puts("usage: stat [-c FORMAT] FILE...\n");
    }
    else if (vfs_strcmp(prog, "find") == 0)
    {
        sh_puts("usage: find [PATH] [-name PAT] [-type f|d] [-maxdepth N]\n");
    }
    else if (vfs_strcmp(prog, "tee") == 0)
    {
        sh_puts("usage: tee [-a] [FILE]...\n");
    }
    else
    {
        sh_puts("usage: ");
        sh_puts(prog);
        sh_puts(" [ARGS]...\n");
    }
    return 2;
}

/*
 * cmd_ls (BusyBox 1_36_stable coreutils/ls.c compat).
 *
 * Mimics ls.c option handling: combined shorts parsed into an option
 * bitmask (getopt32-style), then precedence resolved explicitly: `-d`
 * cancels `-R`, and `-C`/`-x`/`-l`/`-1` are last-wins (ls.c `:C-xl:x-Cl`,
 * `:C-1:1-C`); `-n`/`-g` imply `-l` upstream but ramfs has no uid/gid so
 * they stay rejected here. Display follows the splitdnarray/scan_one_dir
 * split: each operand is stated once (single vfs_find per entry,
 * my_stat-style), files print before directories, per-path errors
 * continue with an accumulated exit code (G.exit_code pattern), and
 * recursion never descends into "." / ".." (SPLIT_SUBDIR).
 *
 * Deliberate deviations: one entry per line only (no column layout, so
 * -C/-x/-1 render identically); directory names always carry trailing
 * '/' (legacy moonsh display old tests rely on), so -F/-p are accepted
 * but change nothing (ramfs has no executables to mark with '*');
 * -A == -a because ramfs stores no "." / ".." entries (spec Sec 3).
 */
enum
{
    LS_OPT_ALL = 1u << 0,      /* -a: show dotfiles */
    LS_OPT_ALMOST = 1u << 1,   /* -A: dotfiles minus . / .. */
    LS_OPT_HUMAN = 1u << 2,    /* -h: human sizes (with -l) */
    LS_OPT_RECUR = 1u << 3,    /* -R: recursive */
    LS_OPT_DIR = 1u << 4,      /* -d: list dirs themselves */
    LS_OPT_CLASSIFY = 1u << 5, /* -F: accepted, '/' always shown */
    LS_OPT_SLASH = 1u << 6,    /* -p: accepted, '/' always shown */
};

static inline int sh_ls_show(const char *name, int show_hidden)
{
    if (!show_hidden && name[0] == '.')
        return 0;
    return 1;
}

static inline void sh_ls_print(int idx, int opt_l, int opt_h)
{
    if (opt_l)
    {
        sh_puts(vfs_nodes[idx].is_dir ? "drwxr-xr-x " : "-rw-r--r-- ");
        sh_puts("1 root root ");
        if (opt_h)
            sh_print_size(vfs_nodes[idx].size);
        else
            sh_print_ulong(vfs_nodes[idx].size);
        sh_puts(" ");
    }
    sh_puts(vfs_nodes[idx].name);
    if (vfs_nodes[idx].is_dir)
        sh_putc('/');
    sh_putc('\n');
}

static inline void sh_ls_list_dir(int pidx, int show_hidden, int opt_l, int opt_h)
{
    int count = 0;
    for (int i = 0; i < VFS_MAX_NODES; i++)
    {
        if (!vfs_nodes[i].in_use)
            continue;
        if (vfs_nodes[i].parent_idx == (uint16_t)pidx && i != pidx)
        {
            if (!sh_ls_show(vfs_nodes[i].name, show_hidden))
                continue;
            sh_ls_print(i, opt_l, opt_h);
            count++;
        }
    }
    if (count == 0 && opt_l)
    {
        sh_puts("(empty)\n");
    }
}

static inline void sh_ls_recurse(const char *disp, int pidx, int show_hidden, int opt_l, int opt_h)
{
    for (int i = 0; i < VFS_MAX_NODES; i++)
    {
        if (!vfs_nodes[i].in_use)
            continue;
        if (vfs_nodes[i].parent_idx != (uint16_t)pidx || i == pidx)
            continue;
        if (vfs_strcmp(vfs_nodes[i].name, ".") == 0 || vfs_strcmp(vfs_nodes[i].name, "..") == 0)
            continue; /* SPLIT_SUBDIR: never descend into . / .. */
        if (!vfs_nodes[i].is_dir)
            continue;
        if (!sh_ls_show(vfs_nodes[i].name, show_hidden))
            continue;
        char child[VFS_PATH_MAX];
        vfs_strcpy(child, disp, sizeof(child));
        if (child[vfs_strlen(child) - 1] != '/')
            vfs_strcat(child, "/", sizeof(child));
        vfs_strcat(child, vfs_nodes[i].name, sizeof(child));
        sh_putc('\n');
        sh_puts(child);
        sh_puts(":\n");
        sh_ls_list_dir(i, show_hidden, opt_l, opt_h);
        sh_ls_recurse(child, i, show_hidden, opt_l, opt_h);
    }
}

static inline int cmd_ls(int argc, char **argv)
{
    unsigned opts = 0;
    char fmt = '1'; /* last-wins display selector: 'C', 'x', 'l', '1' */
    const char *paths[VFS_MAX_NODES];
    int npaths = 0;
    int opts_done = 0;

    for (int i = 1; i < argc; i++)
    {
        if (!opts_done && argv[i][0] == '-' && argv[i][1] != '\0' && vfs_strcmp(argv[i], "--") != 0)
        {
            for (int k = 1; argv[i][k]; k++)
            {
                switch (argv[i][k])
                {
                case 'l':
                    fmt = 'l';
                    break;
                case 'C':
                    fmt = 'C';
                    break;
                case 'x':
                    fmt = 'x';
                    break;
                case '1':
                    fmt = '1';
                    break;
                case 'a':
                    opts |= LS_OPT_ALL;
                    break;
                case 'A':
                    opts |= LS_OPT_ALMOST;
                    break;
                case 'h':
                    opts |= LS_OPT_HUMAN;
                    break;
                case 'R':
                    opts |= LS_OPT_RECUR;
                    break;
                case 'd':
                    opts |= LS_OPT_DIR;
                    break;
                case 'F':
                    opts |= LS_OPT_CLASSIFY;
                    break;
                case 'p':
                    opts |= LS_OPT_SLASH;
                    break;
                default:
                    return sh_unknown_opt("ls", argv[i][k]);
                }
            }
        }
        else if (!opts_done && vfs_strcmp(argv[i], "--") == 0)
        {
            opts_done = 1;
        }
        else if (npaths < VFS_MAX_NODES)
        {
            paths[npaths++] = argv[i];
        }
    }

    if (opts & LS_OPT_DIR)
        opts &= ~LS_OPT_RECUR; /* -d cancels -R (ls.c) */

    int show_hidden = (opts & (LS_OPT_ALL | LS_OPT_ALMOST)) != 0;
    int opt_l = (fmt == 'l');
    int opt_h = (opts & LS_OPT_HUMAN) != 0;
    /* -F/-p need no further action: dirs always show '/' (see sh_ls_print),
       ramfs has no executables to mark. */

    if (npaths == 0)
    {
        paths[npaths++] = ".";
    }

    /* my_stat-style: state each operand exactly once. */
    int pidx[VFS_MAX_NODES];
    char resolved[VFS_PATH_MAX];
    for (int n = 0; n < npaths; n++)
    {
        vfs_resolve_path(sh_cwd, paths[n], resolved, sizeof(resolved));
        pidx[n] = vfs_find(resolved);
    }

    /* splitdnarray-style: count files vs dirs; errors fail this pass. */
    int rc = 0, nfiles = 0, ndirs = 0;
    for (int n = 0; n < npaths; n++)
    {
        if (pidx[n] < 0)
        {
            sh_file_error("ls", paths[n], "No such file or directory");
            rc = 1;
        }
        else if (!vfs_nodes[pidx[n]].is_dir || (opts & LS_OPT_DIR))
        {
            nfiles++;
        }
        else
        {
            ndirs++;
        }
    }

    /* Files first, no headers (splitdnarray display order). */
    for (int n = 0; n < npaths; n++)
    {
        if (pidx[n] < 0)
            continue;
        if (vfs_nodes[pidx[n]].is_dir && (opts & LS_OPT_DIR))
        {
            sh_puts(paths[n]); /* -d: list the dir itself as given */
            sh_putc('\n');
        }
        else if (!vfs_nodes[pidx[n]].is_dir)
        {
            sh_ls_print(pidx[n], opt_l, opt_h);
        }
    }

    /* Then one listing per directory; headers when ambiguous. */
    int multi = (nfiles + ndirs) > 1;
    int first = (nfiles == 0);
    for (int n = 0; n < npaths; n++)
    {
        if (pidx[n] < 0 || !vfs_nodes[pidx[n]].is_dir || (opts & LS_OPT_DIR))
            continue;
        if (multi || (opts & LS_OPT_RECUR))
        {
            if (!first)
                sh_putc('\n');
            sh_puts(paths[n]);
            sh_puts(":\n");
        }
        first = 0;
        sh_ls_list_dir(pidx[n], show_hidden, opt_l, opt_h);
        if (opts & LS_OPT_RECUR)
            sh_ls_recurse(paths[n], pidx[n], show_hidden, opt_l, opt_h);
    }
    return rc;
}

/*
 * cmd_cat (BusyBox 1_36_stable coreutils/cat.c compat).
 *
 * Mimics cat.c option handling and output: combined shorts parsed
 * getopt32-style, then catv()/print_numbered_lines-style emission with a
 * number_state equivalent (width 6 right-aligned, start 1, inc 1, tab
 * separator). `-b` numbers only non-blank lines and overrides `-n` on
 * blanks; `-s` squeezes adjacent blank lines (squeezed lines emit nothing,
 * not even a number); `-E` prints `$` at each line end. `-A`/`-e` imply
 * `-E` only (`-A == -vET` upstream; `-v`/`-T` are text no-ops on ramfs),
 * `-v`/`-T`/`-t`/`-u` are accepted no-ops so valid BusyBox invocations
 * do not trip the unknown-option path.
 *
 * Stdin default follows open_or_warn_stdin: no operands (or `--` alone)
 * reads pipe stdin (`sh_stdin_data`), as does a lone `-` operand; bare
 * `cat` with no pipe data prints nothing and succeeds (cannot block).
 * Multi-file loop continues on error with an accumulated exit code
 * (G.exit_code pattern): one missing entry still prints the others and
 * returns 1.
 *
 * Deliberate deviations: whole-file VFS_FILE_MAX buffering instead of
 * bb_cat streaming (ramfs bound); squeeze/line-number state is continuous
 * across files in one invocation (GNU-style); unterminated trailing input
 * still gets a closing newline (legacy moonsh display old tests rely on).
 */
/*
 * Pipe-stdin length: exact engine count (sh_pipe_len set by the pipe
 * driver). Former strlen() fallback removed 2026-10-07 after the
 * shell_exec_single_cmd save/restore-clobber fix: the unconditional
 * `sh_out_active = old_out` wiped stage-1 buf_pos back to 0, so
 * sh_stdin_len read 0 with data present. The restore is now guarded
 * by did_redir, so this is exact; keep the NULL guard only.
 */
static inline int sh_cat_stdin_len(void)
{
    if (!sh_stdin_data)
        return 0;
    return sh_stdin_len;
}

static inline void sh_cat_print_numbered(unsigned long n)
{
    char digits[24];
    int nd = 0;
    unsigned long t = n;
    if (t == 0)
    {
        digits[nd++] = '0';
    }
    else
    {
        while (t > 0 && nd < 23)
        {
            digits[nd++] = (char)('0' + (t % 10));
            t /= 10;
        }
    }
    for (int i = nd; i < 6; i++)
        sh_putc(' ');
    for (int i = nd - 1; i >= 0; i--)
        sh_putc(digits[i]);
    sh_putc('\t');
}

static inline void sh_cat_emit(const char *data, int len, int opt_b, int opt_n, int opt_s,
                               int opt_e, unsigned long *lineno, int *prev_blank)
{
    int pos = 0;
    while (pos < len)
    {
        int eol = pos;
        while (eol < len && data[eol] != '\n')
            eol++;
        int has_nl = (eol < len);
        int blank = (eol == pos);
        /* -s: squeezed repeats emit nothing, not even a number. */
        if (!(opt_s && blank && *prev_blank))
        {
            if (opt_b ? !blank : opt_n)
                sh_cat_print_numbered((*lineno)++);
            for (int i = pos; i < eol; i++)
                sh_putc(data[i]);
            if (opt_e)
                sh_putc('$');
            sh_putc('\n');
        }
        *prev_blank = blank;
        pos = has_nl ? eol + 1 : len;
    }
}

static inline int cmd_cat(int argc, char **argv)
{
    int opt_n = 0, opt_b = 0, opt_s = 0, opt_e = 0;
    int start = 1;

    while (start < argc && argv[start][0] == '-' && argv[start][1] != '\0' &&
           vfs_strcmp(argv[start], "--") != 0 && vfs_strcmp(argv[start], "-") != 0)
    {
        for (int k = 1; argv[start][k]; k++)
        {
            switch (argv[start][k])
            {
            case 'n':
                opt_n = 1;
                break;
            case 'b':
                opt_b = 1;
                break;
            case 's':
                opt_s = 1;
                break;
            case 'E':
                opt_e = 1;
                break;
            case 'A': /* -A == -vET upstream; only the -E effect applies */
            case 'e': /* -e == -vE upstream; only the -E effect applies */
                opt_e = 1;
                break;
            case 'v': /* accepted no-ops: ramfs files are plain text */
            case 'T':
            case 't':
            case 'u':
                break;
            default:
                return sh_unknown_opt("cat", argv[start][k]);
            }
        }
        start++;
    }
    if (start < argc && vfs_strcmp(argv[start], "--") == 0)
        start++;

    unsigned long lineno = 1; /* number_state start=1, inc=1 */
    int prev_blank = 0;
    int rc = 0;

    /* No operands: default stdin (cat.c: *--argv = "-"). */
    if (start >= argc)
    {
        if (sh_stdin_data)
            sh_cat_emit(sh_stdin_data, sh_cat_stdin_len(), opt_b, opt_n, opt_s, opt_e, &lineno,
                        &prev_blank);
        return 0;
    }

    for (int a = start; a < argc; a++)
    {
        /* Lone "-" reads pipe stdin (open_or_warn_stdin pattern). */
        if (vfs_strcmp(argv[a], "-") == 0)
        {
            if (sh_stdin_data)
                sh_cat_emit(sh_stdin_data, sh_cat_stdin_len(), opt_b, opt_n, opt_s, opt_e, &lineno,
                            &prev_blank);
            continue;
        }

        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[a], resolved, sizeof(resolved));

        int idx = vfs_find(resolved);
        if (idx < 0 || vfs_nodes[idx].is_dir)
        {
            sh_file_error("cat", argv[a], "No such file or directory");
            rc = 1;
            continue;
        }

        char buf[VFS_FILE_MAX];
        int len = vfs_read_file(idx, buf, sizeof(buf));
        if (len < 0)
        {
            rc = 1;
            continue;
        }
        sh_cat_emit(buf, len, opt_b, opt_n, opt_s, opt_e, &lineno, &prev_blank);
    }
    return rc;
}

/*
 * Task 6 shared helpers (BusyBox 1_36_stable coreutils/cp.c, mv.c, rm.c,
 * mkdir.c, touch.c compat).
 *
 * - Multi-operand loops continue on error with an accumulated exit code
 *   (the G.exit_code pattern shared by cp.c/mv.c/rm.c): one bad operand
 *   still processes the rest and returns 1.
 * - `-i` interactivity has no tty prompt plumbing on ramfs (spec Sec 7):
 *   `-i` declines the operation without a tty; `-f` overrides `-i`.
 *   Host tests have no tty, so `-i` always declines there.
 * - Deliberate deviations: no uid/gid/mode preservation, no symlinks
 *   (ramfs has none), whole-file VFS_FILE_MAX buffering instead of
 *   copy_file_chunk streaming (ramfs bound).
 */

/* Basename of a resolved absolute path (no allocation, caller buffer). */
static inline void sh_base_name(const char *res, char *out, int max)
{
    int len = vfs_strlen(res);
    int s = len;
    while (s > 0 && res[s - 1] != '/')
        s--;
    vfs_strcpy(out, res + s, max);
    if (out[0] == '\0')
        vfs_strcpy(out, "/", max);
}

/* Recursive copy of node src_res onto dst_res (cp.c copy_dir/file core).
 * Files are created-or-truncated at dst; dirs are created-or-merged.
 * Returns 0 on success, -1 on any failure (nodes exhausted, type clash). */
static inline int sh_cp_tree(const char *src_res, const char *dst_res)
{
    int sidx = vfs_find(src_res);
    if (sidx < 0)
        return -1;
    if (!vfs_nodes[sidx].is_dir)
    {
        int didx = vfs_find(dst_res);
        if (didx < 0)
        {
            didx = vfs_create_node(dst_res, 0);
            if (didx < 0)
                return -1;
        }
        else if (vfs_nodes[didx].is_dir)
        {
            return -1;
        }
        char buf[VFS_FILE_MAX];
        int len = vfs_read_file(sidx, buf, sizeof(buf));
        if (len < 0)
            return -1;
        if (vfs_write_file(didx, buf, len, 0) < 0)
            return -1;
        return 0;
    }
    int didx = vfs_find(dst_res);
    if (didx < 0)
    {
        didx = vfs_create_node(dst_res, 1);
        if (didx < 0)
            return -1;
    }
    else if (!vfs_nodes[didx].is_dir)
    {
        return -1;
    }
    /* New nodes parent to didx, never to sidx, so index enumeration is stable. */
    for (int i = 0; i < VFS_MAX_NODES; i++)
    {
        if (!vfs_nodes[i].in_use || vfs_nodes[i].parent_idx != (uint16_t)sidx || i == sidx)
            continue;
        char cs[VFS_PATH_MAX], cd[VFS_PATH_MAX];
        vfs_strcpy(cs, src_res, sizeof(cs));
        if (cs[vfs_strlen(cs) - 1] != '/')
            vfs_strcat(cs, "/", sizeof(cs));
        vfs_strcat(cs, vfs_nodes[i].name, sizeof(cs));
        vfs_strcpy(cd, dst_res, sizeof(cd));
        if (cd[vfs_strlen(cd) - 1] != '/')
            vfs_strcat(cd, "/", sizeof(cd));
        vfs_strcat(cd, vfs_nodes[i].name, sizeof(cd));
        if (sh_cp_tree(cs, cd) != 0)
            return -1;
    }
    return 0;
}

/* Recursive removal by resolved path (rm.c remove_dir / mv.c cleanup core).
 * Refuses the root node. Returns 0 on success, -1 on any failure. */
static inline int sh_rm_tree(const char *res)
{
    int idx = vfs_find(res);
    if (idx <= 0)
        return -1;
    if (vfs_nodes[idx].is_dir)
    {
        for (int i = 0; i < VFS_MAX_NODES; i++)
        {
            if (!vfs_nodes[i].in_use || vfs_nodes[i].parent_idx != (uint16_t)idx || i == idx)
                continue;
            char child[VFS_PATH_MAX];
            vfs_strcpy(child, res, sizeof(child));
            if (child[vfs_strlen(child) - 1] != '/')
                vfs_strcat(child, "/", sizeof(child));
            vfs_strcat(child, vfs_nodes[i].name, sizeof(child));
            if (sh_rm_tree(child) != 0)
                return -1;
        }
    }
    return vfs_unlink_node(res);
}

/* mkdir -p core (mkdir.c --parents core): create every missing ancestor in
 * order. Pre-existing dirs succeed; a pre-existing non-dir fails.
 * Returns 0 on success, -1 on failure. */
static inline int sh_mkdir_p(const char *res)
{
    int f = vfs_find(res);
    if (f >= 0)
        return vfs_nodes[f].is_dir ? 0 : -1;
    char prefix[VFS_PATH_MAX];
    int len = vfs_strlen(res);
    for (int i = 1; i <= len; i++)
    {
        if (res[i] != '/' && res[i] != '\0')
            continue;
        int k;
        for (k = 0; k < i && k < VFS_PATH_MAX - 1; k++)
            prefix[k] = res[k];
        prefix[k] = '\0';
        if (prefix[0] == '\0')
            continue;
        int pf = vfs_find(prefix);
        if (pf < 0)
        {
            if (vfs_create_node(prefix, 1) < 0)
                return -1;
        }
        else if (!vfs_nodes[pf].is_dir)
        {
            return -1;
        }
    }
    return vfs_find(res) >= 0 ? 0 : -1;
}

static inline int cmd_touch(int argc, char **argv)
{
    /* touch.c: only -c (do not create) in Phase 1; no-create skips missing
     * files silently. Unknown options use the getopt32-style path. */
    int no_create = 0;
    int start = 1;
    int opts_done = 0;
    while (start < argc && !opts_done && argv[start][0] == '-' && argv[start][1] != '\0')
    {
        if (vfs_strcmp(argv[start], "--") == 0)
        {
            opts_done = 1;
            start++;
            break;
        }
        for (int k = 1; argv[start][k]; k++)
        {
            if (argv[start][k] == 'c')
                no_create = 1;
            else
                return sh_unknown_opt("touch", argv[start][k]);
        }
        start++;
    }
    if (start >= argc)
    {
        sh_puts("usage: touch [-c] FILE...\n");
        return 2;
    }
    int rc = 0; /* continue-on-error across operands (rm.c/cp.c pattern) */
    for (int i = start; i < argc; i++)
    {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[i], resolved, sizeof(resolved));
        int idx = vfs_find(resolved);
        if (idx >= 0)
        {
            vfs_nodes[idx].mtime = vfs_get_time();
        }
        else if (!no_create)
        {
            if (vfs_create_node(resolved, 0) < 0)
            {
                sh_file_error("touch", argv[i], "No such file or directory");
                rc = 1;
            }
        }
    }
    return rc;
}

static inline int cmd_write(int argc, char **argv)
{
    if (argc < 3)
    {
        sh_puts("usage: write <file> <text...>\n");
        return 2;
    }
    char resolved[VFS_PATH_MAX];
    vfs_resolve_path(sh_cwd, argv[1], resolved, sizeof(resolved));

    int idx = vfs_find(resolved);
    if (idx < 0)
    {
        idx = vfs_create_node(resolved, 0);
        if (idx < 0)
        {
            sh_puts("write: cannot create ");
            sh_puts(argv[1]);
            sh_putc('\n');
            return 1;
        }
    }

    /* Join text arguments */
    char content[VFS_FILE_MAX];
    int pos = 0;
    for (int i = 2; i < argc; i++)
    {
        const char *s = argv[i];
        while (*s && pos < VFS_FILE_MAX - 2)
            content[pos++] = *s++;
        if (i < argc - 1 && pos < VFS_FILE_MAX - 2)
            content[pos++] = ' ';
    }
    content[pos] = '\0';

    int w = vfs_write_file(idx, content, pos, 0);
    sh_puts("wrote ");
    sh_print_ulong((unsigned long)(w < 0 ? 0 : w));
    sh_puts(" bytes to ");
    sh_puts(argv[1]);
    sh_putc('\n');
    return 0;
}

/*
 * cmd_rm (BusyBox 1_36_stable coreutils/rm.c compat).
 *
 * Mimics rm.c option handling: `-r`/`-R` recursive, `-f` ignores missing
 * operands and overrides `-i`, `-i` declines every removal without a tty
 * (no prompt plumbing on ramfs, spec Sec 7). Directories without `-r`
 * fail with `Is a directory` even under `-f` (upstream behavior).
 * Multi-operand loop continues on error with an accumulated exit code
 * (G.exit_code pattern in rm.c).
 *
 * Deliberate deviations: the legacy `removed <file>` line is kept on
 * success (upstream rm is silent without -v); no -d (empty-dir) flag.
 */
static inline int cmd_rm(int argc, char **argv)
{
    int force = 0;
    int recursive = 0;
    int interactive = 0;
    int start = 1;
    int opts_done = 0;

    while (start < argc && !opts_done && argv[start][0] == '-' && argv[start][1] != '\0')
    {
        if (vfs_strcmp(argv[start], "--") == 0)
        {
            opts_done = 1;
            start++;
            break;
        }
        for (int k = 1; argv[start][k]; k++)
        {
            if (argv[start][k] == 'f')
                force = 1;
            else if (argv[start][k] == 'r' || argv[start][k] == 'R')
                recursive = 1;
            else if (argv[start][k] == 'i')
                interactive = 1;
            else
                return sh_unknown_opt("rm", argv[start][k]);
        }
        start++;
    }

    if (start >= argc)
    {
        sh_puts("usage: rm [-fiRr] FILE...\n");
        return 2;
    }

    int rc = 0;
    for (int i = start; i < argc; i++)
    {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[i], resolved, sizeof(resolved));

        int idx = vfs_find(resolved);
        if (idx < 0)
        {
            if (force)
                continue; /* rm -f: missing operands are success (rm.c) */
            sh_file_error("rm", argv[i], "No such file or directory");
            rc = 1;
            continue;
        }
        if (interactive && !force)
            continue; /* -i declines without a tty; -f overrides (spec Sec 7) */
        if (vfs_nodes[idx].is_dir && !recursive)
        {
            sh_file_error("rm", argv[i], "Is a directory");
            rc = 1;
            continue;
        }
        int r =
            (vfs_nodes[idx].is_dir && recursive) ? sh_rm_tree(resolved) : vfs_unlink_node(resolved);
        if (r != 0 && !force)
        {
            sh_file_error("rm", argv[i], "No such file or directory");
            rc = 1;
        }
        else if (r == 0)
        {
            sh_puts("removed ");
            sh_puts(argv[i]);
            sh_putc('\n');
        }
    }
    return rc;
}

/*
 * cmd_cp (BusyBox 1_36_stable coreutils/cp.c compat).
 *
 * Mimics cp.c operand handling: `-r`/`-R` copy directories recursively,
 * `-f` overwrites and overrides `-i`, `-i` declines overwrites without a
 * tty (spec Sec 7); a directory source without `-r` is omitted with the
 * upstream `-r not specified` notice; multiple sources require the last
 * operand to be a directory; a directory destination takes the source
 * basename. Each source continues on error with an accumulated exit code
 * (G.exit_code pattern in cp.c).
 *
 * Deliberate deviations: no -a/-d/-p/-L attribute handling (ramfs has no
 * modes/symlinks); unknown flags rejected (usage error 2).
 */
static inline int sh_cp_one(const char *src_given, const char *src_res, const char *dst_given,
                            const char *dst_res, int opt_f, int opt_i, int opt_r)
{
    int sidx = vfs_find(src_res);
    if (sidx < 0)
    {
        sh_file_error("cp", src_given, "No such file or directory");
        return 1;
    }
    if (vfs_nodes[sidx].is_dir && !opt_r)
    {
        sh_puts("cp: -r not specified; omitting directory '");
        sh_puts(src_given);
        sh_puts("'\n");
        return 1;
    }
    char target[VFS_PATH_MAX];
    vfs_strcpy(target, dst_res, sizeof(target));
    int didx = vfs_find(target);
    if (didx >= 0 && vfs_nodes[didx].is_dir)
    {
        char base[VFS_NAME_MAX];
        sh_base_name(src_res, base, sizeof(base));
        if (target[vfs_strlen(target) - 1] != '/')
            vfs_strcat(target, "/", sizeof(target));
        vfs_strcat(target, base, sizeof(target));
    }
    if (vfs_strcmp(src_res, target) == 0)
    {
        sh_puts("cp: '");
        sh_puts(src_given);
        sh_puts("' and '");
        sh_puts(dst_given);
        sh_puts("' are the same file\n");
        return 1;
    }
    if (vfs_nodes[sidx].is_dir)
    {
        int sl = vfs_strlen(src_res);
        if (vfs_strncmp(target, src_res, sl) == 0 && target[sl] == '/')
        {
            sh_puts("cp: cannot copy a directory, '");
            sh_puts(src_given);
            sh_puts("', into itself, '");
            sh_puts(dst_given);
            sh_puts("'\n");
            return 1;
        }
    }
    didx = vfs_find(target);
    if (didx >= 0 && !vfs_nodes[didx].is_dir && opt_i && !opt_f)
        return 0; /* -i declines the overwrite without a tty (spec Sec 7) */
    if (sh_cp_tree(src_res, target) != 0)
    {
        sh_puts("cp: cannot create '");
        sh_puts(dst_given);
        sh_puts("'\n");
        return 1;
    }
    return 0;
}

static inline int cmd_cp(int argc, char **argv)
{
    int opt_f = 0, opt_i = 0, opt_r = 0;
    int start = 1;
    int opts_done = 0;
    while (start < argc && !opts_done && argv[start][0] == '-' && argv[start][1] != '\0')
    {
        if (vfs_strcmp(argv[start], "--") == 0)
        {
            opts_done = 1;
            start++;
            break;
        }
        for (int k = 1; argv[start][k]; k++)
        {
            char o = argv[start][k];
            if (o == 'f')
                opt_f = 1;
            else if (o == 'i')
                opt_i = 1;
            else if (o == 'r' || o == 'R')
                opt_r = 1;
            else
                return sh_unknown_opt("cp", o);
        }
        start++;
    }
    int nops = argc - start;
    if (nops < 2)
    {
        sh_puts("usage: cp [-fiRr] SOURCE... DEST\n");
        return 2;
    }
    if (nops > 2)
    {
        char dr[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[argc - 1], dr, sizeof(dr));
        int didx = vfs_find(dr);
        if (didx < 0 || !vfs_nodes[didx].is_dir)
        {
            sh_puts("cp: target '");
            sh_puts(argv[argc - 1]);
            sh_puts("': Not a directory\n");
            return 1;
        }
        int rc = 0;
        for (int i = start; i < argc - 1; i++)
        {
            char sr[VFS_PATH_MAX];
            vfs_resolve_path(sh_cwd, argv[i], sr, sizeof(sr));
            if (sh_cp_one(argv[i], sr, argv[argc - 1], dr, opt_f, opt_i, opt_r) != 0)
                rc = 1;
        }
        return rc;
    }
    char sr[VFS_PATH_MAX], dr[VFS_PATH_MAX];
    vfs_resolve_path(sh_cwd, argv[start], sr, sizeof(sr));
    vfs_resolve_path(sh_cwd, argv[start + 1], dr, sizeof(dr));
    return sh_cp_one(argv[start], sr, argv[start + 1], dr, opt_f, opt_i, opt_r);
}

/*
 * cmd_mv (BusyBox 1_36_stable coreutils/mv.c compat).
 *
 * Mimics mv.c: `-f` overwrites and overrides `-i`, `-i` declines
 * overwrites without a tty (spec Sec 7); multiple sources require the
 * last operand to be a directory; a directory destination takes the
 * source basename. ramfs has no rename syscall, so move = sh_cp_tree
 * copy + source removal (rm.c sh_rm_tree for directories). Each source
 * continues on error with an accumulated exit code (G.exit_code pattern
 * in mv.c). Missing sources fail upfront under the mv prog name.
 *
 * Deliberate deviations: copy+unlink instead of rename() (same VFS, no
 * cross-device move); no -n (no-clobber) flag in Phase 1.
 */
static inline int sh_mv_one(const char *src_given, const char *src_res, const char *dst_given,
                            const char *dst_res, int opt_f, int opt_i)
{
    /* BusyBox mv.c: missing src fails upfront under the mv prog name. */
    int sidx = vfs_find(src_res);
    if (sidx < 0)
    {
        sh_file_error("mv", src_given, "No such file or directory");
        return 1;
    }
    char target[VFS_PATH_MAX];
    vfs_strcpy(target, dst_res, sizeof(target));
    int didx = vfs_find(target);
    if (didx >= 0 && vfs_nodes[didx].is_dir)
    {
        char base[VFS_NAME_MAX];
        sh_base_name(src_res, base, sizeof(base));
        if (target[vfs_strlen(target) - 1] != '/')
            vfs_strcat(target, "/", sizeof(target));
        vfs_strcat(target, base, sizeof(target));
    }
    if (vfs_strcmp(src_res, target) == 0)
    {
        sh_puts("mv: '");
        sh_puts(src_given);
        sh_puts("' and '");
        sh_puts(dst_given);
        sh_puts("' are the same file\n");
        return 1;
    }
    if (vfs_nodes[sidx].is_dir)
    {
        int sl = vfs_strlen(src_res);
        if (vfs_strncmp(target, src_res, sl) == 0 && target[sl] == '/')
        {
            sh_puts("mv: cannot move a directory, '");
            sh_puts(src_given);
            sh_puts("', into itself, '");
            sh_puts(dst_given);
            sh_puts("'\n");
            return 1;
        }
    }
    didx = vfs_find(target);
    if (didx >= 0 && !vfs_nodes[didx].is_dir && opt_i && !opt_f)
        return 0; /* -i declines the overwrite without a tty (spec Sec 7) */
    if (sh_cp_tree(src_res, target) != 0)
    {
        sh_puts("mv: cannot create '");
        sh_puts(dst_given);
        sh_puts("'\n");
        return 1;
    }
    int r = vfs_nodes[sidx].is_dir ? sh_rm_tree(src_res) : vfs_unlink_node(src_res);
    if (r != 0)
    {
        sh_file_error("mv", src_given, "Cannot remove source file");
        return 1;
    }
    return 0;
}

static inline int cmd_mv(int argc, char **argv)
{
    int opt_f = 0, opt_i = 0;
    int start = 1;
    int opts_done = 0;
    while (start < argc && !opts_done && argv[start][0] == '-' && argv[start][1] != '\0')
    {
        if (vfs_strcmp(argv[start], "--") == 0)
        {
            opts_done = 1;
            start++;
            break;
        }
        for (int k = 1; argv[start][k]; k++)
        {
            char o = argv[start][k];
            if (o == 'f')
                opt_f = 1;
            else if (o == 'i')
                opt_i = 1;
            else
                return sh_unknown_opt("mv", o);
        }
        start++;
    }
    int nops = argc - start;
    if (nops < 2)
    {
        sh_puts("usage: mv [-fi] SOURCE... DEST\n");
        return 2;
    }
    if (nops > 2)
    {
        char dr[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[argc - 1], dr, sizeof(dr));
        int didx = vfs_find(dr);
        if (didx < 0 || !vfs_nodes[didx].is_dir)
        {
            sh_puts("mv: target '");
            sh_puts(argv[argc - 1]);
            sh_puts("': Not a directory\n");
            return 1;
        }
        int rc = 0;
        for (int i = start; i < argc - 1; i++)
        {
            char sr[VFS_PATH_MAX];
            vfs_resolve_path(sh_cwd, argv[i], sr, sizeof(sr));
            if (sh_mv_one(argv[i], sr, argv[argc - 1], dr, opt_f, opt_i) != 0)
                rc = 1;
        }
        return rc;
    }
    char sr[VFS_PATH_MAX], dr[VFS_PATH_MAX];
    vfs_resolve_path(sh_cwd, argv[start], sr, sizeof(sr));
    vfs_resolve_path(sh_cwd, argv[start + 1], dr, sizeof(dr));
    return sh_mv_one(argv[start], sr, argv[start + 1], dr, opt_f, opt_i);
}

/*
 * cmd_mkdir (BusyBox 1_36_stable coreutils/mkdir.c compat).
 *
 * Mimics mkdir.c --parents: `-p` creates every missing ancestor in order
 * (sh_mkdir_p) and treats pre-existing directories as success; without
 * `-p` a single vfs_create_node is attempted so a missing parent fails.
 * Multi-operand loop continues on error with an accumulated exit code.
 */
static inline int cmd_mkdir(int argc, char **argv)
{
    int start = 1;
    int p_opt = 0;
    int opts_done = 0;
    while (start < argc && !opts_done && argv[start][0] == '-' && argv[start][1] != '\0')
    {
        if (vfs_strcmp(argv[start], "--") == 0)
        {
            opts_done = 1;
            start++;
            break;
        }
        for (int k = 1; argv[start][k]; k++)
        {
            if (argv[start][k] == 'p')
                p_opt = 1;
            else
                return sh_unknown_opt("mkdir", argv[start][k]);
        }
        start++;
    }
    if (start >= argc)
    {
        sh_puts("usage: mkdir [-p] <dir...>\n");
        return 2;
    }
    int rc = 0;
    for (int i = start; i < argc; i++)
    {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[i], resolved, sizeof(resolved));
        if (p_opt)
        {
            if (sh_mkdir_p(resolved) == 0)
                continue;
            int e = vfs_find(resolved);
            sh_file_error("mkdir", argv[i], e >= 0 ? "File exists" : "No such file or directory");
            rc = 1;
            continue;
        }
        int r = vfs_create_node(resolved, 1);
        if (r >= 0)
            continue;
        sh_file_error("mkdir", argv[i], r == -1 ? "File exists" : "No such file or directory");
        rc = 1;
    }
    return rc;
}

/*
 * cmd_rmdir (BusyBox 1_36_stable coreutils/rmdir.c compat).
 *
 * `-p` removes the directory then each ancestor while empty, stopping
 * silently at the first failure (best-effort on ramfs: ancestors shared
 * with other entries stay put). Multi-operand loop continues on error
 * with an accumulated exit code.
 */
static inline int cmd_rmdir(int argc, char **argv)
{
    int p_opt = 0;
    int start = 1;
    int opts_done = 0;
    while (start < argc && !opts_done && argv[start][0] == '-' && argv[start][1] != '\0')
    {
        if (vfs_strcmp(argv[start], "--") == 0)
        {
            opts_done = 1;
            start++;
            break;
        }
        for (int k = 1; argv[start][k]; k++)
        {
            if (argv[start][k] == 'p')
                p_opt = 1;
            else
                return sh_unknown_opt("rmdir", argv[start][k]);
        }
        start++;
    }
    if (start >= argc)
    {
        sh_puts("usage: rmdir [-p] DIR...\n");
        return 2;
    }
    int rc = 0;
    for (int i = start; i < argc; i++)
    {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[i], resolved, sizeof(resolved));
        int idx = vfs_find(resolved);
        if (idx < 0 || !vfs_nodes[idx].is_dir)
        {
            sh_puts("rmdir: '");
            sh_puts(argv[i]);
            sh_puts("': Not a directory\n");
            rc = 1;
            continue;
        }
        int r = vfs_unlink_node(resolved);
        if (r != 0)
        {
            sh_puts("rmdir: failed to remove '");
            sh_puts(argv[i]);
            sh_puts("': Directory not empty\n");
            rc = 1;
            continue;
        }
        if (p_opt)
        {
            /* Best-effort ancestors: stop silently at the first failure. */
            char tmp[VFS_PATH_MAX];
            vfs_strcpy(tmp, resolved, sizeof(tmp));
            for (;;)
            {
                int last = -1;
                for (int q = 0; tmp[q]; q++)
                {
                    if (tmp[q] == '/')
                        last = q;
                }
                if (last <= 0)
                    break; /* never attempt "/" (root has no parent) */
                tmp[last] = '\0';
                if (vfs_unlink_node(tmp) != 0)
                    break;
            }
        }
    }
    return rc;
}

/*
 * Task 5: head/tail/wc compat (BusyBox 1_36_stable coreutils/head.c,
 * coreutils/tail.c, coreutils/wc.c).
 *
 * Mimics the upstream option handling: `-n N` (lines) vs `-c N`
 * (bytes), last-wins when both are given; obsolete `-N` (first/last N
 * lines); `tail -n +N` / `tail -c +N` / bare `tail +N` count from line
 * / byte N (`from` mode); `-q` never prints multi-file headers, `-v`
 * always prints them (default: headers only when >1 operand, in the
 * `==> FILE <==` form with a blank line between files). `wc`
 * supports `-l/-w/-c/-m/-L` (default `-lwc`, never `-L`), one row per
 * file plus a `total` row for multi-file input. Stdin default follows
 * open_or_warn_stdin: no operands (or `--` alone) reads pipe stdin,
 * as does a lone `-` operand (explicit `-` prints under the `-` /
 * `standard input` name for wc / head-tail headers). Multi-file loops
 * continue on error with an accumulated exit code (G.exit_code
 * pattern) via sh_file_error; unknown options go through
 * sh_unknown_opt (return 2); unparseable counts print
 * `prog: invalid number 'X'` and return 1.
 *
 * Deliberate deviations: whole-file VFS_FILE_MAX buffering instead of
 * lseek/bb_cat streaming (ramfs bound); `wc` columns are unpadded
 * single-space (existing exact test locks `"3\n"`, not BusyBox/GNU
 * `%7lu` padding); `-m` (chars) equals `-c` (bytes) on ramfs;
 * `tail -f/-F` follow mode is rejected as an unknown option (no
 * blocking reads on ramfs); pipe-stdin length reuses the exact
 * engine count via sh_cat_stdin_len().
 */

/*
 * Strict count parser (xatoul-style): optional leading '+'/'-',
 * then digits only. Sets *is_plus for the tail `+N` from-form.
 * Returns 0 on success, -1 on empty/non-numeric text. Values clamp
 * at 2^30-1 (ramfs bound). shell_eval_expr() is NOT used here:
 * "2+2" must be an invalid number, not 4.
 */
static inline int sh_parse_count(const char *s, long *val, int *is_plus)
{
    int i = 0;
    int neg = 0;
    *is_plus = 0;
    if (!s || !s[0])
        return -1;
    if (s[0] == '+')
    {
        *is_plus = 1;
        i = 1;
    }
    else if (s[0] == '-')
    {
        neg = 1;
        i = 1;
    }
    if (s[i] == '\0')
        return -1;
    long v = 0;
    for (; s[i]; i++)
    {
        if (s[i] < '0' || s[i] > '9')
            return -1;
        v = v * 10 + (s[i] - '0');
        if (v > 0x3fffffffL)
            v = 0x3fffffffL;
    }
    *val = neg ? -v : v;
    return 0;
}

/* Multi-file header (head.c/tail.c "==> FILE <==" form). */
static inline void sh_headtail_header(const char *name, int *first)
{
    if (!(*first))
        sh_putc('\n');
    sh_puts("==> ");
    sh_puts(name);
    sh_puts(" <==\n");
    *first = 0;
}

/*
 * Shared head/tail option parser (getopt32-style over combined
 * shorts). Handles `-n/-c` with separate (`-n 5`) or attached
 * (`-n5`, `-c+3`) values, obsolete `-N`, `-q/-v`, `--`, and (tail
 * only, allow_plus) bare `+N`. On success returns 0 with *start_io
 * at the first operand; on failure the message is already printed
 * and the return value (1 invalid number, 2 usage) is the exit code.
 */
static inline int sh_headtail_opts(const char *prog, int argc, char **argv, int *start_io,
                                   int *mode_io, long *count_io, int *from_io, int *q_io, int *v_io,
                                   int allow_plus)
{
    int start = *start_io;
    while (start < argc)
    {
        const char *a = argv[start];
        if (allow_plus && a[0] == '+' && a[1] != '\0')
        {
            long num;
            int plus;
            if (sh_parse_count(a + 1, &num, &plus) != 0)
                break; /* not a number: treat as a filename operand */
            *mode_io = 'n';
            *count_io = num;
            *from_io = 1;
            start++;
            continue;
        }
        if (a[0] != '-' || a[1] == '\0' || vfs_strcmp(a, "-") == 0)
            break;
        if (vfs_strcmp(a, "--") == 0)
        {
            start++;
            break;
        }
        /* Obsolete "-N": first/last N lines. */
        if (a[1] >= '0' && a[1] <= '9')
        {
            long num;
            int plus;
            if (sh_parse_count(a + 1, &num, &plus) != 0)
            {
                sh_puts(prog);
                sh_puts(": invalid number '");
                sh_puts(a + 1);
                sh_puts("'\n");
                return 1;
            }
            *mode_io = 'n';
            *count_io = num;
            *from_io = 0;
            start++;
            continue;
        }
        for (int k = 1; a[k]; k++)
        {
            char opt = a[k];
            if (opt == 'n' || opt == 'c')
            {
                const char *numstr;
                if (a[k + 1] != '\0')
                    numstr = a + k + 1; /* attached value: -n5, -c+3 */
                else
                {
                    if (start + 1 >= argc)
                    {
                        sh_puts(prog);
                        sh_puts(": option requires an argument -- '");
                        sh_putc(opt);
                        sh_puts("'\nusage: ");
                        sh_puts(prog);
                        sh_puts(" [-n N] [-c N] [-qv] [FILE]...\n");
                        return 2;
                    }
                    numstr = argv[++start];
                }
                long num;
                int plus;
                if (sh_parse_count(numstr, &num, &plus) != 0)
                {
                    sh_puts(prog);
                    sh_puts(": invalid number '");
                    sh_puts(numstr);
                    sh_puts("'\n");
                    return 1;
                }
                *mode_io = opt; /* last of -n/-c wins (head.c/tail.c) */
                *count_io = num;
                if (allow_plus)
                    *from_io = plus ? 1 : 0;
                break; /* value consumed the rest of this arg */
            }
            else if (opt == 'q')
            {
                *q_io = 1;
            }
            else if (opt == 'v')
            {
                *v_io = 1;
            }
            else
            {
                return sh_unknown_opt(prog, opt);
            }
        }
        start++;
    }
    *start_io = start;
    return 0;
}

/* head.c emit: first N lines ('n') or first N bytes ('c'). */
static inline void sh_head_emit(const char *data, int len, int mode, long count)
{
    if (mode == 'c')
    {
        long n = count;
        if (n < 0) /* head -c -N: all but last N bytes (GNU compat) */
            n = (long)len + n;
        if (n < 0)
            n = 0;
        for (long i = 0; i < n && i < len; i++)
            sh_putc(data[i]);
        return;
    }
    if (count >= 0)
    {
        long lines = 0;
        for (int i = 0; i < len && lines < count; i++)
        {
            sh_putc(data[i]);
            if (data[i] == '\n')
                lines++;
        }
        return;
    }
    /* head -n -N: all but last N lines (GNU/BusyBox compat). */
    long omit = -count;
    long total = 0;
    for (int i = 0; i < len; i++)
    {
        if (data[i] == '\n')
            total++;
    }
    if (len > 0 && data[len - 1] != '\n')
        total++; /* unterminated trailing input is a logical line */
    long keep = total - omit;
    long lines = 0;
    if (keep < 0)
        keep = 0;
    for (int i = 0; i < len && lines < keep; i++)
    {
        sh_putc(data[i]);
        if (data[i] == '\n')
            lines++;
    }
}

static inline int cmd_head(int argc, char **argv)
{
    int mode = 'n';
    long count = 10; /* default: first 10 lines (head.c) */
    int from = 0;    /* unused by head; shared parser slot */
    int opt_q = 0, opt_v = 0;
    int start = 1;
    int pr = sh_headtail_opts("head", argc, argv, &start, &mode, &count, &from, &opt_q, &opt_v, 0);
    if (pr != 0)
        return pr;

    int nfiles = argc - start;
    int show = opt_v || (!opt_q && nfiles > 1);
    int rc = 0;
    int first = 1;

    if (nfiles <= 0)
    {
        /* Stdin default (open_or_warn_stdin pattern). */
        if (sh_stdin_data)
            sh_head_emit(sh_stdin_data, sh_cat_stdin_len(), mode, count);
        return 0;
    }
    for (int i = start; i < argc; i++)
    {
        const char *data;
        int len;
        const char *dname;
        char file_buf[VFS_FILE_MAX];
        if (vfs_strcmp(argv[i], "-") == 0)
        {
            if (!sh_stdin_data)
                continue; /* bare "-" with no pipe: nothing (cat pattern) */
            data = sh_stdin_data;
            len = sh_cat_stdin_len();
            dname = "standard input";
        }
        else
        {
            char resolved[VFS_PATH_MAX];
            vfs_resolve_path(sh_cwd, argv[i], resolved, sizeof(resolved));
            int idx = vfs_find(resolved);
            if (idx < 0)
            {
                sh_file_error("head", argv[i], "No such file or directory");
                rc = 1;
                continue;
            }
            if (vfs_nodes[idx].is_dir)
            {
                sh_file_error("head", argv[i], "Is a directory");
                rc = 1;
                continue;
            }
            len = vfs_read_file(idx, file_buf, sizeof(file_buf));
            if (len < 0)
            {
                sh_file_error("head", argv[i], "No such file or directory");
                rc = 1;
                continue;
            }
            data = file_buf;
            dname = argv[i];
        }
        if (show)
            sh_headtail_header(dname, &first);
        sh_head_emit(data, len, mode, count);
    }
    return rc;
}

/* tail.c emit: last N lines/bytes, or from line/byte N when from != 0. */
static inline void sh_tail_emit(const char *data, int len, int mode, long count, int from)
{
    if (len <= 0)
        return;
    if (mode == 'c')
    {
        if (from)
        {
            long off = count - 1; /* +N is 1-based; +0/+1 print all */
            if (off < 0)
                off = 0;
            for (long i = off; i < len; i++)
                sh_putc(data[i]);
        }
        else
        {
            long n = count < 0 ? -count : count; /* -c -N == -c N */
            for (long i = (long)len - n; i < len; i++)
            {
                if (i >= 0)
                    sh_putc(data[i]);
            }
        }
        return;
    }
    if (from)
    {
        long skip = count - 1; /* print from 1-based line `count` */
        long ln = 1;
        if (skip < 0)
            skip = 0;
        for (int i = 0; i < len; i++)
        {
            if (ln > skip)
                sh_putc(data[i]);
            if (data[i] == '\n')
                ln++;
        }
        return;
    }
    long n = count < 0 ? -count : count; /* -n -N == -n N */
    if (n <= 0)
        return;
    long total = 0;
    for (int i = 0; i < len; i++)
    {
        if (data[i] == '\n')
            total++;
    }
    if (data[len - 1] != '\n')
        total++; /* unterminated trailing input is a logical line */
    long skip = total - n;
    long ln = 0;
    if (skip < 0)
        skip = 0;
    for (int i = 0; i < len; i++)
    {
        if (ln >= skip)
            sh_putc(data[i]);
        if (data[i] == '\n')
            ln++;
    }
}

static inline int cmd_tail(int argc, char **argv)
{
    int mode = 'n';
    long count = 10; /* default: last 10 lines (tail.c) */
    int from = 0;    /* tail -n +N / -c +N / bare +N from-form */
    int opt_q = 0, opt_v = 0;
    int start = 1;
    int pr = sh_headtail_opts("tail", argc, argv, &start, &mode, &count, &from, &opt_q, &opt_v, 1);
    if (pr != 0)
        return pr;

    int nfiles = argc - start;
    int show = opt_v || (!opt_q && nfiles > 1);
    int rc = 0;
    int first = 1;

    if (nfiles <= 0)
    {
        /* Stdin default (open_or_warn_stdin pattern). */
        if (sh_stdin_data)
            sh_tail_emit(sh_stdin_data, sh_cat_stdin_len(), mode, count, from);
        return 0;
    }
    for (int i = start; i < argc; i++)
    {
        const char *data;
        int len;
        const char *dname;
        char file_buf[VFS_FILE_MAX];
        if (vfs_strcmp(argv[i], "-") == 0)
        {
            if (!sh_stdin_data)
                continue; /* bare "-" with no pipe: nothing (cat pattern) */
            data = sh_stdin_data;
            len = sh_cat_stdin_len();
            dname = "standard input";
        }
        else
        {
            char resolved[VFS_PATH_MAX];
            vfs_resolve_path(sh_cwd, argv[i], resolved, sizeof(resolved));
            int idx = vfs_find(resolved);
            if (idx < 0)
            {
                sh_file_error("tail", argv[i], "No such file or directory");
                rc = 1;
                continue;
            }
            if (vfs_nodes[idx].is_dir)
            {
                sh_file_error("tail", argv[i], "Is a directory");
                rc = 1;
                continue;
            }
            len = vfs_read_file(idx, file_buf, sizeof(file_buf));
            if (len < 0)
            {
                sh_file_error("tail", argv[i], "No such file or directory");
                rc = 1;
                continue;
            }
            data = file_buf;
            dname = argv[i];
        }
        if (show)
            sh_headtail_header(dname, &first);
        sh_tail_emit(data, len, mode, count, from);
    }
    return rc;
}

/* wc.c counter: newlines, words (isspace-split), longest line. */
static inline void sh_wc_count(const char *data, int len, unsigned long *lines,
                               unsigned long *words, unsigned long *maxline)
{
    unsigned long li = 0, wo = 0, ml = 0, cur = 0;
    int in_word = 0;
    for (int i = 0; i < len; i++)
    {
        char c = data[i];
        if (c == '\n')
        {
            li++;
            if (cur > ml)
                ml = cur;
            cur = 0;
        }
        else
        {
            cur++;
        }
        if (c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r')
            in_word = 0;
        else if (!in_word)
        {
            wo++;
            in_word = 1;
        }
    }
    if (cur > ml)
        ml = cur; /* unterminated trailing line still counts for -L */
    *lines = li;
    *words = wo;
    *maxline = ml;
}

/* wc.c row: selected columns in l/w/c/m/L order, then name (if any). */
static inline void sh_wc_print(unsigned long lines, unsigned long words, unsigned long bytes,
                               unsigned long maxline, int opt_l, int opt_w, int opt_c, int opt_m,
                               int opt_L, const char *name)
{
    int p = 0;
    if (opt_l)
    {
        sh_print_ulong(lines);
        p = 1;
    }
    if (opt_w)
    {
        if (p)
            sh_putc(' ');
        sh_print_ulong(words);
        p = 1;
    }
    if (opt_c)
    {
        if (p)
            sh_putc(' ');
        sh_print_ulong(bytes);
        p = 1;
    }
    if (opt_m)
    {
        if (p)
            sh_putc(' ');
        sh_print_ulong(bytes); /* ramfs is byte-oriented: chars == bytes */
        p = 1;
    }
    if (opt_L)
    {
        if (p)
            sh_putc(' ');
        sh_print_ulong(maxline);
        p = 1;
    }
    if (name)
    {
        if (p)
            sh_putc(' ');
        sh_puts(name);
    }
    sh_putc('\n');
}

static inline int cmd_wc(int argc, char **argv)
{
    int opt_l = 0, opt_w = 0, opt_c = 0, opt_m = 0, opt_L = 0;
    int start = 1;
    while (start < argc)
    {
        const char *a = argv[start];
        if (a[0] != '-' || a[1] == '\0' || vfs_strcmp(a, "-") == 0)
            break;
        if (vfs_strcmp(a, "--") == 0)
        {
            start++;
            break;
        }
        for (int k = 1; a[k]; k++)
        {
            switch (a[k])
            {
            case 'l':
                opt_l = 1;
                break;
            case 'w':
                opt_w = 1;
                break;
            case 'c':
                opt_c = 1;
                break;
            case 'm':
                opt_m = 1;
                break;
            case 'L':
                opt_L = 1;
                break;
            default:
                return sh_unknown_opt("wc", a[k]);
            }
        }
        start++;
    }
    if (!opt_l && !opt_w && !opt_c && !opt_m && !opt_L)
        opt_l = opt_w = opt_c = 1; /* wc.c default: -lwc (never -L) */

    unsigned long t_lines = 0, t_words = 0, t_bytes = 0, t_max = 0;
    int nsuccess = 0;
    int rc = 0;

    if (start >= argc)
    {
        /* Stdin default (open_or_warn_stdin pattern). */
        const char *data = sh_stdin_data ? sh_stdin_data : "";
        int len = sh_stdin_data ? sh_cat_stdin_len() : 0;
        unsigned long li, wo, ml;
        sh_wc_count(data, len, &li, &wo, &ml);
        sh_wc_print(li, wo, (unsigned long)len, ml, opt_l, opt_w, opt_c, opt_m, opt_L, NULL);
        return 0;
    }
    for (int i = start; i < argc; i++)
    {
        const char *data;
        int len;
        const char *dname;
        char file_buf[VFS_FILE_MAX];
        if (vfs_strcmp(argv[i], "-") == 0)
        {
            data = sh_stdin_data ? sh_stdin_data : "";
            len = sh_stdin_data ? sh_cat_stdin_len() : 0;
            dname = "-";
        }
        else
        {
            char resolved[VFS_PATH_MAX];
            vfs_resolve_path(sh_cwd, argv[i], resolved, sizeof(resolved));
            int idx = vfs_find(resolved);
            if (idx < 0)
            {
                sh_file_error("wc", argv[i], "No such file or directory");
                rc = 1;
                continue;
            }
            if (vfs_nodes[idx].is_dir)
            {
                sh_file_error("wc", argv[i], "Is a directory");
                rc = 1;
                continue;
            }
            len = vfs_read_file(idx, file_buf, sizeof(file_buf));
            if (len < 0)
            {
                sh_file_error("wc", argv[i], "No such file or directory");
                rc = 1;
                continue;
            }
            data = file_buf;
            dname = argv[i];
        }
        unsigned long li, wo, ml;
        sh_wc_count(data, len, &li, &wo, &ml);
        sh_wc_print(li, wo, (unsigned long)len, ml, opt_l, opt_w, opt_c, opt_m, opt_L, dname);
        t_lines += li;
        t_words += wo;
        t_bytes += (unsigned long)len;
        if (ml > t_max)
            t_max = ml;
        nsuccess++;
    }
    if (nsuccess > 1) /* wc.c: total row for multi-file input */
        sh_wc_print(t_lines, t_words, t_bytes, t_max, opt_l, opt_w, opt_c, opt_m, opt_L, "total");
    return rc;
}

/*
 * cmd_stat (BusyBox 1_36_stable coreutils/stat.c compat, minimal).
 *
 * Mimics stat.c `-c FORMAT` with the Phase 1 sequences `%n` (given name),
 * `%s` (size bytes), `%F` (file type: "directory"/"regular file"), `%%`,
 * plus `\n`/`\t`/`\\` escapes. Like upstream, no trailing newline is
 * added unless the format contains one. Without `-c` the legacy
 * human-readable block is kept. Multi-operand loop continues on error
 * with an accumulated exit code.
 *
 * Deliberate deviations: no %a/%u/%g/%y (ramfs has no modes/owners and
 * mtime is ticks); no -f/-t filesystem mode.
 */
static inline void sh_stat_print_fmt(const char *fmt, const char *name, unsigned long size,
                                     int is_dir)
{
    for (; *fmt; fmt++)
    {
        if (*fmt == '%')
        {
            fmt++;
            char c = *fmt;
            if (c == '\0')
                break;
            if (c == 'n')
                sh_puts(name);
            else if (c == 's')
                sh_print_ulong(size);
            else if (c == 'F')
                sh_puts(is_dir ? "directory" : "regular file");
            else if (c == '%')
                sh_putc('%');
            else
            {
                sh_putc('%');
                sh_putc(c);
            }
        }
        else if (*fmt == '\\')
        {
            fmt++;
            char c = *fmt;
            if (c == '\0')
                break;
            if (c == 'n')
                sh_putc('\n');
            else if (c == 't')
                sh_putc('\t');
            else if (c == '\\')
                sh_putc('\\');
            else
            {
                sh_putc('\\');
                sh_putc(c);
            }
        }
        else
        {
            sh_putc(*fmt);
        }
    }
}

static inline int cmd_stat(int argc, char **argv)
{
    const char *fmt = NULL;
    int start = 1;
    int opts_done = 0;
    while (start < argc && !opts_done && argv[start][0] == '-' && argv[start][1] != '\0')
    {
        if (vfs_strcmp(argv[start], "--") == 0)
        {
            opts_done = 1;
            start++;
            break;
        }
        if (argv[start][1] == 'c')
        {
            /* -c FORMAT attached (-c%n) or separate (-c %n). */
            if (argv[start][2] != '\0')
                fmt = argv[start] + 2;
            else
            {
                if (start + 1 >= argc)
                {
                    sh_puts("stat: option requires an argument -- 'c'\n");
                    sh_puts("usage: stat [-c FORMAT] FILE...\n");
                    return 2;
                }
                fmt = argv[++start];
            }
            start++;
            continue;
        }
        return sh_unknown_opt("stat", argv[start][1]);
    }
    if (start >= argc)
    {
        sh_puts("usage: stat [-c FORMAT] FILE...\n");
        return 2;
    }
    int rc = 0;
    for (int i = start; i < argc; i++)
    {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[i], resolved, sizeof(resolved));
        int idx = vfs_find(resolved);
        if (idx < 0)
        {
            sh_puts("stat: cannot stat '");
            sh_puts(argv[i]);
            sh_puts("': No such file or directory\n");
            rc = 1;
            continue;
        }
        vfs_node_t *n = &vfs_nodes[idx];
        if (fmt)
        {
            sh_stat_print_fmt(fmt, argv[i], (unsigned long)n->size, n->is_dir);
            continue;
        }
        sh_puts("  File: ");
        sh_puts(argv[i]);
        sh_putc('\n');
        sh_puts("  Size: ");
        sh_print_ulong(n->size);
        sh_puts(" bytes    Type: ");
        sh_puts(n->is_dir ? "Directory\n" : "Regular File\n");
        sh_puts(" Inode: ");
        sh_print_ulong((unsigned long)idx);
        sh_puts("    Access: ");
        sh_puts(n->is_dir ? "(0755/drwxr-xr-x)\n" : "(0644/-rw-r--r--)\n");
        sh_puts(" Modify: ");
        sh_print_ulong((unsigned long)n->mtime);
        sh_puts(" ticks\n");
    }
    return rc;
}

/*
 * cmd_find (BusyBox 1_36_stable findutils/find.c compat, minimal).
 *
 * Mimics the upstream primaries `-name PAT` (fnmatch(3)-style `*`/`?`),
 * `-type f|d`, `-maxdepth N`, and `-print` (default action, accepted
 * no-op). Operands before the expression are starting points (default
 * "."); only nodes under a starting point print, at a depth relative
 * to it (root = depth 0, so -maxdepth 0 prints just the roots).
 * Bad roots and bad primaries continue/fail with an accumulated exit
 * code instead of aborting the whole walk.
 *
 * Deliberate deviations: absolute-path display (BusyBox echoes the
 * root-joined spelling); no -mindepth/-exec/-perm/-size (rejected as
 * unrecognized); no symlink handling (ramfs has none).
 */
static inline int sh_fnmatch(const char *pat, const char *str)
{
    const char *s_star = NULL;
    const char *p_star = NULL;
    while (*str)
    {
        if (*pat == '*')
        {
            p_star = ++pat;
            s_star = str;
        }
        else if (*pat == '?' || *pat == *str)
        {
            pat++;
            str++;
        }
        else if (p_star)
        {
            pat = p_star;
            str = ++s_star;
        }
        else
        {
            return 0;
        }
    }
    while (*pat == '*')
        pat++;
    return *pat == '\0';
}

static inline int cmd_find(int argc, char **argv)
{
    const char *roots[8];
    int nroots = 0;
    const char *name_filter = NULL;
    int type_filter = -1; /* 0=file, 1=dir */
    int maxdepth = -1;    /* -1: unlimited */
    int expr_start = 1;

    if (expr_start < argc && argv[expr_start][0] != '-')
    {
        roots[nroots++] = argv[expr_start++];
    }
    if (nroots == 0)
        roots[nroots++] = ".";
    for (int i = expr_start; i < argc; i++)
    {
        if (vfs_strcmp(argv[i], "-name") == 0)
        {
            if (i + 1 >= argc)
            {
                sh_puts("find: -name requires an argument\n");
                sh_puts("usage: find [PATH] [-name PAT] [-type f|d] [-maxdepth N]\n");
                return 2;
            }
            name_filter = argv[++i];
        }
        else if (vfs_strcmp(argv[i], "-type") == 0)
        {
            if (i + 1 >= argc)
            {
                sh_puts("find: -type requires an argument\n");
                sh_puts("usage: find [PATH] [-name PAT] [-type f|d] [-maxdepth N]\n");
                return 2;
            }
            i++;
            if (argv[i][0] == 'f' && argv[i][1] == '\0')
                type_filter = 0;
            else if (argv[i][0] == 'd' && argv[i][1] == '\0')
                type_filter = 1;
            else
            {
                sh_puts("find: unknown type '");
                sh_puts(argv[i]);
                sh_puts("'\n");
                return 1;
            }
        }
        else if (vfs_strcmp(argv[i], "-maxdepth") == 0)
        {
            if (i + 1 >= argc)
            {
                sh_puts("find: -maxdepth requires an argument\n");
                sh_puts("usage: find [PATH] [-name PAT] [-type f|d] [-maxdepth N]\n");
                return 2;
            }
            i++;
            long v = 0;
            if (argv[i][0] == '\0')
            {
                sh_puts("find: invalid number '");
                sh_puts(argv[i]);
                sh_puts("'\n");
                return 1;
            }
            for (int k = 0; argv[i][k]; k++)
            {
                if (argv[i][k] < '0' || argv[i][k] > '9')
                {
                    sh_puts("find: invalid number '");
                    sh_puts(argv[i]);
                    sh_puts("'\n");
                    return 1;
                }
                v = v * 10 + (argv[i][k] - '0');
                if (v > 0x3fffffffL)
                    v = 0x3fffffffL;
            }
            maxdepth = (int)v;
        }
        else if (vfs_strcmp(argv[i], "-print") == 0)
        {
            continue; /* print is the default action */
        }
        else if (argv[i][0] == '-')
        {
            sh_puts("find: unrecognized: ");
            sh_puts(argv[i]);
            sh_putc('\n');
            sh_puts("usage: find [PATH] [-name PAT] [-type f|d] [-maxdepth N]\n");
            return 2;
        }
        else if (nroots < 8)
        {
            roots[nroots++] = argv[i]; /* extra starting points */
        }
    }

    int ridx[8];
    int nridx = 0;
    int rc = 0;
    for (int r = 0; r < nroots; r++)
    {
        char rr[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, roots[r], rr, sizeof(rr));
        int f = vfs_find(rr);
        if (f < 0)
        {
            sh_file_error("find", roots[r], "No such file or directory");
            rc = 1;
            continue;
        }
        ridx[nridx++] = f;
    }
    if (nridx == 0)
        return rc;

    for (int i = 0; i < VFS_MAX_NODES; i++)
    {
        if (!vfs_nodes[i].in_use)
            continue;
        /* Containment + relative depth against any starting point. */
        int inside = 0;
        for (int r = 0; r < nridx && !inside; r++)
        {
            int d = 0, cur = i;
            while (cur != ridx[r])
            {
                if (cur == 0)
                    break;
                cur = vfs_nodes[cur].parent_idx;
                d++;
            }
            if (cur == ridx[r] && (maxdepth < 0 || d <= maxdepth))
                inside = 1;
        }
        if (!inside)
            continue;
        if (type_filter >= 0 && vfs_nodes[i].is_dir != (uint8_t)type_filter)
            continue;
        if (name_filter && !sh_fnmatch(name_filter, vfs_nodes[i].name))
            continue;

        /* Print matching path */
        if (i == 0)
            sh_puts("/\n");
        else
        {
            /* Construct path upwards */
            char pbuf[VFS_PATH_MAX];
            pbuf[0] = '\0';
            int cur = i;
            while (cur > 0)
            {
                char temp[VFS_PATH_MAX];
                vfs_strcpy(temp, "/", sizeof(temp));
                vfs_strcat(temp, vfs_nodes[cur].name, sizeof(temp));
                vfs_strcat(temp, pbuf, sizeof(temp));
                vfs_strcpy(pbuf, temp, sizeof(pbuf));
                cur = vfs_nodes[cur].parent_idx;
            }
            sh_puts(pbuf);
            sh_putc('\n');
        }
    }
    return rc;
}

/*
 * cmd_tee (BusyBox 1_36_stable coreutils/tee.c compat).
 *
 * Mimics tee.c: `-a` appends instead of truncating, `-i` is accepted as
 * a no-op (no signals on ramfs), stdin is echoed to stdout and copied
 * to every FILE operand. Pipe-stdin length uses the exact engine
 * count via sh_cat_stdin_len() (guarded-restore fix, no fallback).
 * Per-file failures continue with an accumulated
 * exit code; with no operands stdin is echoed and nothing is stored.
 */
static inline int cmd_tee(int argc, char **argv)
{
    int append = 0;
    int start = 1;
    int opts_done = 0;
    while (start < argc && !opts_done && argv[start][0] == '-' && argv[start][1] != '\0')
    {
        if (vfs_strcmp(argv[start], "--") == 0)
        {
            opts_done = 1;
            start++;
            break;
        }
        for (int k = 1; argv[start][k]; k++)
        {
            if (argv[start][k] == 'a')
                append = 1;
            else if (argv[start][k] == 'i')
                continue; /* accepted no-op: no signals on ramfs */
            else
                return sh_unknown_opt("tee", argv[start][k]);
        }
        start++;
    }

    const char *data = sh_stdin_data;
    int len = sh_stdin_data ? sh_cat_stdin_len() : 0;

    int fds[SHELL_ARGS_MAX];
    int nfiles = 0;
    int rc = 0;
    for (int i = start; i < argc && nfiles < SHELL_ARGS_MAX; i++)
    {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[i], resolved, sizeof(resolved));

        int idx = vfs_find(resolved);
        if (idx < 0)
            idx = vfs_create_node(resolved, 0);
        if (idx < 0)
        {
            sh_file_error("tee", argv[i], "No such file or directory");
            rc = 1;
            continue;
        }
        if (vfs_nodes[idx].is_dir)
        {
            sh_file_error("tee", argv[i], "Is a directory");
            rc = 1;
            continue;
        }
        if (!append)
        {
            vfs_nodes[idx].size = 0;
            vfs_nodes[idx].data[0] = '\0';
        }
        fds[nfiles++] = idx;
    }

    if (data && len > 0)
    {
        for (int k = 0; k < len; k++)
            sh_putc(data[k]);
        for (int f = 0; f < nfiles; f++)
            vfs_write_file(fds[f], data, len, append);
    }
    return rc;
}

#endif /* SHELL_FILE_H */
