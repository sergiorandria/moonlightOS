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
        sh_puts("usage: ls [-l] [-a] [-h] [FILE]...\n");
    }
    else if (vfs_strcmp(prog, "cat") == 0)
    {
        sh_puts("usage: cat [-n] <file>\n");
    }
    else if (vfs_strcmp(prog, "touch") == 0)
    {
        sh_puts("usage: touch <file...>\n");
    }
    else if (vfs_strcmp(prog, "write") == 0)
    {
        sh_puts("usage: write <file> <text...>\n");
    }
    else if (vfs_strcmp(prog, "rm") == 0)
    {
        sh_puts("usage: rm [-f] [-r] <file>\n");
    }
    else if (vfs_strcmp(prog, "cp") == 0)
    {
        sh_puts("usage: cp <src> <dst>\n");
    }
    else if (vfs_strcmp(prog, "mv") == 0)
    {
        sh_puts("usage: mv <src> <dst>\n");
    }
    else if (vfs_strcmp(prog, "mkdir") == 0)
    {
        sh_puts("usage: mkdir [-p] <dir...>\n");
    }
    else if (vfs_strcmp(prog, "rmdir") == 0)
    {
        sh_puts("usage: rmdir <dir...>\n");
    }
    else if (vfs_strcmp(prog, "head") == 0)
    {
        sh_puts("usage: head [-n N] [FILE]\n");
    }
    else if (vfs_strcmp(prog, "tail") == 0)
    {
        sh_puts("usage: tail [-n N] [FILE]\n");
    }
    else if (vfs_strcmp(prog, "wc") == 0)
    {
        sh_puts("usage: wc [-lwc] [FILE]...\n");
    }
    else if (vfs_strcmp(prog, "stat") == 0)
    {
        sh_puts("usage: stat <file...>\n");
    }
    else if (vfs_strcmp(prog, "find") == 0)
    {
        sh_puts("usage: find [PATH] [-name PAT] [-type f|d]\n");
    }
    else if (vfs_strcmp(prog, "tee") == 0)
    {
        sh_puts("usage: tee [-a] <file>\n");
    }
    else
    {
        sh_puts("usage: ");
        sh_puts(prog);
        sh_puts(" [ARGS]...\n");
    }
    return 2;
}

static inline int cmd_ls(int argc, char **argv)
{
    int opt_l = 0, opt_a = 0, opt_h = 0;
    const char *path = NULL;
    int opts_done = 0;

    for (int i = 1; i < argc; i++)
    {
        if (!opts_done && argv[i][0] == '-' && argv[i][1] != '\0' && vfs_strcmp(argv[i], "--") != 0)
        {
            for (int k = 1; argv[i][k]; k++)
            {
                if (argv[i][k] == 'l')
                    opt_l = 1;
                else if (argv[i][k] == 'a')
                    opt_a = 1;
                else if (argv[i][k] == 'h')
                    opt_h = 1;
                else
                    return sh_unknown_opt("ls", argv[i][k]);
            }
        }
        else if (!opts_done && vfs_strcmp(argv[i], "--") == 0)
        {
            opts_done = 1;
        }
        else
        {
            path = argv[i];
        }
    }

    char resolved[VFS_PATH_MAX];
    vfs_resolve_path(sh_cwd, path ? path : ".", resolved, sizeof(resolved));

    int pidx = vfs_find(resolved);
    if (pidx < 0)
    {
        sh_file_error("ls", path ? path : ".", "No such file or directory");
        return 1;
    }

    if (!vfs_nodes[pidx].is_dir)
    {
        /* Single file */
        if (opt_l)
        {
            sh_puts("-rw-r--r-- 1 root root ");
            if (opt_h)
                sh_print_size(vfs_nodes[pidx].size);
            else
                sh_print_ulong(vfs_nodes[pidx].size);
            sh_putc(' ');
        }
        sh_puts(vfs_nodes[pidx].name);
        sh_putc('\n');
        return 0;
    }

    /* List directory entries */
    int count = 0;
    for (int i = 0; i < VFS_MAX_NODES; i++)
    {
        if (!vfs_nodes[i].in_use)
            continue;
        if (vfs_nodes[i].parent_idx == (uint16_t)pidx && i != pidx)
        {
            if (!opt_a && vfs_nodes[i].name[0] == '.')
                continue;

            if (opt_l)
            {
                sh_puts(vfs_nodes[i].is_dir ? "drwxr-xr-x " : "-rw-r--r-- ");
                sh_puts("1 root root ");
                if (opt_h)
                    sh_print_size(vfs_nodes[i].size);
                else
                    sh_print_ulong(vfs_nodes[i].size);
                sh_puts(" ");
            }
            sh_puts(vfs_nodes[i].name);
            if (vfs_nodes[i].is_dir)
                sh_putc('/');
            sh_putc('\n');
            count++;
        }
    }
    if (count == 0 && opt_l)
    {
        sh_puts("(empty)\n");
    }
    return 0;
}

static inline int cmd_cat(int argc, char **argv)
{
    int opt_n = 0;
    int start = 1;

    /* Leading short options (Task 4 adds -b/-s/-E; reject others now). */
    while (start < argc && argv[start][0] == '-' && argv[start][1] != '\0' &&
           vfs_strcmp(argv[start], "--") != 0 && vfs_strcmp(argv[start], "-") != 0)
    {
        if (vfs_strcmp(argv[start], "-n") == 0)
        {
            opt_n = 1;
            start++;
        }
        else
        {
            return sh_unknown_opt("cat", argv[start][1]);
        }
    }
    if (start < argc && vfs_strcmp(argv[start], "--") == 0)
        start++;

    if (start >= argc)
    {
        /* Check if stdin from pipe has data */
        if (sh_stdin_data && sh_stdin_len > 0)
        {
            sh_puts(sh_stdin_data);
            return 0;
        }
        sh_puts("usage: cat [-n] <file>\n");
        return 2;
    }

    int rc = 0;
    for (int a = start; a < argc; a++)
    {
        /* Lone "-" reads pipe stdin (BusyBox open_or_warn_stdin pattern). */
        if (vfs_strcmp(argv[a], "-") == 0)
        {
            if (sh_stdin_data && sh_stdin_len > 0)
                sh_puts(sh_stdin_data);
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

        if (opt_n)
        {
            int line_num = 1;
            sh_print_ulong(line_num++);
            sh_puts("  ");
            for (int i = 0; i < len; i++)
            {
                sh_putc(buf[i]);
                if (buf[i] == '\n' && i < len - 1)
                {
                    sh_print_ulong(line_num++);
                    sh_puts("  ");
                }
            }
        }
        else
        {
            sh_puts(buf);
        }
        if (len > 0 && buf[len - 1] != '\n')
            sh_putc('\n');
    }
    return rc;
}

static inline int cmd_touch(int argc, char **argv)
{
    if (argc < 2)
    {
        sh_puts("usage: touch <file...>\n");
        return 2;
    }
    for (int i = 1; i < argc; i++)
    {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[i], resolved, sizeof(resolved));
        int idx = vfs_find(resolved);
        if (idx >= 0)
        {
            vfs_nodes[idx].mtime = vfs_get_time();
        }
        else
        {
            vfs_create_node(resolved, 0);
        }
    }
    return 0;
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

static inline int cmd_rm(int argc, char **argv)
{
    int force = 0;
    int recursive = 0;
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
            else if (argv[start][k] == 'r')
                recursive = 1;
            else
                return sh_unknown_opt("rm", argv[start][k]);
        }
        start++;
    }
    (void)recursive;

    if (start >= argc)
    {
        sh_puts("usage: rm [-f] [-r] <file>\n");
        return 2;
    }

    int rc = 0;
    for (int i = start; i < argc; i++)
    {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[i], resolved, sizeof(resolved));

        int r = vfs_unlink_node(resolved);
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

static inline int cmd_cp(int argc, char **argv)
{
    /* No cp flags in Task 2 (Task 6 adds -f/-i/-r/-R); reject -opts now. */
    int start = 1;
    while (start < argc && argv[start][0] == '-' && argv[start][1] != '\0' &&
           vfs_strcmp(argv[start], "--") != 0)
    {
        return sh_unknown_opt("cp", argv[start][1]);
    }
    if (start < argc && vfs_strcmp(argv[start], "--") == 0)
        start++;
    if (argc - start < 2)
    {
        sh_puts("usage: cp <src> <dst>\n");
        return 2;
    }
    char src_res[VFS_PATH_MAX], dst_res[VFS_PATH_MAX];
    vfs_resolve_path(sh_cwd, argv[start], src_res, sizeof(src_res));
    vfs_resolve_path(sh_cwd, argv[start + 1], dst_res, sizeof(dst_res));

    int sidx = vfs_find(src_res);
    if (sidx < 0 || vfs_nodes[sidx].is_dir)
    {
        sh_file_error("cp", argv[start], "No such file or directory");
        return 1;
    }

    int didx = vfs_find(dst_res);
    if (didx >= 0 && vfs_nodes[didx].is_dir)
    {
        /* Destination is directory: copy with original filename */
        vfs_strcat(dst_res, "/", sizeof(dst_res));
        vfs_strcat(dst_res, vfs_nodes[sidx].name, sizeof(dst_res));
        didx = vfs_find(dst_res);
    }

    if (didx < 0)
    {
        didx = vfs_create_node(dst_res, 0);
        if (didx < 0)
        {
            sh_puts("cp: cannot create destination file\n");
            return 1;
        }
    }

    char buf[VFS_FILE_MAX];
    int len = vfs_read_file(sidx, buf, sizeof(buf));
    if (len >= 0)
    {
        vfs_write_file(didx, buf, len, 0);
    }
    return 0;
}

static inline int cmd_mv(int argc, char **argv)
{
    /* No mv flags in Task 2 (Task 6 adds -f/-i); reject -opts now. */
    int start = 1;
    while (start < argc && argv[start][0] == '-' && argv[start][1] != '\0' &&
           vfs_strcmp(argv[start], "--") != 0)
    {
        return sh_unknown_opt("mv", argv[start][1]);
    }
    if (start < argc && vfs_strcmp(argv[start], "--") == 0)
        start++;
    if (argc - start < 2)
    {
        sh_puts("usage: mv <src> <dst>\n");
        return 2;
    }
    /* BusyBox mv.c: missing src fails upfront under the mv prog name. */
    char src_res[VFS_PATH_MAX];
    vfs_resolve_path(sh_cwd, argv[start], src_res, sizeof(src_res));
    if (vfs_find(src_res) < 0)
    {
        sh_file_error("mv", argv[start], "No such file or directory");
        return 1;
    }
    char *cp_argv[4];
    cp_argv[0] = argv[0];
    cp_argv[1] = argv[start];
    cp_argv[2] = argv[start + 1];
    cp_argv[3] = NULL;
    if (cmd_cp(3, cp_argv) == 0)
    {
        vfs_unlink_node(src_res);
        return 0;
    }
    return 1;
}

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
        int r = vfs_create_node(resolved, 1);
        if (r == 0)
            continue;
        if (r == -1 && p_opt)
            continue; /* mkdir -p: pre-existing dir is success (Task 6 adds recursion) */
        sh_file_error("mkdir", argv[i], r == -1 ? "File exists" : "No such file or directory");
        rc = 1;
    }
    return rc;
}

static inline int cmd_rmdir(int argc, char **argv)
{
    if (argc < 2)
    {
        sh_puts("usage: rmdir <dir...>\n");
        return 2;
    }
    int rc = 0;
    for (int i = 1; i < argc; i++)
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
        }
    }
    return rc;
}

static inline int cmd_head(int argc, char **argv)
{
    int n = 10;
    int start = 1;
    if (start < argc && vfs_strcmp(argv[start], "-n") == 0 && start + 1 < argc)
    {
        int64_t v = 10;
        shell_eval_expr(argv[start + 1], &v);
        n = (int)v;
        start += 2;
    }

    const char *data = sh_stdin_data;
    char file_buf[VFS_FILE_MAX];
    if (start < argc)
    {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[start], resolved, sizeof(resolved));
        int idx = vfs_find(resolved);
        if (idx < 0)
        {
            sh_puts("head: cannot open '");
            sh_puts(argv[start]);
            sh_puts("'\n");
            return 1;
        }
        int len = vfs_read_file(idx, file_buf, sizeof(file_buf));
        if (len < 0)
            return 1;
        data = file_buf;
    }

    if (!data)
        return 0;
    int lines = 0;
    while (*data && lines < n)
    {
        sh_putc(*data);
        if (*data == '\n')
            lines++;
        data++;
    }
    return 0;
}

static inline int cmd_tail(int argc, char **argv)
{
    int n = 10;
    int start = 1;
    if (start < argc && vfs_strcmp(argv[start], "-n") == 0 && start + 1 < argc)
    {
        int64_t v = 10;
        shell_eval_expr(argv[start + 1], &v);
        n = (int)v;
        start += 2;
    }

    const char *data = sh_stdin_data;
    char file_buf[VFS_FILE_MAX];
    if (start < argc)
    {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[start], resolved, sizeof(resolved));
        int idx = vfs_find(resolved);
        if (idx < 0)
        {
            sh_puts("tail: cannot open '");
            sh_puts(argv[start]);
            sh_puts("'\n");
            return 1;
        }
        int len = vfs_read_file(idx, file_buf, sizeof(file_buf));
        if (len < 0)
            return 1;
        data = file_buf;
    }

    if (!data)
        return 0;
    int total_lines = 0;
    for (const char *p = data; *p; p++)
    {
        if (*p == '\n')
            total_lines++;
    }

    int skip = total_lines - n;
    if (skip < 0)
        skip = 0;
    int cur = 0;
    while (*data)
    {
        if (cur >= skip)
            sh_putc(*data);
        if (*data == '\n')
            cur++;
        data++;
    }
    return 0;
}

static inline int cmd_wc(int argc, char **argv)
{
    int opt_l = 0, opt_w = 0, opt_c = 0;
    int start = 1;
    while (start < argc && argv[start][0] == '-')
    {
        for (int k = 1; argv[start][k]; k++)
        {
            if (argv[start][k] == 'l')
                opt_l = 1;
            else if (argv[start][k] == 'w')
                opt_w = 1;
            else if (argv[start][k] == 'c')
                opt_c = 1;
        }
        start++;
    }
    if (!opt_l && !opt_w && !opt_c)
    {
        opt_l = opt_w = opt_c = 1;
    }

    const char *data = sh_stdin_data;
    const char *name = "";
    char file_buf[VFS_FILE_MAX];
    if (start < argc)
    {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[start], resolved, sizeof(resolved));
        int idx = vfs_find(resolved);
        if (idx < 0)
        {
            sh_puts("wc: '");
            sh_puts(argv[start]);
            sh_puts("': No such file\n");
            return 1;
        }
        int len = vfs_read_file(idx, file_buf, sizeof(file_buf));
        if (len < 0)
            return 1;
        data = file_buf;
        name = argv[start];
    }

    if (!data)
        data = "";
    unsigned long lines = 0, words = 0, bytes = 0;
    int in_word = 0;
    for (const char *p = data; *p; p++)
    {
        bytes++;
        if (*p == '\n')
            lines++;
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        {
            in_word = 0;
        }
        else
        {
            if (!in_word)
            {
                words++;
                in_word = 1;
            }
        }
    }

    int printed = 0;
    if (opt_l)
    {
        sh_print_ulong(lines);
        printed = 1;
    }
    if (opt_w)
    {
        if (printed)
            sh_putc(' ');
        sh_print_ulong(words);
        printed = 1;
    }
    if (opt_c)
    {
        if (printed)
            sh_putc(' ');
        sh_print_ulong(bytes);
        printed = 1;
    }
    if (*name)
    {
        if (printed)
            sh_putc(' ');
        sh_puts(name);
    }
    sh_putc('\n');
    return 0;
}

static inline int cmd_stat(int argc, char **argv)
{
    if (argc < 2)
    {
        sh_puts("usage: stat <file...>\n");
        return 2;
    }
    int rc = 0;
    for (int i = 1; i < argc; i++)
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

static inline int cmd_find(int argc, char **argv)
{
    const char *root = (argc > 1 && argv[1][0] != '-') ? argv[1] : ".";
    const char *name_filter = NULL;
    int type_filter = -1; /* 0=file, 1=dir */

    for (int i = 1; i < argc; i++)
    {
        if (vfs_strcmp(argv[i], "-name") == 0 && i + 1 < argc)
        {
            name_filter = argv[++i];
        }
        else if (vfs_strcmp(argv[i], "-type") == 0 && i + 1 < argc)
        {
            i++;
            if (argv[i][0] == 'f')
                type_filter = 0;
            else if (argv[i][0] == 'd')
                type_filter = 1;
        }
    }

    char resolved[VFS_PATH_MAX];
    vfs_resolve_path(sh_cwd, root, resolved, sizeof(resolved));

    for (int i = 0; i < VFS_MAX_NODES; i++)
    {
        if (!vfs_nodes[i].in_use)
            continue;
        if (type_filter >= 0 && vfs_nodes[i].is_dir != (uint8_t)type_filter)
            continue;
        if (name_filter && vfs_strcmp(vfs_nodes[i].name, name_filter) != 0)
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
    return 0;
}

static inline int cmd_tee(int argc, char **argv)
{
    int append = 0;
    int start = 1;
    if (start < argc && vfs_strcmp(argv[start], "-a") == 0)
    {
        append = 1;
        start++;
    }
    if (start >= argc)
    {
        sh_puts("usage: tee [-a] <file>\n");
        return 2;
    }

    char resolved[VFS_PATH_MAX];
    vfs_resolve_path(sh_cwd, argv[start], resolved, sizeof(resolved));

    int idx = vfs_find(resolved);
    if (idx < 0)
        idx = vfs_create_node(resolved, 0);
    if (idx < 0)
        return 1;

    if (sh_stdin_data)
    {
        sh_puts(sh_stdin_data);
        vfs_write_file(idx, sh_stdin_data, sh_stdin_len, append);
    }
    return 0;
}

#endif /* SHELL_FILE_H */
