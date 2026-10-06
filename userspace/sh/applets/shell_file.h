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

static inline int cmd_ls(int argc, char **argv) {
    int opt_l = 0, opt_a = 0, opt_h = 0;
    const char *path = NULL;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            for (int k = 1; argv[i][k]; k++) {
                if (argv[i][k] == 'l') opt_l = 1;
                else if (argv[i][k] == 'a') opt_a = 1;
                else if (argv[i][k] == 'h') opt_h = 1;
            }
        } else {
            path = argv[i];
        }
    }

    char resolved[VFS_PATH_MAX];
    vfs_resolve_path(sh_cwd, path ? path : ".", resolved, sizeof(resolved));

    int pidx = vfs_find(resolved);
    if (pidx < 0) {
        sh_puts("ls: cannot access '");
        sh_puts(path ? path : ".");
        sh_puts("': No such file or directory\n");
        return 1;
    }

    if (!vfs_nodes[pidx].is_dir) {
        /* Single file */
        if (opt_l) {
            sh_puts("-rw-r--r-- 1 root root ");
            if (opt_h) sh_print_size(vfs_nodes[pidx].size);
            else sh_print_ulong(vfs_nodes[pidx].size);
            sh_putc(' ');
        }
        sh_puts(vfs_nodes[pidx].name);
        sh_putc('\n');
        return 0;
    }

    /* List directory entries */
    int count = 0;
    for (int i = 0; i < VFS_MAX_NODES; i++) {
        if (!vfs_nodes[i].in_use) continue;
        if (vfs_nodes[i].parent_idx == (uint16_t)pidx && i != pidx) {
            if (!opt_a && vfs_nodes[i].name[0] == '.') continue;

            if (opt_l) {
                sh_puts(vfs_nodes[i].is_dir ? "drwxr-xr-x " : "-rw-r--r-- ");
                sh_puts("1 root root ");
                if (opt_h) sh_print_size(vfs_nodes[i].size);
                else sh_print_ulong(vfs_nodes[i].size);
                sh_puts(" ");
            }
            sh_puts(vfs_nodes[i].name);
            if (vfs_nodes[i].is_dir) sh_putc('/');
            sh_putc('\n');
            count++;
        }
    }
    if (count == 0 && opt_l) {
        sh_puts("(empty)\n");
    }
    return 0;
}

static inline int cmd_cat(int argc, char **argv) {
    int opt_n = 0;
    int start = 1;

    if (start < argc && vfs_strcmp(argv[start], "-n") == 0) {
        opt_n = 1;
        start++;
    }

    if (start >= argc) {
        /* Check if stdin from pipe has data */
        if (sh_stdin_data && sh_stdin_len > 0) {
            sh_puts(sh_stdin_data);
            return 0;
        }
        sh_puts("usage: cat [-n] <file>\n");
        return 1;
    }

    for (int a = start; a < argc; a++) {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[a], resolved, sizeof(resolved));

        int idx = vfs_find(resolved);
        if (idx < 0 || vfs_nodes[idx].is_dir) {
            sh_puts("cat: no such file: ");
            sh_puts(argv[a]);
            sh_putc('\n');
            continue;
        }

        char buf[VFS_FILE_MAX];
        int len = vfs_read_file(idx, buf, sizeof(buf));
        if (len < 0) continue;

        if (opt_n) {
            int line_num = 1;
            sh_print_ulong(line_num++);
            sh_puts("  ");
            for (int i = 0; i < len; i++) {
                sh_putc(buf[i]);
                if (buf[i] == '\n' && i < len - 1) {
                    sh_print_ulong(line_num++);
                    sh_puts("  ");
                }
            }
        } else {
            sh_puts(buf);
        }
        if (len > 0 && buf[len - 1] != '\n') sh_putc('\n');
    }
    return 0;
}

static inline int cmd_touch(int argc, char **argv) {
    if (argc < 2) {
        sh_puts("usage: touch <file...>\n");
        return 1;
    }
    for (int i = 1; i < argc; i++) {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[i], resolved, sizeof(resolved));
        int idx = vfs_find(resolved);
        if (idx >= 0) {
            vfs_nodes[idx].mtime = vfs_get_time();
        } else {
            vfs_create_node(resolved, 0);
        }
    }
    return 0;
}

static inline int cmd_write(int argc, char **argv) {
    if (argc < 3) {
        sh_puts("usage: write <file> <text...>\n");
        return 1;
    }
    char resolved[VFS_PATH_MAX];
    vfs_resolve_path(sh_cwd, argv[1], resolved, sizeof(resolved));

    int idx = vfs_find(resolved);
    if (idx < 0) {
        idx = vfs_create_node(resolved, 0);
        if (idx < 0) {
            sh_puts("write: cannot create ");
            sh_puts(argv[1]);
            sh_putc('\n');
            return 1;
        }
    }

    /* Join text arguments */
    char content[VFS_FILE_MAX];
    int pos = 0;
    for (int i = 2; i < argc; i++) {
        const char *s = argv[i];
        while (*s && pos < VFS_FILE_MAX - 2) content[pos++] = *s++;
        if (i < argc - 1 && pos < VFS_FILE_MAX - 2) content[pos++] = ' ';
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

static inline int cmd_rm(int argc, char **argv) {
    int force = 0;
    int recursive = 0;
    int start = 1;

    while (start < argc && argv[start][0] == '-') {
        if (vfs_strcmp(argv[start], "-f") == 0) force = 1;
        else if (vfs_strcmp(argv[start], "-r") == 0 || vfs_strcmp(argv[start], "-rf") == 0) recursive = 1;
        start++;
    }
    (void)recursive;

    if (start >= argc) {
        sh_puts("usage: rm [-f] [-r] <file>\n");
        return 1;
    }

    for (int i = start; i < argc; i++) {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[i], resolved, sizeof(resolved));

        int r = vfs_unlink_node(resolved);
        if (r != 0 && !force) {
            sh_puts("rm: cannot remove '");
            sh_puts(argv[i]);
            sh_puts("'\n");
        } else if (r == 0) {
            sh_puts("removed ");
            sh_puts(argv[i]);
            sh_putc('\n');
        }
    }
    return 0;
}

static inline int cmd_cp(int argc, char **argv) {
    if (argc < 3) {
        sh_puts("usage: cp <src> <dst>\n");
        return 1;
    }
    char src_res[VFS_PATH_MAX], dst_res[VFS_PATH_MAX];
    vfs_resolve_path(sh_cwd, argv[1], src_res, sizeof(src_res));
    vfs_resolve_path(sh_cwd, argv[2], dst_res, sizeof(dst_res));

    int sidx = vfs_find(src_res);
    if (sidx < 0 || vfs_nodes[sidx].is_dir) {
        sh_puts("cp: cannot stat '");
        sh_puts(argv[1]);
        sh_puts("': No such file\n");
        return 1;
    }

    int didx = vfs_find(dst_res);
    if (didx >= 0 && vfs_nodes[didx].is_dir) {
        /* Destination is directory: copy with original filename */
        vfs_strcat(dst_res, "/", sizeof(dst_res));
        vfs_strcat(dst_res, vfs_nodes[sidx].name, sizeof(dst_res));
        didx = vfs_find(dst_res);
    }

    if (didx < 0) {
        didx = vfs_create_node(dst_res, 0);
        if (didx < 0) {
            sh_puts("cp: cannot create destination file\n");
            return 1;
        }
    }

    char buf[VFS_FILE_MAX];
    int len = vfs_read_file(sidx, buf, sizeof(buf));
    if (len >= 0) {
        vfs_write_file(didx, buf, len, 0);
    }
    return 0;
}

static inline int cmd_mv(int argc, char **argv) {
    if (argc < 3) {
        sh_puts("usage: mv <src> <dst>\n");
        return 1;
    }
    if (cmd_cp(argc, argv) == 0) {
        char src_res[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[1], src_res, sizeof(src_res));
        vfs_unlink_node(src_res);
        return 0;
    }
    return 1;
}

static inline int cmd_mkdir(int argc, char **argv) {
    int start = 1;
    int p_opt = 0;
    if (start < argc && vfs_strcmp(argv[start], "-p") == 0) {
        p_opt = 1;
        start++;
    }
    if (start >= argc) {
        sh_puts("usage: mkdir [-p] <dir...>\n");
        return 1;
    }
    for (int i = start; i < argc; i++) {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[i], resolved, sizeof(resolved));
        int r = vfs_create_node(resolved, 1);
        if (r < 0 && !p_opt) {
            sh_puts("mkdir: cannot create directory '");
            sh_puts(argv[i]);
            sh_puts("'\n");
        }
    }
    return 0;
}

static inline int cmd_rmdir(int argc, char **argv) {
    if (argc < 2) {
        sh_puts("usage: rmdir <dir...>\n");
        return 1;
    }
    for (int i = 1; i < argc; i++) {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[i], resolved, sizeof(resolved));
        int idx = vfs_find(resolved);
        if (idx < 0 || !vfs_nodes[idx].is_dir) {
            sh_puts("rmdir: '"); sh_puts(argv[i]); sh_puts("': Not a directory\n");
            continue;
        }
        int r = vfs_unlink_node(resolved);
        if (r != 0) {
            sh_puts("rmdir: failed to remove '"); sh_puts(argv[i]); sh_puts("': Directory not empty\n");
        }
    }
    return 0;
}

static inline int cmd_head(int argc, char **argv) {
    int n = 10;
    int start = 1;
    if (start < argc && vfs_strcmp(argv[start], "-n") == 0 && start + 1 < argc) {
        int64_t v = 10;
        shell_eval_expr(argv[start + 1], &v);
        n = (int)v;
        start += 2;
    }

    const char *data = sh_stdin_data;
    char file_buf[VFS_FILE_MAX];
    if (start < argc) {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[start], resolved, sizeof(resolved));
        int idx = vfs_find(resolved);
        if (idx < 0) {
            sh_puts("head: cannot open '"); sh_puts(argv[start]); sh_puts("'\n");
            return 1;
        }
        int len = vfs_read_file(idx, file_buf, sizeof(file_buf));
        if (len < 0) return 1;
        data = file_buf;
    }

    if (!data) return 0;
    int lines = 0;
    while (*data && lines < n) {
        sh_putc(*data);
        if (*data == '\n') lines++;
        data++;
    }
    return 0;
}

static inline int cmd_tail(int argc, char **argv) {
    int n = 10;
    int start = 1;
    if (start < argc && vfs_strcmp(argv[start], "-n") == 0 && start + 1 < argc) {
        int64_t v = 10;
        shell_eval_expr(argv[start + 1], &v);
        n = (int)v;
        start += 2;
    }

    const char *data = sh_stdin_data;
    char file_buf[VFS_FILE_MAX];
    if (start < argc) {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[start], resolved, sizeof(resolved));
        int idx = vfs_find(resolved);
        if (idx < 0) {
            sh_puts("tail: cannot open '"); sh_puts(argv[start]); sh_puts("'\n");
            return 1;
        }
        int len = vfs_read_file(idx, file_buf, sizeof(file_buf));
        if (len < 0) return 1;
        data = file_buf;
    }

    if (!data) return 0;
    int total_lines = 0;
    for (const char *p = data; *p; p++) {
        if (*p == '\n') total_lines++;
    }

    int skip = total_lines - n;
    if (skip < 0) skip = 0;
    int cur = 0;
    while (*data) {
        if (cur >= skip) sh_putc(*data);
        if (*data == '\n') cur++;
        data++;
    }
    return 0;
}

static inline int cmd_wc(int argc, char **argv) {
    int opt_l = 0, opt_w = 0, opt_c = 0;
    int start = 1;
    while (start < argc && argv[start][0] == '-') {
        for (int k = 1; argv[start][k]; k++) {
            if (argv[start][k] == 'l') opt_l = 1;
            else if (argv[start][k] == 'w') opt_w = 1;
            else if (argv[start][k] == 'c') opt_c = 1;
        }
        start++;
    }
    if (!opt_l && !opt_w && !opt_c) { opt_l = opt_w = opt_c = 1; }

    const char *data = sh_stdin_data;
    const char *name = "";
    char file_buf[VFS_FILE_MAX];
    if (start < argc) {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[start], resolved, sizeof(resolved));
        int idx = vfs_find(resolved);
        if (idx < 0) {
            sh_puts("wc: '"); sh_puts(argv[start]); sh_puts("': No such file\n");
            return 1;
        }
        int len = vfs_read_file(idx, file_buf, sizeof(file_buf));
        if (len < 0) return 1;
        data = file_buf;
        name = argv[start];
    }

    if (!data) data = "";
    unsigned long lines = 0, words = 0, bytes = 0;
    int in_word = 0;
    for (const char *p = data; *p; p++) {
        bytes++;
        if (*p == '\n') lines++;
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
            in_word = 0;
        } else {
            if (!in_word) { words++; in_word = 1; }
        }
    }

    int printed = 0;
    if (opt_l) { sh_print_ulong(lines); printed = 1; }
    if (opt_w) { if (printed) sh_putc(' '); sh_print_ulong(words); printed = 1; }
    if (opt_c) { if (printed) sh_putc(' '); sh_print_ulong(bytes); printed = 1; }
    if (*name) { if (printed) sh_putc(' '); sh_puts(name); }
    sh_putc('\n');
    return 0;
}

static inline int cmd_stat(int argc, char **argv) {
    if (argc < 2) {
        sh_puts("usage: stat <file...>\n");
        return 1;
    }
    for (int i = 1; i < argc; i++) {
        char resolved[VFS_PATH_MAX];
        vfs_resolve_path(sh_cwd, argv[i], resolved, sizeof(resolved));
        int idx = vfs_find(resolved);
        if (idx < 0) {
            sh_puts("stat: cannot stat '"); sh_puts(argv[i]); sh_puts("': No such file\n");
            continue;
        }
        vfs_node_t *n = &vfs_nodes[idx];
        sh_puts("  File: "); sh_puts(argv[i]); sh_putc('\n');
        sh_puts("  Size: "); sh_print_ulong(n->size);
        sh_puts(" bytes    Type: "); sh_puts(n->is_dir ? "Directory\n" : "Regular File\n");
        sh_puts(" Inode: "); sh_print_ulong((unsigned long)idx);
        sh_puts("    Access: "); sh_puts(n->is_dir ? "(0755/drwxr-xr-x)\n" : "(0644/-rw-r--r--)\n");
        sh_puts(" Modify: "); sh_print_ulong((unsigned long)n->mtime); sh_puts(" ticks\n");
    }
    return 0;
}

static inline int cmd_find(int argc, char **argv) {
    const char *root = (argc > 1 && argv[1][0] != '-') ? argv[1] : ".";
    const char *name_filter = NULL;
    int type_filter = -1; /* 0=file, 1=dir */

    for (int i = 1; i < argc; i++) {
        if (vfs_strcmp(argv[i], "-name") == 0 && i + 1 < argc) {
            name_filter = argv[++i];
        } else if (vfs_strcmp(argv[i], "-type") == 0 && i + 1 < argc) {
            i++;
            if (argv[i][0] == 'f') type_filter = 0;
            else if (argv[i][0] == 'd') type_filter = 1;
        }
    }

    char resolved[VFS_PATH_MAX];
    vfs_resolve_path(sh_cwd, root, resolved, sizeof(resolved));

    for (int i = 0; i < VFS_MAX_NODES; i++) {
        if (!vfs_nodes[i].in_use) continue;
        if (type_filter >= 0 && vfs_nodes[i].is_dir != (uint8_t)type_filter) continue;
        if (name_filter && vfs_strcmp(vfs_nodes[i].name, name_filter) != 0) continue;

        /* Print matching path */
        if (i == 0) sh_puts("/\n");
        else {
            /* Construct path upwards */
            char pbuf[VFS_PATH_MAX];
            pbuf[0] = '\0';
            int cur = i;
            while (cur > 0) {
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

static inline int cmd_tee(int argc, char **argv) {
    int append = 0;
    int start = 1;
    if (start < argc && vfs_strcmp(argv[start], "-a") == 0) {
        append = 1;
        start++;
    }
    if (start >= argc) {
        sh_puts("usage: tee [-a] <file>\n");
        return 1;
    }

    char resolved[VFS_PATH_MAX];
    vfs_resolve_path(sh_cwd, argv[start], resolved, sizeof(resolved));

    int idx = vfs_find(resolved);
    if (idx < 0) idx = vfs_create_node(resolved, 0);
    if (idx < 0) return 1;

    if (sh_stdin_data) {
        sh_puts(sh_stdin_data);
        vfs_write_file(idx, sh_stdin_data, sh_stdin_len, append);
    }
    return 0;
}

#endif /* SHELL_FILE_H */
