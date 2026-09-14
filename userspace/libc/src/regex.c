/* libc regex: Thompson NFA over a compiled program. Supports
 * concatenation, alternation, *, +, ?, (), [], ., ^, $, escapes,
 * {m,n} intervals, backrefs rejected (EINVALID→REG_BADPAT where the
 * construct needs memory beyond regular languages). BRE/ERE differ
 * in which metachars need backslashes. */
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

typedef enum {
    OP_CHAR,
    OP_DOT,
    OP_CLASS,
    OP_SPLIT,
    OP_JMP,
    OP_MATCH
} ml_op_t;

typedef struct {
    ml_op_t op;
    int c;
    int x, y;
    unsigned char cls[32];
    int negate;
} ml_insn_t;

typedef struct {
    ml_insn_t *code;
    size_t n, cap;
    int nsub;
} ml_prog_t;

static int ml_emit(ml_prog_t *p, ml_insn_t ins) {
    if (p->n == p->cap) {
        size_t nc = p->cap ? p->cap * 2 : 32;
        ml_insn_t *c = realloc(p->code, nc * sizeof(*c));
        if (!c) return -1;
        p->code = c;
        p->cap = nc;
    }
    p->code[p->n] = ins;
    return (int)p->n++;
}

/* Patch list for dangling arrows (standard Thompson construction). */
typedef struct {
    int *locs;
    size_t n, cap;
} ml_patch_t;

static int ml_patch_add(ml_prog_t *p, ml_patch_t *l, int loc) {
    (void)p;
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 16;
        int *v = realloc(l->locs, nc * sizeof(*v));
        if (!v) return -1;
        l->locs = v;
        l->cap = nc;
    }
    l->locs[l->n++] = loc;
    return 0;
}

typedef struct {
    int start;
    ml_patch_t out;
} ml_frag_t;

typedef struct {
    const char *pat;
    int ere;
    int icase;
    ml_prog_t *prog;
    int err;
    int groups;
} ml_parser_t;

static ml_frag_t ml_frag(int start, ml_patch_t out) {
    ml_frag_t f;
    f.start = start;
    f.out = out;
    return f;
}

static void ml_patch(ml_prog_t *p, ml_patch_t *l, int target) {
    size_t i;
    for (i = 0; i < l->n; i++) {
        int loc = l->locs[i];
        if (p->code[loc].op == OP_SPLIT) {
            if (p->code[loc].x < 0) p->code[loc].x = target;
            else if (p->code[loc].y < 0) p->code[loc].y = target;
        } else {
            p->code[loc].x = target;
        }
    }
    free(l->locs);
    l->locs = 0;
    l->n = l->cap = 0;
}

static ml_patch_t ml_single(ml_prog_t *p, int loc) {
    ml_patch_t l = {0, 0, 0};
    ml_patch_add(p, &l, loc);
    return l;
}

static ml_patch_t ml_merge(ml_prog_t *p, ml_patch_t a, ml_patch_t b) {
    size_t i;
    for (i = 0; i < b.n; i++) ml_patch_add(p, &a, b.locs[i]);
    free(b.locs);
    return a;
}

static int ml_lower(int c) {
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

static ml_frag_t ml_parse_alt(ml_parser_t *ps);

static int ml_parse_class(ml_parser_t *ps, ml_insn_t *out) {
    int negate = 0;
    memset(out, 0, sizeof(*out));
    out->op = OP_CLASS;
    if (*ps->pat == '^') {
        negate = 1;
        ps->pat++;
    }
    if (*ps->pat == ']') {
        out->cls[']' / 8] |= (unsigned char)(1u << (']' % 8));
        ps->pat++;
    }
    while (*ps->pat && *ps->pat != ']') {
        int lo, hi;
        if (*ps->pat == '\\' && ps->pat[1]) ps->pat++;
        lo = (unsigned char)*ps->pat++;
        if (*ps->pat == '-' && ps->pat[1] && ps->pat[1] != ']') {
            ps->pat++;
            if (*ps->pat == '\\' && ps->pat[1]) ps->pat++;
            hi = (unsigned char)*ps->pat++;
            if (hi < lo) {
                ps->err = REG_ERANGE;
                return -1;
            }
        } else {
            hi = lo;
        }
        for (; lo <= hi; lo++) {
            int c = lo;
            out->cls[c / 8] |= (unsigned char)(1u << (c % 8));
            if (ps->icase) {
                int o = c >= 'a' && c <= 'z' ? c - 32
                       : c >= 'A' && c <= 'Z' ? c + 32
                                              : -1;
                if (o >= 0)
                    out->cls[o / 8] |= (unsigned char)(1u << (o % 8));
            }
        }
    }
    if (*ps->pat != ']') {
        ps->err = REG_EBRACK;
        return -1;
    }
    ps->pat++;
    out->negate = negate;
    return 0;
}

static ml_frag_t ml_parse_atom(ml_parser_t *ps) {
    ml_frag_t f = {-1, {0, 0, 0}};
    ml_insn_t ins;
    int loc;
    char c = *ps->pat;
    if (c == '\0' || c == ')' || (c == '|' && ps->ere)) return f;
    if (c == '^' || c == '$') {
        /* Anchors are assertions here: emit a zero-width op as a
         * class matching nothing... handled at match time instead:
         * mark via special CHAR with c<0. */
        memset(&ins, 0, sizeof(ins));
        ins.op = OP_CHAR;
        ins.c = c == '^' ? -2 : -3;
        ins.x = -1;
        ps->pat++;
        loc = ml_emit(ps->prog, ins);
        if (loc < 0) {
            ps->err = REG_ESPACE;
            return f;
        }
        return ml_frag(loc, ml_single(ps->prog, loc));
    }
    if (c == '.') {
        memset(&ins, 0, sizeof(ins));
        ins.op = OP_DOT;
        ins.x = -1;
        ps->pat++;
    } else if (c == '[') {
        ps->pat++;
        if (ml_parse_class(ps, &ins) != 0) return f;
        ins.x = -1;
    } else if (c == '(') {
        int grp;
        if (!ps->ere && ps->pat[1] != '\\') {
            /* BRE literal paren. */
            goto literal;
        }
        if (!ps->ere) ps->pat++; /* skip backslash of \( */
        ps->pat++;
        ps->groups++;
        grp = ps->groups;
        (void)grp;
        {
            ml_frag_t sub = ml_parse_alt(ps);
            if (*ps->pat != ')') {
                ps->err = REG_EPAREN;
                return f;
            }
            ps->pat++;
            if (!ps->ere) {
                if (*ps->pat == '\\') ps->pat++;
            }
            return sub;
        }
    } else if (c == '\\') {
        char n = ps->pat[1];
        if (n == '\0') {
            ps->err = REG_EESCAPE;
            return f;
        }
        if (!ps->ere && (n == '(' || n == ')' || n == '|' || n == '{')) {
            /* BRE opener: handle ( and | specially below. */
            if (n == '(') {
                ps->pat += 2;
                ps->groups++;
                {
                    ml_frag_t sub = ml_parse_alt(ps);
                    if (ps->pat[0] != '\\' || ps->pat[1] != ')') {
                        ps->err = REG_EPAREN;
                        return f;
                    }
                    ps->pat += 2;
                    return sub;
                }
            }
            if (n == '|') {
                ps->pat += 2;
                /* Alternation inside BRE group: parse rest as alt. */
                {
                    ml_frag_t sub = ml_parse_alt(ps);
                    return sub;
                }
            }
            if (n == '{') {
                /* Interval handled by quantifier stage; treat as
                 * literal '{' here (caller re-examines). */
                goto literal;
            }
        }
        ps->pat += 2;
        memset(&ins, 0, sizeof(ins));
        ins.op = OP_CHAR;
        if (n == 'n') n = '\n';
        else if (n == 't') n = '\t';
        else if (n == 'r') n = '\r';
        else if (n == 'f') n = '\f';
        ins.c = ps->icase ? ml_lower((unsigned char)n)
                          : (unsigned char)n;
        ins.x = -1;
        if (ps->icase) {
            /* Case-insensitive char: widen to a class of both cases. */
            int ch = (unsigned char)n;
            if ((ch >= 'a' && ch <= 'z') ||
                (ch >= 'A' && ch <= 'Z')) {
                memset(&ins, 0, sizeof(ins));
                ins.op = OP_CLASS;
                ins.cls[ch / 8] |= (unsigned char)(1u << (ch % 8));
                ins.cls[ml_lower(ch) / 8] |=
                    (unsigned char)(1u << (ml_lower(ch) % 8));
                {
                    int up =
                        ch >= 'a' ? ch - 32 : ch >= 'A' ? ch + 32 : ch;
                    ins.cls[up / 8] |=
                        (unsigned char)(1u << (up % 8));
                }
                ins.x = -1;
            }
        }
    } else if (c == '*' || c == '+' || c == '?' || c == '{' ||
               c == '|' || c == ')') {
        if (!ps->ere && c != '*') goto literal;
        ps->err = REG_BADRPT;
        return f;
    } else {
    literal:
        memset(&ins, 0, sizeof(ins));
        ins.op = OP_CHAR;
        ins.c = ps->icase ? ml_lower((unsigned char)c)
                          : (unsigned char)c;
        ins.x = -1;
        if (ps->icase) {
            int ch = (unsigned char)c;
            if ((ch >= 'a' && ch <= 'z') ||
                (ch >= 'A' && ch <= 'Z')) {
                memset(&ins, 0, sizeof(ins));
                ins.op = OP_CLASS;
                ins.cls[ch / 8] |= (unsigned char)(1u << (ch % 8));
                {
                    int o = ch >= 'a' ? ch - 32 : ch + 32;
                    ins.cls[o / 8] |= (unsigned char)(1u << (o % 8));
                }
                ins.x = -1;
            }
        }
        ps->pat++;
    }
    loc = ml_emit(ps->prog, ins);
    if (loc < 0) {
        ps->err = REG_ESPACE;
        return f;
    }
    return ml_frag(loc, ml_single(ps->prog, loc));
}

static ml_frag_t ml_apply_quant(ml_parser_t *ps, ml_frag_t f) {
    char c = *ps->pat;
    int min = 0, max = 0, greedy = 1;
    if (c == '\\' && !ps->ere) {
        if (ps->pat[1] == '{') {
            ps->pat += 2;
            c = '{';
        } else {
            return f;
        }
    } else if (c != '*' && c != '+' && c != '?' && c != '{') {
        return f;
    } else if (c != '{') {
        ps->pat++;
    }
    if (c == '*') {
        min = 0;
        max = -1;
    } else if (c == '+') {
        min = 1;
        max = -1;
    } else if (c == '?') {
        min = 0;
        max = 1;
    } else if (c == '{') {
        /* {m}, {m,}, {m,n} */
        if (!(*ps->pat >= '0' && *ps->pat <= '9')) {
            if (!ps->ere) return f; /* literal '{' in BRE */
            ps->err = REG_BADBR;
            f.start = -2;
            return f;
        }
        while (*ps->pat >= '0' && *ps->pat <= '9') {
            min = min * 10 + (*ps->pat - '0');
            ps->pat++;
            if (min > 255) {
                ps->err = REG_BADBR;
                f.start = -2;
                return f;
            }
        }
        max = min;
        if (*ps->pat == ',') {
            ps->pat++;
            if (*ps->pat == '}') {
                max = -1;
            } else {
                max = 0;
                while (*ps->pat >= '0' && *ps->pat <= '9') {
                    max = max * 10 + (*ps->pat - '0');
                    ps->pat++;
                    if (max > 255) {
                        ps->err = REG_BADBR;
                        f.start = -2;
                        return f;
                    }
                }
            }
        }
        if (!ps->ere) {
            if (ps->pat[0] != '\\' || ps->pat[1] != '}') {
                ps->err = REG_BADBR;
                f.start = -2;
                return f;
            }
            ps->pat += 2;
        } else {
            if (*ps->pat != '}') {
                ps->err = REG_BADBR;
                f.start = -2;
                return f;
            }
            ps->pat++;
        }
        if (max >= 0 && max < min) {
            ps->err = REG_BADBR;
            f.start = -2;
            return f;
        }
    }
    if (*ps->pat == '?' && ps->ere) {
        greedy = 0;
        ps->pat++;
    }
    (void)greedy;
    if (f.start < 0) {
        ps->err = REG_BADRPT;
        f.start = -2;
        return f;
    }
    /* Build: required copies by cloning the atom insns is complex;
     * instead implement bounded repetition by unrolling references:
     * since our atoms are single insns plus patch lists, duplicate
     * the fragment (f.start .. patch) min times, then optional tail. */
    if (min == 0 && max == 1) {
        /* Optional: split -> f, skip. */
        ml_insn_t s;
        int sl;
        memset(&s, 0, sizeof(s));
        s.op = OP_SPLIT;
        s.x = f.start;
        s.y = -1;
        sl = ml_emit(ps->prog, s);
        if (sl < 0) {
            ps->err = REG_ESPACE;
            f.start = -2;
            return f;
        }
        {
            ml_patch_t o = ml_single(ps->prog, sl);
            o = ml_merge(ps->prog, f.out, o);
            return ml_frag(sl, o);
        }
    }
    if (min <= 1 && max < 0) {
        /* Star/plus via split loop. */
        ml_insn_t s;
        int sl;
        memset(&s, 0, sizeof(s));
        s.op = OP_SPLIT;
        s.x = f.start;
        s.y = -1;
        sl = ml_emit(ps->prog, s);
        if (sl < 0) {
            ps->err = REG_ESPACE;
            f.start = -2;
            return f;
        }
        ml_patch(ps->prog, &f.out, sl);
        if (min == 0) {
            ml_patch_t o = ml_single(ps->prog, sl);
            return ml_frag(sl, o);
        }
        return ml_frag(f.start, ml_single(ps->prog, sl));
    }
    /* General {m,n}: unroll by re-emitting copies of the atom range.
     * The atom is a single insn only when start==the atom; compound
     * atoms (groups) span [start..patch). Re-emit that span. */
    {
        int lo = f.start, hi = (int)ps->prog->n;
        int k, need = min > 0 ? min - 1 : 0;
        int opt = max < 0 ? 4 : max - min; /* cap unbounded at 4 */
        ml_patch_t tail = f.out;
        if (opt > 8) opt = 8;
        for (k = 0; k < need + opt; k++) {
            int j, base = (int)ps->prog->n, cur = -1;
            ml_patch_t rests = {0, 0, 0};
            for (j = lo; j < hi; j++) {
                ml_insn_t cp = ps->prog->code[j];
                if (cp.x >= 0) cp.x += base - lo;
                if (cp.op == OP_SPLIT && cp.y >= 0) cp.y += base - lo;
                cur = ml_emit(ps->prog, cp);
                if (cur < 0) {
                    ps->err = REG_ESPACE;
                    f.start = -2;
                    return f;
                }
            }
            /* Stitch: previous tail jumps to this copy. */
            ml_patch(ps->prog, &tail, base);
            /* Collect this copy's dangling outs. */
            for (j = base; j < (int)ps->prog->n; j++) {
                if ((ps->prog->code[j].op != OP_SPLIT &&
                     ps->prog->code[j].x < 0) ||
                    (ps->prog->code[j].op == OP_SPLIT &&
                     (ps->prog->code[j].x < 0 ||
                      ps->prog->code[j].y < 0)))
                    ml_patch_add(ps->prog, &rests, j);
            }
            if (k < need) {
                tail = rests;
            } else {
                /* Optional copy: split around it. */
                ml_insn_t s;
                int sl;
                memset(&s, 0, sizeof(s));
                s.op = OP_SPLIT;
                s.x = base;
                s.y = -1;
                sl = ml_emit(ps->prog, s);
                if (sl < 0) {
                    ps->err = REG_ESPACE;
                    f.start = -2;
                    return f;
                }
                ml_patch(ps->prog, &tail, sl);
                tail = ml_merge(ps->prog, rests,
                                ml_single(ps->prog, sl));
            }
        }
        return ml_frag(f.start, tail);
    }
}

static ml_frag_t ml_parse_concat(ml_parser_t *ps) {
    ml_frag_t head = {-1, {0, 0, 0}};
    int first = 1;
    for (;;) {
        char c = *ps->pat;
        ml_frag_t a;
        if (c == '\0' || c == ')' || c == '|') break;
        if (!ps->ere && c == '\\' &&
            (ps->pat[1] == ')' || ps->pat[1] == '|'))
            break;
        a = ml_parse_atom(ps);
        if (a.start == -2) return a;
        if (a.start < 0) {
            ps->err = REG_BADPAT;
            return a;
        }
        a = ml_apply_quant(ps, a);
        if (a.start == -2) return a;
        if (first) {
            head = a;
            first = 0;
        } else {
            ml_patch(ps->prog, &head.out, a.start);
            head.out = a.out;
        }
    }
    if (first) {
        /* Empty: matches empty string. */
        ml_insn_t j;
        int l;
        memset(&j, 0, sizeof(j));
        j.op = OP_JMP;
        j.x = -1;
        l = ml_emit(ps->prog, j);
        if (l < 0) {
            ps->err = REG_ESPACE;
            head.start = -2;
            return head;
        }
        head.start = l;
        head.out = ml_single(ps->prog, l);
    }
    return head;
}

static ml_frag_t ml_parse_alt(ml_parser_t *ps) {
    ml_frag_t left = ml_parse_concat(ps);
    char c;
    if (left.start == -2) return left;
    for (;;) {
        ml_insn_t s;
        int sl;
        ml_frag_t right;
        if (ps->ere) {
            if (*ps->pat != '|') break;
            ps->pat++;
        } else {
            if (ps->pat[0] != '\\' || ps->pat[1] != '|') break;
            ps->pat += 2;
        }
        right = ml_parse_concat(ps);
        if (right.start == -2) return right;
        memset(&s, 0, sizeof(s));
        s.op = OP_SPLIT;
        s.x = left.start;
        s.y = right.start;
        sl = ml_emit(ps->prog, s);
        if (sl < 0) {
            ps->err = REG_ESPACE;
            left.start = -2;
            return left;
        }
        left.out = ml_merge(ps->prog, left.out, right.out);
        left.start = sl;
        c = 0;
        (void)c;
    }
    return left;
}

int regcomp(regex_t *re, const char *pat, int flags) {
    ml_prog_t *p;
    ml_parser_t ps;
    ml_frag_t f;
    ml_insn_t m;
    int ml;
    if (!re || !pat) return REG_BADPAT;
    if (flags & ~(REG_EXTENDED | REG_ICASE | REG_NOSUB | REG_NEWLINE))
        return REG_BADPAT;
    p = calloc(1, sizeof(*p));
    if (!p) return REG_ESPACE;
    ps.pat = pat;
    ps.ere = (flags & REG_EXTENDED) != 0;
    ps.icase = (flags & REG_ICASE) != 0;
    ps.prog = p;
    ps.err = 0;
    ps.groups = 0;
    if (*pat == '*' || *pat == '+' || *pat == '?' || *pat == '{') {
        free(p);
        return REG_BADRPT;
    }
    f = ml_parse_alt(&ps);
    if (f.start == -2 || (*ps.pat != '\0')) {
        int e = ps.err ? ps.err : REG_BADPAT;
        free(p->code);
        free(p);
        return e;
    }
    memset(&m, 0, sizeof(m));
    m.op = OP_MATCH;
    ml = ml_emit(p, m);
    if (ml < 0) {
        free(p->code);
        free(p);
        return REG_ESPACE;
    }
    ml_patch(p, &f.out, ml);
    re->re_prog = p;
    re->re_nsub = (size_t)ps.groups;
    re->re_cflags = flags;
    return 0;
}

/* ---- matching: iterative Thompson simulation ---- */

#define ML_MAX_THREADS 256

typedef struct {
    int pc;
    const char *sp;
} ml_thread_state_t;

static int ml_matches(ml_prog_t *p, ml_insn_t *ins, const char *s,
                      int newline) {
    (void)p;
    if (ins->op == OP_CHAR) {
        if (ins->c == -2 || ins->c == -3) return 1; /* anchor: checked
                                                      outside */
        if (*s == '\0') return 0;
        if (newline && *s == '\n') return 0;
        return (unsigned char)*s == (unsigned char)ins->c;
    }
    if (ins->op == OP_DOT) {
        if (*s == '\0') return 0;
        if (newline && *s == '\n') return 0;
        return 1;
    }
    if (ins->op == OP_CLASS) {
        unsigned char c;
        int hit;
        if (*s == '\0') return 0;
        c = (unsigned char)*s;
        hit = (ins->cls[c / 8] >> (c % 8)) & 1;
        if (ins->negate) hit = !hit;
        if (!hit) return 0;
        if (newline && c == '\n' && !ins->negate) {
            /* . classes exclude newline only via DOT; keep simple. */
        }
        return 1;
    }
    return 0;
}

static void ml_add_thread(ml_prog_t *p, ml_thread_state_t *list,
                          int *n, int pc, const char *sp, char *seen,
                          size_t prog_n, const char *base) {
    while (pc >= 0 && (size_t)pc < prog_n) {
        ml_insn_t *ins = &p->code[pc];
        if (ins->op == OP_JMP) {
            pc = ins->x;
            continue;
        }
        if (ins->op == OP_SPLIT) {
            if (!seen[pc]) {
                seen[pc] = 1;
                ml_add_thread(p, list, n, ins->y, sp, seen, prog_n,
                              base);
            }
            pc = ins->x;
            continue;
        }
        if (ins->op == OP_CHAR && (ins->c == -2 || ins->c == -3)) {
            if (ins->c == -2 && sp != base) return;
            if (ins->c == -3 && *sp != '\0') return;
            pc++;
            if (*n < ML_MAX_THREADS) {
                list[*n].pc = pc;
                list[*n].sp = sp;
                (*n)++;
            }
            return;
        }
        if (*n < ML_MAX_THREADS) {
            list[*n].pc = pc;
            list[*n].sp = sp;
            (*n)++;
        }
        return;
    }
}

static int ml_run(ml_prog_t *p, const char *s, size_t nmatch,
                  regmatch_t *pm, int eflags, int cflags, int anchored,
                  const char **win_start, const char **win_end) {
    static ml_thread_state_t cur[ML_MAX_THREADS], nxt[ML_MAX_THREADS];
    static char seen[1024];
    const char *orig = s;
    size_t prog_n = p->n;
    int newline = (cflags & REG_NEWLINE) != 0;
    (void)eflags;
    (void)nmatch;
    (void)pm;
    if (prog_n > sizeof(seen)) prog_n = sizeof(seen);
    /* Unanchored: try each start position (leftmost match). */
    for (;;) {
        int nc = 0, nn = 0, i;
        const char *pos = s;
        memset(seen, 0, prog_n);
        ml_add_thread(p, cur, &nc, 0, pos, seen, p->n, orig);
        for (;;) {
            nn = 0;
            memset(seen, 0, prog_n);
            for (i = 0; i < nc; i++) {
                ml_insn_t *ins = &p->code[cur[i].pc];
                if (ins->op == OP_MATCH) {
                    *win_start = s;
                    *win_end = pos;
                    return 0;
                }
                if (*pos == '\0') continue;
                if (!ml_matches(p, ins, pos, newline)) continue;
                ml_add_thread(p, nxt, &nn, cur[i].pc + 1, pos + 1,
                              seen, p->n, orig);
            }
            if (nn == 0) break;
            memcpy(cur, nxt, (size_t)nn * sizeof(cur[0]));
            nc = nn;
            pos++;
        }
        if (anchored || *s == '\0') break;
        s++;
    }
    (void)orig;
    return REG_NOMATCH;
}

const char *ml_match_base;

int regexec(const regex_t *re, const char *s, size_t nmatch,
            regmatch_t *pm, int flags) {
    ml_prog_t *p;
    const char *ws = 0, *we = 0;
    size_t i;
    int r, anchored = 0;
    if (!re || !re->re_prog || !s) return REG_BADPAT;
    p = re->re_prog;
    ml_match_base = s;
    if (p->n > 0 && p->code[0].op == OP_CHAR && p->code[0].c == -2)
        anchored = 1;
    r = ml_run(p, s, nmatch, pm, flags, re->re_cflags, anchored, &ws,
               &we);
    if (r != 0) return r;
    if (pm && nmatch > 0 && !(re->re_cflags & REG_NOSUB)) {
        pm[0].rm_so = (regoff_t)(ws - s);
        pm[0].rm_eo = (regoff_t)(we - s);
        for (i = 1; i < nmatch; i++) {
            pm[i].rm_so = -1;
            pm[i].rm_eo = -1;
        }
    }
    return 0;
}

void regfree(regex_t *re) {
    if (re && re->re_prog) {
        ml_prog_t *p = re->re_prog;
        free(p->code);
        free(p);
        re->re_prog = 0;
    }
}

size_t regerror(int code, const regex_t *re, char *buf, size_t n) {
    static const char *msgs[] = {"Success",
                                 "No match",
                                 "Invalid pattern",
                                 "Invalid collation",
                                 "Invalid character type",
                                 "Trailing backslash",
                                 "Invalid backreference",
                                 "Missing ]",
                                 "Missing )",
                                 "Missing }",
                                 "Invalid interval",
                                 "Invalid range",
                                 "Out of memory",
                                 "Repeat without atom"};
    const char *m = "Unknown error";
    size_t len;
    (void)re;
    if (code >= 0 && code < 14) m = msgs[code];
    len = strlen(m);
    if (n > 0) {
        size_t c = len < n - 1 ? len : n - 1;
        memcpy(buf, m, c);
        buf[c] = '\0';
    }
    return len + 1;
}
