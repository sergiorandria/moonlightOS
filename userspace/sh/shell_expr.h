/*
 * shell_expr.h - Lightweight arithmetic expression parser for moonsh
 *
 * Implements an integer expression evaluator supporting standard C operator
 * precedence without heap allocation:
 * - Parentheses: ( )
 * - Unary: +, -, ~, !
 * - Multiplicative: *, /, %
 * - Additive: +, -
 * - Shifts: <<, >>
 * - Comparisons: ==, !=, <, <=, >, >=
 * - Bitwise: &, ^, |
 * - Logical: &&, ||
 */

#ifndef SHELL_EXPR_H
#define SHELL_EXPR_H

#include <stdint.h>

typedef struct
{
    const char *p;
    int error;
} expr_ctx_t;

static inline void expr_skip_ws(expr_ctx_t *ctx)
{
    while (*ctx->p == ' ' || *ctx->p == '\t')
        ctx->p++;
}

static int64_t expr_parse_or(expr_ctx_t *ctx);

/* Number or parenthesized expression */
static int64_t expr_parse_primary(expr_ctx_t *ctx)
{
    expr_skip_ws(ctx);
    if (*ctx->p == '(')
    {
        ctx->p++;
        int64_t val = expr_parse_or(ctx);
        expr_skip_ws(ctx);
        if (*ctx->p == ')')
        {
            ctx->p++;
        }
        else
        {
            ctx->error = 1; /* Mismatched paren */
        }
        return val;
    }

    /* Unary operators */
    if (*ctx->p == '-')
    {
        ctx->p++;
        return -expr_parse_primary(ctx);
    }
    if (*ctx->p == '+')
    {
        ctx->p++;
        return expr_parse_primary(ctx);
    }
    if (*ctx->p == '~')
    {
        ctx->p++;
        return ~expr_parse_primary(ctx);
    }
    if (*ctx->p == '!')
    {
        ctx->p++;
        return !expr_parse_primary(ctx);
    }

    /* Integer literal (decimal or hex) */
    if (*ctx->p == '0' && (*(ctx->p + 1) == 'x' || *(ctx->p + 1) == 'X'))
    {
        ctx->p += 2;
        int64_t val = 0;
        int digits = 0;
        while (1)
        {
            char c = *ctx->p;
            int d = -1;
            if (c >= '0' && c <= '9')
                d = c - '0';
            else if (c >= 'a' && c <= 'f')
                d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F')
                d = c - 'A' + 10;
            if (d < 0)
                break;
            val = (val << 4) | (int64_t)d;
            digits++;
            ctx->p++;
        }
        if (digits == 0)
            ctx->error = 1;
        return val;
    }

    if (*ctx->p >= '0' && *ctx->p <= '9')
    {
        int64_t val = 0;
        while (*ctx->p >= '0' && *ctx->p <= '9')
        {
            val = val * 10 + (*ctx->p - '0');
            ctx->p++;
        }
        return val;
    }

    ctx->error = 1;
    return 0;
}

/* Multiplicative: *, /, % */
static int64_t expr_parse_mul(expr_ctx_t *ctx)
{
    int64_t left = expr_parse_primary(ctx);
    while (1)
    {
        expr_skip_ws(ctx);
        if (*ctx->p == '*' && *(ctx->p + 1) != '=')
        {
            ctx->p++;
            left = left * expr_parse_primary(ctx);
        }
        else if (*ctx->p == '/' && *(ctx->p + 1) != '=')
        {
            ctx->p++;
            int64_t right = expr_parse_primary(ctx);
            if (right == 0)
            {
                ctx->error = 2; /* Div by zero */
                return 0;
            }
            left = left / right;
        }
        else if (*ctx->p == '%' && *(ctx->p + 1) != '=')
        {
            ctx->p++;
            int64_t right = expr_parse_primary(ctx);
            if (right == 0)
            {
                ctx->error = 2; /* Div by zero */
                return 0;
            }
            left = left % right;
        }
        else
        {
            break;
        }
    }
    return left;
}

/* Additive: +, - */
static int64_t expr_parse_add(expr_ctx_t *ctx)
{
    int64_t left = expr_parse_mul(ctx);
    while (1)
    {
        expr_skip_ws(ctx);
        if (*ctx->p == '+' && *(ctx->p + 1) != '+' && *(ctx->p + 1) != '=')
        {
            ctx->p++;
            left = left + expr_parse_mul(ctx);
        }
        else if (*ctx->p == '-' && *(ctx->p + 1) != '-' && *(ctx->p + 1) != '=')
        {
            ctx->p++;
            left = left - expr_parse_mul(ctx);
        }
        else
        {
            break;
        }
    }
    return left;
}

/* Bitwise shift: <<, >> */
static int64_t expr_parse_shift(expr_ctx_t *ctx)
{
    int64_t left = expr_parse_add(ctx);
    while (1)
    {
        expr_skip_ws(ctx);
        if (*ctx->p == '<' && *(ctx->p + 1) == '<')
        {
            ctx->p += 2;
            left = left << expr_parse_add(ctx);
        }
        else if (*ctx->p == '>' && *(ctx->p + 1) == '>')
        {
            ctx->p += 2;
            left = left >> expr_parse_add(ctx);
        }
        else
        {
            break;
        }
    }
    return left;
}

/* Relational: <, <=, >, >= */
static int64_t expr_parse_rel(expr_ctx_t *ctx)
{
    int64_t left = expr_parse_shift(ctx);
    while (1)
    {
        expr_skip_ws(ctx);
        if (*ctx->p == '<' && *(ctx->p + 1) == '=')
        {
            ctx->p += 2;
            left = (left <= expr_parse_shift(ctx));
        }
        else if (*ctx->p == '>' && *(ctx->p + 1) == '=')
        {
            ctx->p += 2;
            left = (left >= expr_parse_shift(ctx));
        }
        else if (*ctx->p == '<' && *(ctx->p + 1) != '<')
        {
            ctx->p++;
            left = (left < expr_parse_shift(ctx));
        }
        else if (*ctx->p == '>' && *(ctx->p + 1) != '>')
        {
            ctx->p++;
            left = (left > expr_parse_shift(ctx));
        }
        else
        {
            break;
        }
    }
    return left;
}

/* Equality: ==, != */
static int64_t expr_parse_eq(expr_ctx_t *ctx)
{
    int64_t left = expr_parse_rel(ctx);
    while (1)
    {
        expr_skip_ws(ctx);
        if (*ctx->p == '=' && *(ctx->p + 1) == '=')
        {
            ctx->p += 2;
            left = (left == expr_parse_rel(ctx));
        }
        else if (*ctx->p == '!' && *(ctx->p + 1) == '=')
        {
            ctx->p += 2;
            left = (left != expr_parse_rel(ctx));
        }
        else
        {
            break;
        }
    }
    return left;
}

/* Bitwise AND: & */
static int64_t expr_parse_band(expr_ctx_t *ctx)
{
    int64_t left = expr_parse_eq(ctx);
    while (1)
    {
        expr_skip_ws(ctx);
        if (*ctx->p == '&' && *(ctx->p + 1) != '&')
        {
            ctx->p++;
            left = left & expr_parse_eq(ctx);
        }
        else
        {
            break;
        }
    }
    return left;
}

/* Bitwise XOR: ^ */
static int64_t expr_parse_bxor(expr_ctx_t *ctx)
{
    int64_t left = expr_parse_band(ctx);
    while (1)
    {
        expr_skip_ws(ctx);
        if (*ctx->p == '^')
        {
            ctx->p++;
            left = left ^ expr_parse_band(ctx);
        }
        else
        {
            break;
        }
    }
    return left;
}

/* Bitwise OR: | */
static int64_t expr_parse_bor(expr_ctx_t *ctx)
{
    int64_t left = expr_parse_bxor(ctx);
    while (1)
    {
        expr_skip_ws(ctx);
        if (*ctx->p == '|' && *(ctx->p + 1) != '|')
        {
            ctx->p++;
            left = left | expr_parse_bxor(ctx);
        }
        else
        {
            break;
        }
    }
    return left;
}

/* Logical AND: && */
static int64_t expr_parse_land(expr_ctx_t *ctx)
{
    int64_t left = expr_parse_bor(ctx);
    while (1)
    {
        expr_skip_ws(ctx);
        if (*ctx->p == '&' && *(ctx->p + 1) == '&')
        {
            ctx->p += 2;
            int64_t right = expr_parse_bor(ctx);
            left = (left && right);
        }
        else
        {
            break;
        }
    }
    return left;
}

/* Logical OR: || */
static int64_t expr_parse_or(expr_ctx_t *ctx)
{
    int64_t left = expr_parse_land(ctx);
    while (1)
    {
        expr_skip_ws(ctx);
        if (*ctx->p == '|' && *(ctx->p + 1) == '|')
        {
            ctx->p += 2;
            int64_t right = expr_parse_land(ctx);
            left = (left || right);
        }
        else
        {
            break;
        }
    }
    return left;
}

/* Public evaluation function */
static inline int shell_eval_expr(const char *expr_str, int64_t *out_val)
{
    expr_ctx_t ctx;
    ctx.p = expr_str;
    ctx.error = 0;
    int64_t res = expr_parse_or(&ctx);
    expr_skip_ws(&ctx);
    if (*ctx.p != '\0' || ctx.error != 0)
    {
        return -1; /* Syntax or evaluation error */
    }
    *out_val = res;
    return 0;
}

#endif /* SHELL_EXPR_H */
