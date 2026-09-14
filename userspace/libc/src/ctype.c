/* libc ctype (ASCII). */
#include <ctype.h>

int isalpha(int c) { return isupper(c) || islower(c); }

int isdigit(int c) { return c >= '0' && c <= '9'; }

int isalnum(int c) { return isalpha(c) || isdigit(c); }

int isspace(int c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
           c == '\v';
}

int isupper(int c) { return c >= 'A' && c <= 'Z'; }

int islower(int c) { return c >= 'a' && c <= 'z'; }

int isxdigit(int c) {
    return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

int isprint(int c) { return c >= 32 && c < 127; }

int iscntrl(int c) { return c < 32 || c == 127; }

int ispunct(int c) { return isprint(c) && !isalnum(c) && c != ' '; }

int isblank(int c) { return c == ' ' || c == '\t'; }

int isascii(int c) { return c >= 0 && c < 128; }

int isgraph(int c) { return c > 32 && c < 127; }

int toascii(int c) { return c & 0x7F; }

int tolower(int c) { return isupper(c) ? c + 32 : c; }

int toupper(int c) { return islower(c) ? c - 32 : c; }
