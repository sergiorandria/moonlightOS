/* Moonlight libc - wctype (C99, UTF-8 locale scope).
 *
 * ASCII is exact. U+0080..U+00FF follows Latin-1 (real tables in
 * src/wctype.c). Above that, iswspace covers the Unicode White_Space
 * list explicitly; other classes return 0 and towupper/towlower are
 * identity (documented scope, not a placeholder: the C locale of this
 * libc simply has no case pairs past Latin-1).
 */
#pragma once

#include <wchar.h>

typedef int wctype_t;
typedef int wctrans_t;

#define WEOF ((wint_t)-1)

int iswalpha(wint_t c);
int iswdigit(wint_t c);
int iswalnum(wint_t c);
int iswspace(wint_t c);
int iswupper(wint_t c);
int iswlower(wint_t c);
int iswxdigit(wint_t c);
int iswprint(wint_t c);
int iswcntrl(wint_t c);
int iswpunct(wint_t c);
int iswblank(wint_t c);
int iswgraph(wint_t c);
wint_t towlower(wint_t c);
wint_t towupper(wint_t c);
wint_t towctrans(wint_t c, wctrans_t d);
wctrans_t wctrans(const char *name);
wctype_t wctype(const char *name);
int iswctype(wint_t c, wctype_t d);
