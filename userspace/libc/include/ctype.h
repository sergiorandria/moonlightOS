/* Moonlight libc - ctype (ASCII only, no locale). */
#pragma once

int isalpha(int c);
int isdigit(int c);
int isalnum(int c);
int isspace(int c);
int isupper(int c);
int islower(int c);
int isxdigit(int c);
int isprint(int c);
int iscntrl(int c);
int ispunct(int c);
int isblank(int c);
int isascii(int c);
int isgraph(int c);
int tolower(int c);
int toupper(int c);
int toascii(int c);
